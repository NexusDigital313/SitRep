mod cli;
mod collect;
mod event;
mod render;
mod report;
mod rules;

use anyhow::Result;
use clap::{CommandFactory, FromArgMatches};
use cli::{Cli, Command};
use collect::CollectOpts;
use event::{Event, Source};
use report::Verdict;
use rules::RuleSet;
use std::io::IsTerminal;

/// The command is installed under a platform-specific name (`MacSitrep`,
/// `LinuxSitRep`) symlinked to the canonical `sitrep` binary. Parsing through
/// argv[0] rather than `Cli::parse()` means `--help` and every usage and error
/// message names whichever alias the user actually typed, instead of always
/// saying "sitrep".
fn invoked_as() -> &'static str {
    std::env::args_os()
        .next()
        .as_deref()
        .map(std::path::Path::new)
        .and_then(std::path::Path::file_name)
        .map(|n| n.to_string_lossy().into_owned())
        .filter(|n| !n.is_empty())
        // clap wants a 'static name. Leaking one short string that lives as
        // long as the process is the honest way to say "this never frees".
        .map(|n| &*n.leak())
        .unwrap_or("sitrep")
}

fn main() {
    let name = invoked_as();
    let matches = Cli::command().name(name).bin_name(name).get_matches();
    let args = match Cli::from_arg_matches(&matches) {
        Ok(a) => a,
        Err(e) => e.exit(),
    };

    // Decide colour once, globally. render.rs asks the terminal per-write via
    // if_supports_color, but this file styles a few strings directly; an
    // override keeps both honest when output is redirected to a file.
    if args.no_color || !std::io::stdout().is_terminal() {
        render::set_color_override(false);
    }

    match run(&args) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("sitrep: {e:#}");
            std::process::exit(3);
        }
    }
}

fn run(args: &Cli) -> Result<i32> {
    let (mut ruleset, mut problems) = RuleSet::builtin();

    // User rules extend the builtins; ~/.config/sitrep/rules is checked even
    // when --rules-dir is not given.
    let dir = args.rules_dir.clone().map(std::path::PathBuf::from).or_else(default_rules_dir);
    if let Some(dir) = dir {
        problems.extend(ruleset.load_dir(&dir)?);
    }
    for p in &problems {
        eprintln!("sitrep: {p}");
    }

    match &args.command {
        Some(Command::Rules { tag }) => {
            list_rules(&ruleset, tag.as_deref());
            Ok(0)
        }
        Some(Command::Explain { text }) => explain(&ruleset, text, args),
        Some(Command::Learn { write }) => learn(&ruleset, args, *write),
        Some(Command::Watch) => watch(&ruleset, args),
        None => scan(&ruleset, args),
    }
}

fn default_rules_dir() -> Option<std::path::PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| std::path::Path::new(&h).join(".config")))?;
    Some(base.join("sitrep/rules"))
}

fn opts_from(args: &Cli) -> CollectOpts {
    CollectOpts { since: args.since.clone(), include_info: args.all, ..Default::default() }
}

/// The default action: read this machine (or the piped input) and report.
fn scan(ruleset: &RuleSet, args: &Cli) -> Result<i32> {
    let opts = opts_from(args);

    // Piped input wins over the live system, and is detected rather than
    // declared — `... | sitrep` should simply work.
    let collection = match &args.file {
        Some(path) => collect::piped::collect(Some(path), &opts)?,
        None => match collect::piped::try_stdin(&opts)? {
            Some(c) => c,
            None => collect::collect(&opts)?,
        },
    };

    let report = report::build(collection, ruleset, args.all);

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print!("{}", render::pretty(&report));
    }

    Ok(if args.exit_code {
        match report.verdict {
            Verdict::Critical => 2,
            Verdict::Degraded => 1,
            _ => 0,
        }
    } else {
        0
    })
}

/// Translate one line handed over on the command line or on stdin.
fn explain(ruleset: &RuleSet, text: &[String], args: &Cli) -> Result<i32> {
    let line = if text.is_empty() {
        let mut buf = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)?;
        buf.trim().to_string()
    } else {
        text.join(" ")
    };

    if line.is_empty() {
        eprintln!("sitrep: nothing to explain — pass a log line, or pipe one in");
        return Ok(3);
    }

    let (message, unit, pid) = collect::strip_preamble(&line);
    let event = Event::new(Source::Piped, collect::guess_severity(&line), &line)
        .with_message(message)
        .with_unit(unit)
        .with_pid(pid);

    let collection = collect::Collection {
        hostname: "(single line)".into(),
        os: "—".into(),
        scope: "one log line".into(),
        events: vec![event],
        ..Default::default()
    };

    let report = report::build(collection, ruleset, args.all);

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(0);
    }

    if report.findings.is_empty() {
        println!("\n  {}\n", render::yellow("No rule recognises that line."));
        println!("  {}", render::dim("It may still be benign. To write your own explanation,"));
        println!("  {}\n", render::dim("run `sitrep learn` — it drafts the rule for you."));
        return Ok(1);
    }

    print!("{}", render::pretty(&report));
    Ok(0)
}

/// Follow the live log, printing a one-line translation for anything a rule
/// recognises. Deliberately terse — this is meant to sit in a second pane.
fn watch(ruleset: &RuleSet, args: &Cli) -> Result<i32> {
    use std::io::{BufRead, BufReader};
    use std::process::{Command as Proc, Stdio};

    let (program, argv) = follow_command(args.all);

    let mut child = Proc::new(program)
        .args(argv)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| anyhow::anyhow!("could not start `{program}` to follow the log: {e}"))?;

    let stdout = child.stdout.take().expect("stdout was piped");
    eprintln!("{}", render::dim(&format!("  watching {program} — press Ctrl-C to stop\n")));

    for line in BufReader::new(stdout).lines().map_while(Result::ok) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (message, unit, pid) = collect::strip_preamble(line);
        let event = Event::new(Source::Piped, collect::guess_severity(line), line)
            .with_message(message)
            .with_unit(unit)
            .with_pid(pid);

        for m in ruleset.explain(&event) {
            println!("{}  {}", render::badge(m.severity), render::bold(&m.title));
            for line in render::wrap(&m.means, render::width().saturating_sub(8)) {
                println!("        {}", render::dim(&line));
            }
            println!();
        }
    }

    let _ = child.wait();
    Ok(0)
}

#[cfg(target_os = "macos")]
fn follow_command(all: bool) -> (&'static str, Vec<&'static str>) {
    let level = if all { "info" } else { "default" };
    ("/usr/bin/log", vec!["stream", "--style", "compact", "--level", level])
}

#[cfg(not(target_os = "macos"))]
fn follow_command(all: bool) -> (&'static str, Vec<&'static str>) {
    let priority = if all { "6" } else { "4" };
    ("journalctl", vec!["-f", "-n", "0", "--no-pager", "-p", priority])
}

/// The offline way this tool gets smarter: look at what this machine actually
/// logs that no rule explains, and write a draft rule for each shape. The
/// human fills in the prose once; every future run knows it.
fn learn(ruleset: &RuleSet, args: &Cli, write: bool) -> Result<i32> {
    let opts = opts_from(args);
    let collection = match &args.file {
        Some(path) => collect::piped::collect(Some(path), &opts)?,
        None => match collect::piped::try_stdin(&opts)? {
            Some(c) => c,
            None => collect::collect(&opts)?,
        },
    };
    let report = report::build(collection, ruleset, args.all);

    if report.unexplained.is_empty() {
        println!(
            "\n  {}\n",
            render::dim("Every notable line was already explained — nothing to learn.")
        );
        return Ok(0);
    }

    let mut toml = String::new();
    toml.push_str("# Drafted by `sitrep learn` from this machine's own logs.\n");
    toml.push_str("# Each stub matched real lines; fill in the prose and it works forever.\n");
    toml.push_str("# Widen the pattern if it looks too specific, then re-run: sitrep rules\n");

    for u in &report.unexplained {
        let seen_on = u.unit.as_deref().map(|x| format!(", from {x}")).unwrap_or_default();
        let severity = format!("{:?}", u.severity).to_lowercase();

        toml.push_str("\n[[rule]]\n");
        toml.push_str(&format!("id = \"local.{}\"\n", rules::derive_id(&u.sample)));
        toml.push_str(&format!("# seen {} time(s){seen_on}\n", u.count));
        toml.push_str(&format!("match = '{}'\n", rules::derive_pattern(&u.sample)));
        toml.push_str(&format!("severity = \"{severity}\"\n"));
        toml.push_str("title = \"TODO: one line a colleague would understand\"\n");
        toml.push_str("means = \"\"\"\nTODO: what is happening, and why it matters.\n\"\"\"\n");
        toml.push_str("cause = [\"TODO: the usual reason\"]\n");
        toml.push_str("fix = [\"TODO: the command that diagnoses or fixes it\"]\n");
        toml.push_str("tags = []\n");
    }

    if !write {
        println!("{toml}");
        eprintln!(
            "  {}",
            render::dim(&format!(
                "{} stub(s). Review, then re-run with --write to install them.",
                report.unexplained.len()
            ))
        );
        return Ok(0);
    }

    let Some(dir) = default_rules_dir() else {
        anyhow::bail!("could not work out where ~/.config/sitrep/rules lives");
    };
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("learned.toml");

    use std::io::Write;
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&path)?;
    write!(f, "{toml}")?;

    println!("\n  {} {}\n", render::green("wrote"), path.display());
    println!(
        "  {}\n",
        render::dim("Fill in the TODOs and they load automatically on the next run.")
    );
    Ok(0)
}

fn list_rules(ruleset: &RuleSet, tag: Option<&str>) {
    let mut shown = 0;
    println!();
    for rule in ruleset.rules() {
        if let Some(t) = tag
            && !rule.tags.iter().any(|x| x == t)
        {
            continue;
        }
        shown += 1;
        // Pad before styling: escape codes have width on the terminal but not
        // on screen, so {:<28} on a styled string mis-aligns the column.
        println!(
            "  {}{}",
            render::bold(&format!("{:<28}", rule.id)),
            rule.title.split(" — ").next().unwrap_or(&rule.title)
        );
        if !rule.tags.is_empty() {
            println!("  {:<28}{}", "", render::dim(&rule.tags.join(", ")));
        }
    }
    println!();
    match tag {
        Some(t) => println!("  {}\n", render::dim(&format!("{shown} rules tagged '{t}'"))),
        None => println!("  {}\n", render::dim(&format!("{shown} rules loaded"))),
    }
}
