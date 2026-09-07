//! Output. The goal is a page that reads like a report rather than a terminal
//! dump: a status bar, a verdict badge, and findings in colour-gutter blocks.
//!
//! Colour is applied through `if_supports_color`, so redirecting to a file or
//! setting NO_COLOR yields clean plain text with no escape codes and no
//! separate code path to keep in sync.

use crate::event::Severity;
use crate::report::{Report, Verdict};
use owo_colors::{OwoColorize, Style, Stream};

/// Terminal width, clamped: prose past ~100 columns is hard to read, and a
/// terminal narrower than 60 gets a fixed floor rather than broken layout.
pub fn width() -> usize {
    // COLUMNS wins when set, so the output can be pinned in scripts and tests;
    // otherwise ask the terminal.
    std::env::var("COLUMNS")
        .ok()
        .and_then(|c| c.trim().parse::<usize>().ok())
        .or_else(|| terminal_size::terminal_size().map(|(terminal_size::Width(w), _)| w as usize))
        .unwrap_or(80)
        .clamp(60, 100)
}

fn severity_style(s: Severity) -> Style {
    match s {
        Severity::Emergency | Severity::Alert | Severity::Critical => {
            Style::new().bright_red().bold()
        }
        Severity::Error => Style::new().red(),
        Severity::Warning => Style::new().yellow(),
        Severity::Notice => Style::new().cyan(),
        _ => Style::new().dimmed(),
    }
}

fn verdict_style(v: Verdict) -> Style {
    match v {
        Verdict::Critical => Style::new().on_bright_red().black().bold(),
        Verdict::Degraded => Style::new().on_yellow().black().bold(),
        Verdict::Noisy => Style::new().on_cyan().black().bold(),
        Verdict::Healthy => Style::new().on_green().black().bold(),
    }
}

/// Greedy word wrap.
///
/// Rule text comes from TOML block strings, which carry incidental line breaks
/// wherever the rule author happened to wrap the source. Those are not real
/// breaks, so paragraphs are reflowed as a whole; only a blank line separates
/// one paragraph from the next. A dedicated crate would handle CJK and
/// combining marks better, but log prose is overwhelmingly ASCII.
pub(crate) fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();

    // Blank lines are the only paragraph separator; everything else reflows.
    let paragraphs: Vec<String> = text
        .split("\n\n")
        .map(|p| p.split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|p| !p.is_empty())
        .collect();

    for (i, paragraph) in paragraphs.iter().enumerate() {
        if i > 0 {
            lines.push(String::new());
        }
        let mut current = String::new();
        for word in paragraph.split_whitespace() {
            if current.is_empty() {
                current.push_str(word);
            } else if current.chars().count() + 1 + word.chars().count() <= width {
                current.push(' ');
                current.push_str(word);
            } else {
                lines.push(std::mem::take(&mut current));
                current.push_str(word);
            }
        }
        if !current.is_empty() {
            lines.push(current);
        }
    }

    lines
}

/// Cuts a string to a column budget, adding an ellipsis if it had to.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let keep = max.saturating_sub(1);
    let mut out: String = s.chars().take(keep).collect();
    out.push('…');
    out
}

pub fn pretty(report: &Report) -> String {
    let w = width();
    let mut out = String::new();

    header(&mut out, report, w);
    verdict_banner(&mut out, report, w);
    failed_units(&mut out, report, w);
    findings(&mut out, report, w);
    unexplained(&mut out, report, w);
    notes(&mut out, report, w);
    footer(&mut out, report, w);

    out
}

fn header(out: &mut String, r: &Report, w: usize) {
    let left = " SITREP ";
    let right = format!("{} · {} ", r.hostname, r.os);
    let gap = w.saturating_sub(left.chars().count() + right.chars().count());
    let bar = format!("{left}{}{right}", " ".repeat(gap));

    let style = Style::new().on_blue().bright_white().bold();
    out.push('\n');
    out.push_str(&format!("{}\n", bar.if_supports_color(Stream::Stdout, |t| t.style(style))));
}

fn verdict_banner(out: &mut String, r: &Report, w: usize) {
    let badge = format!(" {} ", r.verdict.label());
    let style = verdict_style(r.verdict);

    out.push('\n');
    out.push_str(&format!(
        "  {}  {}\n",
        badge.if_supports_color(Stream::Stdout, |t| t.style(style)),
        r.verdict.summary()
    ));

    let mut facts = vec![
        format!("{} line{} scanned", thousands(r.scanned), if r.scanned == 1 { "" } else { "s" }),
        r.scope.clone(),
    ];
    if let Some(up) = &r.uptime {
        facts.push(format!("up {up}"));
    }
    let line = truncate(&facts.join("  ·  "), w.saturating_sub(4));
    out.push_str(&format!(
        "  {}\n",
        line.if_supports_color(Stream::Stdout, |t| t.dimmed())
    ));
}

fn section(out: &mut String, title: &str, w: usize) {
    let head = format!("── {title} ");
    let rule = format!("{head}{}", "─".repeat(w.saturating_sub(head.chars().count())));
    out.push('\n');
    out.push_str(&format!(
        "{}\n\n",
        rule.if_supports_color(Stream::Stdout, |t| t.style(Style::new().bold()))
    ));
}

fn failed_units(out: &mut String, r: &Report, w: usize) {
    if r.failed_units.is_empty() {
        return;
    }
    section(out, "BROKEN RIGHT NOW", w);

    let name_col = r
        .failed_units
        .iter()
        .map(|u| u.name.chars().count())
        .max()
        .unwrap_or(20)
        .min(w.saturating_sub(30));

    for unit in &r.failed_units {
        let name = truncate(&unit.name, name_col);
        let pad = " ".repeat(name_col.saturating_sub(name.chars().count()));
        out.push_str(&format!(
            "  {} {}{}  {}\n",
            "✗".if_supports_color(Stream::Stdout, |t| t.red()),
            name.if_supports_color(Stream::Stdout, |t| t.style(Style::new().bold())),
            pad,
            unit.detail.if_supports_color(Stream::Stdout, |t| t.dimmed())
        ));
    }
}

fn findings(out: &mut String, r: &Report, w: usize) {
    if r.findings.is_empty() {
        return;
    }
    section(out, "FINDINGS", w);

    let inner = w.saturating_sub(5);

    for (i, f) in r.findings.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        let style = severity_style(f.severity);
        let bar = "▌".if_supports_color(Stream::Stdout, |t| t.style(style)).to_string();
        let mut push = |text: &str| {
            if text.is_empty() {
                out.push_str(&format!(" {bar}\n"));
            } else {
                out.push_str(&format!(" {bar} {text}\n"));
            }
        };

        // Headline: SEVERITY, title, and an occurrence count pinned right.
        let count = if f.count > 1 { format!("×{}", f.count) } else { String::new() };
        let label = f.severity.label();
        let budget = inner.saturating_sub(label.chars().count() + count.chars().count() + 4);
        let title = truncate(&f.title, budget);
        let gap = inner
            .saturating_sub(label.chars().count() + 2 + title.chars().count() + count.chars().count());

        push(&format!(
            "{}  {}{}{}",
            label.if_supports_color(Stream::Stdout, |t| t.style(style)),
            title.if_supports_color(Stream::Stdout, |t| t.style(Style::new().bold())),
            " ".repeat(gap),
            count.if_supports_color(Stream::Stdout, |t| t.dimmed())
        ));
        push("");

        for line in wrap(&f.means, inner) {
            push(&line);
        }

        if !f.cause.is_empty() {
            push("");
            push(&format!(
                "{}",
                "LIKELY CAUSE".if_supports_color(Stream::Stdout, |t| t.style(Style::new().bold().dimmed()))
            ));
            for c in &f.cause {
                for (n, line) in wrap(c, inner.saturating_sub(4)).into_iter().enumerate() {
                    push(&format!("{}{line}", if n == 0 { "  • " } else { "    " }));
                }
            }
        }

        if !f.fix.is_empty() {
            push("");
            push(&format!(
                "{}",
                "WHAT TO DO".if_supports_color(Stream::Stdout, |t| t.style(Style::new().bold().dimmed()))
            ));
            for (n, step) in f.fix.iter().enumerate() {
                for (l, line) in wrap(step, inner.saturating_sub(5)).into_iter().enumerate() {
                    let prefix = if l == 0 { format!("  {}. ", n + 1) } else { "     ".into() };
                    push(&format!("{prefix}{line}"));
                }
            }
        }

        // Provenance: when, and against what.
        let mut meta = Vec::new();
        if let (Some(a), Some(b)) = (&f.first_seen, &f.last_seen) {
            meta.push(if a == b { a.clone() } else { format!("{a} → {b}") });
        }
        if !f.units.is_empty() {
            let units: Vec<&str> = f.units.iter().take(4).map(String::as_str).collect();
            let more = f.units.len().saturating_sub(units.len());
            meta.push(if more > 0 {
                format!("{} +{more} more", units.join(", "))
            } else {
                units.join(", ")
            });
        }
        if !meta.is_empty() {
            push("");
            let line = truncate(&meta.join("   "), inner);
            push(&format!("{}", line.if_supports_color(Stream::Stdout, |t| t.dimmed())));
        }
    }
}

fn unexplained(out: &mut String, r: &Report, w: usize) {
    if r.unexplained.is_empty() {
        return;
    }
    section(out, "NOT RECOGNISED", w);
    out.push_str(&format!(
        "  {}\n\n",
        "No rule explains these. Grouped by shape, worst first."
            .if_supports_color(Stream::Stdout, |t| t.dimmed())
    ));

    for u in &r.unexplained {
        let style = severity_style(u.severity);
        let count = if u.count > 1 { format!(" ×{}", u.count) } else { String::new() };
        let prefix = format!("  {:<9}", u.severity.label());
        let budget = w.saturating_sub(prefix.chars().count() + count.chars().count() + 2);

        out.push_str(&format!(
            "{}{}{}\n",
            prefix.if_supports_color(Stream::Stdout, |t| t.style(style)),
            truncate(u.sample.trim(), budget),
            count.if_supports_color(Stream::Stdout, |t| t.dimmed())
        ));
    }
}

fn notes(out: &mut String, r: &Report, w: usize) {
    if r.notes.is_empty() {
        return;
    }
    section(out, "SCAN WAS INCOMPLETE", w);
    for n in &r.notes {
        for (i, line) in wrap(n, w.saturating_sub(6)).into_iter().enumerate() {
            out.push_str(&format!("  {}{line}\n", if i == 0 { "! " } else { "  " }));
        }
    }
}

fn footer(out: &mut String, r: &Report, _w: usize) {
    if r.verdict == Verdict::Healthy && r.unexplained.is_empty() {
        out.push_str(&format!(
            "\n  {}\n",
            "Nothing to report. That is the good outcome."
                .if_supports_color(Stream::Stdout, |t| t.dimmed())
        ));
    }
    out.push('\n');
}

/// 1284 -> "1,284"
fn thousands(n: usize) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// Styling helpers for the parts of the CLI that print outside a report.
///
/// `OwoColorize::dimmed()` and friends emit escape codes unconditionally, which
/// corrupts redirected output. Everything here goes through
/// `if_supports_color`, so it degrades the same way the report does.
pub fn dim(s: &str) -> String {
    s.if_supports_color(Stream::Stdout, |t| t.dimmed()).to_string()
}

pub fn bold(s: &str) -> String {
    s.if_supports_color(Stream::Stdout, |t| t.bold()).to_string()
}

pub fn green(s: &str) -> String {
    s.if_supports_color(Stream::Stdout, |t| t.green()).to_string()
}

pub fn yellow(s: &str) -> String {
    s.if_supports_color(Stream::Stdout, |t| t.yellow()).to_string()
}

/// The inverse-video severity chip used by `sitrep watch`.
pub fn badge(severity: Severity) -> String {
    let (text, style) = match severity {
        Severity::Emergency | Severity::Alert | Severity::Critical => {
            (" CRIT ", Style::new().on_bright_red().black().bold())
        }
        Severity::Error => (" ERR  ", Style::new().on_red().black().bold()),
        Severity::Warning => (" WARN ", Style::new().on_yellow().black().bold()),
        _ => (" NOTE ", Style::new().on_cyan().black().bold()),
    };
    text.if_supports_color(Stream::Stdout, |t| t.style(style)).to_string()
}

/// Forces colour on or off regardless of what the terminal reports.
pub fn set_color_override(on: bool) {
    owo_colors::set_override(on);
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraps_at_the_requested_width() {
        let lines = wrap("the quick brown fox jumps over the lazy dog", 12);
        assert!(lines.iter().all(|l| l.chars().count() <= 12), "{lines:?}");
        assert_eq!(lines.join(" "), "the quick brown fox jumps over the lazy dog");
    }

    #[test]
    fn wrapping_does_not_split_an_overlong_word() {
        let lines = wrap("supercalifragilistic", 5);
        assert_eq!(lines, vec!["supercalifragilistic"]);
    }

    #[test]
    fn wrapping_trims_the_blank_lines_toml_leaves_behind() {
        let lines = wrap("\n\nhello\n\n", 40);
        assert_eq!(lines, vec!["hello"]);
    }

    #[test]
    fn reflows_across_the_source_line_breaks_toml_introduces() {
        // A TOML block string wrapped by its author at an arbitrary column.
        let text = "macOS stopped an application from touching a file\nor resource \
outside what it is\npermitted to access.";
        let lines = wrap(text, 60);
        assert!(lines.iter().all(|l| l.chars().count() <= 60), "{lines:?}");
        // No orphan fragments left behind by the source formatting.
        assert!(!lines.iter().any(|l| l.trim() == "it is"), "{lines:?}");
        assert_eq!(lines.len(), 2, "should reflow into full lines: {lines:?}");
    }

    #[test]
    fn a_blank_line_still_separates_paragraphs() {
        let lines = wrap("first para\n\nsecond para", 40);
        assert_eq!(lines, vec!["first para", "", "second para"]);
    }

    #[test]
    fn truncate_marks_what_it_cut() {
        assert_eq!(truncate("hello world", 8), "hello w…");
        assert_eq!(truncate("short", 8), "short");
    }

    #[test]
    fn groups_thousands() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1284), "1,284");
        assert_eq!(thousands(1234567), "1,234,567");
    }
}
