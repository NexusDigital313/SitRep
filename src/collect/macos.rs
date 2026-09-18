//! macOS collector: the unified log, launchd, and the diagnostic reports.

use super::{CollectOpts, Collection, FailedUnit, TS_FORMAT, hostname, run};
use crate::event::{Event, Severity, Source};
use anyhow::Result;
use serde::Deserialize;

/// One line of `log show --style ndjson`. Unlisted fields (notably `backtrace`,
/// which can be enormous) are ignored by serde and never allocated.
#[derive(Deserialize)]
struct LogLine {
    #[serde(default)]
    timestamp: String,
    #[serde(default, rename = "messageType")]
    message_type: String,
    #[serde(default, rename = "eventMessage")]
    event_message: String,
    #[serde(default, rename = "processImagePath")]
    process_image_path: String,
    #[serde(default, rename = "processID")]
    process_id: Option<i64>,
    #[serde(default)]
    subsystem: String,
}

pub fn collect(opts: &CollectOpts) -> Result<Collection> {
    let mut c = Collection { hostname: hostname(), ..Default::default() };

    c.os = match (run("sw_vers", &["-productName"]), run("sw_vers", &["-productVersion"])) {
        (Ok(n), Ok(v)) => format!("{} {}", n.trim(), v.trim()),
        _ => "macOS".into(),
    };
    c.uptime = run("uptime", &[]).ok().and_then(|s| parse_uptime(&s));

    c.boot_window = boot_window();

    let span = resolve_span(&opts.since);
    c.scope = format!("unified log, last {span}");

    collect_unified_log(&mut c, &span, opts);
    collect_launchd(&mut c);
    collect_crash_reports(&mut c);

    super::finish(&mut c, opts);
    Ok(c)
}

/// Dozens of services start at once at boot and race each other for sockets,
/// databases and hardware. They lose races they win on the retry seconds
/// later, so anything that stopped happening inside this window is startup
/// noise rather than a live fault.
const BOOT_SETTLE_SECS: i64 = 120;

/// kern.boottime prints: { sec = 1788722345, usec = 381803 } Sun Sep  6 ...
fn boot_time_secs() -> Option<i64> {
    let out = run("sysctl", &["-n", "kern.boottime"]).ok()?;
    out.split("sec = ")
        .nth(1)
        .and_then(|s| s.split(|c: char| !c.is_ascii_digit()).next())
        .and_then(|s| s.parse::<i64>().ok())
}

/// The settling window as (boot, boot + settle), in local
/// `YYYY-MM-DD HH:MM:SS` — the same shape and zone `log show` prints, so the
/// two compare as plain strings.
fn boot_window() -> Option<(String, String)> {
    let secs = boot_time_secs()?;
    Some((local_stamp(secs)?, local_stamp(secs + BOOT_SETTLE_SECS)?))
}

/// Unix seconds as a local timestamp in `TS_FORMAT`.
fn local_stamp(secs: i64) -> Option<String> {
    jiff::Timestamp::from_second(secs)
        .ok()
        .map(|ts| ts.to_zoned(jiff::tz::TimeZone::system()).strftime(TS_FORMAT).to_string())
}

/// `log show` has no notion of "this boot", so translate that into a duration.
fn resolve_span(since: &str) -> String {
    if since != "boot" {
        return since.to_string();
    }
    let Some(secs) = boot_time_secs() else {
        return "1h".into();
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(secs);

    // Round up to the hour, and keep the window sane on a long-lived machine —
    // `log show` gets very slow over multi-day spans.
    let hours = ((now - secs) / 3600 + 1).clamp(1, 24);
    format!("{hours}h")
}

fn collect_unified_log(c: &mut Collection, span: &str, opts: &CollectOpts) {
    let predicate = if opts.include_info {
        "messageType >= 16 OR messageType == 0"
    } else {
        "messageType >= 16"
    };

    let out = match run(
        "/usr/bin/log",
        &["show", "--last", span, "--style", "ndjson", "--predicate", predicate],
    ) {
        Ok(o) => o,
        Err(e) => {
            c.notes.push(format!("could not read the unified log: {e}"));
            return;
        }
    };

    let mut total = 0usize;
    let mut redacted = 0usize;

    for line in out.lines() {
        let line = line.trim();
        if !line.starts_with('{') {
            continue;
        }
        let Ok(entry) = serde_json::from_str::<LogLine>(line) else {
            continue;
        };
        if entry.event_message.is_empty() {
            continue;
        }

        total += 1;
        if entry.event_message.contains("<private>") {
            redacted += 1;
        }

        let process = entry
            .process_image_path
            .rsplit('/')
            .next()
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .or_else(|| (!entry.subsystem.is_empty()).then(|| entry.subsystem.clone()));

        let raw = format!(
            "{} {}: {}",
            entry.timestamp,
            process.as_deref().unwrap_or("?"),
            entry.event_message
        );

        c.events.push(
            Event::new(Source::UnifiedLog, Severity::from_macos(&entry.message_type), raw)
                .with_message(entry.event_message)
                .with_timestamp(Some(entry.timestamp))
                .with_unit(process)
                .with_pid(entry.process_id.and_then(|p| u32::try_from(p).ok())),
        );
    }

    if let Some(note) = redaction_note(total, redacted) {
        c.notes.push(note);
    }
}

/// The macOS counterpart to Linux's "kernel messages unavailable" warning.
/// macOS replaces private values — paths, process names, the thing that actually
/// failed — with `<private>` at the moment the message is written, so a rule that
/// would have matched on that text silently does not. Worth saying out loud
/// rather than reporting a clean bill of health.
///
/// Do not reword this to suggest re-running under sudo. Measured on macOS 26.6:
/// the same 20-minute window read as root and as the user returned an identical
/// 707 of 5904 lines redacted. Privilege makes no difference to what is already
/// written; only enabling private-data logging does, and only from then on.
fn redaction_note(total: usize, redacted: usize) -> Option<String> {
    // A handful of redacted lines is normal and not worth a warning; a large
    // share of them means the scan genuinely could not see what happened.
    if total == 0 || redacted * 10 < total {
        return None;
    }
    let pct = (redacted * 100).div_ceil(total);
    Some(format!(
        "{redacted} of {total} log lines ({pct}%) hid their details as <private>, so rules \
that match on those details cannot fire. The logging system redacts as it writes, so \
re-reading will not recover them; enabling private-data logging needs admin rights and \
only affects messages logged afterwards."
    ))
}

/// `launchctl list` columns are PID, last exit status, label.
///
/// The PID column is the one that says whether a job is broken *now*: a number
/// means it is running, "-" means it is not. The status column is the exit
/// code of its *last* run, which a perfectly healthy running job still carries
/// after failing once and recovering. Reading status alone reports recovered
/// jobs as currently broken.
fn collect_launchd(c: &mut Collection) {
    let out = match run("launchctl", &["list"]) {
        Ok(o) => o,
        Err(e) => {
            c.notes.push(format!("could not query launchd: {e}"));
            return;
        }
    };

    for line in out.lines().skip(1) {
        let mut cols = line.split('\t');
        let (Some(pid), Some(status), Some(label)) = (cols.next(), cols.next(), cols.next()) else {
            continue;
        };
        let status = status.trim();
        if status == "-" || status == "0" {
            continue;
        }
        let Ok(code) = status.parse::<i32>() else {
            continue;
        };

        let running = pid.trim().parse::<u32>().is_ok();
        let label = label.trim().to_string();

        let how = if code < 0 {
            format!("killed by signal {} ({})", -code, signal_name(-code))
        } else {
            format!("exited with status {code}")
        };
        let detail = if running {
            format!("running now; a previous run {how}")
        } else {
            format!("not running; last run {how}")
        };

        c.failed_units.push(FailedUnit { name: label.clone(), detail, running });

        // Synthesized so the rule engine can explain it like any other line.
        // The wording says only what `launchctl list` actually proves — that a
        // run ended badly. Whether launchd is *throttling* the job is a further
        // claim that needs a throttle message to back it, so it belongs to the
        // rule that matches one, not to every non-zero exit code.
        let msg = if running {
            format!("{label}: launchd job is running; a previous run {how}")
        } else {
            format!("{label}: launchd job is not running; last run {how}")
        };
        let severity = if running { Severity::Notice } else { Severity::Warning };
        c.events.push(
            Event::new(Source::Launchd, severity, msg.clone())
                .with_message(msg)
                .with_unit(Some(label)),
        );
    }
}

fn signal_name(n: i32) -> &'static str {
    match n {
        2 => "SIGINT",
        3 => "SIGQUIT",
        4 => "SIGILL",
        6 => "SIGABRT",
        9 => "SIGKILL",
        11 => "SIGSEGV",
        15 => "SIGTERM",
        _ => "unknown",
    }
}

/// Crash reports are files, not log lines. Their filenames alone say enough to
/// be worth reporting; reading every report body would be slow and mostly noise.
fn collect_crash_reports(c: &mut Collection) {
    let mut dirs: Vec<std::path::PathBuf> = vec!["/Library/Logs/DiagnosticReports".into()];
    if let Some(home) = std::env::var_os("HOME") {
        dirs.push(std::path::Path::new(&home).join("Library/Logs/DiagnosticReports"));
    }

    let cutoff = std::time::SystemTime::now() - std::time::Duration::from_secs(7 * 24 * 3600);

    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
                continue;
            };
            // .diag files are routine performance samples, not crashes.
            if !matches!(ext, "ips" | "crash" | "panic" | "hang") {
                continue;
            }
            let modified = entry.metadata().and_then(|m| m.modified()).ok();
            if modified.is_some_and(|m| m < cutoff) {
                continue;
            }
            // Without a timestamp a crash report cannot be told from a current
            // one, and a week-old crash ends up setting today's verdict.
            let timestamp = modified
                .and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok())
                .and_then(|d| local_stamp(d.as_secs() as i64));

            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("?");
            let process = name.split('_').next().unwrap_or(name);

            let (severity, what) = match ext {
                "panic" => (Severity::Critical, "Kernel panic report"),
                "hang" => (Severity::Warning, "Application Not Responding — hang report"),
                _ => (Severity::Error, "Crashed Thread — crash report"),
            };

            let msg = format!("{what} for {process} ({name})");
            c.events.push(
                Event::new(Source::Crash, severity, msg.clone())
                    .with_message(msg)
                    .with_timestamp(timestamp)
                    .with_unit(Some(process.to_string())),
            );
        }
    }
}

/// Pulls "up 10:54" out of the uptime line, ignoring load averages.
fn parse_uptime(s: &str) -> Option<String> {
    let start = s.find("up ")? + 3;
    let rest = &s[start..];
    let end = rest.find(", load").or_else(|| rest.find(" user")).unwrap_or(rest.len());
    let trimmed = rest[..end].trim().trim_end_matches(',');
    let cleaned = trimmed.rsplit_once(", ").map(|(a, _)| a).unwrap_or(trimmed);
    let normalized = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    (!normalized.is_empty()).then_some(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_uptime_line() {
        let s = " 2:12  up 10:54, 4 users, load averages: 1.27 1.33 1.24";
        assert_eq!(parse_uptime(s).as_deref(), Some("10:54"));
    }

    #[test]
    fn parses_multi_day_uptime() {
        let s = "10:15  up 3 days,  2:41, 2 users, load averages: 2.1 1.9 1.7";
        assert_eq!(parse_uptime(s).as_deref(), Some("3 days, 2:41"));
    }

    #[test]
    fn ndjson_line_with_backtrace_deserializes() {
        let raw = r#"{"messageType":"Fault","eventMessage":"boom","processImagePath":"/usr/libexec/airportd","processID":461,"subsystem":"com.apple.WiFiManager","timestamp":"2026-09-07 01:43:02.768977-0400","backtrace":{"frames":[{"imageOffset":1,"imageUUID":"X"}]}}"#;
        let parsed: LogLine = serde_json::from_str(raw).expect("should ignore backtrace");
        assert_eq!(parsed.event_message, "boom");
        assert_eq!(parsed.process_id, Some(461));
        assert_eq!(Severity::from_macos(&parsed.message_type), Severity::Error);
    }

    #[test]
    fn heavy_redaction_is_reported_as_an_incomplete_scan() {
        let note = redaction_note(100, 40).expect("40% redacted should warn");
        assert!(note.contains("40%"), "note should quantify: {note}");
        assert!(note.contains("private-data logging"), "note should say what would help: {note}");
        assert!(
            !note.to_lowercase().contains("re-run with sudo"),
            "must not promise that re-reading recovers already-redacted lines: {note}"
        );
        assert!(!note.contains("  "), "note must not carry stray padding: {note:?}");
    }

    #[test]
    fn incidental_redaction_stays_quiet() {
        assert_eq!(redaction_note(100, 5), None, "a few <private> lines are normal");
        assert_eq!(redaction_note(0, 0), None, "an empty scan warns about nothing");
    }

    #[test]
    fn non_boot_span_passes_through() {
        assert_eq!(resolve_span("2h"), "2h");
    }
}
