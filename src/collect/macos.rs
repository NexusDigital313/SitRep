//! macOS collector: the unified log, launchd, and the diagnostic reports.

use super::{Collection, CollectOpts, FailedUnit, hostname, run};
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

    let span = resolve_span(&opts.since);
    c.scope = format!("unified log, last {span}");

    collect_unified_log(&mut c, &span, opts);
    collect_launchd(&mut c);
    collect_crash_reports(&mut c);

    super::finish(&mut c, opts);
    Ok(c)
}

/// `log show` has no notion of "this boot", so translate that into a duration.
fn resolve_span(since: &str) -> String {
    if since != "boot" {
        return since.to_string();
    }
    // kern.boottime prints: { sec = 1788722345, usec = 381803 } Sun Sep  6 ...
    let Ok(out) = run("sysctl", &["-n", "kern.boottime"]) else {
        return "1h".into();
    };
    let Some(secs) = out
        .split("sec = ")
        .nth(1)
        .and_then(|s| s.split(|c: char| !c.is_ascii_digit()).next())
        .and_then(|s| s.parse::<i64>().ok())
    else {
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
}

/// `launchctl list` columns are PID, last exit status, label. A status of "-"
/// means it has not run; anything else non-zero means it ended badly.
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
        let (Some(_pid), Some(status), Some(label)) = (cols.next(), cols.next(), cols.next())
        else {
            continue;
        };
        let status = status.trim();
        if status == "-" || status == "0" {
            continue;
        }
        let Ok(code) = status.parse::<i32>() else {
            continue;
        };

        let detail = if code < 0 {
            format!("killed by signal {} ({})", -code, signal_name(-code))
        } else {
            format!("exited with status {code}")
        };

        c.failed_units
            .push(FailedUnit { name: label.trim().to_string(), detail: detail.clone() });

        // Synthesized so the rule engine can explain it like any other line.
        let msg = format!("{}: Service exited with abnormal code {code} — {detail}", label.trim());
        c.events.push(
            Event::new(Source::Launchd, Severity::Warning, msg.clone())
                .with_message(msg)
                .with_unit(Some(label.trim().to_string())),
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
    let mut dirs: Vec<std::path::PathBuf> =
        vec!["/Library/Logs/DiagnosticReports".into()];
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
            if entry.metadata().and_then(|m| m.modified()).is_ok_and(|m| m < cutoff) {
                continue;
            }

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
    fn non_boot_span_passes_through() {
        assert_eq!(resolve_span("2h"), "2h");
    }
}
