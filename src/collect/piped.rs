//! Reads logs from a file or stdin instead of from the live system.
//!
//! This is what lets a Mac analyse a Linux box:
//!   ssh web01 journalctl -b -o json | SitRep -
//!
//! Format is sniffed rather than declared, because asking the user to label
//! their own paste is a bad trade for a few lines of detection.

use super::{CollectOpts, Collection, field_text, format_micros, guess_severity, strip_preamble};
use crate::event::{Event, Severity, Source};
use anyhow::{Context, Result};
use serde_json::Value;
use std::io::Read;

#[derive(Debug, PartialEq, Clone, Copy)]
enum Format {
    /// journalctl -o json
    JournalJson,
    /// macOS `log show --style ndjson`
    UnifiedNdjson,
    /// Anything else — syslog-ish text, or a raw paste.
    Text,
}

/// Logs are not guaranteed to be valid UTF-8 — a truncated write or a device
/// spewing binary will produce stray bytes — and refusing to read the whole
/// file over one of them is the wrong trade. Replace them and carry on.
fn read_lossy_stdin() -> Result<String> {
    let mut bytes = Vec::new();
    std::io::stdin().read_to_end(&mut bytes).context("reading stdin")?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Reads stdin only if it is actually carrying something.
///
/// Testing `is_terminal()` alone is not enough: under cron, systemd, or a CI
/// runner stdin is a pipe or /dev/null with nothing in it, and treating that as
/// "the user piped me logs" would silently report on zero lines. Returning
/// `None` lets the caller fall through to scanning the live machine.
pub fn try_stdin(opts: &CollectOpts) -> Result<Option<Collection>> {
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        return Ok(None);
    }

    let buf = read_lossy_stdin()?;
    if buf.trim().is_empty() {
        return Ok(None);
    }

    Ok(Some(from_text(buf, "standard input", opts)))
}

pub fn collect(path: Option<&str>, opts: &CollectOpts) -> Result<Collection> {
    let (body, origin) = match path {
        None | Some("-") => (read_lossy_stdin()?, "standard input".to_string()),
        Some(p) => {
            let bytes = std::fs::read(p).with_context(|| format!("reading {p}"))?;
            (String::from_utf8_lossy(&bytes).into_owned(), p.to_string())
        }
    };

    Ok(from_text(body, &origin, opts))
}

fn from_text(body: String, origin: &str, opts: &CollectOpts) -> Collection {
    let format = sniff(&body);
    let mut c = Collection {
        hostname: "(piped input)".into(),
        os: "unknown".into(),
        scope: format!("{origin} ({})", describe(format)),
        ..Default::default()
    };

    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let event = match format {
            Format::JournalJson => parse_journal_json(line),
            Format::UnifiedNdjson => parse_unified_ndjson(line),
            Format::Text => Some(parse_text(line)),
        };
        // Deliberately no severity filter here. For plain text the severity is
        // only a guess from keywords, and a line like "System clock time
        // jumped" guesses as info while a rule would rank it a warning. The
        // report layer drops non-notable lines that no rule claimed, which is
        // the right place for that decision.
        if let Some(e) = event {
            c.events.push(e);
        }
    }

    if c.events.is_empty() {
        c.notes.push("no log lines could be read from the input".into());
    }

    super::finish(&mut c, opts);
    c
}

/// Looks at the first few non-blank lines rather than only the first, since
/// tools sometimes emit a banner before the data.
fn sniff(body: &str) -> Format {
    for line in body.lines().filter(|l| !l.trim().is_empty()).take(5) {
        let line = line.trim();
        if !line.starts_with('{') {
            continue;
        }
        if line.contains("\"MESSAGE\"") || line.contains("\"__REALTIME_TIMESTAMP\"") {
            return Format::JournalJson;
        }
        if line.contains("\"eventMessage\"") || line.contains("\"messageType\"") {
            return Format::UnifiedNdjson;
        }
    }
    Format::Text
}

fn describe(f: Format) -> &'static str {
    match f {
        Format::JournalJson => "journald JSON",
        Format::UnifiedNdjson => "macOS unified log",
        Format::Text => "plain text",
    }
}

fn parse_journal_json(line: &str) -> Option<Event> {
    if !line.starts_with('{') {
        return None;
    }
    let v: Value = serde_json::from_str(line).ok()?;
    let message = field_text(&v, "MESSAGE")?;
    if message.is_empty() {
        return None;
    }

    let unit = field_text(&v, "_SYSTEMD_UNIT")
        .or_else(|| field_text(&v, "SYSLOG_IDENTIFIER"))
        .or_else(|| field_text(&v, "_COMM"));

    let source = match field_text(&v, "_TRANSPORT").as_deref() {
        Some("kernel") => Source::Kernel,
        _ if unit.as_deref().is_some_and(|u| u.ends_with(".service")) => Source::Systemd,
        _ => Source::Journal,
    };

    let severity = field_text(&v, "PRIORITY")
        .and_then(|p| p.parse::<u8>().ok())
        .map(Severity::from_syslog)
        .unwrap_or_else(|| guess_severity(&message));

    let timestamp = field_text(&v, "__REALTIME_TIMESTAMP").and_then(|us| format_micros(&us));
    let raw = format!(
        "{} {}: {}",
        timestamp.as_deref().unwrap_or("?"),
        unit.as_deref().unwrap_or("?"),
        message
    );

    Some(
        Event::new(source, severity, raw)
            .with_message(message)
            .with_timestamp(timestamp)
            .with_unit(unit)
            .with_pid(field_text(&v, "_PID").and_then(|p| p.parse().ok())),
    )
}

fn parse_unified_ndjson(line: &str) -> Option<Event> {
    if !line.starts_with('{') {
        return None;
    }
    let v: Value = serde_json::from_str(line).ok()?;
    let message = v.get("eventMessage")?.as_str()?.to_string();
    if message.is_empty() {
        return None;
    }

    let severity = v
        .get("messageType")
        .and_then(|m| m.as_str())
        .map(Severity::from_macos)
        .unwrap_or_else(|| guess_severity(&message));

    let unit = v
        .get("processImagePath")
        .and_then(|p| p.as_str())
        .and_then(|p| p.rsplit('/').next())
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let timestamp = v.get("timestamp").and_then(|t| t.as_str()).map(str::to_string);
    let raw = format!(
        "{} {}: {}",
        timestamp.as_deref().unwrap_or("?"),
        unit.as_deref().unwrap_or("?"),
        message
    );

    Some(
        Event::new(Source::UnifiedLog, severity, raw)
            .with_message(message)
            .with_timestamp(timestamp)
            .with_unit(unit)
            .with_pid(v.get("processID").and_then(|p| p.as_u64()).map(|p| p as u32)),
    )
}

fn parse_text(line: &str) -> Event {
    let (message, unit, pid) = strip_preamble(line);
    let source = if unit.as_deref() == Some("kernel") { Source::Kernel } else { Source::Piped };
    Event::new(source, guess_severity(message), line)
        .with_message(message)
        .with_unit(unit)
        .with_pid(pid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniffs_journald_json() {
        let body = r#"{"MESSAGE":"hi","PRIORITY":"3"}"#;
        assert_eq!(sniff(body), Format::JournalJson);
    }

    #[test]
    fn sniffs_macos_ndjson() {
        let body = r#"{"eventMessage":"hi","messageType":"Error"}"#;
        assert_eq!(sniff(body), Format::UnifiedNdjson);
    }

    #[test]
    fn sniffs_plain_text() {
        assert_eq!(sniff("Sep  7 01:02:03 host sshd[1]: nope"), Format::Text);
    }

    #[test]
    fn sniffs_past_a_leading_banner() {
        let body = "Filtering the log data using ...\n{\"eventMessage\":\"hi\"}";
        assert_eq!(sniff(body), Format::UnifiedNdjson);
    }

    #[test]
    fn parses_a_journald_record() {
        let line = r#"{"MESSAGE":"Out of memory: Killed process 1 (x)","PRIORITY":"2","_TRANSPORT":"kernel","_PID":"1"}"#;
        let e = parse_journal_json(line).expect("should parse");
        assert_eq!(e.severity, Severity::Critical);
        assert_eq!(e.source, Source::Kernel);
        assert_eq!(e.pid, Some(1));
    }

    #[test]
    fn classifies_a_dot_service_unit_as_systemd() {
        let line = r#"{"MESSAGE":"boom","PRIORITY":"3","_SYSTEMD_UNIT":"nginx.service"}"#;
        assert_eq!(parse_journal_json(line).unwrap().source, Source::Systemd);
    }

    #[test]
    fn skips_records_with_no_message() {
        assert!(parse_journal_json(r#"{"PRIORITY":"3"}"#).is_none());
        assert!(parse_journal_json("not json").is_none());
    }

    #[test]
    fn keeps_lines_a_rule_can_rank_even_when_the_keyword_guess_is_info() {
        // "System clock time jumped" has no severity keyword, so guess_severity
        // rates it info — but linux.ntp-unsync explains it as a warning. The
        // reader must not drop it before the rules ever see it.
        let body = "Sep  7 03:13:01 web01 chronyd[701]: System clock time jumped by -4.2 seconds\n";
        let c = from_text(body.to_string(), "test", &CollectOpts::default());
        assert_eq!(c.events.len(), 1, "line was dropped before rule matching");
        assert_eq!(c.events[0].severity, Severity::Info, "guess is info, as expected");
    }

    #[test]
    fn text_lines_keep_their_unit_and_pid() {
        let e = parse_text("Sep  7 01:02:03 web01 sshd[4821]: Failed password for root");
        assert_eq!(e.unit.as_deref(), Some("sshd"));
        assert_eq!(e.pid, Some(4821));
        assert_eq!(e.severity, Severity::Error);
    }
}
