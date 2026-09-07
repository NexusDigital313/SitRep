//! Platform collectors. Each one shells out to the native logging tools and
//! normalizes whatever comes back into `Event`s.

use crate::event::{Event, Severity};
use anyhow::Result;
use regex::Regex;
use serde_json::Value;
use std::process::Command;
use std::sync::LazyLock;

// Both collectors compile everywhere — they use nothing but std, serde and
// jiff, and shelling out to a missing command is already handled. Only the
// dispatch below is conditional. This keeps the Linux collector type-checked
// and unit-tested when building on a Mac, which is where it is developed.
// The collector for the other platform is compiled but never called here.
#[cfg_attr(target_os = "macos", allow(dead_code))]
pub mod linux;
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub mod macos;

#[cfg(not(target_os = "macos"))]
pub use linux as platform;
#[cfg(target_os = "macos")]
pub use macos as platform;

pub mod piped;

/// journald fields are usually strings, but binary or multi-valued fields come
/// back as arrays of byte values or arrays of strings.
fn field_text(v: &Value, key: &str) -> Option<String> {
    match v.get(key)? {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Array(items) => {
            // An array of numbers is raw bytes; an array of strings is a
            // repeated field, of which the first is representative.
            if items.iter().all(|i| i.is_number()) {
                let bytes: Vec<u8> =
                    items.iter().filter_map(|i| i.as_u64()).map(|n| n as u8).collect();
                Some(String::from_utf8_lossy(&bytes).into_owned())
            } else {
                items.first().and_then(|i| i.as_str()).map(str::to_string)
            }
        }
        _ => None,
    }
}

/// journald timestamps are microseconds since the epoch, as a string.
fn format_micros(us: &str) -> Option<String> {
    let micros: i64 = us.parse().ok()?;
    jiff::Timestamp::from_microsecond(micros)
        .ok()
        .map(|ts| ts.strftime("%Y-%m-%d %H:%M:%S").to_string())
}

#[derive(Debug, Clone)]
pub struct CollectOpts {
    /// How far back to look, in the native syntax of the platform's tool
    /// ("1h", "2 days ago", "boot").
    pub since: String,
    /// Hard cap on events kept, so a screaming machine cannot exhaust memory.
    pub max_events: usize,
    /// Include notice/info as well as warning-and-worse.
    pub include_info: bool,
}

impl Default for CollectOpts {
    fn default() -> Self {
        Self { since: "boot".into(), max_events: 20_000, include_info: false }
    }
}

/// A service that is currently in a failed state, as opposed to a log line
/// about something that failed once in the past.
#[derive(Debug, Clone)]
pub struct FailedUnit {
    pub name: String,
    pub detail: String,
}

/// Everything one run gathered.
#[derive(Debug, Default)]
pub struct Collection {
    pub hostname: String,
    pub os: String,
    pub uptime: Option<String>,
    /// Human description of what was searched, for the report header.
    pub scope: String,
    pub events: Vec<Event>,
    pub failed_units: Vec<FailedUnit>,
    /// Things that went wrong while collecting — a missing command, a
    /// permission problem. Surfaced so the report never silently under-reports.
    pub notes: Vec<String>,
}

/// Sorts worst-first and applies the event cap, noting the cap if it bites.
///
/// Sorting before truncating matters: if the cap is hit, the lines that survive
/// are the most severe ones, not an arbitrary prefix.
pub fn finish(c: &mut Collection, opts: &CollectOpts) {
    // Stable sort, so equal-severity events keep chronological order.
    c.events.sort_by_key(|e| e.severity);
    if c.events.len() > opts.max_events {
        c.notes.push(format!(
            "more than {} notable lines — kept the {} most severe and stopped there; \
             narrow the window with --since to see the rest",
            opts.max_events, opts.max_events
        ));
        c.events.truncate(opts.max_events);
    }
}

/// Runs a command and returns stdout. Never panics; a missing binary or a
/// non-zero exit becomes an `Err` the caller turns into a collection note.
pub fn run(program: &str, args: &[&str]) -> std::result::Result<String, String> {
    let out = Command::new(program).args(args).output().map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => format!("`{program}` is not installed"),
        std::io::ErrorKind::PermissionDenied => format!("not allowed to run `{program}`"),
        _ => format!("could not run `{program}`: {e}"),
    })?;

    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();

    // Some tools (journalctl without privileges, log show under sandbox) exit
    // non-zero but still print usable output. Keep it if there is any.
    if !out.status.success() && stdout.trim().is_empty() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let first = stderr.lines().next().unwrap_or("no output").trim();
        return Err(format!("`{program}` failed: {first}"));
    }

    Ok(stdout)
}

/// Best-effort severity for a line with no structured level attached, used for
/// piped input and for text-mode fallbacks.
pub fn guess_severity(line: &str) -> Severity {
    let l = line.to_ascii_lowercase();
    // Ordered most severe first; the first hit wins.
    const MARKERS: &[(&str, Severity)] = &[
        ("panic", Severity::Emergency),
        ("emergency", Severity::Emergency),
        ("fatal", Severity::Critical),
        ("critical", Severity::Critical),
        ("segfault", Severity::Critical),
        ("out of memory", Severity::Critical),
        ("error", Severity::Error),
        ("failed", Severity::Error),
        ("failure", Severity::Error),
        ("cannot", Severity::Error),
        ("denied", Severity::Warning),
        ("warning", Severity::Warning),
        ("warn", Severity::Warning),
        ("deprecated", Severity::Notice),
    ];
    for (needle, sev) in MARKERS {
        if l.contains(needle) {
            return *sev;
        }
    }
    Severity::Info
}

/// Splits a log line into (message, unit, pid) by removing the preamble.
///
/// Both patterns are anchored and require a real timestamp. An earlier version
/// simply cut at the first `": "` in the line, which silently destroyed the
/// message whenever the preamble had no colon of its own: macOS compact lines
/// like
///
/// ```text
/// 2026-09-07 02:33:32.176 E  kernel[0:58fab] (Sandbox) ... for Sandbox: WebKit(11425) deny(1) ...
/// ```
///
/// had their `Sandbox: ` stripped as if it were the preamble, so the rule
/// looking for exactly that text could never fire. Leaving a line untouched is
/// always safe; over-trimming is not.
fn syslog_preamble() -> &'static Regex {
    static RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"(?x)
            ^
            (?:<\d{1,3}>)?                                   # optional syslog priority
            (?:
                \w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}       # Sep  7 01:02:03
              | \d{4}-\d{2}-\d{2}[T\ ]\d{2}:\d{2}:\d{2}   # 2026-09-07T01:02:03
                (?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?
            )
            \s+
            (?:[\w.-]+\s+)?                                 # optional hostname
            (?P<tag>[\w.@/-]+)                               # sshd, kernel, nginx.service
            (?:\[(?P<pid>\d+)\])?
            :\ +
            ",
        )
        .expect("static preamble pattern")
    });
    &RE
}

/// macOS `log stream --style compact`: no colon after the process name.
fn compact_preamble() -> &'static Regex {
    static RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+\s+\S{1,3}\s+(?P<tag>[\w.-]+)\[(?P<pid>\d+)(?::[0-9a-fx]+)?\]\s+",
        )
        .expect("static compact pattern")
    });
    &RE
}

pub fn strip_preamble(line: &str) -> (&str, Option<String>, Option<u32>) {
    for re in [syslog_preamble(), compact_preamble()] {
        let Some(caps) = re.captures(line) else { continue };
        let whole = caps.get(0).expect("group 0 always exists");
        return (
            &line[whole.end()..],
            caps.name("tag").map(|m| m.as_str().to_string()),
            caps.name("pid").and_then(|m| m.as_str().parse().ok()),
        );
    }
    (line, None, None)
}

/// Reads whatever the platform offers.
pub fn collect(opts: &CollectOpts) -> Result<Collection> {
    platform::collect(opts)
}

/// Shared helper: the machine's name, however the platform spells it.
pub fn hostname() -> String {
    run("hostname", &["-s"])
        .or_else(|_| run("hostname", &[]))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "this machine".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_syslog_preamble_with_pid() {
        let line = "Sep  7 01:02:03 web01 sshd[4821]: Failed password for root from 10.0.0.1";
        let (msg, unit, pid) = strip_preamble(line);
        assert_eq!(msg, "Failed password for root from 10.0.0.1");
        assert_eq!(unit.as_deref(), Some("sshd"));
        assert_eq!(pid, Some(4821));
    }

    #[test]
    fn strips_preamble_without_pid() {
        let line = "Sep  7 01:02:03 web01 kernel: Out of memory";
        let (msg, unit, pid) = strip_preamble(line);
        assert_eq!(msg, "Out of memory");
        assert_eq!(unit.as_deref(), Some("kernel"));
        assert_eq!(pid, None);
    }

    #[test]
    fn keeps_a_message_whose_own_text_contains_a_colon() {
        // The regression that motivated anchoring: the rule for this line looks
        // for the literal "Sandbox: ", which the old first-colon logic ate.
        let line = "2026-09-07 02:33:32.176 E  kernel[0:58fab] (Sandbox) 20 duplicate \
reports for Sandbox: com.apple.WebKit.Networking(11425) deny(1) mach-lookup";
        let (msg, unit, pid) = strip_preamble(line);
        assert!(msg.contains("Sandbox: com.apple.WebKit.Networking(11425) deny(1)"), "{msg}");
        assert_eq!(unit.as_deref(), Some("kernel"));
        assert_eq!(pid, Some(0));
    }

    #[test]
    fn parses_an_iso_timestamped_syslog_line() {
        let line = "2026-09-07T01:02:03+00:00 web01 nginx[221]: upstream timed out";
        let (msg, unit, pid) = strip_preamble(line);
        assert_eq!(msg, "upstream timed out");
        assert_eq!(unit.as_deref(), Some("nginx"));
        assert_eq!(pid, Some(221));
    }

    #[test]
    fn does_not_trim_a_line_that_merely_contains_a_colon() {
        let line = "error: could not connect to database: timeout";
        let (msg, unit, _) = strip_preamble(line);
        assert_eq!(msg, line, "no timestamp means no preamble to strip");
        assert_eq!(unit, None);
    }

    #[test]
    fn leaves_plain_lines_alone() {
        let line = "just some text with no preamble at all";
        let (msg, _, _) = strip_preamble(line);
        assert_eq!(msg, line);
    }

    #[test]
    fn severity_guessing_prefers_the_worst_marker() {
        assert_eq!(guess_severity("kernel panic - not syncing"), Severity::Emergency);
        assert_eq!(guess_severity("Failed to start nginx"), Severity::Error);
        assert_eq!(guess_severity("nothing interesting here"), Severity::Info);
    }

    #[test]
    fn reads_plain_string_fields() {
        let v = serde_json::json!({"MESSAGE": "hello"});
        assert_eq!(field_text(&v, "MESSAGE").as_deref(), Some("hello"));
    }

    #[test]
    fn decodes_byte_array_messages() {
        // journald encodes non-UTF8 messages as an array of byte values.
        let v = serde_json::json!({"MESSAGE": [104, 105]});
        assert_eq!(field_text(&v, "MESSAGE").as_deref(), Some("hi"));
    }

    #[test]
    fn takes_first_of_a_repeated_field() {
        let v = serde_json::json!({"_SYSTEMD_UNIT": ["a.service", "b.service"]});
        assert_eq!(field_text(&v, "_SYSTEMD_UNIT").as_deref(), Some("a.service"));
    }

    #[test]
    fn missing_field_is_none() {
        assert_eq!(field_text(&serde_json::json!({}), "NOPE"), None);
    }

    #[test]
    fn formats_journald_microseconds() {
        assert_eq!(format_micros("1609459200000000").as_deref(), Some("2021-01-01 00:00:00"));
    }

    #[test]
    fn rejects_unparseable_timestamp() {
        assert_eq!(format_micros("not-a-number"), None);
    }

    #[test]
    fn missing_binary_is_an_error_not_a_panic() {
        assert!(run("definitely-not-a-real-binary-xyz", &[]).is_err());
    }
}
