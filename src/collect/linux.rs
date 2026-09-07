//! Linux collector: journald, systemd unit state, and the kernel ring buffer.
//!
//! Everything goes through `journalctl -o json` rather than text output. The
//! text formats have changed across systemd versions and lose the unit and
//! priority fields; the JSON export is stable and unambiguous.

use super::{
    Collection, CollectOpts, FailedUnit, field_text, format_micros, guess_severity, hostname, run,
    strip_preamble,
};
use crate::event::{Event, Severity, Source};
use anyhow::Result;
use serde_json::Value;

pub fn collect(opts: &CollectOpts) -> Result<Collection> {
    let mut c = Collection { hostname: hostname(), ..Default::default() };

    c.os = read_os_pretty_name().unwrap_or_else(|| "Linux".into());
    c.uptime = run("uptime", &["-p"]).ok().map(|s| s.trim().trim_start_matches("up ").to_string());

    let (window, scope) = match opts.since.as_str() {
        "boot" => (vec!["-b".to_string()], "this boot".to_string()),
        other => (vec!["--since".into(), other.into()], format!("since {other}")),
    };
    c.scope = format!("journal, {scope}");

    collect_journal(&mut c, &window, opts);
    collect_failed_units(&mut c);

    if c.events.is_empty() && c.notes.iter().any(|n| n.contains("journalctl")) {
        collect_syslog_fallback(&mut c);
    }

    super::finish(&mut c, opts);
    Ok(c)
}

fn collect_journal(c: &mut Collection, window: &[String], opts: &CollectOpts) {
    let priority = if opts.include_info { "6" } else { "4" };

    let mut args: Vec<&str> = vec!["--no-pager", "-o", "json", "-p", priority];
    args.extend(window.iter().map(String::as_str));

    let out = match run("journalctl", &args) {
        Ok(o) => o,
        Err(e) => {
            c.notes.push(format!("could not read the journal: {e}"));
            return;
        }
    };

    let mut seen_kernel = false;
    for line in out.lines() {
        let line = line.trim();
        if !line.starts_with('{') {
            continue;
        }
        let Ok(v) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let Some(message) = field_text(&v, "MESSAGE") else {
            continue;
        };
        if message.is_empty() {
            continue;
        }

        let transport = field_text(&v, "_TRANSPORT").unwrap_or_default();
        let is_kernel = transport == "kernel";
        seen_kernel |= is_kernel;

        let unit = field_text(&v, "_SYSTEMD_UNIT")
            .or_else(|| field_text(&v, "SYSLOG_IDENTIFIER"))
            .or_else(|| field_text(&v, "_COMM"));

        let source = if is_kernel {
            Source::Kernel
        } else if unit.as_deref().is_some_and(|u| u.ends_with(".service")) {
            Source::Systemd
        } else {
            Source::Journal
        };

        let severity = field_text(&v, "PRIORITY")
            .and_then(|p| p.parse::<u8>().ok())
            .map(Severity::from_syslog)
            .unwrap_or_else(|| guess_severity(&message));

        let timestamp = field_text(&v, "__REALTIME_TIMESTAMP").and_then(|us| format_micros(&us));
        let pid = field_text(&v, "_PID").and_then(|p| p.parse::<u32>().ok());

        let raw = format!(
            "{} {}: {}",
            timestamp.as_deref().unwrap_or("?"),
            unit.as_deref().unwrap_or("?"),
            message
        );

        c.events.push(
            Event::new(source, severity, raw)
                .with_message(message)
                .with_timestamp(timestamp)
                .with_unit(unit)
                .with_pid(pid),
        );
    }

    // A journal with no kernel records usually means the journal is not
    // persistent, or we lack the group membership to see them.
    if !seen_kernel {
        collect_dmesg(c);
    }
}

/// Only used when the journal did not surface kernel records.
fn collect_dmesg(c: &mut Collection) {
    let Ok(out) = run("dmesg", &["--level=emerg,alert,crit,err,warn", "--notime"])
        .or_else(|_| run("dmesg", &[]))
    else {
        c.notes.push("kernel messages unavailable (try running with sudo)".into());
        return;
    };

    for line in out.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // dmesg without --notime prefixes "[  123.456] ".
        let message = line
            .strip_prefix('[')
            .and_then(|r| r.split_once("] "))
            .map(|(_, m)| m)
            .unwrap_or(line);

        c.events.push(
            Event::new(Source::Kernel, guess_severity(message), line).with_message(message),
        );
    }
}

fn collect_failed_units(c: &mut Collection) {
    let out = match run(
        "systemctl",
        &["--failed", "--no-legend", "--no-pager", "--plain", "--all"],
    ) {
        Ok(o) => o,
        Err(e) => {
            c.notes.push(format!("could not list failed units: {e}"));
            return;
        }
    };

    for line in out.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut cols = line.split_whitespace();
        let Some(name) = cols.next() else { continue };
        // UNIT LOAD ACTIVE SUB DESCRIPTION...
        let rest: Vec<&str> = cols.collect();
        let detail = if rest.len() > 3 { rest[3..].join(" ") } else { rest.join(" ") };

        c.failed_units.push(FailedUnit {
            name: name.to_string(),
            detail: if detail.is_empty() { "failed".into() } else { detail },
        });
    }
}

/// Last resort for non-systemd machines, or where the journal is unreadable.
fn collect_syslog_fallback(c: &mut Collection) {
    for path in ["/var/log/syslog", "/var/log/messages"] {
        let Ok(body) = std::fs::read_to_string(path) else {
            continue;
        };
        c.notes.push(format!("journal unavailable — read {path} instead"));
        c.scope = format!("{path} (tail)");

        // Only the tail; these files can be enormous.
        for line in body.lines().rev().take(5000) {
            let (message, unit, pid) = strip_preamble(line);
            // No severity filter — see the note in collect::piped::from_text.
            let severity = guess_severity(message);
            let source = if unit.as_deref() == Some("kernel") { Source::Kernel } else { Source::Journal };
            c.events.push(
                Event::new(source, severity, line)
                    .with_message(message)
                    .with_unit(unit)
                    .with_pid(pid),
            );
        }
        return;
    }
}

fn read_os_pretty_name() -> Option<String> {
    let body = std::fs::read_to_string("/etc/os-release").ok()?;
    body.lines()
        .find_map(|l| l.strip_prefix("PRETTY_NAME="))
        .map(|v| v.trim_matches('"').to_string())
}

