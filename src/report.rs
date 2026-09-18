//! Turns a pile of events into a ranked set of findings a person can act on.

use crate::collect::{Collection, FailedUnit, TS_PREFIX};
use crate::event::{Severity, Source};
use crate::rules::{RuleSet, fingerprint};
use serde::Serialize;
use std::collections::{BTreeSet, HashMap};

/// The one-word answer, for anyone who reads nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Healthy,
    Noisy,
    Degraded,
    Critical,
}

impl Verdict {
    pub fn label(self) -> &'static str {
        match self {
            Self::Healthy => "HEALTHY",
            Self::Noisy => "NOISY",
            Self::Degraded => "DEGRADED",
            Self::Critical => "CRITICAL",
        }
    }

    pub fn summary(self) -> &'static str {
        match self {
            Self::Healthy => "Nothing here needs your attention.",
            Self::Noisy => "Some grumbling, but nothing is actually broken.",
            Self::Degraded => "Something is broken and worth looking at.",
            Self::Critical => "Something is seriously wrong. Start at the top.",
        }
    }
}

/// Why a finding is shown but left out of the verdict. The verdict answers
/// "is something wrong *now*"; these are both real, and both history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Stale {
    /// Began and ended inside the post-boot settling window.
    SettledAtBoot,
    /// Happened before the oldest line this run read — a crash report from
    /// yesterday surfacing in a one-hour scan, typically.
    OutsideWindow,
}

/// One explained problem, with every occurrence folded together.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub rule_id: String,
    pub severity: Severity,
    pub title: String,
    pub means: String,
    pub cause: Vec<String>,
    pub fix: Vec<String>,
    pub tags: Vec<String>,
    pub count: usize,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    /// The processes or units this was seen against.
    pub units: BTreeSet<String>,
    /// A few raw lines, as evidence.
    pub samples: Vec<String>,
    /// Set when this is real but not current. Still reported; excluded from
    /// the verdict.
    pub stale: Option<Stale>,
}

/// Lines no rule matched, folded by shape so a thousand near-identical
/// messages occupy one row instead of a thousand.
#[derive(Debug, Clone, Serialize)]
pub struct Unexplained {
    pub severity: Severity,
    pub count: usize,
    pub sample: String,
    pub unit: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub hostname: String,
    pub os: String,
    pub uptime: Option<String>,
    pub scope: String,
    pub verdict: Verdict,
    /// How many log lines were examined.
    pub scanned: usize,
    pub findings: Vec<Finding>,
    pub unexplained: Vec<Unexplained>,
    #[serde(serialize_with = "ser_units")]
    pub failed_units: Vec<FailedUnit>,
    /// Problems encountered while collecting, so a partial scan is never
    /// mistaken for a clean bill of health.
    pub notes: Vec<String>,
}

fn ser_units<S: serde::Serializer>(v: &[FailedUnit], s: S) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeSeq;
    let mut seq = s.serialize_seq(Some(v.len()))?;
    for u in v {
        seq.serialize_element(
            &serde_json::json!({"name": u.name, "detail": u.detail, "running": u.running}),
        )?;
    }
    seq.end()
}

/// How many raw lines to keep as evidence under each finding.
const MAX_SAMPLES: usize = 3;
/// How many distinct unexplained shapes to report.
const MAX_UNEXPLAINED: usize = 12;

/// `include_info` keeps unrecognised lines below warning level in the report;
/// lines a rule explains are always kept, whatever their level.
pub fn build(collection: Collection, rules: &RuleSet, include_info: bool) -> Report {
    // Events may each stand for many identical lines, so the headline count
    // is the sum of their multiplicities, not the number of rows. Launchd and
    // crash-report events are synthesized from other sources rather than read
    // from a log, so they are not lines and are not counted — including them
    // made the header disagree with the redaction note directly below it.
    let scanned: usize = collection
        .events
        .iter()
        .filter(|e| !matches!(e.source, Source::Launchd | Source::Crash))
        .map(|e| e.folded as usize)
        .sum();
    let mut findings: HashMap<(String, String), Finding> = HashMap::new();
    let mut unknown: HashMap<String, Unexplained> = HashMap::new();

    for event in &collection.events {
        let matches = rules.explain(event);

        if matches.is_empty() {
            if !include_info && !event.severity.is_notable() {
                continue;
            }
            let entry = unknown.entry(fingerprint(&event.message)).or_insert_with(|| Unexplained {
                severity: event.severity,
                count: 0,
                sample: event.message.clone(),
                unit: event.unit.clone(),
            });
            entry.count += event.folded as usize;
            entry.severity = entry.severity.min(event.severity);
            continue;
        }

        for m in matches {
            let key = (m.rule.id.clone(), m.title.clone());
            let entry = findings.entry(key).or_insert_with(|| Finding {
                rule_id: m.rule.id.clone(),
                severity: m.severity,
                title: m.title.clone(),
                means: m.means.trim().to_string(),
                cause: m.cause.clone(),
                fix: m.fix.clone(),
                tags: m.rule.tags.clone(),
                count: 0,
                first_seen: None,
                last_seen: None,
                units: BTreeSet::new(),
                samples: Vec::new(),
                stale: None,
            });

            entry.count += event.folded as usize;
            entry.severity = entry.severity.min(m.severity);

            if let Some(unit) = &event.unit {
                entry.units.insert(unit.clone());
            }
            for ts in
                [event.timestamp.as_ref(), event.last_timestamp.as_ref()].into_iter().flatten()
            {
                match &entry.first_seen {
                    Some(f) if f.as_str() <= ts.as_str() => {}
                    _ => entry.first_seen = Some(ts.clone()),
                }
                match &entry.last_seen {
                    Some(l) if l.as_str() >= ts.as_str() => {}
                    _ => entry.last_seen = Some(ts.clone()),
                }
            }
            if entry.samples.len() < MAX_SAMPLES {
                let line = event.raw.trim();
                if !entry.samples.iter().any(|s| s == line) {
                    entry.samples.push(line.to_string());
                }
            }
        }
    }

    let mut findings: Vec<Finding> = findings.into_values().collect();

    // Two ways a finding can be real without being current. Dozens of daemons
    // lose startup races they win on the retry, and a crash report is kept for
    // a week regardless of how short a window was scanned; reporting either as
    // a live fault is how a healthy Mac gets called DEGRADED. They stay in the
    // report, they just do not drive the verdict.
    for f in &mut findings {
        let bounds =
            |t: &Option<String>| t.as_deref().and_then(|t| t.get(..TS_PREFIX)).map(str::to_string);
        let (Some(first), Some(last)) = (bounds(&f.first_seen), bounds(&f.last_seen)) else {
            continue;
        };

        // Checked first: something older than everything read is outside the
        // window whatever else is true of it, including a crash that predates
        // this boot entirely and would otherwise look like a startup race.
        if collection.window_start.as_ref().is_some_and(|start| last.as_str() < start.as_str()) {
            f.stale = Some(Stale::OutsideWindow);
        } else if collection.boot_window.as_ref().is_some_and(|(start, end)| {
            first.as_str() >= start.as_str() && last.as_str() <= end.as_str()
        }) {
            f.stale = Some(Stale::SettledAtBoot);
        }
    }
    // Severity first, then by how often it happened, then alphabetically so
    // two runs over the same data produce byte-identical output.
    // Severity first, then live problems ahead of ones that settled at boot,
    // then by how often it happened, then alphabetically so two runs over the
    // same data produce byte-identical output.
    findings.sort_by(|a, b| {
        a.severity
            .cmp(&b.severity)
            .then(a.stale.is_some().cmp(&b.stale.is_some()))
            .then(b.count.cmp(&a.count))
            .then(a.title.cmp(&b.title))
    });

    let mut unexplained: Vec<Unexplained> = unknown.into_values().collect();
    unexplained.sort_by(|a, b| {
        a.severity.cmp(&b.severity).then(b.count.cmp(&a.count)).then(a.sample.cmp(&b.sample))
    });
    unexplained.truncate(MAX_UNEXPLAINED);

    let verdict = verdict_for(&findings, &collection.failed_units);

    Report {
        hostname: collection.hostname,
        os: collection.os,
        uptime: collection.uptime,
        scope: collection.scope,
        verdict,
        scanned,
        findings,
        unexplained,
        failed_units: collection.failed_units,
        notes: collection.notes,
    }
}

/// The verdict answers "is something wrong *now*", not "did anything ever go
/// wrong". Findings that settled at boot, and jobs that failed once and are
/// running again, are both excluded — they are history, not symptoms.
fn verdict_for(findings: &[Finding], failed: &[FailedUnit]) -> Verdict {
    let worst = findings.iter().filter(|f| f.stale.is_none()).map(|f| f.severity).min();
    let broken_now = failed.iter().any(|u| !u.running);

    match worst {
        Some(s) if s <= Severity::Critical => Verdict::Critical,
        Some(Severity::Error) => Verdict::Degraded,
        _ if broken_now => Verdict::Degraded,
        Some(_) => Verdict::Noisy,
        // Nothing current, but something was reported: grumbling, not breakage.
        None if !findings.is_empty() || !failed.is_empty() => Verdict::Noisy,
        None => Verdict::Healthy,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::Collection;
    use crate::event::{Event, Source};

    fn collection_with(lines: &[(Severity, &str)]) -> Collection {
        Collection {
            hostname: "test".into(),
            events: lines.iter().map(|(sev, msg)| Event::new(Source::Kernel, *sev, *msg)).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn identical_problems_fold_into_one_finding_with_a_count() {
        let (rules, _) = RuleSet::builtin();
        let c = collection_with(&[
            (Severity::Critical, "Out of memory: Killed process 100 (mysqld)"),
            (Severity::Critical, "Out of memory: Killed process 200 (mysqld)"),
        ]);
        let r = build(c, &rules, false);
        let oom: Vec<_> = r.findings.iter().filter(|f| f.rule_id == "linux.oom-killer").collect();
        assert_eq!(oom.len(), 1, "same process should fold to one finding");
        assert_eq!(oom[0].count, 2);
    }

    #[test]
    fn different_processes_stay_separate_findings() {
        let (rules, _) = RuleSet::builtin();
        let c = collection_with(&[
            (Severity::Critical, "Out of memory: Killed process 100 (mysqld)"),
            (Severity::Critical, "Out of memory: Killed process 200 (nginx)"),
        ]);
        let r = build(c, &rules, false);
        let oom = r.findings.iter().filter(|f| f.rule_id == "linux.oom-killer").count();
        assert_eq!(oom, 2);
    }

    #[test]
    fn the_oom_title_names_the_process_it_killed() {
        let (rules, _) = RuleSet::builtin();
        let c =
            collection_with(&[(Severity::Critical, "Out of memory: Killed process 4821 (mysqld)")]);
        let r = build(c, &rules, false);
        assert!(
            r.findings.iter().any(|f| f.title.contains("mysqld")),
            "expected the captured process name in the title, got {:?}",
            r.findings.iter().map(|f| &f.title).collect::<Vec<_>>()
        );
    }

    #[test]
    fn unmatched_lines_group_by_shape() {
        let (rules, _) = RuleSet::builtin();
        let c = collection_with(&[
            (Severity::Error, "widget 4 exploded after 91 attempts"),
            (Severity::Error, "widget 7 exploded after 12 attempts"),
        ]);
        let r = build(c, &rules, false);
        assert_eq!(r.unexplained.len(), 1);
        assert_eq!(r.unexplained[0].count, 2);
    }

    #[test]
    fn all_keeps_unrecognised_info_lines_that_the_default_hides() {
        let (rules, _) = RuleSet::builtin();
        let quiet = &[(Severity::Info, "nothing anyone needs to know about")];
        assert!(build(collection_with(quiet), &rules, false).unexplained.is_empty());
        assert_eq!(build(collection_with(quiet), &rules, true).unexplained.len(), 1);
    }

    #[test]
    fn a_quiet_machine_reads_healthy() {
        let (rules, _) = RuleSet::builtin();
        let r = build(collection_with(&[]), &rules, false);
        assert_eq!(r.verdict, Verdict::Healthy);
    }

    #[test]
    fn an_oom_kill_is_critical() {
        let (rules, _) = RuleSet::builtin();
        let c = collection_with(&[(Severity::Critical, "Out of memory: Killed process 1 (x)")]);
        assert_eq!(build(c, &rules, false).verdict, Verdict::Critical);
    }

    #[test]
    fn failed_units_alone_make_a_machine_degraded() {
        let (rules, _) = RuleSet::builtin();
        let c = Collection {
            failed_units: vec![FailedUnit {
                name: "nginx.service".into(),
                detail: "failed".into(),
                running: false,
            }],
            ..Default::default()
        };
        assert_eq!(build(c, &rules, false).verdict, Verdict::Degraded);
    }

    #[test]
    fn findings_are_ordered_worst_first() {
        let (rules, _) = RuleSet::builtin();
        let c = collection_with(&[
            (Severity::Warning, "Failed password for root from 10.0.0.1"),
            (Severity::Critical, "Out of memory: Killed process 1 (x)"),
        ]);
        let r = build(c, &rules, false);
        assert!(r.findings[0].severity < r.findings[1].severity);
    }

    /// The bug this guards: `launchctl list` prints the PID in column 1 and the
    /// *last* exit status in column 2. A running job that failed once and
    /// recovered carries a non-zero status forever, and was being reported as
    /// "BROKEN RIGHT NOW".
    #[test]
    fn a_running_job_with_an_old_failure_is_not_broken_now() {
        let (rules, _) = RuleSet::builtin();
        let c = Collection {
            failed_units: vec![FailedUnit {
                name: "com.example.agent".into(),
                detail: "running now; a previous run exited with status 1".into(),
                running: true,
            }],
            ..Default::default()
        };
        assert_ne!(build(c, &rules, false).verdict, Verdict::Degraded);
    }

    #[test]
    fn a_stopped_job_with_a_failure_is_still_degraded() {
        let (rules, _) = RuleSet::builtin();
        let c = Collection {
            failed_units: vec![FailedUnit {
                name: "com.example.agent".into(),
                detail: "not running; last run exited with status 1".into(),
                running: false,
            }],
            ..Default::default()
        };
        assert_eq!(build(c, &rules, false).verdict, Verdict::Degraded);
    }

    /// Everything flagged happened within two minutes of boot and stopped.
    /// That is services racing at startup, not a degraded machine.
    #[test]
    fn findings_that_settled_at_boot_do_not_degrade_the_verdict() {
        let (rules, _) = RuleSet::builtin();
        let event = Event::new(
            Source::UnifiedLog,
            Severity::Error,
            "Sandbox: contactsd(99) deny(1) file-read-data /Library",
        )
        .with_timestamp(Some("2026-09-18 12:34:40".into()));

        let c = Collection {
            events: vec![event],
            boot_window: Some(("2026-09-18 12:34:33".into(), "2026-09-18 12:36:33".into())),
            ..Default::default()
        };
        let r = build(c, &rules, false);
        assert!(
            r.findings.iter().all(|f| f.stale == Some(Stale::SettledAtBoot)),
            "should be marked as settled at boot"
        );
        assert_ne!(r.verdict, Verdict::Degraded);
    }

    #[test]
    fn the_same_finding_after_the_boot_window_still_counts() {
        let (rules, _) = RuleSet::builtin();
        let event = Event::new(
            Source::UnifiedLog,
            Severity::Error,
            "Sandbox: contactsd(99) deny(1) file-read-data /Library",
        )
        .with_timestamp(Some("2026-09-18 14:02:11".into()));

        let c = Collection {
            events: vec![event],
            boot_window: Some(("2026-09-18 12:34:33".into(), "2026-09-18 12:36:33".into())),
            ..Default::default()
        };
        let r = build(c, &rules, false);
        assert!(r.findings.iter().all(|f| f.stale.is_none()));
    }

    /// A line from *before* this boot must not be mistaken for a startup race
    /// just because it is older than the end of the settling window.
    #[test]
    fn something_from_before_this_boot_is_not_a_startup_race() {
        let (rules, _) = RuleSet::builtin();
        let event = Event::new(
            Source::UnifiedLog,
            Severity::Error,
            "Sandbox: contactsd(99) deny(1) file-read-data /Library",
        )
        .with_timestamp(Some("2026-09-18 11:47:58".into()));

        let c = Collection {
            events: vec![event],
            boot_window: Some(("2026-09-18 12:34:33".into(), "2026-09-18 12:36:33".into())),
            ..Default::default()
        };
        assert!(build(c, &rules, false).findings.iter().all(|f| f.stale.is_none()));
    }

    /// The Jamf case: a crash twelve hours old kept a one-hour scan DEGRADED.
    /// It still gets reported — it just stops setting the verdict.
    #[test]
    fn a_crash_older_than_the_scanned_window_does_not_degrade_the_verdict() {
        let (rules, _) = RuleSet::builtin();
        let crash = Event::new(
            Source::Crash,
            Severity::Error,
            "Crashed Thread — crash report for someApp (someApp-2026-09-18-010735.ips)",
        )
        .with_timestamp(Some("2026-09-18 01:07:35".into()));
        let recent = Event::new(Source::UnifiedLog, Severity::Notice, "nothing much happened")
            .with_timestamp(Some("2026-09-18 12:40:00".into()));

        let c = Collection {
            events: vec![crash, recent],
            window_start: Some("2026-09-18 12:03:00".into()),
            ..Default::default()
        };
        let r = build(c, &rules, false);
        let crash_finding =
            r.findings.iter().find(|f| f.rule_id == "macos.app-crash").expect("crash still shown");
        assert_eq!(crash_finding.stale, Some(Stale::OutsideWindow));
        assert_ne!(r.verdict, Verdict::Degraded);
    }

    /// A non-zero exit code alone does not prove launchd is throttling
    /// anything; the throttle finding must require a real throttle message.
    #[test]
    fn a_bare_exit_code_does_not_claim_throttling() {
        let (rules, _) = RuleSet::builtin();
        let e = Event::new(
            Source::Launchd,
            Severity::Warning,
            "com.example.agent: launchd job is running; a previous run exited with status 1",
        );
        for m in rules.explain(&e) {
            assert!(
                !m.means.contains("slowing down its restart attempts"),
                "{} claimed throttling without a throttle message",
                m.rule.id
            );
        }
    }
}
