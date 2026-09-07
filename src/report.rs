//! Turns a pile of events into a ranked set of findings a person can act on.

use crate::collect::{Collection, FailedUnit};
use crate::event::Severity;
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
        seq.serialize_element(&serde_json::json!({"name": u.name, "detail": u.detail}))?;
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
    let scanned = collection.events.len();
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
            entry.count += 1;
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
            });

            entry.count += 1;
            entry.severity = entry.severity.min(m.severity);

            if let Some(unit) = &event.unit {
                entry.units.insert(unit.clone());
            }
            if let Some(ts) = &event.timestamp {
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
    // Severity first, then by how often it happened, then alphabetically so
    // two runs over the same data produce byte-identical output.
    findings.sort_by(|a, b| {
        a.severity.cmp(&b.severity).then(b.count.cmp(&a.count)).then(a.title.cmp(&b.title))
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

fn verdict_for(findings: &[Finding], failed: &[FailedUnit]) -> Verdict {
    let worst = findings.iter().map(|f| f.severity).min();

    match worst {
        Some(s) if s <= Severity::Critical => Verdict::Critical,
        Some(Severity::Error) => Verdict::Degraded,
        _ if !failed.is_empty() => Verdict::Degraded,
        Some(_) => Verdict::Noisy,
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
}
