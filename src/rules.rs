//! The translation layer: regex patterns paired with plain-English explanations.
//!
//! Rules live in TOML so a user can drop their own into `~/.config/sitrep/rules/`
//! without recompiling. All patterns are matched in a single pass with a
//! `RegexSet`, then only the handful that hit get run again for captures.

use crate::event::{Event, Severity, Source};
use anyhow::{Context, Result};
use regex::{Regex, RegexSet};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// One pattern and what it means to a human.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Rule {
    pub id: String,
    /// The regex. Named captures are available to the templated text fields.
    #[serde(rename = "match")]
    pub pattern: String,
    /// Overrides the severity the log line claimed. A kernel line can arrive at
    /// `info` and still be the most important thing on the box.
    #[serde(default)]
    pub severity: Option<Severity>,
    /// One line. Shown as the finding's headline. Supports `{capture}`.
    pub title: String,
    /// The paragraph that does the actual translating. Supports `{capture}`.
    pub means: String,
    #[serde(default)]
    pub cause: Vec<String>,
    #[serde(default)]
    pub fix: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    /// Restricts the rule to certain sources, so a userspace line saying
    /// "I/O error" cannot masquerade as a dying disk.
    #[serde(default)]
    pub sources: Option<Vec<Source>>,
    /// Which OS this rule's advice is written for. Defaults to the pack the
    /// rule was loaded from, so `linux.toml` never explains a macOS line in
    /// terms of systemd. `None` means the advice holds anywhere.
    #[serde(default)]
    pub platform: Option<Platform>,
}

/// The OS a rule's prose assumes. This is deliberately not a build-time
/// `cfg!`: SitRep reads piped logs from other machines, so a Mac must still be
/// able to explain `journalctl` output from a Linux box.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    Linux,
    Macos,
}

impl Platform {
    /// Whether a rule for this OS may fire on a line from `source`.
    ///
    /// `Piped`, `Crash` and `Kernel` are neutral and belong to both. Both
    /// operating systems have a kernel, and when SitRep is handed plain text
    /// rather than structured output it cannot tell whose kernel it is
    /// reading — a macOS sandbox denial is logged by `kernel[0:...]` just as a
    /// Linux OOM kill is. Only the sources that name one platform outright
    /// (`Journal`, `Systemd` against `UnifiedLog`, `Launchd`) actually gate.
    pub fn accepts(self, source: Source) -> bool {
        match source {
            Source::Piped | Source::Crash | Source::Kernel => true,
            Source::Journal | Source::Systemd => self == Self::Linux,
            Source::UnifiedLog | Source::Launchd => self == Self::Macos,
        }
    }
}

#[derive(Debug, Deserialize)]
struct RuleFile {
    #[serde(default)]
    rule: Vec<Rule>,
}

/// A compiled set of rules, ready to match against.
pub struct RuleSet {
    rules: Vec<Rule>,
    /// Parallel to `rules`; index N here is the compiled form of rule N.
    regexes: Vec<Regex>,
    set: RegexSet,
}

/// What a rule produced when it matched a line.
pub struct Match<'a> {
    pub rule: &'a Rule,
    pub title: String,
    pub means: String,
    pub cause: Vec<String>,
    pub fix: Vec<String>,
    pub severity: Severity,
}

impl RuleSet {
    /// Compiles rules, skipping (and reporting) any whose regex is bad so one
    /// broken user rule cannot take the whole tool down.
    pub fn compile(rules: Vec<Rule>) -> (Self, Vec<String>) {
        let mut good = Vec::new();
        let mut regexes = Vec::new();
        let mut errors = Vec::new();
        let mut seen: HashMap<String, ()> = HashMap::new();

        for rule in rules {
            if seen.insert(rule.id.clone(), ()).is_some() {
                errors.push(format!("duplicate rule id '{}' (later one ignored)", rule.id));
                continue;
            }
            match Regex::new(&rule.pattern) {
                Ok(re) => {
                    regexes.push(re);
                    good.push(rule);
                }
                Err(e) => errors.push(format!("rule '{}' has an invalid pattern: {e}", rule.id)),
            }
        }

        let set = RegexSet::new(good.iter().map(|r| &r.pattern))
            .expect("every pattern already compiled individually");

        (Self { rules: good, regexes, set }, errors)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Loads every rule pack baked into the binary. All of them load on every
    /// platform on purpose — piped input may come from another machine — but
    /// each pack stamps its rules with the OS its prose assumes, and
    /// `explain` refuses to fire a rule against a line from the wrong one.
    pub fn builtin() -> (Self, Vec<String>) {
        let mut rules = Vec::new();
        let mut errors = Vec::new();

        let packs: [(&str, &str, Option<Platform>); 3] = [
            ("common", include_str!("../rules/common.toml"), None),
            ("linux", include_str!("../rules/linux.toml"), Some(Platform::Linux)),
            ("macos", include_str!("../rules/macos.toml"), Some(Platform::Macos)),
        ];

        for (name, body, platform) in packs {
            match toml::from_str::<RuleFile>(body) {
                Ok(f) => rules.extend(f.rule.into_iter().map(|mut r| {
                    // An explicit `platform =` in the file wins, so a pack can
                    // still carry a genuinely cross-platform rule.
                    r.platform = r.platform.or(platform);
                    r
                })),
                Err(e) => errors.push(format!("builtin rule pack '{name}' failed to parse: {e}")),
            }
        }

        let (set, mut compile_errors) = Self::compile(rules);
        errors.append(&mut compile_errors);
        (set, errors)
    }

    /// Adds every `*.toml` in a directory. Missing directory is not an error —
    /// most people will never create one.
    pub fn load_dir(&mut self, dir: &Path) -> Result<Vec<String>> {
        let mut errors = Vec::new();
        if !dir.is_dir() {
            return Ok(errors);
        }

        let mut extra = Vec::new();
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .with_context(|| format!("reading rule directory {}", dir.display()))?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "toml"))
            .collect();
        entries.sort();

        for path in entries {
            let body = match std::fs::read_to_string(&path) {
                Ok(b) => b,
                Err(e) => {
                    errors.push(format!("could not read {}: {e}", path.display()));
                    continue;
                }
            };
            match toml::from_str::<RuleFile>(&body) {
                Ok(f) => extra.extend(f.rule),
                Err(e) => errors.push(format!("{} failed to parse: {e}", path.display())),
            }
        }

        if !extra.is_empty() {
            let mut all = std::mem::take(&mut self.rules);
            all.extend(extra);
            let (rebuilt, mut errs) = Self::compile(all);
            *self = rebuilt;
            errors.append(&mut errs);
        }

        Ok(errors)
    }

    /// Returns every rule that matches this event, richest first. Most lines
    /// match nothing, and `RegexSet` makes that case cheap.
    pub fn explain(&self, event: &Event) -> Vec<Match<'_>> {
        let hay = &event.message;
        let mut out = Vec::new();

        for idx in self.set.matches(hay).into_iter() {
            let rule = &self.rules[idx];

            if let Some(allowed) = &rule.sources
                && !allowed.contains(&event.source)
            {
                continue;
            }

            // A Linux rule must never explain a macOS line, or vice versa.
            // This is what stops `Failed to start scan with error 105` from
            // bluetoothd being answered with `systemctl status`.
            if let Some(platform) = rule.platform
                && !platform.accepts(event.source)
            {
                continue;
            }

            // Re-run the individual regex; we need the named captures that
            // RegexSet deliberately does not collect.
            let Some(caps) = self.regexes[idx].captures(hay) else {
                continue;
            };
            let vars = capture_map(&self.regexes[idx], &caps);

            out.push(Match {
                rule,
                title: fill(&rule.title, &vars),
                means: fill(&rule.means, &vars),
                cause: rule.cause.iter().map(|c| fill(c, &vars)).collect(),
                fix: rule.fix.iter().map(|f| fill(f, &vars)).collect(),
                severity: rule.severity.unwrap_or(event.severity),
            });
        }

        out
    }
}

/// Named captures as a lookup table for templating.
fn capture_map(re: &Regex, caps: &regex::Captures<'_>) -> HashMap<String, String> {
    re.capture_names()
        .flatten()
        .filter_map(|name| caps.name(name).map(|m| (name.to_string(), m.as_str().to_string())))
        .collect()
}

/// Substitutes `{name}` with the matching capture. Unknown placeholders are
/// left alone rather than blanked, so a typo in a rule is visible instead of
/// silently producing a sentence with a hole in it.
fn fill(template: &str, vars: &HashMap<String, String>) -> String {
    if !template.contains('{') {
        return template.to_string();
    }

    let mut out = String::with_capacity(template.len());
    let mut rest = template;

    while let Some(start) = rest.find('{') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('}') {
            Some(end) => {
                let key = &after[..end];
                match vars.get(key) {
                    Some(v) => out.push_str(v),
                    None => {
                        out.push('{');
                        out.push_str(key);
                        out.push('}');
                    }
                }
                rest = &after[end + 1..];
            }
            None => {
                out.push_str(&rest[start..]);
                return out;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Collapses a line to its shape so that a thousand near-identical unmatched
/// lines become one row with a count instead of a thousand rows.
pub fn fingerprint(message: &str) -> String {
    const CALENDAR: [&str; 19] = [
        "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun", "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];

    // Weekday and month names vary the same way numbers do — one recurring
    // message dated across a week is one problem, not seven.
    let message: String = message
        .split_whitespace()
        .map(|w| if CALENDAR.contains(&w.trim_end_matches(',')) { "#" } else { w })
        .collect::<Vec<_>>()
        .join(" ");

    let mut out = String::with_capacity(message.len());
    let mut chars = message.chars().peekable();

    while let Some(c) = chars.next() {
        // A leading sign belongs to the number that follows it, but only where a
        // sign can actually appear. Without this, `(-1)` and `(0)` fingerprint
        // differently and one recurring message splits into two groups.
        let signed = c == '-'
            && chars.peek().is_some_and(char::is_ascii_digit)
            && !out.chars().next_back().is_some_and(|p| p.is_ascii_alphanumeric());

        if signed || c.is_ascii_digit() || (c.is_ascii_hexdigit() && !c.is_ascii_alphabetic()) {
            // Swallow the whole numeric run, emit one placeholder.
            while chars.peek().is_some_and(|n| {
                n.is_ascii_hexdigit() || *n == 'x' || *n == ':' || *n == '.' || *n == '-'
            }) {
                chars.next();
            }
            out.push('#');
        } else {
            out.push(c);
        }
    }

    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Builds a starter regex from a message the rules did not recognise: escape
/// everything, then loosen the digits. Deliberately over-specific — it is a
/// draft for a human to widen, not a finished rule.
pub fn derive_pattern(message: &str) -> String {
    // Keep the pattern to roughly one line's worth of distinctive text.
    let mut trimmed = message.trim();
    if trimmed.chars().count() > 90 {
        let cut: String = trimmed.chars().take(90).collect();
        let end = cut.rfind(' ').unwrap_or(cut.len());
        trimmed = &message[..end];
    }

    let escaped = regex::escape(trimmed.trim());
    let mut out = String::with_capacity(escaped.len());
    let mut chars = escaped.chars().peekable();

    while let Some(c) = chars.next() {
        if c.is_ascii_digit() {
            while chars.peek().is_some_and(char::is_ascii_digit) {
                chars.next();
            }
            out.push_str(r"\d+");
        } else {
            out.push(c);
        }
    }
    out
}

/// A filesystem- and TOML-safe id derived from the first few real words.
pub fn derive_id(message: &str) -> String {
    let words: Vec<String> = message
        .split_whitespace()
        // Digits are dropped, not kept: the derived pattern generalises them to
        // `\d+`, so an id built from one run's pid would differ from the next
        // run's for the very same rule, and `learn --write` would install a
        // duplicate every time.
        .map(|w| w.chars().filter(char::is_ascii_alphabetic).collect::<String>().to_lowercase())
        .filter(|w| w.len() > 2)
        .take(4)
        .collect();

    if words.is_empty() { "unnamed".into() } else { words.join("-") }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn fills_named_placeholders() {
        let v = vars(&[("proc", "mysqld"), ("pid", "4821")]);
        assert_eq!(fill("killed {proc} ({pid})", &v), "killed mysqld (4821)");
    }

    #[test]
    fn leaves_unknown_placeholders_visible() {
        assert_eq!(fill("hello {nope}", &vars(&[])), "hello {nope}");
    }

    #[test]
    fn tolerates_unclosed_brace() {
        assert_eq!(fill("hello {oops", &vars(&[])), "hello {oops");
    }

    #[test]
    fn fingerprints_collapse_varying_numbers() {
        let a = fingerprint("connection from 10.0.0.4 port 55231 closed");
        let b = fingerprint("connection from 192.168.1.9 port 4001 closed");
        assert_eq!(a, b);
    }

    #[test]
    fn fingerprints_collapse_negative_numbers_with_positive_ones() {
        // Seen live on macOS: 1,584 identical kernel warnings split into two
        // groups because one carried (-1) and the other (0).
        let a = fingerprint("memorystatus_control error: CONVERT_MEMLIMIT_MB(-1) returned -1 22");
        let b = fingerprint("memorystatus_control error: CONVERT_MEMLIMIT_MB(0) returned -1 22");
        assert_eq!(a, b, "a sign should not split one problem into two groups");
    }

    #[test]
    fn fingerprints_keep_hyphenated_words_intact() {
        // The sign rule must not fire mid-word, or UTF-8 and UTF-16 collapse
        // into unrelated text.
        assert_ne!(fingerprint("decoded as UTF-8 stream"), fingerprint("decoded as UTF stream"));
    }

    #[test]
    fn fingerprints_collapse_dates_as_well_as_numbers() {
        let a = fingerprint("Start date Mon Sep 28 02:00:00 2026 cannot be met");
        let b = fingerprint("Start date Thu Sep 24 02:00:00 2026 cannot be met");
        assert_eq!(a, b, "weekday-only differences should fold together");
    }

    #[test]
    fn builtin_rules_all_compile() {
        let (set, errors) = RuleSet::builtin();
        assert!(errors.is_empty(), "builtin rule packs had errors: {errors:?}");
        assert!(!set.is_empty(), "no builtin rules loaded");
    }

    #[test]
    fn bad_pattern_is_skipped_not_fatal() {
        let rules = vec![
            Rule {
                id: "bad".into(),
                pattern: "((((".into(),
                severity: None,
                title: "x".into(),
                means: "x".into(),
                cause: vec![],
                fix: vec![],
                tags: vec![],
                sources: None,
                platform: None,
            },
            Rule {
                id: "good".into(),
                pattern: "hello".into(),
                severity: None,
                title: "x".into(),
                means: "x".into(),
                cause: vec![],
                fix: vec![],
                tags: vec![],
                sources: None,
                platform: None,
            },
        ];
        let (set, errors) = RuleSet::compile(rules);
        assert_eq!(set.len(), 1);
        assert_eq!(errors.len(), 1);
    }

    #[test]
    fn a_derived_pattern_matches_the_line_it_came_from() {
        let msg = "widget 4821 exploded after 91 attempts";
        let re = Regex::new(&derive_pattern(msg)).expect("derived pattern must compile");
        assert!(re.is_match(msg));
        // ...and generalises over the numbers it saw.
        assert!(re.is_match("widget 7 exploded after 3 attempts"));
    }

    #[test]
    fn derived_patterns_escape_regex_metacharacters() {
        let msg = "failed to open /var/log/*.log (permission denied?)";
        let re = Regex::new(&derive_pattern(msg)).expect("must compile");
        assert!(re.is_match(msg));
    }

    #[test]
    fn derives_a_readable_id() {
        assert_eq!(derive_id("Failed to start nginx 12 daemon"), "failed-start-nginx-daemon");
        assert_eq!(derive_id("42 7"), "unnamed");
    }

    #[test]
    fn derived_ids_are_stable_when_only_numbers_change() {
        let a = derive_id("Peer connection [pid=779] lacks APSConnectionInitiateEntitlement");
        let b = derive_id("Peer connection [pid=4210] lacks APSConnectionInitiateEntitlement");
        assert_eq!(a, b, "the same rule must keep one id across runs");
        assert!(!a.contains(|c: char| c.is_ascii_digit()), "id kept a volatile number: {a}");
    }

    #[test]
    fn source_restriction_is_honoured() {
        let rules = vec![Rule {
            id: "kern-only".into(),
            pattern: "I/O error".into(),
            severity: None,
            title: "disk".into(),
            means: "disk".into(),
            cause: vec![],
            fix: vec![],
            tags: vec![],
            sources: Some(vec![Source::Kernel]),
            platform: None,
        }];
        let (set, _) = RuleSet::compile(rules);

        let kern = Event::new(Source::Kernel, Severity::Error, "I/O error on sda");
        let user = Event::new(Source::Journal, Severity::Error, "I/O error on sda");

        assert_eq!(set.explain(&kern).len(), 1);
        assert_eq!(set.explain(&user).len(), 0);
    }

    /// The bug this guards: `linux.unit-start-failed` matched bluetoothd's
    /// "Failed to start scan with error 105" on a Mac and answered it with
    /// `systemctl status`, which does not exist on macOS.
    #[test]
    fn a_linux_rule_never_explains_a_macos_line() {
        let (set, _) = RuleSet::builtin();
        let mac =
            Event::new(Source::UnifiedLog, Severity::Error, "Failed to start scan with error 105");
        for m in set.explain(&mac) {
            assert!(
                !m.rule.id.starts_with("linux."),
                "{} fired on a macOS line: {}",
                m.rule.id,
                m.means
            );
        }
    }

    #[test]
    fn no_macos_line_is_ever_answered_with_linux_tooling() {
        let (set, _) = RuleSet::builtin();
        for text in [
            "Failed to start scan with error 105",
            "Out of memory: Killed process 100 (mysqld)",
            "Service exited with abnormal code 1",
        ] {
            let e = Event::new(Source::UnifiedLog, Severity::Error, text);
            for m in set.explain(&e) {
                let prose = format!("{} {} {}", m.means, m.cause.join(" "), m.fix.join(" "));
                for word in ["systemctl", "journalctl", "systemd", "SELinux", "AppArmor"] {
                    assert!(!prose.contains(word), "{} told a Mac about {word}", m.rule.id);
                }
            }
        }
    }

    #[test]
    fn a_macos_rule_never_explains_a_linux_line() {
        let (set, _) = RuleSet::builtin();
        let lin = Event::new(
            Source::Journal,
            Severity::Error,
            "Sandbox: foo(1) deny(1) file-read-data /x",
        );
        for m in set.explain(&lin) {
            assert!(!m.rule.id.starts_with("macos."), "{} fired on a Linux line", m.rule.id);
        }
    }

    /// `ssh web01 journalctl -b -o json | SitRep` is a documented workflow, so
    /// piped input must keep reaching both packs — the platform gate is about
    /// where a line came from, not what this binary was built for.
    #[test]
    fn piped_input_still_reaches_both_platforms() {
        let (set, _) = RuleSet::builtin();
        let oom =
            Event::new(Source::Piped, Severity::Critical, "Out of memory: Killed process 1 (x)");
        assert!(
            set.explain(&oom).iter().any(|m| m.rule.id.starts_with("linux.")),
            "a Linux rule must still explain a piped Linux line"
        );
    }
}
