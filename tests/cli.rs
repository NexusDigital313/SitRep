//! End-to-end tests: run the real binary against captured logs.
//!
//! These guard the whole pipeline — parse, match, rank, render — in a way the
//! unit tests cannot, and they are the only coverage the Linux collector's
//! output format gets on a macOS development machine.

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_sitrep");

fn run(args: &[&str]) -> (String, i32) {
    let out = Command::new(BIN).args(args).output().expect("binary should run");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        out.status.code().unwrap_or(-1),
    )
}

#[test]
fn journald_json_yields_a_critical_verdict_with_the_right_top_finding() {
    let (stdout, _) = run(&["-f", "fixtures/linux/journal-bad-day.json", "--json"]);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");

    assert_eq!(v["verdict"], "critical");
    let ids: Vec<&str> =
        v["findings"].as_array().unwrap().iter().map(|f| f["rule_id"].as_str().unwrap()).collect();

    for expected in [
        "linux.oom-killer",
        "linux.ext4-error",
        "linux.remount-readonly",
        "linux.start-limit",
        "linux.disk-full",
        "linux.ssh-bruteforce",
        "linux.segfault",
        "linux.conntrack-full",
    ] {
        assert!(ids.contains(&expected), "missing {expected} in {ids:?}");
    }
}

#[test]
fn captures_are_substituted_into_the_finding_text() {
    let (stdout, _) = run(&["-f", "fixtures/linux/journal-bad-day.json", "--json"]);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let all = v.to_string();

    assert!(all.contains("killed mysqld"), "process name should reach the title");
    assert!(all.contains("corruption detected on sdb1"), "device should reach the title");
}

#[test]
fn near_identical_unknown_lines_collapse_to_one_row() {
    let (stdout, _) = run(&["-f", "fixtures/linux/journal-bad-day.json", "--json"]);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let unexplained = v["unexplained"].as_array().unwrap();

    let widgets: Vec<_> =
        unexplained.iter().filter(|u| u["sample"].as_str().unwrap().contains("widget")).collect();
    assert_eq!(widgets.len(), 1, "three widget lines should fold into one group");
    assert_eq!(widgets[0]["count"], 3);
}

#[test]
fn plain_syslog_text_is_understood_without_a_format_flag() {
    let (stdout, _) = run(&["-f", "fixtures/linux/syslog-plain.txt", "--json"]);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    // All five lines are explained, including the two whose keyword-guessed
    // severity is below warning.
    assert_eq!(v["findings"].as_array().unwrap().len(), 5, "{stdout}");
    assert_eq!(v["verdict"], "critical");
}

#[test]
fn macos_compact_lines_keep_the_text_their_rules_need() {
    // Regression: the preamble trimmer used to cut at the first ": " in the
    // line, eating the literal "Sandbox: " that the sandbox rule matches on.
    let (stdout, _) = run(&["-f", "fixtures/macos/log-stream-compact.txt", "--json"]);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let ids: Vec<&str> =
        v["findings"].as_array().unwrap().iter().map(|f| f["rule_id"].as_str().unwrap()).collect();
    assert!(ids.contains(&"macos.sandbox-deny"), "expected a sandbox finding, got {ids:?}");
}

#[test]
fn exit_code_is_opt_in_and_reflects_severity() {
    let (_, quiet) = run(&["-f", "fixtures/linux/journal-bad-day.json"]);
    assert_eq!(quiet, 0, "without --exit-code, a bad machine still exits 0");

    let (_, loud) = run(&["-f", "fixtures/linux/journal-bad-day.json", "--exit-code"]);
    assert_eq!(loud, 2, "critical should exit 2");
}

#[test]
fn redirected_output_carries_no_escape_codes() {
    for args in [
        vec!["-f", "fixtures/linux/journal-bad-day.json"],
        vec!["learn", "-f", "fixtures/linux/journal-bad-day.json"],
        vec!["rules"],
        vec!["explain", "Out of memory: Killed process 1 (x)"],
    ] {
        let (stdout, _) = run(&args);
        assert!(!stdout.contains('\u{1b}'), "ANSI escape leaked from {args:?}");
    }
}

#[test]
fn learn_drafts_a_pattern_that_matches_what_it_came_from() {
    let (stdout, code) = run(&["learn", "-f", "fixtures/linux/journal-bad-day.json"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("[[rule]]"), "should emit TOML");
    assert!(stdout.contains(r"widget \d+ failed handshake after \d+ retries"), "{stdout}");
    // The stub must be parseable as-is, TODOs and all.
    toml::from_str::<toml::Value>(&stdout).expect("drafted stubs must be valid TOML");
}

#[test]
fn explain_reports_when_it_recognises_nothing() {
    let (_, code) = run(&["explain", "zxqwv completely unknown gibberish line"]);
    assert_eq!(code, 1, "an unrecognised line should exit non-zero");
}
