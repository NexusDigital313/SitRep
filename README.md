# sitrep

Reads the logs your machine already keeps and tells you what's wrong, in English.

Every operating system logs constantly, and almost none of it is written for a
human. `sitrep` reads it for you — `journalctl`, `systemctl` and `dmesg` on
Linux; the unified log, `launchd` and crash reports on macOS — matches it
against a library of known failure patterns, and prints a ranked report that
says what happened, why it matters, and what to type next.

```
 SITREP                                                    web01 · Debian 12

   CRITICAL   Something is seriously wrong. Start at the top.
  1,284 lines scanned  ·  journal, this boot  ·  up 6 days

── BROKEN RIGHT NOW ─────────────────────────────────────────────────────────

  ✗ mysql.service    failed

── FINDINGS ─────────────────────────────────────────────────────────────────

 ▌ CRITICAL  Ran out of memory — the kernel killed mysqld                 ×3
 ▌
 ▌ The machine ran out of usable RAM. Linux does not simply freeze when this
 ▌ happens: it picks the process it judges most expendable and kills it
 ▌ outright. This time that was mysqld (process 4821). Whatever mysqld was
 ▌ doing stopped mid-flight, and anything depending on it will have failed too.
 ▌
 ▌ LIKELY CAUSE
 ▌   • A process gradually leaked memory until nothing was left
 ▌   • A legitimate workload was simply larger than this machine can hold
 ▌   • Little or no swap configured, so there was no cushion to fall back on
 ▌
 ▌ WHAT TO DO
 ▌   1. See the full picture of the kill: journalctl -k -b | grep -A20 'Out of
 ▌      memory'
 ▌   2. Cap the offending service so it dies politely instead: add
 ▌      MemoryMax=1G to its unit file
 ▌   3. Add swap as a stopgap: fallocate -l 2G /swapfile && mkswap /swapfile
 ▌
 ▌ 2026-09-07 01:39:11 → 2026-09-07 02:23:37   mysql.service
```

## It runs offline

`sitrep` makes no network connections. There is no API, no account, no
telemetry, and no HTTP or TLS library linked into the binary at all — you can
check with `cargo tree`. It reads local logs, matches local rules, and prints.
That is the whole program. It works on an airgapped box, and nothing about your
logs leaves the machine.

## Install

```sh
cargo install --path .        # from a clone
cargo install sitrep          # once published
```

One static-ish binary, no runtime, no dependencies to install on the target.
Build it once per platform: the macOS and Linux collectors live in the same
source tree and are selected at compile time.

## Use

```sh
sitrep                        # what is wrong with this machine
sitrep --since 2h             # narrow the window
sitrep explain "<log line>"   # translate one line you pasted
sitrep watch                  # follow the log live, translating as it goes
sitrep rules --tag disk       # what it knows how to recognise
sitrep learn                  # draft rules for what it could not explain
```

It reads piped input too, which is how you check a Linux server from a Mac:

```sh
ssh web01 journalctl -b -o json | sitrep
ssh web01 'journalctl -b -o json' | sitrep --json | jq '.findings[0]'
cat /var/log/syslog | sitrep
```

journald JSON, macOS `ndjson`, and plain syslog text are detected automatically.

### Flags worth knowing

| Flag | Does |
|---|---|
| `--since <spec>` | `boot`, `2h`, `"yesterday"`. Defaults to `boot` on Linux, `1h` on macOS — the unified log is much larger. |
| `--all` | Include notice and info level, not just warnings and worse. |
| `--json` | Machine-readable output, for monitoring or piping to `jq`. |
| `--exit-code` | Exit 1 if degraded, 2 if critical. For cron and CI. |
| `--no-color` | Force plain text. Also happens automatically when redirected. |
| `--rules-dir` | Load extra rules from somewhere other than the default. |

## How it gets smarter

The knowledge is data, not code: TOML files pairing a regex with the English
that explains it. About 50 ship built in, covering the things that actually take
machines down — OOM kills, filesystem corruption, dying disks, crash loops,
SSH brute force, full disks, thermal throttling, SELinux and sandbox denials,
kernel panics.

Anything it does not recognise is grouped by shape and counted, so a thousand
near-identical lines occupy one row. `sitrep learn` turns those groups into
draft rules with the regex already written for you:

```sh
sitrep learn                  # print stubs for review
sitrep learn --write          # install them to ~/.config/sitrep/rules/
```

Fill in the prose once, and every future run explains that line. Rules are plain
files, so they can be committed, shared, and reviewed like anything else.

```toml
[[rule]]
id = "local.widget-handshake"
match = 'widget \d+ failed handshake after \d+ retries'
severity = "warning"
title = "The widget daemon could not reach its peer"
means = """
widgetd retries the handshake and gives up. Usually the peer is down rather
than anything wrong on this machine.
"""
cause = ["The peer service is not running", "A firewall is dropping the connection"]
fix = ["Check the peer is up: systemctl status widgetd", "Confirm port 7700 is open"]
tags = ["network"]
```

Rules in `~/.config/sitrep/rules/*.toml` are loaded on every run and extend the
built-ins. A rule with a bad regex is reported and skipped, never fatal.

## What it reads

| | Linux | macOS |
|---|---|---|
| Logs | `journalctl -o json`, `dmesg` | `log show --style ndjson` |
| Service state | `systemctl --failed` | `launchctl list` |
| Crashes | `systemd-coredump` records | `~/Library/Logs/DiagnosticReports` |
| Fallback | `/var/log/syslog`, `/var/log/messages` | — |

Nothing needs root. Without it some kernel messages may be unavailable, and
`sitrep` says so in a "scan was incomplete" section rather than quietly
reporting a clean bill of health.

## Development

```sh
cargo test                    # 51 tests, no network, no fixtures needed at runtime
cargo build --release
```

Both platform collectors compile on both platforms — only the dispatch is
conditional — so the Linux collector stays type-checked and unit-tested when
built on a Mac. Fixtures under `fixtures/` are real log captures used to
exercise the Linux path from a development machine that isn't Linux.

## License

MIT
