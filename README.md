# SitRep

Reads the logs your machine already keeps and tells you what's wrong, in English.

Every operating system logs constantly, and almost none of it is written for a
human. `SitRep` reads it for you — `journalctl`, `systemctl` and `dmesg` on
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

`SitRep` makes no network connections. There is no API, no account, no
telemetry, and no HTTP or TLS library linked into the binary at all — you can
check with `cargo tree`. It reads local logs, matches local rules, and prints.
That is the whole program. It works on an airgapped box, and nothing about your
logs leaves the machine.

## Install

`SitRep` is the command everywhere, with a platform-named alias alongside it.
One source tree, one binary per OS:

| Platform | Commands | Get it |
|---|---|---|
| macOS (Intel + Apple silicon) | **`SitRep`**, `MacSitRep` | `MacSitRep-universal.tar.gz` from Releases |
| Linux x86_64 / arm64 | **`SitRep`**, `LinuxSitRep` | `SitRep-linux-*.tar.gz` or the `.deb` from Releases |

```sh
# From a clone — installs SitRep plus the platform alias
make install                       # -> ~/.cargo/bin, no sudo
sudo make install PREFIX=/usr/local

# Debian / Ubuntu — installs SitRep and LinuxSitRep
sudo dpkg -i sitrep_0.1.0_amd64.deb

# Plain cargo — gives you `SitRep` only, no alias
cargo install --path .
```

Linux release binaries are statically linked against musl: one file, no
dependencies, runs on any distribution including ancient glibc. macOS ships a
universal binary. Every archive also contains a `SitRep` symlink, so either
name works.

`SitRep` is the real binary; `MacSitRep` and `LinuxSitRep` are symlinks to it.
The program reads `argv[0]`, so `--help`, `--version` and every error message
name whichever alias you actually typed:

```
$ MacSitRep --version
MacSitRep 0.1.0
```

If `~/.cargo/bin` is not on your `PATH`:

```sh
echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.zshrc   # or ~/.bashrc
```

## Use

Examples below say `SitRep`; `MacSitRep` and `LinuxSitRep` work identically.

```sh
SitRep                        # what is wrong with this machine
SitRep --since 2h             # narrow the window
SitRep explain "<log line>"   # translate one line you pasted
SitRep watch                  # follow the log live, translating as it goes
SitRep rules --tag disk       # what it knows how to recognise
SitRep learn                  # draft rules for what it could not explain
```

It reads piped input too, which is how you check a Linux server from a Mac:

```sh
ssh web01 journalctl -b -o json | SitRep
ssh web01 'journalctl -b -o json' | SitRep --json | jq '.findings[0]'
cat /var/log/syslog | SitRep
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
near-identical lines occupy one row. `SitRep learn` turns those groups into
draft rules with the regex already written for you:

```sh
SitRep learn                  # print stubs for review
SitRep learn --write          # install them to ~/.config/sitrep/rules/
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
`SitRep` says so in a "scan was incomplete" section rather than quietly
reporting a clean bill of health.

## Development

```sh
make test                     # 63 tests
make lint                     # clippy -D warnings, plus rustfmt
make build
```

Both platform collectors compile on both platforms — only the dispatch is
conditional — so the Linux collector stays type-checked and unit-tested when
built on a Mac. Fixtures under `fixtures/` are real log captures used to
exercise the Linux path from a development machine that isn't Linux.

### CI

`ci.yml` runs three jobs:

- **test** — fmt, clippy and the full suite on Linux and macOS.
- **smoke-linux** — runs the binary against a *live* systemd machine. The unit
  and fixture tests cover the parsing; this is the only thing exercising the
  real `journalctl` / `systemctl` / `dmesg` invocations, so it is where a
  Mac-developed Linux collector actually gets proven.
- **offline** — enforces the offline guarantee as a test. It fails the build if
  a networking crate enters the dependency tree, if anything in `src/` touches
  a socket API, or if an optional feature appears that could reintroduce one.

`release.yml` fires on a `v*` tag and publishes musl-static Linux binaries
(x86_64 + arm64), `.deb` packages, and a macOS universal binary, each with a
SHA-256. It verifies the Linux binaries are genuinely static and installs the
`.deb` to confirm both command names work before publishing.

```sh
git tag v0.1.0 && git push origin v0.1.0
```

The arm64 Linux binary is cross-compiled with `cross` in Docker, since
GitHub's free ARM runners are public-repo only. If this repo ever goes public,
switching that matrix entry to a `ubuntu-24.04-arm` runner with `cross: false`
is faster.

## License

MIT
