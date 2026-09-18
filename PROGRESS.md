# SitRep — progress

Last updated: 2026-09-18. Branch `macos-finish`, 4 commits ahead of `master`, **not pushed**.

## State

The macOS side is finished and verified against a live Mac (macOS 26.6.2, Apple
silicon). 68 tests, `make lint` clean. The Linux side is untouched this round —
it still compiles and is unit-tested on both platforms, but nothing was
exercised against a real systemd box.

```sh
make test          # 68
make lint          # clippy -D warnings + rustfmt
make install       # -> ~/.cargo/bin, plus the MacSitRep alias
```

## What was done

Everything below was found by running the binary against a real unified log,
not by reading code.

**Grouping split one problem in two.** `fingerprint()` collapsed digit runs but
not a leading sign, so `CONVERT_MEMLIMIT_MB(-1)` and `(0)` hashed apart — 1,584
identical kernel warnings reported as ×812 and ×772. Signs are now part of the
number, guarded so the rule cannot fire mid-word (`UTF-8` stays intact).

**`learn --write` installed a duplicate rule every run.** Derived ids kept
volatile numbers (`local.peer-connection-pid779-lacks`) while the pattern
generalised them to `\d+`. Ids now drop digits the way the pattern does.

**macOS never reported an incomplete scan.** Linux warns when kernel messages
are unavailable; macOS had no equivalent, yet 12–14% of lines here come back as
`<private>`. Added a note that reports the proportion.

> The note deliberately does **not** say "re-run with sudo". Measured on macOS
> 26.6: the same 20-minute window read as root and as the user returned an
> identical 707 of 5904 lines redacted. Redaction happens at write time, so
> privilege changes nothing after the fact. There is a test asserting the sudo
> wording never comes back.

**The macOS release job would have failed on the first `v*` tag.**
`tar --format=gnu` is GNU-tar syntax; macOS runners use bsdtar, which spells it
`gnutar` and rejects `gnu`. Switched to `ustar`, which both accept. The Linux
job at line 84 keeps `gnu` — correct there.

**Offline guarantee is now a hard gate on macOS.** `ci.yml` can only check it
informationally because a musl static has no dynamic symbol table; Mach-O has
one. The gate treats an unreadable slice as failure (an earlier version read
zero symbols from `nc`/`ping`/`ssh` because system binaries are `arm64e`, not
`arm64` — it looked like a pass and was `nm` erroring). Proven to fire against a
universal binary calling `socket()`/`getaddrinfo()`.

**Fold duplicates before the event cap.** `finish()` sorted by severity and
truncated to 20,000 *raw* lines. A busy Mac logs ~290k lines an hour, so with
`--all` the cap threw away whole kinds of problem, low-severity first. 300
syspolicyd notarization failures — the cause of this machine's 58 Gatekeeper
rejections — were invisible in every mode: excluded by the default predicate
(they are Default level) and truncated away under `--all`. Events now carry
`folded` and `last_timestamp`, and the report multiplies by those, so ×N counts
and first/last-seen ranges stay exact. Live: `--all --since 1h` scans 293,697
lines without hitting the cap and reports the notarization failure ×323.

Plus a rule for the notarization failure itself, a fix for `rules` running long
ids into the title (`{:<28}` pads but never truncates), and "1 **rules**".

## Round two — false positives on a healthy Mac (2026-09-18)

A live run one minute after login reported **DEGRADED** on a machine with
nothing wrong with it. Five bugs, all found by running the binary, all fixed;
77 tests, `make lint` clean.

**Every Linux rule was live on macOS.** `builtin()` loaded all three packs
unconditionally while its doc comment claimed it loaded "the rule packs for this
platform" — 28 of 49 loaded rules were Linux ones. `linux.unit-start-failed`
matched bluetoothd's "Failed to start scan with error 105" and answered it with
`systemctl status`, a command macOS does not have.

> Fixed by gating on the *source of the line*, not `cfg!(target_os)`. Compile-time
> gating would have broken `ssh web01 journalctl | SitRep`, which is a documented
> workflow. `Rule` gained a `platform`, each pack stamps its own, and `explain`
> refuses a rule whose platform does not accept the event's source. `Piped`,
> `Crash` and `Kernel` are neutral and reach both packs — both operating systems
> have a kernel, and the compact-text parser cannot tell whose it is reading. That
> last point is not theoretical: it is what the macOS fixture test caught.

**A running job was reported as "BROKEN RIGHT NOW".** `collect_launchd` discarded
the PID column (`Some(_pid)`) and judged on the status column alone. In
`launchctl list` the PID is what says whether a job is alive; the status is the
exit code of its *last* run, which a healthy running job carries forever after
failing once and recovering. Now split into two sections that mean opposite
things, and only a job that is genuinely not running can degrade the verdict.

**The throttling claim was manufactured.** Every non-zero exit synthesized the
string "Service exited with abnormal code", which `macos.launchd-throttle`
matched, printing "launchd is now deliberately slowing down its restart
attempts". `launchctl print` showed no throttling at all. The throttle rule now
requires an actual throttle message; two new rules say only what `launchctl
list` proves.

**The verdict had no notion of *now*.** One Error-severity line from forty
seconds after boot outranked seventeen minutes of a clean idle machine. Boot
time was already collected, and only used for display. Findings whose last
occurrence falls inside a 120-second post-boot settling window are now marked
`boot_transient`, still reported and still visible, but excluded from the
verdict — dozens of daemons lose startup races they win on the retry.

**An out-of-window crash set the verdict.** Crash reports are kept for seven
days on purpose — the filename carries the date, so an old one is legible — but
a Jamf crash twelve hours old was still enough to call a one-hour scan DEGRADED.
Showing it is right; letting it answer "is something wrong now" is not. Crash
events now carry their file's mtime, `finish()` records the oldest line actually
read, and anything older than that is marked `OutsideWindow`.

> `boot_transient` became `Option<Stale>` to hold both reasons. Fixing this
> also exposed a bug in the boot window itself: it tested only the upper bound,
> so everything logged *before* this boot counted as a startup race. It now
> requires a finding to start and end inside the window.

**`macos.gatekeeper` matched on a bare "invalid signature"**, catching an Apple
private-entitlement check in `cmio.registerassistantservice` and prescribing
`codesign`, `spctl` and `xattr -d com.apple.quarantine`. The alternative now
requires a real bundle path, and `macos.private-entitlement` explains the
entitlement case correctly instead.

Also: "lines scanned" counted synthesized launchd and crash events as log lines,
so the header said 34,319 while the redaction note beneath it said 34,317.

## Still open after round two

- Not pushed. Still `macos-finish`, now further ahead of `master`.

## Not done

- **Not pushed.** `macos-finish` is local only. Decide whether it goes to
  `origin` or straight onto `master`.
- **Linux side untouched.** Note the OOM rule's prose says "Linux does not
  simply freeze" and will print that verbatim on a Mac if it ever matches.
- **Universal binary builds but has never been released.** Verified locally end
  to end (both arches, `lipo`, tarball unpacks with symlink, both names run).
  Homebrew's Rust ships only the arm64 std, so this needed a throwaway rustup
  with `RUSTUP_HOME`/`CARGO_HOME` pointed at a scratch dir — do that again
  rather than installing rustup normally, since `~/.cargo/bin` is first on PATH
  and would shadow the Homebrew toolchain.
- **Crash reports ignore `--since`** — fixed 7-day window, so a 15-minute scan
  can surface an older crash. Still a deliberate call, and still legible from
  the filename. Superseded in part by round two: an older crash is now marked
  `OutsideWindow` and reported without setting the verdict.
- **`--since boot` on macOS** is clamped to 24h because `log show` gets very
  slow over multi-day spans.

## Gotchas worth remembering

- `sitrep` lowercase works on this Mac only because APFS is case-insensitive;
  argv[0] then echoes back "sitrep". On Linux it is command-not-found. Use
  `SitRep` in anything destined for a server.
- A **DEGRADED** verdict is normal on a healthy Mac — sandbox denials and
  codesign grumbles are routine background noise.
- `SitRep watch` prints nothing until a line matches a rule; on an idle machine
  that is roughly one a minute. To force one:
  `logger "Sandbox: testproc(123) deny(1) file-read-data /tmp/x"`.
