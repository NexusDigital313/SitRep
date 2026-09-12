# SitRep — progress

Last updated: 2026-09-12. Branch `macos-finish`, 4 commits ahead of `master`, **not pushed**.

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
  can surface an older crash. Left as a design call; the filename carries the
  date, so it is legible.
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
