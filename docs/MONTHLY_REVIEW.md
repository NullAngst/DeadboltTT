# Monthly Security and Code Review

Once a month, about an hour. `bash scripts/monthly-review.sh` runs the automatic parts and writes a dated report skeleton to `docs/reviews/YYYY-MM.md`. You fill in the manual parts and commit the report.

Why every month? Because an anti-malware tool that isn't current is worse than none: it tells you you're safe when you aren't. ClamAV alone has shipped batches of parser CVE fixes this year, and a root daemon with old crates is a liability.

Start by reading last month's report. Its Open list is the first thing on this month's plate.

## 1. Run the script

```
cd DeadboltTT
bash scripts/monthly-review.sh
```

It runs and records:

1. `cargo update`, then `cargo audit` and `cargo deny check` (known-vulnerable crates, yanked crates, license changes).
2. `cargo outdated --root-deps-only`, so you see which direct crates have new major versions. Install it once with `cargo install cargo-outdated` if it's missing.
3. `pip-audit` against `gui/requirements-audit.txt`.
4. The test suite: `cargo test`, `pytest gui/`, `shellcheck` on every script.
5. `clamd --version`, the signature date, freshclam's service status, `opensnitchd -version`.
6. `systemd-analyze security` for `deadboltd` and `deadbolt-worker`.
7. Permissions and mount options on `/var/lib/deadbolt` and the quarantine folder.
8. `git log --since="1 month ago" --stat`, the change list for this review.

Anything that failed or was skipped is listed at the bottom of the report under "Automatic checks that need a look".

## 2. Check upstream

- ClamAV: compare the installed version with the latest on the ClamAV releases page. Read any security notes. Check your branch isn't near end of life (1.4 is the LTS line).
- OpenSnitch: check releases and the issue tracker for rule-matching bugs or bypasses.
- Rust toolchain: `rustup update`, rebuild, rerun the tests.
- GitHub Actions: for every `uses:` line in `.github/workflows/`, check the action's repo for a new major version or a security notice. Actions are referenced by major tag on purpose (SHA pins go stale), so this check is what keeps that honest.
- Kernel: note the running version, and check the dashboard still says "blocking" for real-time.

## 3. Code review pass

Read every file in this month's change list. Then, changes or not, check these hot spots, since they're where a root daemon goes wrong:

- `grep -rn unsafe crates/`: the only real uses are in `crates/deadbolt-shield/src/sys.rs`, each with a `SAFETY:` comment saying why it's sound. Everything else carries `forbid(unsafe_code)` or `deny(unsafe_code)`.
- Every D-Bus method in `crates/deadboltd/src/dbus.rs` calls a polkit gate as its first statement. The `polkit_coverage` test enumerates the methods and fails on a missing check. Confirm it ran and passed in the report.
- Paths: anything acting on a file goes through a descriptor (`openat2` with `RESOLVE_NO_SYMLINKS` in `crates/deadbolt-worker/src/fsops.rs`), not a path string. Search for `std::fs::` calls on client-supplied paths.
- Subprocesses: `grep -rn "Command::new\|subprocess" crates/ gui/`. Every call uses an argument vector. No shell, no string concatenation into arguments.
- Parsers: TOML settings, clamd replies, the virus-event socket, the worker protocol and OpenSnitch log parsing all reject oversized or malformed input.
- Quarantine move and restore (`crates/deadbolt-worker/src/quarantine.rs`): inode check before unlink, no overwrite on restore, execute and setuid bits stripped. The worker socket is still root-only and the worker still refuses peers that aren't uid 0.
- OpenSnitch rule generation (`crates/deadboltd/src/network.rs`): built from structs, serialized with serde_json, regex data escaped with `regex::escape`.

## 4. Check the running system

- `systemd-analyze security deadboltd` and `deadbolt-worker` are still under 4.0. If a score rose, find out which directive changed.
- The quarantine folder is still `0700 root:root`, and `findmnt /var/lib/deadbolt/quarantine` shows `noexec,nosuid,nodev`.
- The polkit policy is unchanged from the package: `dpkg -V deadbolt` (or `rpm -V deadbolt`).
- Canary files are present and unchanged: `deadboltctl shield canaries`.
- Shield allowlist: remove anything stale. Every entry is root-owned and not user-writable. No interpreters.
- Exclusions: remove any that are no longer needed. Each exclusion is a blind spot.
- Network rules: `ls /etc/opensnitchd/rules/*deadbolt-*` matches what the Network page shows.

## 5. Read the logs

- History: repeated detections of the same file or signature mean something keeps coming back.
- Shield near misses, scores 50 to 99, which the daemon logs: `deadboltctl history --kind shield`. Look for a legit tool getting close, or a pattern worth a lower threshold.
- Any fanotify queue overflow (the Protection page shows the count) or clamonacc errors in `/var/log/deadbolt/onaccess.log`.
- Quarantine: purge what's confirmed bad, report what was a false positive.

## 6. Live tests

- Tools page, Test protection (EICAR), passes. Or `deadboltctl test eicar`.
- Tools page, Test ransomware shield, passes. Or `deadboltctl test shield`.
- Block and unblock one app, and confirm with `curl` from it or the app itself.

## 7. Close out

Fill in the report: what was updated, what was found, what was fixed, what's deferred and why. Commit `docs/reviews/YYYY-MM.md`. If anything was fixed, tag a release so the packages rebuild with current dependencies.

If a check fails and you can't fix it that day, write it under "Open" with a date. Next month starts by reading that list.
