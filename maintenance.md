# Maintenance

How to check Deadbolt and keep it current every couple of months. The monthly security review in `docs/MONTHLY_REVIEW.md` is the deeper version of this; on months you only have twenty minutes, do this list.

## Every couple of months

1. Pull and update crates: `git pull && cargo update`, since releases should ship current crates and nothing is pinned.
2. Check for known-vulnerable crates: `cargo audit && cargo deny check`. A failure here blocks a release in CI too.
3. Build and test: `cargo clippy --all-targets -- -D warnings && cargo test`, then `QT_QPA_PLATFORM=offscreen python3 -m pytest gui/`.
4. Lint the rest: `pipx run ruff check gui/` (or whichever way you run ruff) and `shellcheck tools/deadbolt-shield-test scripts/*.sh packaging/*.sh packaging/scripts/*.sh`.
5. Check ClamAV: `clamd --version` against the ClamAV releases page. If your distro is behind on a security fix, the dashboard says so ("a ClamAV security update is waiting"). Update through your package manager, never by bundling.
6. Check OpenSnitch: compare `opensnitchd -version` with its releases, and skim its issue tracker for rule-matching bugs.
7. Check the GitHub Actions in `.github/workflows/`: for each `uses:` line, look at the action's repo for a new major version or a security notice, and bump the tag if there is one.
8. Run the live tests on a real machine: `deadboltctl test eicar` and `deadboltctl test shield`. Both should pass.
9. Look at near misses: `deadboltctl history --kind shield`. A legit tool scoring 50 to 99 again and again is a candidate for the allowlist, or a sign the scoring needs a look.
10. Tag a release (`git tag v0.x.y && git push --tags`) so the packages rebuild with current dependencies, and add an entry to `changes.md`.

## When something breaks

- Daemon won't start: `journalctl -u deadboltd -b`. The two refusals it prints on purpose are "inside a container" and a self-protection problem (one of its folders is writable by someone other than root). Fix the permission, don't loosen the check.
- Red banner "Missing required packages": Settings, System requirements has the install command. Copy, paste, done. `deadboltctl doctor` prints the same table on a server.
- Real-time says notify-only: the kernel lacks `CONFIG_FANOTIFY_ACCESS_PERMISSIONS`. Nothing to fix in Deadbolt.
- A filesystem shows as unprotected: it refused a fanotify mark (network filesystems usually do). That's a fact about the filesystem, and the dashboard says so instead of failing silently.
- A legit app keeps getting frozen: choose Always allow (root-owned binaries only), or add an exclusion for the folder it works in.
- clamd and the distro's clamav-daemon both running: an upgrade brought the distro unit back. The daemon re-masks it on the next package transaction; to do it now, run the wizard's clamd step again (`deadboltctl setup`).

## Where things live

- Settings: `/etc/deadbolt/deadbolt.toml` (the generated `/etc/deadbolt/clamd.conf` is overwritten, so don't edit it)
- State: `/var/lib/deadbolt` (history database, incidents, allowlist, canary list, quarantine)
- Logs: `journalctl -u deadboltd -u deadbolt-worker -u deadbolt-clamd -u deadbolt-clamonacc`, plus `/var/log/deadbolt/onaccess.log`
- Per-user GUI settings: `~/.config/deadbolt/gui.json`
