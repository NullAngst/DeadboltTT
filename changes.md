# Changes

2026.11.12 - Build and release

* The Release workflow runs when a release is published on GitHub, instead of on a pushed tag matching `v*`
* It can also be run by hand from the Actions tab with a tag, to build and attach files to an existing release or rebuild one
* Files are attached with `gh release upload --clobber`, so a rerun replaces them instead of failing
* The workflow checks that a release exists for the tag and that the tag reads as a version, and says so plainly if not
* `build-packages.sh` accepts `V1.2.3` as well as `v1.2.3`, and rejects versions that do not start with a digit before nfpm sees them
* CI can be run by hand from the Actions tab (workflow_dispatch)
* maintenance.md describes publishing a release from the web UI

Reasons for changes: releases published from the web UI got no files. The existing tags are `V1.0.0` and `F1.0.1`, and the old trigger matched only lowercase `v*`, so the Release workflow never ran. The build seen on release was the CI workflow, which also runs on tag pushes but only keeps its packages as a run artifact. Triggering on the published release removes the dependence on tag spelling. CI had no manual trigger at all.

2026.11.12 - Bug fix

* OpenSnitch rule files are still written to a temp name and renamed into place, then get their trailing newline appended, so opensnitchd's rules watcher sees a Write event and loads the rule right away
* Applies to per-app block rules, LAN allow rules, and the deny-temp-folders rule
* New unit test: rule files are complete JSON with one trailing newline, rewrites work, no temp file is left behind
* CI checks opensnitchd logged "Ruleset changed" for the block rule before testing curl, and "Logs on failure" prints the rules folder and the end of the OpenSnitch log

Reasons for changes: the network block test reported "Blocked curl" but curl still reached the internet. OpenSnitch's rules watcher (daemon/rule/loader.go, liveReloadWorker) reloads only on fsnotify Write and Remove events. Deadbolt's rename into place arrives as Create, which it ignores, so new rules stayed on disk unloaded until opensnitchd restarted. Unblocking happened to work, since deleting a file is a Remove. Checked with a watcher built on OpenSnitch's own fsnotify version (1.4.7) and its exact filter: the old write pattern produced only ignored Create events, the new one produced a reload of the complete file. Appending the newline keeps the reason for the rename: at every moment the .json file is complete, valid JSON.

2026.11.12 - Bug fix

* The worker's file helpers fall back to walking the path one component at a time with `openat(O_NOFOLLOW)` when `openat2` returns ENOSYS. Symlinks are still refused in every component, with the same ELOOP error
* Covers scanning, quarantine, restore and canary planting, which all go through these helpers
* New unit test for the fallback: symlinked directory, symlinked file, "..", creating relative to a directory descriptor, and "/"
* CI runs the worker's tests a second time under `systemd-run` with the unit's seccomp settings (RestrictSUIDSGID, @system-service)

Reasons for changes: the scan step now printed the reason, "Function not implemented (os error 38)". deadbolt-worker.service has RestrictSUIDSGID=yes, and systemd blocks openat2 entirely under that setting with ENOSYS, because seccomp cannot read the mode inside struct open_how and so cannot tell whether a call creates a setuid file. Every file operation in the worker used openat2 with no fallback, so under systemd it could not open anything: scans errored, and quarantine, restore and canaries were broken the same way. The fallback keeps both protections instead of dropping RestrictSUIDSGID. Reproduced locally with a seccomp filter that answers openat2 with ENOSYS: all 12 worker tests, including the quarantine round trip, pass with it in place.

2026.11.11 - Bug fix

* The worker sends back why a file could not be scanned ("path: reason") for the first 20 failures in a job, instead of only counting them
* Scan summaries carry those reasons in a new `problems` list, and `deadboltctl scan` prints them under "not scanned:"
* `deadboltctl scan` exits 2 when no threats were found but some files could not be scanned. Threats still exit 1
* A file removed, or replaced by something that is not a regular file, between the walk and the scan is skipped instead of counted as an error
* README exit code line covers the new case

Reasons for changes: the "Exit codes 0, 1, 2" step showed every manual scan failing on its one file, clean or EICAR, and the output gave a count with no reason. The clean scan still exited 0, which told a script the files were clean when clamd never read them. clamscan uses the same order (threats, then errors, then clean). Skipping vanished files keeps the weekly scheduled scan, whose unit only accepts exits 0 and 1, from failing on ordinary churn like browser caches. The cause of the scan errors themselves is still open: with these changes the next CI run prints clamd's reason in the step log.

2026.11.11 - Bug fix

* The shield decides whether a filesystem is read-only from its superblock options in mountinfo, not the mount options
* A written file whose name gained a suffix right after the write ("a.docx.locked") still counts under its original type
* The status banner goes amber when the shield is running but watching no filesystems
* `deadboltctl test shield` says which filesystems the shield is watching, and which it could not, when the test fails

Reasons for changes: the integration job failed at "Shield freezes the simulator" with all 200 files encrypted and nothing frozen. deadboltd runs with ProtectSystem=strict and ProtectHome=read-only, so inside its own namespace / and /home are read-only binds of writable filesystems. The shield read the per-mount "ro" flag, skipped every mount that held /home, /srv and /mnt, and silently watched nothing. A filesystem-wide fanotify mark still sees writes made through the writable mounts outside the sandbox, so only a read-only superblock should be skipped. Reproduced with a read-only root namespace: the old code marked nothing and the simulator finished all 200 files; the new code marked / and froze the simulator's bash loop after about 20 files. The suffix fallback closes a race where the descriptor's path is read after mv has already renamed the file. Nothing on the dashboard showed the shield was blind, hence the new banner.

2026.11.11 - Bug fix

* `deadbolt-clamd.service` runs clamd under Deadbolt's own AppArmor profile, `deadbolt-clamd`, through `AppArmorProfile=-deadbolt-clamd`, and starts after `apparmor.service`
* New profile `data/apparmor/deadbolt-clamd`, installed to `/etc/apparmor.d/deadbolt-clamd` as a config file (deb conffile, rpm noreplace), with `/etc/apparmor.d/local/deadbolt-clamd` for local additions
* Post-install loads the profile before clamd is started or restarted; pre-remove unloads it. The distro's `/usr/sbin/clamd` profile is never edited
* `packaging/manifest.txt` has a `config` kind, which `build-packages.sh` packages as `config|noreplace`
* `deadboltctl doctor` has a kernel row, "AppArmor profile deadbolt-clamd", required when a distro clamd profile is loaded
* CI checks that the profile is loaded after install, and "Logs on failure" prints AppArmor denials from the kernel log
* maintenance.md and docs/SECURITY.md cover the profile

Reasons for changes: the integration job ended with "clamd is installed but its service is not running" while clamonacc was fine. Ubuntu's clamav-daemon ships an enforcing AppArmor profile for /usr/sbin/clamd that only allows /etc/clamav/clamd.conf and /run/clamav/clamd.ctl. Deadbolt's clamd reads /etc/deadbolt/clamd.conf and listens on /run/deadbolt-clamd/clamd.ctl, so it was denied, exited, and sat in auto-restart. clamonacc has no distro profile, which is why only clamd showed as stopped. The same profile ships on Debian and openSUSE, so this broke real installs too, not just CI. A named profile selected by the unit was picked over editing the distro's local override, since that file belongs to the distro package's world and clamd also has to read whatever descriptors the worker passes it, which the distro profile does not allow.

2026.11.09 - Bug fix

* The "done" setup step refreshes the system requirements report before setup reports status
* `deadboltctl setup` lists which required tools are missing or stopped when it ends red, and points to `deadboltctl doctor`
* The CI "Logs on failure" step runs `deadboltctl doctor` and `systemctl status` on Deadbolt's units before dumping the journal

Reasons for changes: with the socket fixed, the integration job got through every setup step and still ended with "Missing required packages or services". The requirements report is cached by the first setup step, "kernel", which runs before the "clamd" step starts deadbolt-clamd and deadbolt-clamonacc. Both units were recorded as stopped, and nothing refreshed the cache until a package change or a daemon restart, so a correct setup always ended red. The extra output is so the next failure says what is actually wrong instead of one banner line.

2026.11.09 - Bug fix

* `deadbolt-worker` hands its socket to the peer uid (root) after binding, still mode 0600
* The worker exits with an error if the chmod or chown on its socket fails, instead of ignoring it
* `docs/SECURITY.md` states the socket's owner and mode

Reasons for changes: the integration job failed at `deadboltctl setup --yes` with "deadbolt-worker is not reachable: Permission denied (os error 13)". The worker created the socket as deadbolt-worker with mode 0600, and deadboltd runs as root without CAP_DAC_OVERRIDE, so root had no write permission on the socket and connect() failed. Owning the socket as root fixes that without giving the daemon any new capability. The socket stays root-only, and the worker still checks the peer uid.

2026.11.05 - Build fix

* CI and release workflows call `bash packaging/build-packages.sh` instead of running it directly
* `install.sh` and `uninstall.sh` call the post-install and pre-remove scripts through `bash`
* README, `docs/MONTHLY_REVIEW.md` and the script usage lines say `bash ...` for every repo script

Reasons for changes: the GitHub web uploader stores every file as 644, so "Build packages" failed with "Permission denied" (exit 126). Calling scripts through bash makes the build and source installs work no matter how the files reach the repo. Installed files are unaffected, since the packages and install.sh set modes from packaging/manifest.txt.

2026.11.04 - Initial build

* Root daemon `deadboltd` (Rust, tokio, zbus) on the D-Bus system bus as `io.github.nullangst.Deadbolt1`, six interfaces, every method behind a polkit check, enforced by a test
* File worker `deadbolt-worker` as its own system user: folder walks, FILDES scanning through clamd sessions, scrambled quarantine with inode-checked moves and no-overwrite restores, canary planting, startup items review
* Ransomware shield (`deadbolt-shield`): two fanotify groups, per-app scoring over a rolling window, canary files, cgroup freeze or SIGSTOP through pidfds, freezes the interpreter driving short-lived writers, hash-and-owner checked allowlist
* Real-time protection through Deadbolt's own clamd and clamonacc units, with a generated clamd.conf and the distro units masked
* Per-app network blocking through OpenSnitch rule files, with Wine/Bottles `.exe` and Flatpak app ID matching
* System requirements check from `data/packages.toml`, with install commands for apt, dnf, zypper and pacman
* PyQt6 desktop app with tray, first-run wizard, frozen-app dialog, eight pages, and System, Light, Dark, Verdigris, Kawaii Light and Kawaii Dark themes
* ratatui TUI for servers and `deadboltctl` with `--json` and fixed exit codes
* Dolphin, Nautilus and Thunar "Scan with Deadbolt" menus
* Hardened systemd units (deadboltd 2.9, deadbolt-worker 1.4 on `systemd-analyze security`), noexec quarantine mount, scan and purge timers
* `.deb` and `.rpm` for `deadbolt` and `deadbolt-server` from one manifest, `install.sh` and `uninstall.sh` for source installs
* GitHub Actions: lint, tests, cargo audit and cargo deny on every push, a root integration job on a real kernel, and packages plus a source tarball on every `v*` tag
* Monthly review script and checklist

Reasons for changes: first build of the Deadbolt build spec, in one run.
