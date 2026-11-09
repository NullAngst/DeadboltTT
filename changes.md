# Changes

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
