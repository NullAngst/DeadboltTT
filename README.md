# Deadbolt: Track and Terminate

Deadbolt is a normal-looking anti-malware app for Linux desktops and servers that drives ClamAV, fanotify, and OpenSnitch.

It does five jobs:

1. Manual scans of a file, a folder, or a preset (Quick, Home, Full, Custom).
2. Real-time scanning of files as they're opened, through clamd and clamonacc.
3. Ransomware detection: it spots a process mass-encrypting files, freezes it, and lets you kill it or let it go.
4. Quarantine or delete what it finds.
5. Per-app network blocking, so a game or a photo editor can't reach the internet.

It ships as three pieces: a root daemon (`deadboltd`), a Qt app that lives in the system tray (`deadbolt`), and a terminal UI for headless servers (`deadbolt-tui`), plus `deadboltctl` for scripts and cron.

Deadbolt writes no scan engine, no signature format and no firewall of its own. Where a mature tool already does the job, Deadbolt configures it and reads its output. The one piece of new detection logic is the ransomware shield, because nothing packaged for Linux does that job.

## Prerequisites

- Linux with systemd, kernel 5.17 or newer, cgroup v2 (every current desktop distro qualifies)
- A kernel with `CONFIG_FANOTIFY=y` and `CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y`. Without access permissions real-time still scans and alerts but can't block, and the dashboard says "notify-only" instead of pretending.
- ClamAV: `clamd`, `clamonacc`, `clamscan`, `freshclam`
- polkit and D-Bus
- PyQt6 from your distro, for the desktop app
- Optional: OpenSnitch 1.7.1 or newer (network blocking), udisks2 (USB auto-scan), upower (skip scans on battery), openssl (shield self-test), lynis, rkhunter, chkrootkit, debsums, snapper/btrfs-progs/ZFS (recovery helper), fangfrisch (extra signature feeds)

Deadbolt never bundles any of these. They come from your distro, so their security fixes arrive with your normal updates and never need a Deadbolt release. Settings, System requirements shows what's missing and the exact install command for your package manager. It shows the command. It does not run it.

I use apt, so here's my list. It depends on your system:

| Distro | Required | Optional |
|---|---|---|
| Debian, Ubuntu, Kubuntu | `clamav clamav-daemon clamav-freshclam python3-pyqt6 polkitd` | `opensnitch udisks2 upower iproute2 openssl lynis rkhunter chkrootkit debsums python3-nautilus` |
| Fedora | `clamav clamd clamav-freshclam python3-pyqt6 polkit` | `opensnitch udisks2 upower iproute openssl lynis rkhunter chkrootkit` |
| openSUSE | `clamav python3-PyQt6 polkit` | `opensnitch udisks2 upower iproute2 openssl lynis rkhunter chkrootkit` |
| Arch | `clamav python-pyqt6 polkit` | `opensnitch udisks2 upower iproute2 openssl lynis rkhunter chkrootkit` |

The full per-tool table lives in `data/packages.toml`. Supporting another distro is a data edit there, not code.

## Install

### From a package (Debian, Ubuntu, Kubuntu, Fedora, openSUSE)

1. Download the `.deb` or `.rpm` for your system from the Releases page. `deadbolt` is the desktop version, `deadbolt-server` is the daemon, TUI and CLI with no GUI files.
2. Install it with your package manager, since that pulls in ClamAV and polkit for you: `sudo apt install ./deadbolt_0.1.0_amd64.deb`, or `sudo dnf install ./deadbolt-0.1.0-1.x86_64.rpm`, or whichever fits.
3. Open Deadbolt from your app menu. The first-run wizard starts by itself.
4. Walk through the wizard. It checks the kernel, takes over clamd, updates signatures, plants canary files for the shield, sets up OpenSnitch if you have it, and asks about the tray and the weekly scan. On a server, run `sudo deadboltctl setup` instead (add `--yes` to accept the OpenSnitch change without a prompt).

The package installs files and starts the daemon, but it turns no protection on by itself. Protection changes your system, so you agree to it first.

### From source (everything else)

1. Install Rust (the current stable toolchain, `rustup` is easiest) and the prerequisites above.
2. Clone the repo: `git clone https://github.com/NullAngst/DeadboltTT && cd DeadboltTT`
3. Build as yourself: `cargo build --release`, since building as root leaves root-owned files in your checkout.
4. Install: `sudo bash packaging/install.sh`, or `sudo bash packaging/install.sh --server` for a headless box. Run it through `bash` since a GitHub web upload or a zip download can drop the execute bit.
5. Run the wizard: open Deadbolt from the app menu, or `sudo deadboltctl setup` on a server.

To remove a source install, `sudo bash packaging/uninstall.sh`. Add `--purge` to also remove settings, history and logs. It asks before it touches the quarantine folder.

Immutable distros (Silverblue, Kinoite, SteamOS) and containers are out of scope for v1. The daemon refuses to start inside a container and says why, since fanotify and cgroup freezing behave differently there.

## Using it

### The window

Sidebar on the left, a status banner on top, six tiles, a big Quick Scan button. The banner has three states, each with one fix button:

- Green: "Your computer is protected."
- Amber: "Attention needed: signatures are 5 days old." Button: Update now.
- Red: "At risk: real-time protection is off." Button: Turn on.

Closing the window hides it to the tray. Protection keeps running either way, because the daemon does the work. The tray menu's Quit says "Quit (protection keeps running)" so nobody is misled.

Themes: System (follows Plasma and keeps Breeze), Light, Dark, Verdigris, Kawaii Light and Kawaii Dark, in Settings. The status colors are fixed and contrast-checked in every theme.

### Scanning

- Quick covers `~/Downloads`, `~/Desktop`, `/tmp`, `/var/tmp`, `~/.local/bin`, `~/.config/autostart`, `~/.config/systemd/user` and browser extension folders.
- Home is your whole home folder. Full is `/` minus `/proc`, `/sys`, `/dev`, `/run` and the quarantine folder, and it asks for your password since it reads files you can't.
- Drag files onto the window, or right-click "Scan with Deadbolt" in Dolphin, Nautilus (needs `python3-nautilus`) or Thunar (the wizard offers to add it, since Thunar has no system-wide menu folder).

From a terminal: `deadboltctl scan ~/Downloads --action quarantine`. Exit codes are fixed: 0 clean, 1 threats found, 2 error. A scan with no threats where some files could not be scanned exits 2 and lists why, the same order clamscan uses. Every command takes `--json`.

A weekly Quick scan runs Sundays at 3 AM, set up by the wizard. A missed scan runs at the next boot. Scheduled scans use half the normal threads and skip when you're on battery.

### Real-time protection

clamonacc does the work. Files are scanned when they're opened, and with a capable kernel an infected file can't be opened at all. Root processes are scanned too, so `apt` runs and system services are a bit slower. That's the accepted cost, and Settings has a toggle to skip root if it hurts.

PUT LARGE GAME LIBRARIES IN THE EXCLUSION LIST. With blocking on, the first open of every big file waits on clamd. Steam libraries and Bottles prefixes are the usual offenders. The 25 MB real-time size limit helps, but an exclusion is the real fix.

### The ransomware shield

The shield watches what each app does to your files over a rolling 20 second window: files whose header no longer matches their type, text files that suddenly look random, the same new suffix appearing on file after file, the same note dropped in several folders, originals deleted right after a new copy is written, and decoy "canary" files being touched. When an app's score crosses the line, the whole app is frozen. Then you choose: Kill, Allow once, or Always allow. No answer means it stays frozen. That's deliberate.

Be clear on the limit: this catches the pattern after it starts. The first handful of files get hit before the score crosses the line. Freezing stops the rest. Backups and snapshots are still the real fix. The Tools page has a recovery helper that lists the latest snapshot from before an incident (snapper, btrfs or ZFS) and the files the app touched, and shows the restore command. It does not restore on its own.

Some legit tools look exactly like ransomware (`gzip file.txt` writes `file.txt.gz` and deletes the original), so package managers, backup tools, compilers and compressors are allowlisted. An allowlist entry is tied to the executable's path and SHA-256, and the binary must be root-owned and not writable by any regular user, so malware can't drop itself at `~/.local/bin/borg` and walk through. Interpreters (`python3`, `bash`, `node` and friends) are never allowlisted, even if you try. Allowing one would allow every script on the box.

Script-driven ransomware runs one short process per file from a shell or Python loop. When the offender has already exited, the shield freezes the interpreter driving it instead, so the loop stops too.

### Quarantine

Quarantined files go to `/var/lib/deadbolt/quarantine`, which is root-only (0700) and mounted `noexec,nosuid,nodev`. Each file is stored scrambled so it can't run, can't be opened by accident, and can't set off another scanner. Listing, restoring or deleting asks for your password. Why not a folder in your home? Because malware running as you could restore anything you own.

Restore puts the file back with its owner, mode and timestamp, except the execute bit, which stays off unless you tick "Restore execute permission". It refuses to overwrite an existing file.

Delete is a plain unlink. It does not shred, since overwriting means nothing on an SSD or a copy-on-write filesystem.

### Network blocking

With OpenSnitch installed, the Network page lists your apps with an Allowed/Blocked toggle and an "Allow local network" box. Deadbolt writes OpenSnitch rule files named `*deadbolt-*`, and touches nothing else in OpenSnitch's rules folder. Windows apps under Wine, Proton or Bottles are matched by their `.exe`, so blocking one game doesn't block every Windows app. Flatpak apps are matched by their app ID.

If you use `opensnitch-ui`, Deadbolt leaves OpenSnitch's config alone. If you don't, the wizard shows you the two settings it changes (allow by default, no UI address, so the daemon never waits on a popup) before it changes them.

Blocking applies to new connections. Hit "Drop existing connections" to cut ones already open. Bottles apps whose desktop entry doesn't name the `.exe` need "Add executable" with the `.exe` picked by hand.

### Servers

`deadbolt-tui` gives a server everything the GUI has, minus the tray. Run it with `sudo` over SSH. Tabs 1 to 8, keys in the footer, `?` for the full list, `q` quits the TUI only. A shield freeze pops up in any open TUI session. `--ascii` gives plain borders for terminals that mangle box drawing.

`deadboltctl` covers scripting and monitoring:

```
deadboltctl status
deadboltctl scan /srv/uploads --action quarantine
deadboltctl scan --profile home
deadboltctl quarantine list
deadboltctl quarantine restore <id> --to /tmp/restored
deadboltctl shield events
deadboltctl shield kill <id>
deadboltctl net block /usr/bin/gimp --allow-lan
deadboltctl update
deadboltctl doctor
deadboltctl test eicar
deadboltctl test shield
```

`deadboltctl doctor` exits 0 when everything required is present and 2 when something is missing, so it drops straight into a monitoring check.

## How it fits together

The GUI, TUI and CLI never touch files or services themselves. They ask `deadboltd` over the D-Bus system bus (`io.github.nullangst.Deadbolt1`), polkit approves or refuses, and the daemon drives clamd, the kernel, the quarantine store and OpenSnitch.

| Piece | Runs as | Does |
|---|---|---|
| `deadboltd` | root, with only CAP_SYS_ADMIN, CAP_DAC_READ_SEARCH, CAP_KILL, CAP_SYS_PTRACE | Decides. Runs the shield, answers D-Bus, talks to polkit, writes OpenSnitch rules. No network. |
| `deadbolt-worker` | its own `deadbolt-worker` user with four file capabilities | All file work: walking folders, handing descriptors to clamd, quarantine moves and restores, canaries. Takes jobs only from root. |
| `deadbolt-clamd` | `clamav` | ClamAV's engine with Deadbolt's generated config. Never gets file access of its own. |
| `deadbolt-clamonacc` | root | Real-time scanning. |

Deadbolt runs its own clamd from `/etc/deadbolt/clamd.conf`, which it generates from `/etc/deadbolt/deadbolt.toml`, because Debian rewrites `/etc/clamav/clamd.conf` on upgrades. The wizard masks the distro's `clamav-daemon` and `clamav-clamonacc` so two clamd processes don't each eat a gigabyte of RAM. Uninstalling unmasks them. If an upgrade unmasks them, the daemon notices and masks them again, with a notification.

Runtime sockets: the daemon's event socket is `/run/deadbolt/events.sock`, clamd's is `/run/deadbolt-clamd/clamd.ctl` and the worker's is `/run/deadbolt-worker/worker.sock`. Each service owns its own runtime folder, since a service running as `clamav` or `deadbolt-worker` can't create files in a root-owned one.

## Risks and limits

| Risk | What it means | What Deadbolt does about it |
|---|---|---|
| ClamAV's Linux detection is modest | Signatures catch known Windows malware and common Linux threats well, new Linux malware poorly | The shield covers the ransomware case by behavior. Optional extra feeds. This README says it plainly. |
| The shield acts after the first files | Some files get encrypted before the score crosses 100 | Canaries trip early. Keep backups and snapshots. |
| Shield false positives | A legit tool freezes mid-job | Allowlist, near-miss logging, a frozen app thaws with one click, nothing is killed without you |
| Freezing a terminal-launched process | A command run from Konsole shares Konsole's scope, so freezing the scope would freeze the terminal | Deadbolt falls back to SIGSTOP on the process tree when the scope holds anything else |
| clamonacc slows big file opens | The first open of a large file waits on a scan | 25 MB on-access limit, exclusions for game libraries |
| Real-time scans root too | apt runs and system services are slower | The size limit applies, Deadbolt's own file work is excluded, and Settings has a toggle to skip root |
| OpenSnitch bypass | A process in an unprivileged user namespace can dodge path matching, per OpenSnitch's own docs | The Network page shows the user-namespace setting where it exists. Blocking keeps honest apps offline. It is not a sandbox. |
| Containers and immutable distros | fanotify and cgroup freeze behave differently in containers; image-based systems can't take .deb or .rpm | The daemon refuses to start in a container and says why. Immutable distros are out of scope for v1. |
| Distro clamd takeover | A ClamAV upgrade could unmask or re-enable the distro units | The daemon checks unit state at startup and after every package transaction, and re-masks after notifying |
| Root daemon with home access | A bug in deadboltd has root reach into every home folder | Narrow capabilities, hardened units, descriptor-based file handling, and a monthly review of exactly those code paths |
| Network filesystems | Only writes made from this machine are seen on NFS or SMB, and some filesystems refuse a fanotify mark | Unmarkable filesystems show on the dashboard as unprotected by name, never fail silently |
| Frozen apps across a daemon restart | cgroup freeze and SIGSTOP outlive the daemon | The incident stays on disk. Thaw by hand with `systemctl` or `kill -CONT`, or decide again from the history. |

## Updating

Packages: your package manager updates Deadbolt like anything else. ClamAV and OpenSnitch update with your distro. Signatures update through freshclam, and the dashboard warns when they're three days stale.

Source installs: `git pull`, `cargo build --release`, `sudo bash packaging/install.sh`. The install step restarts the daemon so the new binaries take over.

Maintenance, monthly review and changelog: `maintenance.md`, `docs/MONTHLY_REVIEW.md`, `changes.md`.

## License

GPL-3.0-or-later. ClamAV is GPLv2, and Deadbolt only calls its binaries and talks to clamd over its socket, so the two sit side by side fine.

Now real-time scanning, the ransomware shield, quarantine and network blocking are all running behind one tray icon, and everything is working as it should be. Tinker with the exclusions, the shield sensitivity and the schedules as you see fit.
