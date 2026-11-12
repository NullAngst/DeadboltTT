# Security model and reporting

## Reporting a problem

Open a private security advisory on the GitHub repo (Security tab, "Report a vulnerability"). Please don't file a public issue for anything that lets a local user get root, read files they shouldn't, or turn protection off silently.

## What the app itself is trusted with

A root daemon that moves files and freezes processes is a juicy target, so it gets the least power that still does the job, and every privileged call is checked by polkit.

### Privilege split

- `deadboltd` runs as root with exactly `CAP_SYS_ADMIN` (fanotify), `CAP_DAC_READ_SEARCH` (file handles for event paths), `CAP_KILL` (freeze and kill) and `CAP_SYS_PTRACE` (reading `/proc/<pid>/exe` of other users' processes). It decides. It doesn't open user files for scanning or move them. It has no network: `RestrictAddressFamilies=AF_UNIX AF_NETLINK` and `IPAddressDeny=any`. The one job that needs `CAP_NET_ADMIN`, `ss -K` for "Drop existing connections", runs in a transient unit through `systemd-run` instead of widening the daemon.
- `deadbolt-worker` runs as its own system user with exactly `CAP_DAC_READ_SEARCH`, `CAP_DAC_OVERRIDE`, `CAP_FOWNER` and `CAP_CHOWN`. It walks folders, opens files and passes the descriptors to clamd, does quarantine moves, restores and purges, and plants canaries. It takes jobs only over `/run/deadbolt-worker/worker.sock`, a 0600 socket owned by root in a 0700 folder, and it checks the peer's credentials and refuses anyone but uid 0. It is excluded from on-access scanning so Deadbolt never scans its own work. It runs in a private network namespace. This is the main exposure, since reading and moving files in `/home`, `/srv`, `/mnt` and the real `/tmp` is its whole job, and the monthly review looks at it every time.
- clamd stays as the `clamav` user and never gets file access of its own. It only sees descriptors the worker passes it. On AppArmor systems it runs under Deadbolt's own named profile, `deadbolt-clamd` (`/etc/apparmor.d/deadbolt-clamd`), selected by `AppArmorProfile=` in the unit, since the distro profile for `/usr/sbin/clamd` only allows the distro's config and socket paths. That profile allows reading any file, since passed descriptors are checked against it too, and limits writes to its socket folder, the private `/tmp` and the VirusEvent socket. Read access is still bounded by the `clamav` user's permissions and the unit's sandbox.
- The GUI, TUI and CLI are unprivileged clients. The GUI refuses to run as root.

### polkit actions

| Action | Active local user | Inactive or remote session |
|---|---|---|
| `io.github.nullangst.deadbolt.scan` (paths you can read, status, history) | yes | auth_admin |
| `...scan-system` (paths you can't read, Full scans, system tools) | auth_admin_keep | auth_admin |
| `...quarantine-manage` | auth_admin_keep | auth_admin |
| `...shield-decide` (a frozen app you own) | yes | auth_admin |
| `...shield-decide-other` | auth_admin | auth_admin |
| `...settings` (any setting, exclusions, allowlist) | auth_admin_keep | auth_admin |
| `...network` | auth_admin_keep | auth_admin |
| `...protection-toggle` (pause or turn off) | auth_admin_keep | auth_admin |

So a background process can't quietly turn protection off. The `polkit_coverage` unit test fails the build if a D-Bus method doesn't call a polkit gate as its first statement.

### Input handling

- Every path from a client is resolved with `openat2` and `RESOLVE_NO_SYMLINKS` where Deadbolt acts on the file, and scan requests are checked against what the caller's uid could read, so "scan" can't be used to probe root-only files.
- Files are acted on through descriptors from scan to quarantine, so a symlink swapped in mid-operation gets nothing. The original is unlinked only if it is still the inode that was scanned.
- The daemon never deletes or quarantines on the say-so of a message alone. It rescans the file with clamd first.
- The virus-event socket accepts only the `clamav` user (checked by peer credentials) and only a path plus a signature name, length-capped.
- OpenSnitch rule files are generated from structs and serialized with serde_json, never string-built. App paths are validated as existing absolute paths. Regex data for Wine rules is escaped with `regex::escape`.
- Settings are parsed from TOML into typed structs. Unknown keys are rejected.
- No subprocess anywhere is started through a shell.

### Self-protection

- The daemon's own folders (`/usr/libexec/deadbolt`, `/etc/deadbolt`, `/var/lib/deadbolt`) must be root-owned and not writable by anyone else. The daemon refuses to start if they are.
- Turning protection off or pausing it sends a signal every running Deadbolt GUI turns into a desktop notification, so an off-switch is never silent. A desktop with no Deadbolt GUI running sees it in the history and the TUI. (Notifying sessions with no Deadbolt client at all would mean the daemon reaching into user sessions, which it deliberately doesn't do.)
- The shield never allowlists interpreters, even if you try.
- Quarantine is root-only, scrambled, and mounted `noexec,nosuid,nodev`.

## Known limits

See "Risks and limits" in the README. The short version: ClamAV's Linux detection is modest, the shield acts after the first files, and network blocking keeps honest apps offline but is not a sandbox.
