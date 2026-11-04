//! Startup items review: what runs at login or on a schedule.

use deadbolt_common::perm;
use deadbolt_common::protocol::StartupItem;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// First real program in an Exec= or ExecStart= line or a cron command.
pub fn target_of(cmd: &str) -> String {
    let mut words = cmd
        .split_whitespace()
        .map(|w| w.trim_matches(|c| c == '"' || c == '\''));
    // systemd prefixes like "-", "@", "+", "!"
    let mut first = words.next().unwrap_or("");
    while first.contains('=') || first == "env" || first == "/usr/bin/env" {
        first = match words.next() {
            Some(w) => w,
            None => return String::new(),
        };
    }
    let first = first.trim_start_matches(['-', '@', '+', '!', ':']);
    if first.starts_with('/') {
        return first.to_string();
    }
    for dir in [
        "/usr/local/bin",
        "/usr/bin",
        "/bin",
        "/usr/local/sbin",
        "/usr/sbin",
        "/sbin",
    ] {
        let p = Path::new(dir).join(first);
        if p.is_file() {
            return p.to_string_lossy().into_owned();
        }
    }
    first.to_string()
}

fn key_value<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.lines()
        .find_map(|l| l.trim().strip_prefix(key)?.trim_start().strip_prefix('='))
        .map(str::trim)
}

fn owner_of(p: &Path) -> String {
    std::fs::metadata(p)
        .map(|m| perm::user_name(m.uid()))
        .unwrap_or_default()
}

fn read_capped(p: &Path) -> Option<String> {
    let m = std::fs::symlink_metadata(p).ok()?;
    if !m.is_file() || m.len() > 256 * 1024 {
        return None;
    }
    std::fs::read_to_string(p).ok()
}

fn files_in(dir: &Path, ext: &str) -> Vec<std::path::PathBuf> {
    std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| ext.is_empty() || p.extension().is_some_and(|x| x == ext))
                .collect()
        })
        .unwrap_or_default()
}

fn desktop_items(dir: &Path, kind: &str, out: &mut Vec<StartupItem>) {
    for f in files_in(dir, "desktop") {
        let Some(text) = read_capped(&f) else {
            continue;
        };
        if key_value(&text, "Hidden") == Some("true") {
            continue;
        }
        let exec = key_value(&text, "Exec").unwrap_or("");
        out.push(StartupItem {
            kind: kind.into(),
            name: key_value(&text, "Name").unwrap_or("").to_string(),
            file: f.to_string_lossy().into_owned(),
            target: target_of(exec),
            owner: owner_of(&f),
        });
    }
}

fn cron_lines(text: &str, system: bool) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter(|l| !l.split_whitespace().next().unwrap_or("").contains('='))
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            let skip = if l.starts_with('@') { 1 } else { 5 } + usize::from(system);
            for _ in 0..skip {
                f.next()?;
            }
            Some(f.collect::<Vec<_>>().join(" "))
        })
        .collect()
}

pub fn collect(homes: &[(u32, String)]) -> Vec<StartupItem> {
    let mut out = Vec::new();
    desktop_items(Path::new("/etc/xdg/autostart"), "xdg-autostart", &mut out);
    for (_, home) in homes {
        let h = Path::new(home);
        desktop_items(&h.join(".config/autostart"), "autostart", &mut out);
        for f in files_in(&h.join(".config/systemd/user"), "service") {
            let Some(text) = read_capped(&f) else {
                continue;
            };
            out.push(StartupItem {
                kind: "systemd-user".into(),
                name: f
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                file: f.to_string_lossy().into_owned(),
                target: target_of(key_value(&text, "ExecStart").unwrap_or("")),
                owner: owner_of(&f),
            });
        }
    }
    let mut cron_files: Vec<(std::path::PathBuf, bool)> = vec![("/etc/crontab".into(), true)];
    cron_files.extend(
        files_in(Path::new("/etc/cron.d"), "")
            .into_iter()
            .map(|p| (p, true)),
    );
    for spool in ["/var/spool/cron/crontabs", "/var/spool/cron"] {
        cron_files.extend(
            files_in(Path::new(spool), "")
                .into_iter()
                .filter(|p| p.is_file())
                .map(|p| (p, false)),
        );
    }
    for (f, system) in cron_files {
        let Some(text) = read_capped(&f) else {
            continue;
        };
        for cmd in cron_lines(&text, system) {
            out.push(StartupItem {
                kind: "cron".into(),
                name: cmd.chars().take(80).collect(),
                file: f.to_string_lossy().into_owned(),
                target: target_of(&cmd),
                owner: owner_of(&f),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets() {
        assert_eq!(target_of("/opt/x/run --flag"), "/opt/x/run");
        assert_eq!(
            target_of("env FOO=1 /home/u/.local/bin/miner"),
            "/home/u/.local/bin/miner"
        );
        assert_eq!(target_of("-/usr/lib/thing"), "/usr/lib/thing");
    }

    #[test]
    fn cron() {
        let t = "SHELL=/bin/sh\n# c\n*/5 * * * * /home/u/.x/y -q\n@reboot /tmp/evil\n";
        assert_eq!(cron_lines(t, false), vec!["/home/u/.x/y -q", "/tmp/evil"]);
        assert_eq!(
            cron_lines("17 * * * * root cd / && run-parts x", true),
            vec!["cd / && run-parts x"]
        );
    }
}
