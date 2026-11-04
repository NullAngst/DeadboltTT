//! Extra utilities, each a wrapper around a tool that already exists. They run
//! in a transient systemd unit (systemd-run) so they get a normal, unsandboxed
//! environment instead of deadboltd's hardened one.

use deadbolt_common::types::Incident;
use serde::Serialize;
use std::time::Duration;
use tokio::process::Command;

#[derive(Debug, Clone, Serialize)]
pub struct ToolResult {
    pub tool: String,
    pub ok: bool,
    pub summary: String,
    pub findings: Vec<String>,
    pub raw: String,
}

fn argv(tool: &str) -> Option<Vec<&'static str>> {
    Some(match tool {
        "rkhunter" => vec![
            "rkhunter",
            "--check",
            "--skip-keypress",
            "--report-warnings-only",
            "--nocolors",
        ],
        "chkrootkit" => vec!["chkrootkit", "-q"],
        "lynis" => vec!["lynis", "audit", "system", "--quick", "--no-colors"],
        "debsums" => vec!["debsums", "-s"],
        "rpm-verify" => vec!["rpm", "-Va"],
        _ => return None,
    })
}

pub async fn run(tool: &str) -> ToolResult {
    let Some(args) = argv(tool) else {
        return ToolResult {
            tool: tool.into(),
            ok: false,
            summary: format!("unknown tool {tool}"),
            findings: vec![],
            raw: String::new(),
        };
    };
    if crate::requirements::which(args[0]).is_none() {
        return ToolResult {
            tool: tool.into(),
            ok: false,
            summary: format!("{} is not installed", args[0]),
            findings: vec![],
            raw: String::new(),
        };
    }
    let mut cmd = Command::new("systemd-run");
    cmd.args([
        "--wait",
        "--pipe",
        "--quiet",
        "--collect",
        "--setenv=LC_ALL=C",
        "--",
    ])
    .args(&args);
    cmd.stdin(std::process::Stdio::null());
    let out = tokio::time::timeout(Duration::from_secs(3600), cmd.output()).await;
    let (raw, code) = match out {
        Ok(Ok(o)) => {
            let mut s = String::from_utf8_lossy(&o.stdout).into_owned();
            s.push_str(&String::from_utf8_lossy(&o.stderr));
            (s, o.status.code().unwrap_or(-1))
        }
        Ok(Err(e)) => (format!("cannot start: {e}"), -1),
        Err(_) => ("timed out after an hour".into(), -1),
    };
    let raw: String = raw.chars().take(1 << 20).collect();
    let (summary, findings) = interpret(tool, &raw, code);
    ToolResult {
        tool: tool.into(),
        ok: code >= 0,
        summary,
        findings,
        raw,
    }
}

/// Turn raw tool output into a one-line summary and plain findings.
pub fn interpret(tool: &str, raw: &str, code: i32) -> (String, Vec<String>) {
    match tool {
        "rkhunter" => {
            let f: Vec<String> = raw
                .lines()
                .filter(|l| l.contains("Warning:"))
                .map(|l| l.trim().replace("Warning: ", ""))
                .collect();
            let s = if f.is_empty() {
                "No warnings.".into()
            } else {
                format!(
                    "{} warning{} to look at. Many are harmless on a normal desktop.",
                    f.len(),
                    if f.len() == 1 { "" } else { "s" }
                )
            };
            (s, f)
        }
        "chkrootkit" => {
            let f: Vec<String> = raw
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(String::from)
                .collect();
            let s = if f.is_empty() {
                "Nothing suspicious reported.".into()
            } else {
                format!(
                    "{} line{} reported.",
                    f.len(),
                    if f.len() == 1 { "" } else { "s" }
                )
            };
            (s, f)
        }
        "lynis" => {
            let index = raw
                .lines()
                .find(|l| l.contains("Hardening index"))
                .and_then(|l| l.split(':').nth(1))
                .map(|v| v.split_whitespace().next().unwrap_or("").to_string())
                .unwrap_or_default();
            let report = std::fs::read_to_string("/var/log/lynis-report.dat").unwrap_or_default();
            let f: Vec<String> = report
                .lines()
                .filter_map(|l| l.strip_prefix("suggestion[]="))
                .map(|l| {
                    let parts: Vec<&str> = l.split('|').collect();
                    format!(
                        "{}: {}",
                        parts.first().unwrap_or(&""),
                        parts.get(1).unwrap_or(&"")
                    )
                })
                .take(10)
                .collect();
            (
                if index.is_empty() {
                    "Audit finished.".into()
                } else {
                    format!("Hardening index {index} out of 100.")
                },
                f,
            )
        }
        "debsums" | "rpm-verify" => {
            let f: Vec<String> = raw
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .take(500)
                .map(String::from)
                .collect();
            let s = if f.is_empty() && code == 0 {
                "Every package file matches its package.".into()
            } else {
                format!(
                    "{} file{} no longer match their package. Config files you edited show up here too.",
                    f.len(),
                    if f.len() == 1 { "" } else { "s" }
                )
            };
            (s, f)
        }
        _ => (String::new(), Vec::new()),
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Snapshot {
    pub source: String,
    pub name: String,
    pub time: i64,
    pub restore_hint: String,
}

async fn out(args: &[&str]) -> String {
    match Command::new(args[0])
        .args(&args[1..])
        .env("LC_ALL", "C")
        .stdin(std::process::Stdio::null())
        .output()
        .await
    {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).into_owned(),
        _ => String::new(),
    }
}

/// Snapshots from snapper, btrfs and ZFS. Lists only; never restores.
pub async fn snapshots() -> Vec<Snapshot> {
    let mut v = Vec::new();
    if crate::requirements::which("zfs").is_some() {
        for l in out(&[
            "zfs",
            "list",
            "-H",
            "-p",
            "-t",
            "snapshot",
            "-o",
            "name,creation",
        ])
        .await
        .lines()
        {
            let mut f = l.split('\t');
            if let (Some(n), Some(t)) = (f.next(), f.next().and_then(|t| t.trim().parse().ok())) {
                let ds = n.split('@').next().unwrap_or(n);
                v.push(Snapshot { source: "zfs".into(), name: n.into(), time: t, restore_hint: format!("Files are readable under <mountpoint of {ds}>/.zfs/snapshot/{}/ ; copy back what you need, or: zfs rollback {n}", n.split('@').nth(1).unwrap_or("")) });
            }
        }
    }
    if crate::requirements::which("snapper").is_some() {
        let text = out(&[
            "snapper",
            "--csvout",
            "list",
            "--columns",
            "config,number,date",
        ])
        .await;
        for l in text.lines().skip(1) {
            let f: Vec<&str> = l.split(',').collect();
            if f.len() < 3 {
                continue;
            }
            let t = time::PrimitiveDateTime::parse(
                f[2],
                &time::macros::format_description!("[year]-[month]-[day] [hour]:[minute]:[second]"),
            )
            .map(|d| d.assume_utc().unix_timestamp())
            .unwrap_or(0);
            v.push(Snapshot {
                source: "snapper".into(),
                name: format!("{} #{}", f[0], f[1]),
                time: t,
                restore_hint: format!("snapper -c {} undochange {}..0 <files>", f[0], f[1]),
            });
        }
    } else if crate::requirements::which("btrfs").is_some() {
        for l in out(&["btrfs", "subvolume", "list", "-s", "/"])
            .await
            .lines()
        {
            // ID 260 gen 9 cgen 9 top level 5 otime 2026-10-01 10:00:00 path .snapshots/1/snapshot
            let Some(path) = l.split(" path ").nth(1) else {
                continue;
            };
            let t = l
                .split(" otime ")
                .nth(1)
                .and_then(|r| r.get(..19))
                .and_then(|s| {
                    time::PrimitiveDateTime::parse(
                        s,
                        &time::macros::format_description!(
                            "[year]-[month]-[day] [hour]:[minute]:[second]"
                        ),
                    )
                    .ok()
                })
                .map(|d| d.assume_utc().unix_timestamp())
                .unwrap_or(0);
            v.push(Snapshot {
                source: "btrfs".into(),
                name: path.into(),
                time: t,
                restore_hint: format!("cp -a --reflink=auto /{path}/<file> <file>"),
            });
        }
    }
    v.sort_by_key(|s| std::cmp::Reverse(s.time));
    v
}

#[derive(Debug, Clone, Serialize)]
pub struct Recovery {
    pub incident: Incident,
    pub snapshot: Option<Snapshot>,
    pub files: Vec<String>,
    pub note: String,
}

pub fn recovery_for(incident: &Incident, snaps: &[Snapshot]) -> Recovery {
    let snap = snaps
        .iter()
        .filter(|s| s.time > 0 && s.time < incident.time)
        .max_by_key(|s| s.time)
        .cloned();
    let note = match &snap {
        Some(s) => format!("Latest snapshot before the incident: {} ({}). Deadbolt shows the command, it does not restore on its own.", s.name, s.source),
        None => "No snapshot from before the incident was found. Restore the listed files from your backups.".into(),
    };
    Recovery {
        incident: incident.clone(),
        snapshot: snap,
        files: incident.files.clone(),
        note,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interpretations() {
        let (s, f) = interpret(
            "rkhunter",
            "Warning: The command '/usr/bin/lwp-request' has been replaced\nok\n",
            1,
        );
        assert_eq!(f.len(), 1);
        assert!(s.starts_with("1 warning"));
        let (s, _) = interpret("debsums", "", 0);
        assert!(s.starts_with("Every package"));
        let (s, _) = interpret(
            "lynis",
            "  Hardening index : 64 [############        ]\n",
            0,
        );
        assert_eq!(s, "Hardening index 64 out of 100.");
    }

    #[test]
    fn picks_latest_before() {
        let inc = Incident {
            id: "i".into(),
            time: 1000,
            app: String::new(),
            exe: String::new(),
            pid: 1,
            uid: 1000,
            user: String::new(),
            cgroup: String::new(),
            freeze_method: String::new(),
            score: 100,
            signals: vec![],
            files: vec!["/a".into()],
            binary_signature: None,
            state: "killed".into(),
        };
        let snaps = vec![
            Snapshot {
                source: "zfs".into(),
                name: "after".into(),
                time: 2000,
                restore_hint: String::new(),
            },
            Snapshot {
                source: "zfs".into(),
                name: "before".into(),
                time: 900,
                restore_hint: String::new(),
            },
            Snapshot {
                source: "zfs".into(),
                name: "older".into(),
                time: 100,
                restore_hint: String::new(),
            },
        ];
        assert_eq!(recovery_for(&inc, &snaps).snapshot.unwrap().name, "before");
    }
}
