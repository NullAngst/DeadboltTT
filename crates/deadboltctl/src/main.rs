//! deadboltctl: scripting and cron. Every command takes --json, and exit
//! codes are fixed: 0 clean, 1 threats found, 2 error.
#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use deadbolt_client::{Client, ClientError, Signal};
use deadbolt_common::exitcode;
use deadbolt_common::types::*;
use serde_json::{Value, json};
use std::io::{IsTerminal, Write};
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "deadboltctl",
    version,
    about = "Control Deadbolt from the command line"
)]
struct Cli {
    /// Machine-readable output.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Protection status.
    Status,
    /// Scan paths, or a preset profile.
    Scan {
        paths: Vec<String>,
        /// quick, home, full or custom
        #[arg(long)]
        profile: Option<String>,
        /// What to do with threats: quarantine, delete or report.
        #[arg(long, default_value = "report")]
        action: String,
        /// Used by the systemd timer.
        #[arg(long, hide = true)]
        scheduled: bool,
    },
    /// Quarantined files.
    Quarantine {
        #[command(subcommand)]
        cmd: QCmd,
    },
    /// The ransomware shield.
    Shield {
        #[command(subcommand)]
        cmd: SCmd,
    },
    /// Per-app network blocking.
    Net {
        #[command(subcommand)]
        cmd: NCmd,
    },
    /// Update signatures now.
    Update,
    /// Check every backend tool and kernel feature. Exit 2 if something required is missing.
    Doctor,
    /// First-run setup, the same steps as the GUI wizard.
    Setup {
        /// Answer yes to every step, including the OpenSnitch config change.
        #[arg(long)]
        yes: bool,
    },
    /// Pause protection (minutes, 0 = until restart).
    Pause { minutes: u32 },
    /// Resume protection.
    Resume,
    /// Event history.
    History {
        #[arg(long)]
        kind: Option<String>,
        #[arg(long)]
        csv: bool,
        #[arg(long, default_value_t = 50)]
        limit: u32,
    },
    /// Self tests.
    Test {
        #[command(subcommand)]
        cmd: TCmd,
    },
    /// Run rkhunter, chkrootkit, lynis, debsums or rpm-verify.
    Tool { name: String },
}

#[derive(Subcommand)]
enum QCmd {
    List,
    Restore {
        id: String,
        #[arg(long)]
        to: Option<String>,
        #[arg(long)]
        exec: bool,
        #[arg(long)]
        exclude: bool,
    },
    Delete {
        id: String,
    },
    /// Delete items older than the configured days (--auto) or --days N.
    Purge {
        #[arg(long)]
        auto: bool,
        #[arg(long)]
        days: Option<u32>,
    },
}

#[derive(Subcommand)]
enum SCmd {
    Events,
    Frozen,
    Kill {
        id: String,
    },
    Allow {
        id: String,
        #[arg(long)]
        always: bool,
    },
    Canaries,
    Recovery {
        id: String,
    },
}

#[derive(Subcommand)]
enum NCmd {
    List,
    Block {
        target: String,
        #[arg(long)]
        allow_lan: bool,
        /// native (a path), flatpak (an app id) or wine (an .exe name)
        #[arg(long, default_value = "native")]
        kind: String,
        #[arg(long)]
        name: Option<String>,
    },
    Unblock {
        target: String,
        #[arg(long, default_value = "native")]
        kind: String,
        #[arg(long)]
        name: Option<String>,
    },
    Connections,
}

#[derive(Subcommand)]
enum TCmd {
    /// Write the EICAR test file and confirm real-time blocks it.
    Eicar,
    /// Run the shield simulator and confirm the shield freezes it.
    Shield {
        /// Leave the simulator frozen instead of killing it.
        #[arg(long)]
        no_kill: bool,
    },
}

struct Out {
    json: bool,
}

impl Out {
    fn print(&self, human: impl AsRef<str>, v: Value) {
        if self.json {
            println!("{v}");
        } else {
            println!("{}", human.as_ref());
        }
    }
}

fn fail(out: &Out, e: impl std::fmt::Display) -> i32 {
    let msg = e.to_string();
    if out.json {
        println!("{}", json!({"error": msg}));
    } else {
        eprintln!("deadboltctl: {msg}");
    }
    exitcode::ERROR
}

fn when(t: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(t)
        .ok()
        .and_then(|d| {
            d.format(&time::macros::format_description!(
                "[year]-[month]-[day] [hour]:[minute] UTC"
            ))
            .ok()
        })
        .unwrap_or_else(|| t.to_string())
}

async fn wait_for<F: FnMut(&Signal) -> bool>(
    rx: &mut tokio::sync::mpsc::Receiver<Signal>,
    secs: u64,
    mut f: F,
) -> Option<Signal> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    loop {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Some(s)) if f(&s) => return Some(s),
            Ok(Some(_)) => {}
            _ => return None,
        }
    }
}

async fn run(cli: Cli) -> Result<i32, ClientError> {
    let out = Out { json: cli.json };
    let c = Client::connect().await?;
    match cli.cmd {
        Cmd::Status => {
            let s = c.status().await?;
            let human = format!(
                "{}\nReal-time: {} ({})\nShield: {}\nSignatures: {} days old, engine {}\nQuarantine: {} items\nNetwork blocks: {}",
                s.reason,
                if s.realtime.running { "on" } else { "off" },
                s.realtime.mode,
                if s.shield.enabled && s.shield.running {
                    "on"
                } else {
                    "off"
                },
                s.signatures
                    .age_days
                    .map(|d| d.to_string())
                    .unwrap_or_else(|| "?".into()),
                s.signatures.engine,
                s.quarantine_count,
                s.network_blocks
            );
            out.print(human, serde_json::to_value(&s).unwrap_or_default());
            Ok(if matches!(s.level, Level::Red) {
                exitcode::ERROR
            } else {
                exitcode::CLEAN
            })
        }
        Cmd::Scan {
            paths,
            profile,
            action,
            scheduled,
        } => {
            if !matches!(action.as_str(), "quarantine" | "delete" | "report") {
                return Ok(fail(&out, "--action must be quarantine, delete or report"));
            }
            let mut rx = c.signals().await?;
            let profile = profile.unwrap_or_default();
            if paths.is_empty() && profile.is_empty() {
                return Ok(fail(
                    &out,
                    "give paths to scan or --profile quick|home|full|custom",
                ));
            }
            if scheduled
                && std::env::var_os("DEADBOLT_SCAN_ON_BATTERY").is_none()
                && on_battery().await
            {
                out.print(
                    "On battery, skipping the scheduled scan.",
                    json!({"skipped": "battery"}),
                );
                return Ok(exitcode::CLEAN);
            }
            let job = c
                .scan(
                    &paths,
                    &profile,
                    if scheduled { "scheduled" } else { "manual" },
                )
                .await?;
            let tty = std::io::stderr().is_terminal() && !out.json;
            let fin = wait_for(&mut rx, 7 * 86_400, |s| {
                if s.member == "Progress"
                    && tty
                    && let Ok(p) = serde_json::from_str::<ScanProgress>(&s.json)
                    && p.job == job
                {
                    let mut e = std::io::stderr();
                    let _ = write!(e, "\r{}/{} files, {} found   ", p.done, p.total, p.found);
                    let _ = e.flush();
                }
                s.member == "Finished" && s.json.contains(&job)
            })
            .await;
            if tty {
                eprintln!();
            }
            let Some(fin) = fin else {
                return Ok(fail(&out, "lost track of the scan"));
            };
            let mut summary: ScanSummary =
                serde_json::from_str(&fin.json).map_err(|e| ClientError::Decode(e.to_string()))?;
            if action != "report" {
                for d in summary
                    .detections
                    .iter_mut()
                    .filter(|d| d.action == "pending")
                {
                    *d = c.scan_act(&job, &d.path, &action).await?;
                }
            }
            let mut human = format!(
                "{} files scanned, {} threats",
                summary.files,
                summary.detections.len()
            );
            for d in &summary.detections {
                human.push_str(&format!("\n{}: {} ({})", d.path, d.signature, d.action));
            }
            out.print(human, serde_json::to_value(&summary).unwrap_or_default());
            Ok(if summary.detections.is_empty() {
                exitcode::CLEAN
            } else {
                exitcode::THREATS
            })
        }
        Cmd::Quarantine { cmd } => match cmd {
            QCmd::List => {
                let items = c.quarantine_list().await?;
                let mut human = String::new();
                for i in &items {
                    human.push_str(&format!(
                        "{}  {}  {}  {}  {}\n",
                        i.id,
                        when(i.date),
                        i.signature,
                        i.source.as_str(),
                        i.original_path
                    ));
                }
                if items.is_empty() {
                    human = "Quarantine is empty.".into();
                }
                out.print(
                    human.trim_end(),
                    serde_json::to_value(&items).unwrap_or_default(),
                );
                Ok(exitcode::CLEAN)
            }
            QCmd::Restore {
                id,
                to,
                exec,
                exclude,
            } => {
                let p = c
                    .quarantine_restore(&id, to.as_deref().unwrap_or(""), exec, exclude)
                    .await?;
                out.print(format!("Restored to {p}"), json!({"restored": p}));
                Ok(exitcode::CLEAN)
            }
            QCmd::Delete { id } => {
                c.quarantine_delete(&id).await?;
                out.print("Deleted.", json!({"deleted": id}));
                Ok(exitcode::CLEAN)
            }
            QCmd::Purge { auto, days } => {
                let d = match (auto, days) {
                    (_, Some(d)) => d,
                    (true, None) => c.settings().await?.quarantine.auto_delete_days,
                    (false, None) => return Ok(fail(&out, "give --auto or --days N")),
                };
                let n = if d == 0 {
                    0
                } else {
                    c.quarantine_purge(d).await?
                };
                out.print(
                    format!("Removed {n} item(s) older than {d} days."),
                    json!({"removed": n, "days": d}),
                );
                Ok(exitcode::CLEAN)
            }
        },
        Cmd::Shield { cmd } => match cmd {
            SCmd::Events => {
                let v = c.incidents().await?;
                let mut human = String::new();
                for i in &v {
                    human.push_str(&format!(
                        "{}  {}  {}  {}  score {}  {}\n",
                        i.id,
                        when(i.time),
                        i.state,
                        i.app,
                        i.score,
                        i.exe
                    ));
                }
                if v.is_empty() {
                    human = "No shield incidents.".into();
                }
                out.print(
                    human.trim_end(),
                    serde_json::to_value(&v).unwrap_or_default(),
                );
                Ok(exitcode::CLEAN)
            }
            SCmd::Frozen => {
                let v = c.frozen().await?;
                let human = if v.is_empty() {
                    "Nothing is frozen.".to_string()
                } else {
                    v.iter()
                        .map(|i| format!("{}  {} (pid {}, {})", i.id, i.exe, i.pid, i.user))
                        .collect::<Vec<_>>()
                        .join("\n")
                };
                out.print(human, serde_json::to_value(&v).unwrap_or_default());
                Ok(exitcode::CLEAN)
            }
            SCmd::Kill { id } => {
                let i = c.decide(&id, "kill").await?;
                out.print(
                    format!("{}: {}", i.exe, i.state),
                    serde_json::to_value(&i).unwrap_or_default(),
                );
                Ok(exitcode::CLEAN)
            }
            SCmd::Allow { id, always } => {
                let i = c
                    .decide(&id, if always { "allow-always" } else { "allow-once" })
                    .await?;
                out.print(
                    format!("{}: {}", i.exe, i.state),
                    serde_json::to_value(&i).unwrap_or_default(),
                );
                Ok(exitcode::CLEAN)
            }
            SCmd::Canaries => {
                let v = c.canaries().await?;
                let human = v
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .map(|x| {
                                format!(
                                    "{}  {}",
                                    if x["unchanged"].as_bool() == Some(true) {
                                        "ok     "
                                    } else {
                                        "CHANGED"
                                    },
                                    x["path"].as_str().unwrap_or("")
                                )
                            })
                            .collect::<Vec<_>>()
                            .join("\n")
                    })
                    .unwrap_or_default();
                out.print(human, v);
                Ok(exitcode::CLEAN)
            }
            SCmd::Recovery { id } => {
                let v = c.recovery(&id).await?;
                let mut human = v["note"].as_str().unwrap_or("").to_string();
                if let Some(h) = v["snapshot"]["restore_hint"].as_str() {
                    human.push_str(&format!("\nCommand: {h}"));
                }
                for f in v["files"].as_array().into_iter().flatten() {
                    human.push_str(&format!("\n  {}", f.as_str().unwrap_or("")));
                }
                out.print(human, v);
                Ok(exitcode::CLEAN)
            }
        },
        Cmd::Net { cmd } => match cmd {
            NCmd::List => {
                let apps = c.net_apps().await?;
                let human = apps
                    .iter()
                    .map(|a| {
                        format!(
                            "{}  {:<30} {}",
                            if a.blocked { "BLOCKED" } else { "allowed" },
                            a.name,
                            a.target
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                out.print(human, serde_json::to_value(&apps).unwrap_or_default());
                Ok(exitcode::CLEAN)
            }
            NCmd::Block {
                target,
                allow_lan,
                kind,
                name,
            } => {
                let n = name.unwrap_or_else(|| {
                    target
                        .rsplit(['/', '\\'])
                        .next()
                        .unwrap_or(&target)
                        .to_string()
                });
                c.net_set(&n, &kind, &target, true, allow_lan).await?;
                out.print(
                    format!(
                        "Blocked {n}{}",
                        if allow_lan {
                            ", local network allowed"
                        } else {
                            ""
                        }
                    ),
                    json!({"blocked": target}),
                );
                Ok(exitcode::CLEAN)
            }
            NCmd::Unblock { target, kind, name } => {
                let n = name.unwrap_or_else(|| {
                    target
                        .rsplit(['/', '\\'])
                        .next()
                        .unwrap_or(&target)
                        .to_string()
                });
                c.net_set(&n, &kind, &target, false, false).await?;
                out.print(format!("Unblocked {n}"), json!({"unblocked": target}));
                Ok(exitcode::CLEAN)
            }
            NCmd::Connections => {
                let v = c.net_connections().await?;
                let human = v
                    .iter()
                    .map(|x| {
                        format!(
                            "{:<5} {:<24} {:<24} {} ({})",
                            x.proto, x.local, x.peer, x.process, x.pid
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                out.print(human, serde_json::to_value(&v).unwrap_or_default());
                Ok(exitcode::CLEAN)
            }
        },
        Cmd::Update => {
            let r = c.update_signatures().await?;
            out.print(r.clone(), json!({"result": r}));
            Ok(exitcode::CLEAN)
        }
        Cmd::Doctor => {
            let r = c.requirements(true).await?;
            let mut human = format!(
                "{:<12} {:<9} {:<10} {:<28} {}\n",
                "TOOL", "NEEDED", "STATE", "VERSION", "USED FOR"
            );
            for row in &r.rows {
                let state = match (row.installed, row.running) {
                    (false, _) => "MISSING",
                    (true, Some(false)) => "STOPPED",
                    _ => "ok",
                };
                human.push_str(&format!(
                    "{:<12} {:<9} {:<10} {:<28} {}\n",
                    row.tool,
                    if row.required { "required" } else { "optional" },
                    state,
                    row.version.chars().take(27).collect::<String>(),
                    row.feature
                ));
            }
            human.push_str("\nKERNEL\n");
            for k in &r.kernel {
                human.push_str(&format!(
                    "{:<32} {:<4} {}\n",
                    k.name,
                    if k.ok { "ok" } else { "NO" },
                    k.detail
                ));
            }
            if !r.install_command.is_empty() {
                human.push_str(&format!(
                    "\nInstall what is missing:\n  {}\n",
                    r.install_command
                ));
            }
            out.print(
                human.trim_end(),
                serde_json::to_value(&r).unwrap_or_default(),
            );
            let kernel_bad = r.kernel.iter().any(|k| k.required && !k.ok);
            Ok(if r.missing_required || kernel_bad {
                exitcode::ERROR
            } else {
                exitcode::CLEAN
            })
        }
        Cmd::Setup { yes } => {
            let mut log = Vec::new();
            for step in ["kernel", "clamd", "signatures", "shield"] {
                if !out.json {
                    eprintln!("setup: {step}...");
                }
                let r = c.setup_step(step).await?;
                log.push(json!({"step": step, "result": r}));
            }
            let preview = c.setup_step("network-preview").await?;
            if preview["available"].as_bool() == Some(true) {
                if yes {
                    log.push(json!({"step": "network", "result": c.setup_step("network").await?}));
                } else if !out.json {
                    eprintln!(
                        "setup: OpenSnitch found. Re-run with --yes to let Deadbolt set it to allow-by-default with no UI address."
                    );
                }
            }
            log.push(json!({"step": "schedules", "result": c.setup_step("schedules").await?}));
            log.push(json!({"step": "done", "result": c.setup_step("done").await?}));
            let st = c.status().await?;
            out.print(
                format!("Setup finished. {}", st.reason),
                json!({"steps": log, "status": st}),
            );
            Ok(if matches!(st.level, Level::Red) {
                exitcode::ERROR
            } else {
                exitcode::CLEAN
            })
        }
        Cmd::Pause { minutes } => {
            c.pause(minutes).await?;
            out.print("Protection paused.", json!({"paused": minutes}));
            Ok(exitcode::CLEAN)
        }
        Cmd::Resume => {
            c.resume().await?;
            out.print("Protection resumed.", json!({"resumed": true}));
            Ok(exitcode::CLEAN)
        }
        Cmd::History { kind, csv, limit } => {
            let f = json!({"kind": kind.unwrap_or_default(), "limit": limit});
            if csv {
                print!("{}", c.history_csv(&f).await?);
                return Ok(exitcode::CLEAN);
            }
            let v = c.history(&f).await?;
            let human = v
                .iter()
                .map(|e| format!("{}  {:<10} {}", when(e.time), e.kind, e.summary))
                .collect::<Vec<_>>()
                .join("\n");
            out.print(human, serde_json::to_value(&v).unwrap_or_default());
            Ok(exitcode::CLEAN)
        }
        Cmd::Test { cmd } => match cmd {
            TCmd::Eicar => test_eicar(&c, &out).await,
            TCmd::Shield { no_kill } => test_shield(&c, &out, no_kill).await,
        },
        Cmd::Tool { name } => {
            let mut rx = c.signals().await?;
            let id = c.run_tool(&name).await?;
            let s = wait_for(&mut rx, 3600, |s| {
                s.member == "ToolFinished" && s.json.contains(&id)
            })
            .await;
            let Some(s) = s else {
                return Ok(fail(&out, "tool did not finish within an hour"));
            };
            let v: Value = serde_json::from_str(&s.json).unwrap_or_default();
            let r = &v["result"];
            let mut human = r["summary"].as_str().unwrap_or("").to_string();
            for f in r["findings"].as_array().into_iter().flatten() {
                human.push_str(&format!("\n  {}", f.as_str().unwrap_or("")));
            }
            out.print(human, r.clone());
            Ok(if r["ok"].as_bool() == Some(true) {
                exitcode::CLEAN
            } else {
                exitcode::ERROR
            })
        }
    }
}

async fn on_battery() -> bool {
    tokio::process::Command::new("busctl")
        .args([
            "get-property",
            "org.freedesktop.UPower",
            "/org/freedesktop/UPower",
            "org.freedesktop.UPower",
            "OnBattery",
        ])
        .output()
        .await
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).trim() == "b true")
}

async fn test_eicar(c: &Client, out: &Out) -> Result<i32, ClientError> {
    let mut rx = c.signals().await?;
    let dir = std::env::temp_dir();
    let dir = if dir.starts_with("/tmp") {
        std::path::PathBuf::from("/var/tmp")
    } else {
        dir
    };
    let path = dir.join(format!("deadbolt-eicar-{}.com", std::process::id()));
    if let Err(e) = std::fs::write(&path, deadbolt_client::eicar()) {
        // With prevention on, even the write can be refused. That is a pass.
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            out.print(
                "Real-time protection blocked the test file. Pass.",
                json!({"pass": true, "blocked": true}),
            );
            return Ok(exitcode::CLEAN);
        }
        return Ok(fail(out, format!("cannot write the test file: {e}")));
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let read = std::fs::read(&path);
    let blocked = matches!(&read, Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied);
    let p = path.to_string_lossy().into_owned();
    let det = wait_for(&mut rx, 30, |s| {
        s.member == "Detection" && s.json.contains(&p)
    })
    .await;
    let _ = std::fs::remove_file(&path);
    let pass = blocked || det.is_some();
    let human = match (blocked, det.is_some()) {
        (true, true) => "Real-time protection blocked the EICAR test file and reported it. Pass.".to_string(),
        (true, false) => "The open was blocked, but no detection was reported within 30 seconds.".to_string(),
        (false, true) => "Detected, but the open was not blocked: real-time is notify-only on this kernel.".to_string(),
        (false, false) => "FAIL: the EICAR test file was neither blocked nor reported. Check that real-time protection is on.".to_string(),
    };
    out.print(
        human,
        json!({"pass": pass, "blocked": blocked, "reported": det.is_some()}),
    );
    Ok(if pass {
        exitcode::CLEAN
    } else {
        exitcode::ERROR
    })
}

async fn test_shield(c: &Client, out: &Out, no_kill: bool) -> Result<i32, ClientError> {
    let mut rx = c.signals().await?;
    let script = deadbolt_common::paths::SHIELD_TEST;
    let mut child = match tokio::process::Command::new(script)
        .stdin(std::process::Stdio::null())
        .spawn()
    {
        Ok(ch) => ch,
        Err(e) => return Ok(fail(out, format!("cannot start {script}: {e}"))),
    };
    let inc = wait_for(&mut rx, 120, |s| s.member == "Incident").await;
    let Some(inc) = inc else {
        let _ = child.kill().await;
        out.print(
            "FAIL: the simulator was not frozen within two minutes.",
            json!({"pass": false}),
        );
        return Ok(exitcode::ERROR);
    };
    let incident: Incident =
        serde_json::from_str(&inc.json).map_err(|e| ClientError::Decode(e.to_string()))?;
    let mut state = incident.state.clone();
    if !no_kill {
        state = c.decide(&incident.id, "kill").await?.state;
        let _ = tokio::time::timeout(Duration::from_secs(10), child.wait()).await;
    }
    if !no_kill {
        clean_simulator_leftovers();
    }
    let human = format!(
        "Pass: the shield froze {} (score {}, {} files touched). State: {state}. Incident saved as {}.",
        incident.exe,
        incident.score,
        incident.files.len(),
        incident.id
    );
    out.print(
        human,
        json!({"pass": true, "incident": incident, "state": state}),
    );
    Ok(exitcode::CLEAN)
}

/// A killed simulator cannot run its own cleanup. Remove its dummy folders.
fn clean_simulator_leftovers() {
    let mut bases = vec![
        std::env::var("HOME").unwrap_or_default(),
        "/srv".to_string(),
    ];
    if let Ok(d) = std::env::var("DEADBOLT_TEST_DIR") {
        bases.push(d);
    }
    for b in bases.iter().filter(|b| !b.is_empty()) {
        let Ok(rd) = std::fs::read_dir(b) else {
            continue;
        };
        for e in rd.filter_map(|e| e.ok()) {
            let is_ours = e
                .file_name()
                .to_string_lossy()
                .starts_with(".deadbolt-shield-test.");
            let is_dir = e.file_type().is_ok_and(|t| t.is_dir());
            if is_ours && is_dir {
                let _ = std::fs::remove_dir_all(e.path());
            }
        }
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let as_json = cli.json;
    let code = match run(cli).await {
        Ok(c) => c,
        Err(e) => {
            let out = Out { json: as_json };
            if e.daemon_down() {
                fail(
                    &out,
                    "deadboltd is not running. Start it with: sudo systemctl start deadboltd",
                )
            } else {
                fail(&out, e)
            }
        }
    };
    std::process::exit(code);
}
