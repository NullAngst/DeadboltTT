//! Daemon state and the logic behind every D-Bus method.

use crate::history::History;
use crate::network::Rules;
use crate::requirements;
use crate::units;
use crate::worker::{Worker, WorkerError};
use deadbolt_common::paths;
use deadbolt_common::perm;
use deadbolt_common::protocol::{Reply, Request, ScanOptions};
use deadbolt_common::settings::{Settings, ThreatAction};
use deadbolt_common::types::*;
use deadbolt_shield::allowlist::Allowlist;
use deadbolt_shield::freeze::{self, Frozen};
use deadbolt_shield::score::AppKey;
use deadbolt_shield::{Monitor, ShieldEvent};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};

pub const IFACE_STATUS: &str = "io.github.nullangst.Deadbolt1.Status";
pub const IFACE_SCAN: &str = "io.github.nullangst.Deadbolt1.Scan";
pub const IFACE_SHIELD: &str = "io.github.nullangst.Deadbolt1.Shield";
pub const IFACE_SETTINGS: &str = "io.github.nullangst.Deadbolt1.Settings";

pub struct FrozenEntry {
    pub incident: Incident,
    pub frozen: Frozen,
    pub key: AppKey,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Persist {
    pub setup_done: bool,
    pub last_scan: Option<ScanSummary>,
}

pub struct Job {
    pub summary: ScanSummary,
    pub progress: Option<ScanProgress>,
    pub owner: u32,
}

pub struct App {
    pub settings: RwLock<Settings>,
    pub conn: OnceLock<zbus::Connection>,
    pub worker: Worker,
    pub history: History,
    pub monitor: OnceLock<Monitor>,
    pub allow: Arc<Allowlist>,
    pub frozen: Mutex<HashMap<String, FrozenEntry>>,
    pub incidents: Mutex<Vec<Incident>>,
    pub jobs: Mutex<HashMap<String, Job>>,
    pub persist: Mutex<Persist>,
    pub paused_until: Mutex<Option<i64>>,
    pub reqs: Mutex<Option<RequirementsReport>>,
    pub blocking: AtomicBool,
    pub dedupe: Mutex<HashMap<(u64, u64, String), Instant>>,
    pub signatures: Mutex<SignatureState>,
    pub rules: Rules,
}

pub type Shared = Arc<App>;

pub fn err<E: std::fmt::Display>(e: E) -> zbus::fdo::Error {
    zbus::fdo::Error::Failed(e.to_string())
}

impl App {
    pub fn new(settings: Settings, history: History, allow: Arc<Allowlist>) -> App {
        let persist: Persist = std::fs::read(paths::STATE_FILE)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        App {
            settings: RwLock::new(settings),
            conn: OnceLock::new(),
            worker: Worker::new(),
            history,
            monitor: OnceLock::new(),
            allow,
            frozen: Mutex::new(HashMap::new()),
            incidents: Mutex::new(Vec::new()),
            jobs: Mutex::new(HashMap::new()),
            persist: Mutex::new(persist),
            paused_until: Mutex::new(None),
            reqs: Mutex::new(None),
            blocking: AtomicBool::new(false),
            dedupe: Mutex::new(HashMap::new()),
            signatures: Mutex::new(SignatureState {
                engine: String::new(),
                updated: None,
                age_days: None,
                engine_outdated: false,
            }),
            rules: Rules::new(),
        }
    }

    pub fn settings(&self) -> Settings {
        self.settings.read().map(|s| s.clone()).unwrap_or_default()
    }

    fn save_persist(&self) {
        if let Ok(p) = self.persist.lock()
            && let Ok(data) = serde_json::to_vec_pretty(&*p)
        {
            let tmp = format!("{}.tmp", paths::STATE_FILE);
            if std::fs::write(&tmp, data).is_ok() {
                let _ = std::fs::rename(tmp, paths::STATE_FILE);
            }
        }
    }

    pub async fn emit(&self, iface: &str, name: &str, body: &impl Serialize) {
        let Some(conn) = self.conn.get() else { return };
        let json = serde_json::to_string(body).unwrap_or_default();
        if let Err(e) = conn
            .emit_signal(
                None::<&str>,
                deadbolt_common::OBJECT_PATH,
                iface,
                name,
                &(json,),
            )
            .await
        {
            tracing::debug!("signal {name} not sent: {e}");
        }
    }

    pub async fn status_changed(&self) {
        let st = self.status().await;
        self.emit(IFACE_STATUS, "StatusChanged", &st).await;
    }

    // ---------- status ----------

    pub async fn refresh_signatures(&self) {
        let (engine, _) = deadbolt_common::clamd::version(Path::new(paths::CLAMD_SOCK))
            .map(|v| deadbolt_common::clamd::split_version(&v))
            .unwrap_or_default();
        let engine = if engine.is_empty() {
            // clamd down: ask the binary.
            tokio::process::Command::new("clamd")
                .arg("--version")
                .output()
                .await
                .ok()
                .map(|o| {
                    deadbolt_common::clamd::split_version(&String::from_utf8_lossy(&o.stdout)).0
                })
                .unwrap_or_default()
        } else {
            engine
        };
        let updated = crate::profiles::signature_time(Path::new("/var/lib/clamav"));
        let age_days = updated.map(|t| ((now() - t).max(0) / 86_400) as u32);
        let pm = self
            .reqs
            .lock()
            .ok()
            .and_then(|r| r.as_ref().map(|r| r.package_manager.clone()))
            .unwrap_or_default();
        let engine_outdated = crate::profiles::engine_outdated(&pm).await;
        if let Ok(mut s) = self.signatures.lock() {
            *s = SignatureState {
                engine,
                updated,
                age_days,
                engine_outdated,
            };
        }
    }

    pub async fn refresh_requirements(&self) -> RequirementsReport {
        let r = requirements::check().await;
        self.blocking.store(
            requirements::blocking_supported(&r.kernel),
            Ordering::SeqCst,
        );
        if let Ok(mut g) = self.reqs.lock() {
            *g = Some(r.clone());
        }
        r
    }

    pub fn requirements(&self) -> Option<RequirementsReport> {
        self.reqs.lock().ok().and_then(|r| r.clone())
    }

    pub async fn status(&self) -> Status {
        let s = self.settings();
        let reqs = self.requirements();
        let rt_running = units::is_active(units::CLAMONACC).await;
        let clamd_running = units::is_active(units::CLAMD).await;
        let worker_up = self.worker.ping().await;
        let sig = self
            .signatures
            .lock()
            .map(|s| s.clone())
            .unwrap_or(SignatureState {
                engine: String::new(),
                updated: None,
                age_days: None,
                engine_outdated: false,
            });
        let marks = self.monitor.get().map(|m| m.marks()).unwrap_or_default();
        let shield_running = self.monitor.get().is_some();
        let frozen = self.frozen.lock().map(|f| f.len() as u64).unwrap_or(0);
        let canaries = std::fs::read(paths::CANARY_INDEX)
            .ok()
            .and_then(|b| serde_json::from_slice::<Vec<String>>(&b).ok())
            .map(|v| v.len() as u64)
            .unwrap_or(0);
        let paused_until = self.paused_until.lock().ok().and_then(|p| *p);
        let quarantine_count = std::fs::read_dir(paths::QUARANTINE_DIR)
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .filter(|e| e.file_name().to_string_lossy().ends_with(".json"))
                    .count() as u64
            })
            .unwrap_or(0);
        let network_blocks = self
            .rules
            .ours()
            .iter()
            .filter(|(f, _)| f.starts_with("100-"))
            .count() as u64;
        let persist = self.persist.lock().map(|p| p.clone()).unwrap_or_default();
        let mode = if self.blocking.load(Ordering::SeqCst) && s.realtime.prevention {
            "blocking"
        } else {
            "notify-only"
        };

        let (level, reason, fix) =
            if reqs.as_ref().is_some_and(|r| r.missing_required) || !clamd_running || !worker_up {
                (
                    Level::Red,
                    "Missing required packages or services. Open System requirements.".to_string(),
                    "requirements",
                )
            } else if !persist.setup_done {
                (
                    Level::Amber,
                    "Attention needed: finish first-run setup to turn protection on.".into(),
                    "setup",
                )
            } else if frozen > 0 {
                (
                    Level::Red,
                    format!(
                        "At risk: {frozen} app{} frozen by the ransomware shield, waiting for you.",
                        if frozen == 1 { " is" } else { "s are" }
                    ),
                    "shield",
                )
            } else if paused_until.is_some() {
                (
                    Level::Amber,
                    "Attention needed: protection is paused.".into(),
                    "resume",
                )
            } else if !s.realtime.enabled || !rt_running {
                (
                    Level::Red,
                    "At risk: real-time protection is off.".into(),
                    "enable-realtime",
                )
            } else if sig.age_days.is_some_and(|d| d >= 3) {
                (
                    Level::Amber,
                    format!(
                        "Attention needed: signatures are {} days old.",
                        sig.age_days.unwrap_or(0)
                    ),
                    "update-signatures",
                )
            } else if sig.engine_outdated {
                (
                Level::Amber,
                "Attention needed: a ClamAV security update is waiting in your package manager."
                    .into(),
                "requirements",
            )
            } else if !marks.unprotected.is_empty() && s.shield.enabled {
                (
                    Level::Amber,
                    format!(
                        "Attention needed: {} folder{} not covered by the ransomware shield.",
                        marks.unprotected.len(),
                        if marks.unprotected.len() == 1 {
                            " is"
                        } else {
                            "s are"
                        }
                    ),
                    "shield",
                )
            } else if !s.shield.enabled {
                (
                    Level::Amber,
                    "Attention needed: the ransomware shield is off.".into(),
                    "shield",
                )
            } else {
                (Level::Green, "Your computer is protected.".into(), "")
            };

        Status {
            level,
            reason,
            fix: fix.into(),
            realtime: RealtimeState {
                enabled: s.realtime.enabled,
                running: rt_running,
                mode: mode.into(),
            },
            shield: ShieldState {
                enabled: s.shield.enabled,
                running: shield_running,
                protected: marks.protected,
                unprotected: marks.unprotected,
                canaries,
                frozen,
            },
            signatures: sig,
            last_scan: persist.last_scan,
            quarantine_count,
            network_blocks,
            paused_until,
            setup_done: persist.setup_done,
            overflow_count: self.monitor.get().map(|m| m.overflow_count()).unwrap_or(0),
        }
    }

    // ---------- detections ----------

    fn is_dupe(&self, dev: u64, ino: u64, sig: &str) -> bool {
        let Ok(mut d) = self.dedupe.lock() else {
            return false;
        };
        d.retain(|_, t| t.elapsed() < Duration::from_secs(60));
        let k = (dev, ino, sig.to_string());
        if d.contains_key(&k) {
            return true;
        }
        d.insert(k, Instant::now());
        false
    }

    /// Act on a file only after the worker rescans it with clamd.
    pub async fn act_on(
        &self,
        path: &str,
        action: ThreatAction,
        source: Source,
        claimed: &str,
    ) -> Detection {
        let mut det = Detection {
            path: path.into(),
            signature: claimed.into(),
            source,
            action: "reported".into(),
            quarantine_id: None,
            time: now(),
        };
        let (sig, dev, ino) = match self
            .worker
            .call(Request::ScanFile { path: path.into() })
            .await
        {
            Ok(Reply::Verdict {
                signature: Some(s),
                dev,
                ino,
                ..
            }) => (s, dev, ino),
            Ok(Reply::Verdict {
                signature: None, ..
            }) => {
                det.action = "clean on rescan, nothing done".into();
                return det;
            }
            Ok(_) => {
                det.action = "failed: unexpected reply from the worker".into();
                return det;
            }
            Err(e) => {
                det.action = format!("failed: {e}");
                return det;
            }
        };
        det.signature = sig.clone();
        match action {
            ThreatAction::Ask => det.action = "pending".into(),
            ThreatAction::ReportOnly => det.action = "reported".into(),
            ThreatAction::Quarantine => {
                match self
                    .worker
                    .call(Request::Quarantine {
                        path: path.into(),
                        signature: sig.clone(),
                        source,
                        dev: Some(dev),
                        ino: Some(ino),
                    })
                    .await
                {
                    Ok(Reply::Quarantined { item }) => {
                        det.action = "quarantined".into();
                        det.quarantine_id = Some(item.id);
                    }
                    Ok(_) => det.action = "failed: unexpected reply".into(),
                    Err(e) => det.action = format!("failed: {e}"),
                }
            }
            ThreatAction::Delete => match self
                .worker
                .call(Request::Delete {
                    path: path.into(),
                    dev: Some(dev),
                    ino: Some(ino),
                })
                .await
            {
                Ok(_) => det.action = "deleted".into(),
                Err(e) => det.action = format!("failed: {e}"),
            },
        }
        det
    }

    pub fn wording(det: &Detection) -> String {
        let name = Path::new(&det.path)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| det.path.clone());
        let what = match det.action.as_str() {
            "quarantined" => "Moved to quarantine.".to_string(),
            "deleted" => "Deleted.".to_string(),
            "pending" => "Waiting for your choice.".to_string(),
            "reported" => "Reported only, nothing was changed.".to_string(),
            other => format!("{}{}.", other[..1].to_uppercase(), &other[1..]),
        };
        format!("Threat found in {name}: {}. {what}", det.signature)
    }

    pub async fn record_detection(&self, det: &Detection) {
        self.history.log(
            "detection",
            &Self::wording(det),
            &serde_json::to_string(det).unwrap_or_default(),
        );
        self.emit(IFACE_SCAN, "Detection", det).await;
    }

    /// A real-time hit reported by clamonacc's log or the VirusEvent hook.
    pub async fn realtime_hit(self: &Arc<Self>, path: String, sig: String) {
        if !path.starts_with('/') {
            return;
        }
        let meta = std::fs::symlink_metadata(&path);
        let (dev, ino) = match &meta {
            Ok(m) => {
                use std::os::unix::fs::MetadataExt;
                (m.dev(), m.ino())
            }
            Err(_) => return,
        };
        if self.is_dupe(dev, ino, &sig) {
            return;
        }
        let action = self.settings().actions.realtime;
        let det = self.act_on(&path, action, Source::Realtime, &sig).await;
        self.record_detection(&det).await;
        self.status_changed().await;
    }

    // ---------- scans ----------

    pub async fn start_scan(
        self: &Arc<Self>,
        owner: u32,
        paths: Vec<String>,
        skip: Vec<String>,
        profile: &str,
        source: Source,
        as_uid: Option<u32>,
    ) -> Result<String, String> {
        let s = self.settings();
        let paths: Vec<String> = paths
            .into_iter()
            .filter_map(|p| {
                std::fs::canonicalize(&p)
                    .ok()
                    .map(|c| c.to_string_lossy().into_owned())
            })
            .collect();
        if paths.is_empty() {
            return Err("nothing to scan: none of the paths exist".into());
        }
        let job = uuid::Uuid::new_v4().to_string();
        let sessions = if matches!(source, Source::Scheduled) {
            (s.scan.max_threads / 2).max(1)
        } else {
            s.scan.max_threads
        };
        let opts = ScanOptions {
            job: job.clone(),
            paths,
            exclusions: s.scan.exclusions.clone(),
            one_filesystem: s.scan.one_filesystem,
            skip,
            sessions,
            as_uid,
        };
        let mut rx = self
            .worker
            .stream(Request::Scan(opts))
            .await
            .map_err(|e| e.to_string())?;
        let summary = ScanSummary {
            job: job.clone(),
            profile: profile.to_string(),
            source,
            started: now(),
            finished: 0,
            files: 0,
            errors: 0,
            detections: Vec::new(),
            state: JobState::Counting,
        };
        if let Ok(mut j) = self.jobs.lock() {
            j.insert(
                job.clone(),
                Job {
                    summary,
                    progress: None,
                    owner,
                },
            );
        }
        self.history
            .log("scan", &format!("{} scan started", title(profile)), "");
        let action = match source {
            Source::Scheduled => s.actions.scheduled,
            _ => s.actions.manual,
        };
        let me = self.clone();
        let jid = job.clone();
        tokio::spawn(async move {
            while let Some(rep) = rx.recv().await {
                match rep {
                    Reply::Progress(p) => {
                        if let Ok(mut j) = me.jobs.lock()
                            && let Some(job) = j.get_mut(&jid)
                        {
                            job.summary.state = p.state.clone();
                            job.progress = Some(p.clone());
                        }
                        me.emit(IFACE_SCAN, "Progress", &p).await;
                    }
                    Reply::Found {
                        path,
                        signature,
                        dev,
                        ino,
                        ..
                    } => {
                        let det = if action == ThreatAction::Ask {
                            Detection {
                                path,
                                signature,
                                source,
                                action: "pending".into(),
                                quarantine_id: None,
                                time: now(),
                            }
                        } else {
                            if me.is_dupe(dev, ino, &signature) {
                                continue;
                            }
                            me.act_on(&path, action, source, &signature).await
                        };
                        if let Ok(mut j) = me.jobs.lock()
                            && let Some(job) = j.get_mut(&jid)
                        {
                            job.summary.detections.push(det.clone());
                        }
                        me.record_detection(&det).await;
                    }
                    Reply::Error { message } => {
                        me.history.log("scan", "Scan problem", &message);
                    }
                    Reply::Done {
                        files,
                        errors,
                        cancelled,
                        ..
                    } => {
                        let summary = {
                            let Ok(mut j) = me.jobs.lock() else { break };
                            let Some(job) = j.get_mut(&jid) else { break };
                            job.summary.finished = now();
                            job.summary.files = files;
                            job.summary.errors = errors;
                            job.summary.state = if cancelled {
                                JobState::Cancelled
                            } else {
                                JobState::Done
                            };
                            job.summary.clone()
                        };
                        let n = summary.detections.len();
                        me.history.log(
                            "scan",
                            &format!(
                                "{} scan {}: {files} files, {n} threat{}",
                                title(&summary.profile),
                                if cancelled { "cancelled" } else { "finished" },
                                if n == 1 { "" } else { "s" }
                            ),
                            &serde_json::to_string(&summary).unwrap_or_default(),
                        );
                        if let Ok(mut p) = me.persist.lock() {
                            p.last_scan = Some(summary.clone());
                        }
                        me.save_persist();
                        me.emit(IFACE_SCAN, "Finished", &summary).await;
                        me.status_changed().await;
                        break;
                    }
                    _ => {}
                }
            }
            // Keep finished jobs around for a while so clients can fetch results.
            tokio::time::sleep(Duration::from_secs(3600)).await;
            if let Ok(mut j) = me.jobs.lock() {
                j.remove(&jid);
            }
        });
        Ok(job)
    }

    pub async fn control(&self, job: &str, cmd: &str) -> Result<(), String> {
        self.worker
            .call(Request::Control {
                job: job.into(),
                command: cmd.into(),
            })
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// Act on a pending manual-scan result.
    pub async fn act_pending(&self, job: &str, path: &str, action: ThreatAction) -> Detection {
        let det = self.act_on(path, action, Source::Manual, "").await;
        if let Ok(mut j) = self.jobs.lock()
            && let Some(job) = j.get_mut(job)
            && let Some(d) = job.summary.detections.iter_mut().find(|d| d.path == path)
        {
            *d = det.clone();
        }
        self.record_detection(&det).await;
        det
    }

    // ---------- shield ----------

    pub async fn on_shield_event(self: &Arc<Self>, ev: ShieldEvent) {
        match ev {
            ShieldEvent::Trip(t) => {
                let mut incident = t.incident;
                if let Ok(Reply::Verdict { signature, .. }) = self
                    .worker
                    .call(Request::ScanFile {
                        path: incident.exe.clone(),
                    })
                    .await
                {
                    incident.binary_signature = signature;
                }
                self.save_incident(&incident);
                self.history.log(
                    "shield",
                    &format!(
                        "Ransomware shield froze {} ({}), score {}",
                        incident.app, incident.exe, incident.score
                    ),
                    &serde_json::to_string(&incident).unwrap_or_default(),
                );
                if let Ok(mut f) = self.frozen.lock() {
                    f.insert(
                        incident.id.clone(),
                        FrozenEntry {
                            incident: incident.clone(),
                            frozen: t.frozen,
                            key: t.key,
                        },
                    );
                }
                if let Ok(mut i) = self.incidents.lock() {
                    i.push(incident.clone());
                }
                self.emit(IFACE_SHIELD, "Incident", &incident).await;
                self.status_changed().await;
            }
            ShieldEvent::NearMiss { app, exe, score } => {
                self.history.log(
                    "shield",
                    &format!("Shield near miss: {app} scored {score}"),
                    &exe,
                );
            }
            ShieldEvent::Overflow { total } => {
                self.history.log(
                    "shield",
                    "fanotify queue overflowed, some file events were lost",
                    &total.to_string(),
                );
                self.status_changed().await;
            }
            ShieldEvent::Error(e) => {
                tracing::warn!("{e}");
                self.history.log("shield", "Shield problem", &e);
            }
        }
    }

    pub fn save_incident(&self, inc: &Incident) {
        let p = format!("{}/{}.json", paths::INCIDENT_DIR, inc.id);
        if let Ok(data) = serde_json::to_vec_pretty(inc) {
            let _ = std::fs::write(p, data);
        }
    }

    pub fn incident_owner(&self, id: &str) -> Option<u32> {
        self.frozen.lock().ok()?.get(id).map(|e| e.incident.uid)
    }

    pub async fn decide(&self, id: &str, choice: &str) -> Result<Incident, String> {
        let entry = self
            .frozen
            .lock()
            .map_err(|_| "lock")?
            .remove(id)
            .ok_or("no frozen app with that id")?;
        let FrozenEntry {
            mut incident,
            frozen,
            key,
        } = entry;
        let alive = freeze::alive(&frozen);
        let mut note = String::new();
        match choice {
            "kill" => {
                freeze::kill(&frozen).map_err(|e| e.to_string())?;
                incident.state = "killed".into();
                // Never quarantine a binary that belongs to a package (an
                // interpreter running a script, say): that would break the system.
                match deadbolt_shield::allowlist::owning_package(&incident.exe) {
                    Some(pkg) => {
                        note = format!(
                            "{} belongs to package {pkg}, so it was not quarantined",
                            incident.exe
                        )
                    }
                    None => {
                        let req = match self.settings().actions.ransomware {
                            ThreatAction::Delete => Request::Delete {
                                path: incident.exe.clone(),
                                dev: None,
                                ino: None,
                            },
                            _ => Request::Quarantine {
                                path: incident.exe.clone(),
                                signature: incident
                                    .binary_signature
                                    .clone()
                                    .unwrap_or_else(|| "Deadbolt.Shield.MassEncryption".into()),
                                source: Source::Ransomware,
                                dev: None,
                                ino: None,
                            },
                        };
                        match self.worker.call(req).await {
                            Ok(Reply::Quarantined { item }) => {
                                note = format!("executable quarantined as {}", item.id)
                            }
                            Ok(_) => note = "executable deleted".into(),
                            Err(WorkerError::Failed(m)) | Err(WorkerError::Bad(m)) => {
                                note = format!("executable not removed: {m}")
                            }
                            Err(e) => note = format!("executable not removed: {e}"),
                        }
                    }
                }
            }
            "allow-once" => {
                freeze::thaw(&frozen).map_err(|e| e.to_string())?;
                incident.state = if alive {
                    "allowed-once".into()
                } else {
                    "gone".into()
                };
            }
            "allow-always" => {
                freeze::thaw(&frozen).map_err(|e| e.to_string())?;
                match self.allow.add(&incident.exe, false) {
                    Ok(()) => {
                        let _ = self.allow.save(Path::new(paths::ALLOWLIST_FILE));
                        incident.state = "allowed-always".into();
                    }
                    Err(e) => {
                        incident.state = "allowed-once".into();
                        note = format!("thawed, but not added to the allowlist: {e}");
                    }
                }
            }
            other => {
                // Put it back; nothing changed.
                if let Ok(mut f) = self.frozen.lock() {
                    f.insert(
                        id.into(),
                        FrozenEntry {
                            incident,
                            frozen,
                            key,
                        },
                    );
                }
                return Err(format!("unknown choice {other}"));
            }
        }
        if let Some(m) = self.monitor.get() {
            m.reset(&key);
        }
        if !note.is_empty() {
            incident.signals.push(format!("note: {note}"));
        }
        self.save_incident(&incident);
        if let Ok(mut i) = self.incidents.lock()
            && let Some(x) = i.iter_mut().find(|x| x.id == incident.id)
        {
            *x = incident.clone();
        }
        self.history.log(
            "shield",
            &format!("{}: {} ({})", incident.app, incident.state, incident.exe),
            &note,
        );
        self.emit(IFACE_SHIELD, "Decided", &incident).await;
        self.status_changed().await;
        Ok(incident)
    }

    pub fn incident_list(&self) -> Vec<Incident> {
        let mut v: Vec<Incident> = std::fs::read_dir(paths::INCIDENT_DIR)
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .filter(|e| e.file_name().to_string_lossy().ends_with(".json"))
                    .filter_map(|e| std::fs::read(e.path()).ok())
                    .filter(|b| b.len() < 4 << 20)
                    .filter_map(|b| serde_json::from_slice(&b).ok())
                    .collect()
            })
            .unwrap_or_default();
        v.sort_by_key(|i: &Incident| std::cmp::Reverse(i.time));
        v
    }

    // ---------- protection on/off ----------

    pub async fn pause(self: &Arc<Self>, minutes: u32, by: u32) -> Result<(), String> {
        let until = if minutes == 0 {
            0
        } else {
            now() + i64::from(minutes) * 60
        };
        units::systemctl(&["stop", units::CLAMONACC]).await?;
        if let Some(m) = self.monitor.get() {
            m.set_paused(true);
        }
        if let Ok(mut p) = self.paused_until.lock() {
            *p = Some(until);
        }
        let who = perm::user_name(by);
        let text = if minutes == 0 {
            "until restart".to_string()
        } else {
            format!("for {minutes} minutes")
        };
        self.history.log(
            "protection",
            &format!("Protection paused {text} by {who}"),
            "",
        );
        self.emit(
            IFACE_STATUS,
            "ProtectionChanged",
            &serde_json::json!({"on": false, "until": until, "by": who}),
        )
        .await;
        self.status_changed().await;
        if minutes > 0 {
            let me = self.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(u64::from(minutes) * 60)).await;
                let still = me.paused_until.lock().ok().and_then(|p| *p) == Some(until);
                if still {
                    let _ = me.resume(0).await;
                }
            });
        }
        Ok(())
    }

    pub async fn resume(&self, by: u32) -> Result<(), String> {
        if let Ok(mut p) = self.paused_until.lock() {
            *p = None;
        }
        if let Some(m) = self.monitor.get() {
            m.set_paused(false);
        }
        if self.settings().realtime.enabled {
            units::systemctl(&["start", units::CLAMONACC]).await?;
        }
        let who = if by == 0 {
            "schedule".to_string()
        } else {
            perm::user_name(by)
        };
        self.history
            .log("protection", &format!("Protection resumed ({who})"), "");
        self.emit(
            IFACE_STATUS,
            "ProtectionChanged",
            &serde_json::json!({"on": true, "by": who}),
        )
        .await;
        self.status_changed().await;
        Ok(())
    }

    // ---------- settings ----------

    pub fn shield_config(&self, s: &Settings) -> deadbolt_shield::Config {
        let mut ex = s.scan.exclusions.clone();
        ex.extend(s.shield.ignore.iter().cloned());
        ex.push(paths::QUARANTINE_DIR.into());
        deadbolt_shield::Config {
            watch_paths: s.shield.watch_paths.clone(),
            exclude_prefixes: ex,
            threshold: s.shield.sensitivity.threshold(),
            window_secs: s.shield.window_secs,
            ignore_uids: perm::uid_of(paths::WORKER_USER).into_iter().collect(),
        }
    }

    pub fn write_clamd_conf(&self, s: &Settings) -> std::io::Result<bool> {
        let new = units::clamd_conf(s, self.blocking.load(Ordering::SeqCst));
        let old = std::fs::read_to_string(paths::CLAMD_CONF).unwrap_or_default();
        if old == new {
            return Ok(false);
        }
        let tmp = format!("{}.tmp", paths::CLAMD_CONF);
        std::fs::write(&tmp, new)?;
        std::fs::set_permissions(&tmp, std::os::unix::fs::PermissionsExt::from_mode(0o644))?;
        std::fs::rename(tmp, paths::CLAMD_CONF)?;
        Ok(true)
    }

    pub async fn apply_settings(
        self: &Arc<Self>,
        new: Settings,
        by: u32,
    ) -> Result<Vec<String>, String> {
        new.validate().map_err(|e| e.to_string())?;
        let old = self.settings();
        let tmp = format!("{}.tmp", paths::SETTINGS_FILE);
        std::fs::write(&tmp, new.to_toml()).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, paths::SETTINGS_FILE).map_err(|e| e.to_string())?;
        if let Ok(mut s) = self.settings.write() {
            *s = new.clone();
        }
        let mut log = Vec::new();
        let setup_done = self.persist.lock().map(|p| p.setup_done).unwrap_or(false);
        if self.write_clamd_conf(&new).map_err(|e| e.to_string())? && setup_done {
            let _ = units::systemctl(&["restart", units::CLAMD]).await;
            if new.realtime.enabled {
                let _ = units::systemctl(&["restart", units::CLAMONACC]).await;
            }
            log.push("clamd settings applied".into());
        }
        if setup_done && old.realtime.enabled != new.realtime.enabled {
            let r = if new.realtime.enabled {
                units::systemctl(&["enable", "--now", units::CLAMONACC]).await
            } else {
                units::systemctl(&["disable", "--now", units::CLAMONACC]).await
            };
            if let Err(e) = r {
                log.push(e);
            }
            let who = perm::user_name(by);
            self.history.log(
                "protection",
                &format!(
                    "Real-time protection turned {} by {who}",
                    if new.realtime.enabled { "on" } else { "off" }
                ),
                "",
            );
            self.emit(
                IFACE_STATUS,
                "ProtectionChanged",
                &serde_json::json!({"on": new.realtime.enabled, "by": who, "what": "realtime"}),
            )
            .await;
        }
        if old.schedules != new.schedules && setup_done {
            log.extend(units::apply_schedules(&new).await);
        }
        if let Some(m) = self.monitor.get() {
            m.set_config(self.shield_config(&new));
            m.set_paused(
                !new.shield.enabled || self.paused_until.lock().ok().and_then(|p| *p).is_some(),
            );
            if old.shield.enabled != new.shield.enabled {
                let who = perm::user_name(by);
                self.history.log(
                    "protection",
                    &format!(
                        "Ransomware shield turned {} by {who}",
                        if new.shield.enabled { "on" } else { "off" }
                    ),
                    "",
                );
                self.emit(
                    IFACE_STATUS,
                    "ProtectionChanged",
                    &serde_json::json!({"on": new.shield.enabled, "by": who, "what": "shield"}),
                )
                .await;
            }
        }
        if old.network.deny_tmp != new.network.deny_tmp
            && self.rules.available()
            && let Err(e) = self.rules.set_deny_tmp(new.network.deny_tmp)
        {
            log.push(e);
        }
        self.history.log(
            "setup",
            &format!("Settings changed by {}", perm::user_name(by)),
            "",
        );
        self.status_changed().await;
        Ok(log)
    }

    // ---------- first run ----------

    pub async fn plant_canaries(&self) -> Result<usize, String> {
        let homes = perm::login_homes();
        match self.worker.call(Request::PlantCanaries { homes }).await {
            Ok(Reply::Canaries { paths: list }) => {
                let _ = std::fs::write(
                    paths::CANARY_INDEX,
                    serde_json::to_vec_pretty(&list).unwrap_or_default(),
                );
                // Plain list for the package removal script, which has no JSON parser.
                let plain: String = list
                    .iter()
                    .filter(|p| !p.contains('\n'))
                    .map(|p| format!("{p}\n"))
                    .collect();
                let _ = std::fs::write(paths::CANARY_LIST, plain);
                if let Some(m) = self.monitor.get() {
                    m.set_canaries(list.clone());
                }
                Ok(list.len())
            }
            Ok(_) => Err("unexpected reply".into()),
            Err(e) => Err(e.to_string()),
        }
    }

    pub async fn setup_step(self: &Arc<Self>, step: &str) -> Result<serde_json::Value, String> {
        use serde_json::json;
        match step {
            "kernel" => {
                let r = self.refresh_requirements().await;
                Ok(
                    json!({"kernel": r.kernel, "mode": if self.blocking.load(Ordering::SeqCst) { "blocking" } else { "notify-only" }}),
                )
            }
            "clamd" => {
                let mut log = units::take_over_clamd().await;
                let s = self.settings();
                self.write_clamd_conf(&s).map_err(|e| e.to_string())?;
                for u in [units::CLAMD, units::WORKER] {
                    if let Err(e) = units::systemctl(&["enable", "--now", u]).await {
                        log.push(format!("{u}: {e}"));
                    }
                }
                if s.realtime.enabled
                    && let Err(e) = units::systemctl(&["enable", "--now", units::CLAMONACC]).await
                {
                    log.push(format!("{}: {e}", units::CLAMONACC));
                }
                Ok(json!({"log": log}))
            }
            "signatures" => {
                let r = units::restart_freshclam().await;
                // Wait up to five minutes for a database to show up or change.
                let before = crate::profiles::signature_time(Path::new("/var/lib/clamav"));
                for _ in 0..60 {
                    let t = crate::profiles::signature_time(Path::new("/var/lib/clamav"));
                    if t.is_some()
                        && (before.is_none()
                            || t != before
                            || deadbolt_common::clamd::ping(Path::new(paths::CLAMD_SOCK)))
                    {
                        break;
                    }
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
                let _ = deadbolt_common::clamd::reload(Path::new(paths::CLAMD_SOCK));
                self.refresh_signatures().await;
                Ok(json!({"result": r.unwrap_or_else(|e| e)}))
            }
            "shield" => {
                let n = self.plant_canaries().await?;
                Ok(json!({"canaries": n, "running": self.monitor.get().is_some()}))
            }
            "network-preview" => {
                if !self.rules.available() {
                    return Ok(json!({"available": false}));
                }
                let uses_ui = requirements::which("opensnitch-ui").is_some();
                let cur = std::fs::read_to_string(paths::OPENSNITCH_CONFIG).unwrap_or_default();
                let new = if uses_ui {
                    cur.clone()
                } else {
                    crate::network::quiet_config(&cur)?
                };
                Ok(json!({"available": true, "uses_ui": uses_ui, "current": cur, "new": new}))
            }
            "network" => {
                if !self.rules.available() {
                    return Ok(json!({"available": false}));
                }
                if requirements::which("opensnitch-ui").is_some() {
                    return Ok(
                        json!({"changed": false, "reason": "opensnitch-ui is installed, its config is left alone"}),
                    );
                }
                let cur =
                    std::fs::read_to_string(paths::OPENSNITCH_CONFIG).map_err(|e| e.to_string())?;
                let new = crate::network::quiet_config(&cur)?;
                std::fs::write(paths::OPENSNITCH_CONFIG, new).map_err(|e| e.to_string())?;
                let _ = units::systemctl(&["restart", "opensnitch.service"]).await;
                Ok(json!({"changed": true}))
            }
            "schedules" => Ok(json!({"log": units::apply_schedules(&self.settings()).await})),
            "done" => {
                if let Ok(mut p) = self.persist.lock() {
                    p.setup_done = true;
                }
                self.save_persist();
                self.history.log("setup", "First-run setup finished", "");
                // The report cached by the "kernel" step predates the "clamd" step,
                // so it still lists deadbolt-clamd and deadbolt-clamonacc as stopped.
                self.refresh_requirements().await;
                self.status_changed().await;
                Ok(json!({"done": true}))
            }
            other => Err(format!("unknown setup step {other}")),
        }
    }
}

pub fn title(profile: &str) -> String {
    let mut c = profile.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => "Custom".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wording_is_plain() {
        let d = Detection {
            path: "/home/u/invoice.pdf".into(),
            signature: "Win.Trojan.Agent-123".into(),
            source: Source::Realtime,
            action: "quarantined".into(),
            quarantine_id: None,
            time: 0,
        };
        assert_eq!(
            App::wording(&d),
            "Threat found in invoice.pdf: Win.Trojan.Agent-123. Moved to quarantine."
        );
        for bad in ["neutralized", "eliminated", "Danger", "!"] {
            assert!(!App::wording(&d).contains(bad));
        }
    }
}
