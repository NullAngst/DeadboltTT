//! The six D-Bus interfaces on /io/github/nullangst/Deadbolt1.
//!
//! RULE: the first statement of every method is a `self.app.gate*` call.
//! The polkit_coverage test reads this file and fails if one is missing.

use crate::app::{App, Shared, err};
use crate::polkit::{self, Caller};
use deadbolt_common::Action;
use deadbolt_common::perm::{self, Identity};
use deadbolt_common::protocol::{Reply, Request};
use deadbolt_common::settings::{Settings, ThreatAction};
use deadbolt_common::types::Source;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::Arc;
use zbus::fdo::{Error as FdoError, Result};
use zbus::interface;
use zbus::message::Header;

/// Gate helpers live on App so every method reads `self.app.gate...`.
impl App {
    fn conn(&self) -> Result<&zbus::Connection> {
        self.conn
            .get()
            .ok_or_else(|| FdoError::Failed("daemon is starting".into()))
    }

    pub async fn gate(&self, hdr: &Header<'_>, action: Action) -> Result<Caller> {
        polkit::check(self.conn()?, hdr, action).await
    }

    /// scan for paths the caller can read, scan-system otherwise.
    /// Takes the raw JSON path list so parsing happens behind the gate.
    pub async fn gate_scan(
        &self,
        hdr: &Header<'_>,
        paths_json: &str,
        profile: &str,
        source: &str,
    ) -> Result<(Caller, Vec<String>)> {
        if paths_json.len() > 1 << 20 {
            return Err(FdoError::InvalidArgs("path list too large".into()));
        }
        let paths: Vec<String> = if paths_json.trim().is_empty() {
            Vec::new()
        } else {
            serde_json::from_str(paths_json)
                .map_err(|e| FdoError::InvalidArgs(format!("paths must be a JSON list: {e}")))?
        };
        if paths
            .iter()
            .any(|p| !p.starts_with('/') || p.contains('\0'))
        {
            return Err(FdoError::InvalidArgs("paths must be absolute".into()));
        }
        let system =
            (paths.is_empty() && profile != "quick" && profile != "home") || source == "scheduled";
        let who = polkit::caller(self.conn()?, hdr).await?;
        let id = Identity::of(who.uid);
        let readable = !system && paths.iter().all(|p| perm::can_read(Path::new(p), &id));
        let who = polkit::check(
            self.conn()?,
            hdr,
            if readable {
                Action::Scan
            } else {
                Action::ScanSystem
            },
        )
        .await?;
        Ok((who, paths))
    }

    /// shield-decide for your own app, shield-decide-other for anyone else's.
    pub async fn gate_shield(&self, hdr: &Header<'_>, incident: &str) -> Result<Caller> {
        let who = polkit::caller(self.conn()?, hdr).await?;
        let owner = self.incident_owner(incident);
        let action = if owner == Some(who.uid) {
            Action::ShieldDecide
        } else {
            Action::ShieldDecideOther
        };
        polkit::check(self.conn()?, hdr, action).await
    }

    /// Acting on a file you own needs scan; on anyone else's, quarantine-manage.
    pub async fn gate_act(&self, hdr: &Header<'_>, path: &str) -> Result<Caller> {
        let who = polkit::caller(self.conn()?, hdr).await?;
        let owns = std::fs::symlink_metadata(path).is_ok_and(|m| m.uid() == who.uid);
        polkit::check(
            self.conn()?,
            hdr,
            if owns {
                Action::Scan
            } else {
                Action::QuarantineManage
            },
        )
        .await
    }
}

fn json<T: serde::Serialize>(v: &T) -> Result<String> {
    serde_json::to_string(v).map_err(err)
}

fn home_of(uid: u32) -> Option<String> {
    nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
        .ok()
        .flatten()
        .map(|u| u.dir.to_string_lossy().into_owned())
}

// ---------------------------------------------------------------- Status

pub struct StatusIface {
    pub app: Shared,
}

#[interface(name = "io.github.nullangst.Deadbolt1.Status")]
impl StatusIface {
    async fn get_status(&self, #[zbus(header)] hdr: Header<'_>) -> Result<String> {
        self.app.gate(&hdr, Action::Scan).await?;
        json(&self.app.status().await)
    }

    async fn requirements(&self, #[zbus(header)] hdr: Header<'_>, refresh: bool) -> Result<String> {
        self.app.gate(&hdr, Action::Scan).await?;
        let r = match (refresh, self.app.requirements()) {
            (false, Some(r)) => r,
            _ => self.app.refresh_requirements().await,
        };
        json(&r)
    }

    async fn version(&self, #[zbus(header)] hdr: Header<'_>) -> Result<String> {
        self.app.gate(&hdr, Action::Scan).await?;
        Ok(env!("CARGO_PKG_VERSION").to_string())
    }

    #[zbus(signal)]
    async fn status_changed(
        e: &zbus::object_server::SignalEmitter<'_>,
        json: &str,
    ) -> zbus::Result<()>;
    #[zbus(signal)]
    async fn protection_changed(
        e: &zbus::object_server::SignalEmitter<'_>,
        json: &str,
    ) -> zbus::Result<()>;
    #[zbus(signal)]
    async fn usb_mounted(
        e: &zbus::object_server::SignalEmitter<'_>,
        json: &str,
    ) -> zbus::Result<()>;
}

// ---------------------------------------------------------------- Scan

pub struct ScanIface {
    pub app: Shared,
}

#[interface(name = "io.github.nullangst.Deadbolt1.Scan")]
impl ScanIface {
    /// paths: explicit targets, or empty with a preset profile.
    /// source: "manual" or "scheduled" (scheduled only from root).
    async fn start(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        paths_json: String,
        profile: String,
        source: String,
    ) -> Result<String> {
        let (who, paths) = self
            .app
            .gate_scan(&hdr, &paths_json, &profile, &source)
            .await?;
        let src = match source.as_str() {
            "scheduled" if who.uid == 0 => Source::Scheduled,
            "scheduled" => {
                return Err(FdoError::AccessDenied(
                    "only the scheduler starts scheduled scans".into(),
                ));
            }
            _ => Source::Manual,
        };
        let s = self.app.settings();
        let (targets, skip, as_uid) = if paths.is_empty() {
            // User Quick/Home cover the caller's home; root and scheduled scans cover every home.
            let home = if who.uid == 0 { None } else { home_of(who.uid) };
            let p = crate::profiles::resolve(&profile, &s, home.as_deref())
                .ok_or_else(|| FdoError::InvalidArgs(format!("unknown profile {profile}")))?;
            if p.system && who.uid != 0 {
                // Re-check: a system preset needs scan-system.
                self.app.gate(&hdr, Action::ScanSystem).await?;
            }
            (
                p.paths,
                p.skip,
                if p.system || who.uid == 0 {
                    None
                } else {
                    Some(who.uid)
                },
            )
        } else {
            let skip = deadbolt_common::paths::FULL_SCAN_SKIP
                .iter()
                .map(|x| x.to_string())
                .collect();
            let id = Identity::of(who.uid);
            let mine = paths.iter().all(|p| perm::can_read(Path::new(p), &id));
            (
                paths,
                skip,
                if mine && who.uid != 0 {
                    Some(who.uid)
                } else {
                    None
                },
            )
        };
        let label = if profile.is_empty() {
            "custom".to_string()
        } else {
            profile
        };
        self.app
            .start_scan(who.uid, targets, skip, &label, src, as_uid)
            .await
            .map_err(err)
    }

    async fn pause(&self, #[zbus(header)] hdr: Header<'_>, job: String) -> Result<()> {
        let who = self.app.gate(&hdr, Action::Scan).await?;
        self.own_job(&job, who.uid)?;
        self.app.control(&job, "pause").await.map_err(err)
    }

    async fn resume(&self, #[zbus(header)] hdr: Header<'_>, job: String) -> Result<()> {
        let who = self.app.gate(&hdr, Action::Scan).await?;
        self.own_job(&job, who.uid)?;
        self.app.control(&job, "resume").await.map_err(err)
    }

    async fn cancel(&self, #[zbus(header)] hdr: Header<'_>, job: String) -> Result<()> {
        let who = self.app.gate(&hdr, Action::Scan).await?;
        self.own_job(&job, who.uid)?;
        self.app.control(&job, "cancel").await.map_err(err)
    }

    async fn jobs(&self, #[zbus(header)] hdr: Header<'_>) -> Result<String> {
        let who = self.app.gate(&hdr, Action::Scan).await?;
        let j = self.app.jobs.lock().map_err(err)?;
        let v: Vec<serde_json::Value> = j
            .values()
            .filter(|x| who.uid == 0 || x.owner == who.uid)
            .map(|x| serde_json::json!({"summary": x.summary, "progress": x.progress}))
            .collect();
        json(&v)
    }

    async fn result(&self, #[zbus(header)] hdr: Header<'_>, job: String) -> Result<String> {
        let who = self.app.gate(&hdr, Action::Scan).await?;
        self.own_job(&job, who.uid)?;
        let j = self.app.jobs.lock().map_err(err)?;
        let x = j
            .get(&job)
            .ok_or_else(|| FdoError::InvalidArgs("no such job".into()))?;
        json(&serde_json::json!({"summary": x.summary, "progress": x.progress}))
    }

    /// Act on a pending result: action is "quarantine", "delete" or "report".
    async fn act(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        job: String,
        path: String,
        action: String,
    ) -> Result<String> {
        self.app.gate_act(&hdr, &path).await?;
        let a = match action.as_str() {
            "quarantine" => ThreatAction::Quarantine,
            "delete" => ThreatAction::Delete,
            "report" => ThreatAction::ReportOnly,
            _ => {
                return Err(FdoError::InvalidArgs(
                    "action must be quarantine, delete or report".into(),
                ));
            }
        };
        json(&self.app.act_pending(&job, &path, a).await)
    }

    #[zbus(signal)]
    async fn progress(e: &zbus::object_server::SignalEmitter<'_>, json: &str) -> zbus::Result<()>;
    #[zbus(signal)]
    async fn detection(e: &zbus::object_server::SignalEmitter<'_>, json: &str) -> zbus::Result<()>;
    #[zbus(signal)]
    async fn finished(e: &zbus::object_server::SignalEmitter<'_>, json: &str) -> zbus::Result<()>;
}

impl ScanIface {
    fn own_job(&self, job: &str, uid: u32) -> Result<()> {
        let j = self.app.jobs.lock().map_err(err)?;
        match j.get(job) {
            Some(x) if uid == 0 || x.owner == uid => Ok(()),
            Some(_) => Err(FdoError::AccessDenied(
                "that scan belongs to someone else".into(),
            )),
            None => Err(FdoError::InvalidArgs("no such job".into())),
        }
    }
}

// ---------------------------------------------------------------- Quarantine

pub struct QuarantineIface {
    pub app: Shared,
}

#[interface(name = "io.github.nullangst.Deadbolt1.Quarantine")]
impl QuarantineIface {
    async fn list(&self, #[zbus(header)] hdr: Header<'_>) -> Result<String> {
        self.app.gate(&hdr, Action::QuarantineManage).await?;
        match self
            .app
            .worker
            .call(Request::QuarantineList)
            .await
            .map_err(err)?
        {
            Reply::Items { mut items } => {
                for i in &mut items {
                    i.key.clear();
                }
                json(&items)
            }
            _ => Err(FdoError::Failed("unexpected reply".into())),
        }
    }

    async fn restore(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        id: String,
        to: String,
        restore_exec: bool,
        exclude: bool,
    ) -> Result<String> {
        let who = self.app.gate(&hdr, Action::QuarantineManage).await?;
        let to = if to.is_empty() { None } else { Some(to) };
        let rep = self
            .app
            .worker
            .call(Request::Restore {
                id: id.clone(),
                to,
                restore_exec,
            })
            .await
            .map_err(err)?;
        let Reply::Restored { path } = rep else {
            return Err(FdoError::Failed("unexpected reply".into()));
        };
        if exclude {
            let mut s = self.app.settings();
            if !s.scan.exclusions.contains(&path) {
                s.scan.exclusions.push(path.clone());
                s.realtime.exclude_paths.push(path.clone());
            }
            self.app.apply_settings(s, who.uid).await.map_err(err)?;
        }
        self.app
            .history
            .log("action", &format!("Restored {path} from quarantine"), &id);
        self.app.status_changed().await;
        Ok(path)
    }

    async fn delete(&self, #[zbus(header)] hdr: Header<'_>, id: String) -> Result<()> {
        self.app.gate(&hdr, Action::QuarantineManage).await?;
        self.app
            .worker
            .call(Request::QuarantineDelete { id: id.clone() })
            .await
            .map_err(err)?;
        self.app
            .history
            .log("action", "Deleted a quarantined file", &id);
        self.app.status_changed().await;
        Ok(())
    }

    async fn purge(&self, #[zbus(header)] hdr: Header<'_>, older_than_days: i32) -> Result<u64> {
        self.app.gate(&hdr, Action::QuarantineManage).await?;
        match self
            .app
            .worker
            .call(Request::Purge {
                older_than_days: older_than_days.max(0) as u32,
            })
            .await
            .map_err(err)?
        {
            Reply::Purged { removed } => Ok(removed),
            _ => Err(FdoError::Failed("unexpected reply".into())),
        }
    }
}

// ---------------------------------------------------------------- Shield

pub struct ShieldIface {
    pub app: Shared,
}

#[interface(name = "io.github.nullangst.Deadbolt1.Shield")]
impl ShieldIface {
    async fn incidents(&self, #[zbus(header)] hdr: Header<'_>) -> Result<String> {
        self.app.gate(&hdr, Action::Scan).await?;
        json(&self.app.incident_list())
    }

    async fn frozen(&self, #[zbus(header)] hdr: Header<'_>) -> Result<String> {
        self.app.gate(&hdr, Action::Scan).await?;
        let f = self.app.frozen.lock().map_err(err)?;
        let v: Vec<_> = f.values().map(|e| e.incident.clone()).collect();
        json(&v)
    }

    /// choice: "kill", "allow-once" or "allow-always".
    async fn decide(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        id: String,
        choice: String,
    ) -> Result<String> {
        self.app.gate_shield(&hdr, &id).await?;
        json(&self.app.decide(&id, &choice).await.map_err(err)?)
    }

    async fn canaries(&self, #[zbus(header)] hdr: Header<'_>) -> Result<String> {
        self.app.gate(&hdr, Action::Scan).await?;
        let list: Vec<String> = std::fs::read(deadbolt_common::paths::CANARY_INDEX)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        let v: Vec<serde_json::Value> = list
            .iter()
            .map(|p| {
                let ok = std::fs::read(p).ok().is_some_and(|b| {
                    deadbolt_common::canary::FILES
                        .iter()
                        .any(|(_, c)| *c == b.as_slice())
                });
                serde_json::json!({"path": p, "present": Path::new(p).exists(), "unchanged": ok})
            })
            .collect();
        json(&v)
    }

    async fn replant_canaries(&self, #[zbus(header)] hdr: Header<'_>) -> Result<u32> {
        self.app.gate(&hdr, Action::Settings).await?;
        self.app
            .plant_canaries()
            .await
            .map(|n| n as u32)
            .map_err(err)
    }

    async fn allowlist(&self, #[zbus(header)] hdr: Header<'_>) -> Result<String> {
        self.app.gate(&hdr, Action::Scan).await?;
        json(&self.app.allow.entries())
    }

    async fn allowlist_add(&self, #[zbus(header)] hdr: Header<'_>, path: String) -> Result<()> {
        self.app.gate(&hdr, Action::Settings).await?;
        self.app.allow.add(&path, false).map_err(err)?;
        self.app
            .allow
            .save(Path::new(deadbolt_common::paths::ALLOWLIST_FILE))
            .map_err(err)
    }

    async fn allowlist_remove(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        path: String,
    ) -> Result<bool> {
        self.app.gate(&hdr, Action::Settings).await?;
        let r = self.app.allow.remove(&path);
        self.app
            .allow
            .save(Path::new(deadbolt_common::paths::ALLOWLIST_FILE))
            .map_err(err)?;
        Ok(r)
    }

    async fn recovery(&self, #[zbus(header)] hdr: Header<'_>, id: String) -> Result<String> {
        self.app.gate(&hdr, Action::Scan).await?;
        let inc = self
            .app
            .incident_list()
            .into_iter()
            .find(|i| i.id == id)
            .ok_or_else(|| FdoError::InvalidArgs("no such incident".into()))?;
        let snaps = crate::tools::snapshots().await;
        json(&crate::tools::recovery_for(&inc, &snaps))
    }

    #[zbus(signal)]
    async fn incident(e: &zbus::object_server::SignalEmitter<'_>, json: &str) -> zbus::Result<()>;
    #[zbus(signal)]
    async fn decided(e: &zbus::object_server::SignalEmitter<'_>, json: &str) -> zbus::Result<()>;
}

// ---------------------------------------------------------------- Network

pub struct NetworkIface {
    pub app: Shared,
}

#[interface(name = "io.github.nullangst.Deadbolt1.Network")]
impl NetworkIface {
    async fn available(&self, #[zbus(header)] hdr: Header<'_>) -> Result<bool> {
        self.app.gate(&hdr, Action::Scan).await?;
        Ok(self.app.rules.available() && crate::requirements::which("opensnitchd").is_some())
    }

    async fn apps(&self, #[zbus(header)] hdr: Header<'_>) -> Result<String> {
        let who = self.app.gate(&hdr, Action::Scan).await?;
        let mut apps = crate::network::list_apps(home_of(who.uid).as_deref());
        // Rules for executables added by hand show up too.
        self.app.rules.annotate(&mut apps);
        json(&apps)
    }

    async fn rules(&self, #[zbus(header)] hdr: Header<'_>) -> Result<String> {
        self.app.gate(&hdr, Action::Scan).await?;
        let v: Vec<serde_json::Value> = self
            .app
            .rules
            .ours()
            .into_iter()
            .map(|(f, r)| serde_json::json!({"file": f, "description": r.description, "action": r.action}))
            .collect();
        json(&v)
    }

    /// kind: native, flatpak or wine. target: path, app id, or .exe name.
    async fn set_blocked(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        name: String,
        kind: String,
        target: String,
        blocked: bool,
        allow_lan: bool,
    ) -> Result<()> {
        let who = self.app.gate(&hdr, Action::Network).await?;
        if !self.app.rules.available() {
            return Err(FdoError::NotSupported("OpenSnitch is not installed".into()));
        }
        self.app
            .rules
            .set_blocked(&name, &kind, &target, blocked, allow_lan)
            .map_err(err)?;
        self.app.history.log(
            "block",
            &format!(
                "{} {name}{}",
                if blocked { "Blocked" } else { "Unblocked" },
                if blocked && allow_lan {
                    " (local network allowed)"
                } else {
                    ""
                }
            ),
            &format!("{kind}: {target} by {}", perm::user_name(who.uid)),
        );
        self.app.status_changed().await;
        Ok(())
    }

    async fn connections(&self, #[zbus(header)] hdr: Header<'_>) -> Result<String> {
        self.app.gate(&hdr, Action::Scan).await?;
        json(&crate::network::connections().await)
    }

    async fn recently_blocked(&self, #[zbus(header)] hdr: Header<'_>) -> Result<String> {
        self.app.gate(&hdr, Action::Scan).await?;
        let log =
            std::fs::read_to_string(deadbolt_common::paths::OPENSNITCH_LOG).unwrap_or_default();
        let tail = &log[log.len().saturating_sub(512 * 1024)..];
        let tail = tail.split_once('\n').map(|(_, r)| r).unwrap_or(tail);
        json(&crate::network::recently_blocked(tail, 100))
    }

    /// Drop open sockets of processes whose executable is `target`.
    async fn drop_connections(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        target: String,
    ) -> Result<u32> {
        self.app.gate(&hdr, Action::Network).await?;
        let conns: Vec<_> = crate::network::connections()
            .await
            .into_iter()
            .filter(|c| {
                c.pid > 0
                    && deadbolt_shield::procinfo::exe(c.pid).as_deref() == Some(target.as_str())
            })
            .collect();
        Ok(crate::network::drop_connections(&conns).await as u32)
    }
}

// ---------------------------------------------------------------- Settings

pub struct SettingsIface {
    pub app: Shared,
}

#[interface(name = "io.github.nullangst.Deadbolt1.Settings")]
impl SettingsIface {
    async fn get(&self, #[zbus(header)] hdr: Header<'_>) -> Result<String> {
        self.app.gate(&hdr, Action::Scan).await?;
        json(&self.app.settings())
    }

    async fn set(&self, #[zbus(header)] hdr: Header<'_>, settings_json: String) -> Result<String> {
        let who = self.app.gate(&hdr, Action::Settings).await?;
        if settings_json.len() > 1 << 20 {
            return Err(FdoError::InvalidArgs("settings too large".into()));
        }
        let new: Settings = serde_json::from_str(&settings_json)
            .map_err(|e| FdoError::InvalidArgs(e.to_string()))?;
        let turning_off = (self.app.settings().realtime.enabled && !new.realtime.enabled)
            || (self.app.settings().shield.enabled && !new.shield.enabled);
        if turning_off {
            self.app.gate(&hdr, Action::ProtectionToggle).await?;
        }
        json(&self.app.apply_settings(new, who.uid).await.map_err(err)?)
    }

    /// minutes = 0 pauses until restart.
    async fn pause(&self, #[zbus(header)] hdr: Header<'_>, minutes: i32) -> Result<()> {
        let who = self.app.gate(&hdr, Action::ProtectionToggle).await?;
        self.app
            .pause(minutes.clamp(0, 7 * 24 * 60) as u32, who.uid)
            .await
            .map_err(err)
    }

    async fn resume(&self, #[zbus(header)] hdr: Header<'_>) -> Result<()> {
        let who = self.app.gate(&hdr, Action::Scan).await?;
        self.app.resume(who.uid).await.map_err(err)
    }

    async fn update_signatures(&self, #[zbus(header)] hdr: Header<'_>) -> Result<String> {
        self.app.gate(&hdr, Action::Scan).await?;
        let r = crate::units::restart_freshclam().await.map_err(err)?;
        self.app
            .history
            .log("update", "Signature update requested", &r);
        Ok(r)
    }

    async fn history(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        filter_json: String,
    ) -> Result<String> {
        self.app.gate(&hdr, Action::Scan).await?;
        let f: crate::history::Filter = if filter_json.is_empty() {
            Default::default()
        } else {
            serde_json::from_str(&filter_json).map_err(|e| FdoError::InvalidArgs(e.to_string()))?
        };
        json(&self.app.history.query(&f))
    }

    async fn history_csv(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        filter_json: String,
    ) -> Result<String> {
        self.app.gate(&hdr, Action::Scan).await?;
        let f: crate::history::Filter = if filter_json.is_empty() {
            crate::history::Filter {
                limit: 10_000,
                ..Default::default()
            }
        } else {
            serde_json::from_str(&filter_json).map_err(|e| FdoError::InvalidArgs(e.to_string()))?
        };
        Ok(crate::history::to_csv(&self.app.history.query(&f)))
    }

    /// Monthly counts for rows older than the retention period.
    async fn history_rollup(&self, #[zbus(header)] hdr: Header<'_>) -> Result<String> {
        self.app.gate(&hdr, Action::Scan).await?;
        json(&self.app.history.rollup())
    }

    async fn setup_step(&self, #[zbus(header)] hdr: Header<'_>, step: String) -> Result<String> {
        self.app.gate(&hdr, Action::Settings).await?;
        json(&self.app.setup_step(&step).await.map_err(err)?)
    }

    async fn startup_items(&self, #[zbus(header)] hdr: Header<'_>) -> Result<String> {
        let who = self.app.gate(&hdr, Action::Scan).await?;
        let me = perm::user_name(who.uid);
        match self
            .app
            .worker
            .call(Request::StartupItems)
            .await
            .map_err(err)?
        {
            Reply::Startup { items } => {
                let v: Vec<_> = items
                    .into_iter()
                    .filter(|i| who.uid == 0 || i.owner == me || i.owner == "root")
                    .collect();
                json(&v)
            }
            _ => Err(FdoError::Failed("unexpected reply".into())),
        }
    }

    /// Run rkhunter, chkrootkit, lynis, debsums or rpm-verify. Result comes as ToolFinished.
    async fn run_tool(&self, #[zbus(header)] hdr: Header<'_>, tool: String) -> Result<String> {
        self.app.gate(&hdr, Action::ScanSystem).await?;
        let id = uuid::Uuid::new_v4().to_string();
        let app = self.app.clone();
        let id2 = id.clone();
        tokio::spawn(async move {
            let r = crate::tools::run(&tool).await;
            app.history
                .log("scan", &format!("{tool}: {}", r.summary), "");
            app.emit(
                crate::app::IFACE_SETTINGS,
                "ToolFinished",
                &serde_json::json!({"id": id2, "result": r}),
            )
            .await;
        });
        Ok(id)
    }

    #[zbus(signal)]
    async fn tool_finished(
        e: &zbus::object_server::SignalEmitter<'_>,
        json: &str,
    ) -> zbus::Result<()>;
}

pub async fn serve(app: Shared) -> zbus::Result<zbus::Connection> {
    let path = deadbolt_common::OBJECT_PATH;
    let conn = zbus::connection::Builder::system()
        .name(deadbolt_common::BUS_NAME)
        .serve_at(path, StatusIface { app: app.clone() })
        .serve_at(path, ScanIface { app: app.clone() })
        .serve_at(path, QuarantineIface { app: app.clone() })
        .serve_at(path, ShieldIface { app: app.clone() })
        .serve_at(path, NetworkIface { app: app.clone() })
        .serve_at(
            path,
            SettingsIface {
                app: Arc::clone(&app),
            },
        )
        .build()
        .await?;
    Ok(conn)
}

#[cfg(test)]
mod tests {
    /// Every D-Bus method calls a polkit gate before doing work.
    #[test]
    fn polkit_coverage() {
        let src = include_str!("dbus.rs");
        let mut in_iface = false;
        let mut signal_next = false;
        let mut methods = 0;
        let lines: Vec<&str> = src.lines().collect();
        for (i, l) in lines.iter().enumerate() {
            let t = l.trim();
            if t.starts_with("#[interface(") {
                in_iface = true;
                continue;
            }
            if in_iface && *l == "}" {
                in_iface = false;
                continue;
            }
            if !in_iface {
                continue;
            }
            if t.starts_with("#[zbus(signal)]") {
                signal_next = true;
                continue;
            }
            if t.starts_with("async fn ") || t.starts_with("fn ") {
                if signal_next {
                    signal_next = false;
                    continue;
                }
                // find the line that opens the body, then the first statement
                let mut j = i;
                while !lines[j].trim_end().ends_with('{') {
                    j += 1;
                }
                // The first statement, with formatting whitespace removed.
                let body: String = lines[j + 1..]
                    .iter()
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty() && !s.starts_with("//"))
                    .collect::<Vec<_>>()
                    .join("");
                let first = body.split(';').next().unwrap_or("");
                assert!(
                    first.contains("self.app.gate"),
                    "method at line {} does not call a polkit gate first: {first}",
                    i + 1
                );
                methods += 1;
            }
        }
        assert!(
            methods >= 35,
            "only found {methods} methods, parser is broken"
        );
    }
}
