//! deadboltd: the one root process. It decides; deadbolt-worker does the file
//! work, clamd does the scanning, the kernel does the freezing, OpenSnitch
//! does the blocking. Clients talk to it over the D-Bus system bus.
#![forbid(unsafe_code)]

mod app;
mod dbus;
mod history;
mod network;
mod polkit;
mod profiles;
mod requirements;
mod tools;
mod units;
mod watchers;
mod worker;

use app::App;
use deadbolt_common::paths;
use deadbolt_common::settings::Settings;
use deadbolt_shield::allowlist::Allowlist;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::Arc;

fn in_container() -> Option<String> {
    for f in ["/.dockerenv", "/run/.containerenv"] {
        if Path::new(f).exists() {
            return Some(f.to_string());
        }
    }
    if let Ok(o) = std::process::Command::new("systemd-detect-virt")
        .arg("--container")
        .output()
        && o.status.success()
    {
        let what = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if what != "none" && !what.is_empty() {
            return Some(what);
        }
    }
    None
}

/// The daemon's own files must be root-owned and writable by nobody else.
fn self_protection_problems() -> Vec<String> {
    let mut bad = Vec::new();
    for dir in [paths::LIBEXEC_DIR, paths::ETC_DIR, paths::LIB_DIR] {
        match std::fs::symlink_metadata(dir) {
            Ok(m) if m.file_type().is_symlink() => bad.push(format!("{dir} is a symlink")),
            Ok(m) if m.uid() != 0 => bad.push(format!("{dir} is not owned by root")),
            Ok(m) if m.mode() & 0o022 != 0 => {
                bad.push(format!("{dir} is writable by group or others"))
            }
            Ok(_) => {}
            Err(e) => bad.push(format!("{dir}: {e}")),
        }
        if let Ok(rd) = std::fs::read_dir(dir) {
            for e in rd.filter_map(|e| e.ok()) {
                if let Ok(m) = e.metadata()
                    && (m.uid() != 0 || m.mode() & 0o022 != 0)
                    && e.file_name() != "quarantine"
                {
                    bad.push(format!(
                        "{} must be root-owned and not group/other writable",
                        e.path().display()
                    ));
                }
            }
        }
    }
    bad
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--version") {
        println!("deadboltd {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    if args.iter().any(|a| a == "--print-clamd-conf") {
        // What /etc/deadbolt/clamd.conf would contain for the current settings.
        let s = Settings::load(Path::new(paths::SETTINGS_FILE)).unwrap_or_default();
        print!("{}", units::clamd_conf(&s, true));
        return;
    }
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_target(false)
        .without_time()
        .init();

    if !nix::unistd::geteuid().is_root() {
        eprintln!("deadboltd must run as root (it is started by deadboltd.service)");
        std::process::exit(2);
    }
    if let Some(what) = in_container() {
        eprintln!(
            "deadboltd: refusing to start inside a container ({what}). fanotify and cgroup freeze do not behave the same there."
        );
        std::process::exit(2);
    }
    let problems = self_protection_problems();
    if !problems.is_empty() {
        for p in &problems {
            eprintln!("deadboltd: {p}");
        }
        eprintln!("deadboltd: refusing to start until these are fixed");
        std::process::exit(2);
    }
    let _ = std::fs::create_dir_all(paths::INCIDENT_DIR);

    let (settings, settings_err) = match Settings::load(Path::new(paths::SETTINGS_FILE)) {
        Ok(s) => (s, None),
        Err(e) => (Settings::default(), Some(e.to_string())),
    };
    let history = history::History::open(Path::new(paths::HISTORY_DB)).unwrap_or_else(|e| {
        tracing::error!("history database unavailable, using memory: {e}");
        history::History::memory()
    });
    if let Some(e) = &settings_err {
        tracing::error!("{e}; running with defaults until it is fixed");
        history.log(
            "setup",
            "Settings file is invalid, running with defaults",
            e,
        );
    }
    let allow = Arc::new(Allowlist::load(Path::new(paths::ALLOWLIST_FILE)));
    if allow.entries().is_empty() {
        allow.seed_defaults();
        let _ = allow.save(Path::new(paths::ALLOWLIST_FILE));
    }

    let app = Arc::new(App::new(settings.clone(), history, allow.clone()));
    app.refresh_requirements().await;
    app.refresh_signatures().await;
    let setup_done = app.persist.lock().map(|p| p.setup_done).unwrap_or(false);
    if setup_done && let Err(e) = app.write_clamd_conf(&settings) {
        tracing::error!("cannot write {}: {e}", paths::CLAMD_CONF);
    }

    // Ransomware shield.
    let kernel_ok = app
        .requirements()
        .map(|r| {
            r.kernel
                .iter()
                .any(|k| k.name == "fanotify rename events" && k.ok)
        })
        .unwrap_or(false);
    if kernel_ok {
        let (tx, rx) = std::sync::mpsc::channel();
        let ud = deadbolt_common::userdata::UserData::load_or_builtin(paths::USER_DATA_EXTENSIONS);
        let mon =
            deadbolt_shield::Monitor::new(app.shield_config(&settings), allow.clone(), ud, tx);
        let canaries: Vec<String> = std::fs::read(paths::CANARY_INDEX)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        mon.set_canaries(canaries);
        mon.set_paused(!settings.shield.enabled);
        match mon.start() {
            Ok(()) => {
                let _ = app.monitor.set(mon);
                let handle = tokio::runtime::Handle::current();
                let a2 = app.clone();
                std::thread::spawn(move || {
                    while let Ok(ev) = rx.recv() {
                        let a = a2.clone();
                        handle.spawn(async move { a.on_shield_event(ev).await });
                    }
                });
            }
            Err(e) => {
                tracing::error!("ransomware shield could not start: {e}");
                app.history.log(
                    "shield",
                    "Ransomware shield could not start",
                    &e.to_string(),
                );
            }
        }
    } else {
        tracing::warn!("kernel lacks fanotify rename reporting (5.17+), ransomware shield is off");
    }

    let conn = match dbus::serve(app.clone()).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "deadboltd: cannot claim {} on the system bus: {e}",
                deadbolt_common::BUS_NAME
            );
            std::process::exit(2);
        }
    };
    let _ = app.conn.set(conn);

    tokio::spawn(watchers::events_socket(app.clone()));
    tokio::spawn(watchers::tail_onaccess(app.clone()));
    tokio::spawn(watchers::package_watch(app.clone()));
    tokio::spawn(watchers::signature_watch(app.clone()));
    tokio::spawn(watchers::retention(app.clone()));
    tokio::spawn(watchers::usb_watch(app.clone()));

    if setup_done && units::distro_units_back().await {
        app.history.log(
            "protection",
            "Distro ClamAV units were enabled again, masking them",
            "",
        );
        units::take_over_clamd().await;
    }
    tracing::info!("deadboltd {} ready", env!("CARGO_PKG_VERSION"));
    app.status_changed().await;

    let mut term = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(s) => s,
        Err(_) => {
            std::future::pending::<()>().await;
            return;
        }
    };
    tokio::select! {
        _ = term.recv() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
    // Frozen apps stay frozen across a daemon restart: cgroup.freeze and
    // SIGSTOP both outlive us. Record that so nobody is surprised.
    let n = app.frozen.lock().map(|f| f.len()).unwrap_or(0);
    if n > 0 {
        app.history.log(
            "shield",
            &format!("deadboltd stopped with {n} app(s) still frozen"),
            "Use systemctl to thaw: see README, Ransomware shield.",
        );
    }
}
