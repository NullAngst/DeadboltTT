//! deadbolt-worker: does Deadbolt's file work as its own system user, with
//! exactly CAP_DAC_READ_SEARCH, CAP_DAC_OVERRIDE, CAP_FOWNER and CAP_CHOWN.
//! It takes jobs only from the daemon (peer uid 0) over its socket, and it is
//! excluded from on-access scanning so Deadbolt never scans its own work.
#![forbid(unsafe_code)]

mod canaries;
mod fsops;
mod quarantine;
mod scan;
mod startup;

use deadbolt_common::paths;
use deadbolt_common::perm;
use deadbolt_common::protocol::{Reply, Request, read_line, write_line};
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use std::io::BufReader;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

struct Cfg {
    socket: PathBuf,
    clamd: PathBuf,
    quarantine: PathBuf,
    peer_uid: u32,
}

fn parse_args() -> Result<Cfg, String> {
    let mut cfg = Cfg {
        socket: paths::WORKER_SOCK.into(),
        clamd: paths::CLAMD_SOCK.into(),
        quarantine: paths::QUARANTINE_DIR.into(),
        peer_uid: 0,
    };
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let mut val = || args.next().ok_or_else(|| format!("{a} needs a value"));
        match a.as_str() {
            "--socket" => cfg.socket = val()?.into(),
            "--clamd" => cfg.clamd = val()?.into(),
            "--quarantine" => cfg.quarantine = val()?.into(),
            // For the integration tests only: accept a non-root daemon.
            "--peer-uid" => cfg.peer_uid = val()?.parse().map_err(|_| "bad --peer-uid")?,
            "--version" => {
                println!("deadbolt-worker {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    Ok(cfg)
}

fn handle(cfg: &Cfg, stream: UnixStream) -> std::io::Result<()> {
    let writer = Arc::new(Mutex::new(stream.try_clone()?));
    let mut reader = BufReader::new(stream);
    let send = |r: &Reply| -> std::io::Result<()> {
        let mut w = writer
            .lock()
            .map_err(|_| std::io::Error::other("writer poisoned"))?;
        write_line(&mut *w, r)
    };
    let store = quarantine::Store::new(&cfg.quarantine);
    while let Some(req) = read_line::<_, Request>(&mut reader)? {
        let reply = match req {
            Request::Ping => Reply::Ok,
            Request::Scan(opts) => {
                let w = writer.clone();
                let out: scan::Out = Arc::new(Mutex::new(move |r: &Reply| {
                    if let Ok(mut s) = w.lock() {
                        let _ = write_line(&mut *s, r);
                    }
                }));
                scan::run(opts, &cfg.clamd, out);
                continue;
            }
            Request::Control { job, command } => {
                if scan::control(&job, &command) {
                    Reply::Ok
                } else {
                    Reply::Error {
                        message: format!("no running job {job}"),
                    }
                }
            }
            Request::ScanFile { path } => scan::verdict(&cfg.clamd, Path::new(&path)),
            Request::Quarantine {
                path,
                signature,
                source,
                dev,
                ino,
            } => {
                let expect = dev.zip(ino);
                match store.quarantine(Path::new(&path), &signature, source, expect) {
                    Ok(item) => Reply::Quarantined { item },
                    Err(e) => Reply::Error {
                        message: e.to_string(),
                    },
                }
            }
            Request::Delete { path, dev, ino } => {
                let p = Path::new(&path);
                let r = match dev.zip(ino) {
                    Some((d, i)) => fsops::unlink_if_same(p, d, i),
                    None => fsops::open_read(p)
                        .and_then(|fd| fsops::stat_fd(&fd))
                        .and_then(|st| fsops::unlink_if_same(p, st.st_dev, st.st_ino)),
                };
                match r {
                    Ok(()) => Reply::Ok,
                    Err(e) => Reply::Error {
                        message: e.to_string(),
                    },
                }
            }
            Request::QuarantineList => match store.list() {
                Ok(items) => Reply::Items { items },
                Err(e) => Reply::Error {
                    message: e.to_string(),
                },
            },
            Request::Restore {
                id,
                to,
                restore_exec,
            } => match store.restore(&id, to.as_deref().map(Path::new), restore_exec) {
                Ok(p) => Reply::Restored {
                    path: p.to_string_lossy().into_owned(),
                },
                Err(e) => Reply::Error {
                    message: e.to_string(),
                },
            },
            Request::QuarantineDelete { id } => match store.delete(&id) {
                Ok(()) => Reply::Ok,
                Err(e) => Reply::Error {
                    message: e.to_string(),
                },
            },
            Request::Purge { older_than_days } => match store.purge(older_than_days) {
                Ok(removed) => Reply::Purged { removed },
                Err(e) => Reply::Error {
                    message: e.to_string(),
                },
            },
            Request::PlantCanaries { homes } => Reply::Canaries {
                paths: canaries::plant(&homes),
            },
            Request::RemoveCanaries => {
                let list: Vec<String> = std::fs::read(paths::CANARY_INDEX)
                    .ok()
                    .and_then(|b| serde_json::from_slice(&b).ok())
                    .unwrap_or_default();
                canaries::remove(&list);
                Reply::Ok
            }
            Request::StartupItems => Reply::Startup {
                items: startup::collect(&perm::login_homes()),
            },
        };
        send(&reply)?;
    }
    Ok(())
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_target(false)
        .without_time()
        .init();
    let cfg = match parse_args() {
        Ok(c) => Arc::new(c),
        Err(e) => {
            eprintln!("deadbolt-worker: {e}");
            std::process::exit(2);
        }
    };
    if nix::unistd::geteuid().is_root()
        && cfg.peer_uid == 0
        && std::env::var_os("DEADBOLT_WORKER_ALLOW_ROOT").is_none()
    {
        eprintln!("deadbolt-worker: refusing to run as root, it runs as the deadbolt-worker user");
        std::process::exit(2);
    }
    let _ = std::fs::remove_file(&cfg.socket);
    let listener = match UnixListener::bind(&cfg.socket) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("deadbolt-worker: cannot bind {}: {e}", cfg.socket.display());
            std::process::exit(2);
        }
    };
    // The daemon runs as root without CAP_DAC_OVERRIDE, so it can only connect
    // if the socket belongs to it. Hand the socket to the peer uid (root in
    // production) and keep it 0600, so only that uid can connect at all.
    // CAP_CHOWN covers the chown. The 0700 folder stays ours; the daemon
    // gets through it with CAP_DAC_READ_SEARCH.
    if let Err(e) = std::fs::set_permissions(&cfg.socket, std::fs::Permissions::from_mode(0o600)) {
        eprintln!(
            "deadbolt-worker: cannot chmod {}: {e}",
            cfg.socket.display()
        );
        std::process::exit(2);
    }
    if let Err(e) = std::os::unix::fs::chown(&cfg.socket, Some(cfg.peer_uid), None) {
        eprintln!(
            "deadbolt-worker: cannot give {} to uid {}: {e}",
            cfg.socket.display(),
            cfg.peer_uid
        );
        std::process::exit(2);
    }
    tracing::info!("listening on {}", cfg.socket.display());
    for conn in listener.incoming() {
        let Ok(stream) = conn else { continue };
        let peer = getsockopt(&stream, PeerCredentials).map(|c| c.uid()).ok();
        if peer != Some(cfg.peer_uid) {
            tracing::warn!("refused a connection from uid {peer:?}");
            continue;
        }
        let cfg = cfg.clone();
        std::thread::spawn(move || {
            if let Err(e) = handle(&cfg, stream) {
                tracing::debug!("connection ended: {e}");
            }
        });
    }
}
