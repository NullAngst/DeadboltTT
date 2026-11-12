//! Walking and scanning. The worker opens each file itself and hands the
//! descriptor to clamd with FILDES inside an IDSESSION, so clamd never needs
//! read access to user files. Falls back to clamscan when clamd is down.

use crate::fsops;
use deadbolt_common::clamd::{self, Session, Verdict};
use deadbolt_common::perm::{self, Identity};
use deadbolt_common::protocol::{Reply, ScanOptions};
use deadbolt_common::types::{JobState, ScanProgress};
use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

#[derive(Default)]
pub struct JobCtl {
    pub paused: AtomicBool,
    pub cancelled: AtomicBool,
}

fn jobs() -> &'static Mutex<HashMap<String, Arc<JobCtl>>> {
    static J: OnceLock<Mutex<HashMap<String, Arc<JobCtl>>>> = OnceLock::new();
    J.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn control(job: &str, cmd: &str) -> bool {
    let Ok(map) = jobs().lock() else { return false };
    let Some(c) = map.get(job) else { return false };
    match cmd {
        "pause" => c.paused.store(true, Ordering::SeqCst),
        "resume" => c.paused.store(false, Ordering::SeqCst),
        "cancel" => c.cancelled.store(true, Ordering::SeqCst),
        _ => return false,
    }
    true
}

fn under(path: &Path, prefix: &str) -> bool {
    path.starts_with(prefix)
}

/// Yields every regular file under the targets, honoring skips, exclusions
/// and the one-filesystem toggle. Never follows symlinks.
pub fn walk<'a>(
    opts: &'a ScanOptions,
    who: Option<&'a Identity>,
) -> impl Iterator<Item = PathBuf> + 'a {
    opts.paths.iter().flat_map(move |root| {
        walkdir::WalkDir::new(root)
            .follow_links(false)
            .same_file_system(opts.one_filesystem)
            .into_iter()
            .filter_entry(move |e| {
                let p = e.path();
                !opts.skip.iter().any(|s| under(p, s))
                    && !opts.exclusions.iter().any(|s| under(p, s))
                    && who.is_none_or(|w| !e.file_type().is_dir() || perm::can_read(p, w))
            })
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .map(|e| e.into_path())
            .filter(move |p| who.is_none_or(|w| perm::can_read(p, w)))
    })
}

/// Per-file errors sent back with their reason; the rest are only counted.
const REPORTED_ERRORS: u64 = 20;

/// `Ok(None)`: the file was removed or replaced by something that is not a
/// regular file after the walk listed it. Nothing is left to scan, so it is
/// neither an error nor a scanned file.
pub fn scan_one(sess: &mut Session, path: &Path) -> Result<Option<(Verdict, u64, u64)>, String> {
    let fd = match fsops::open_read(path) {
        Ok(fd) => fd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    let st = fsops::stat_fd(&fd).map_err(|e| e.to_string())?;
    if !fsops::is_regular(&st) {
        return Ok(None);
    }
    let v = sess.scan_fd(fd.as_fd()).map_err(|e| e.to_string())?;
    Ok(Some((v, st.st_dev, st.st_ino)))
}

pub type Out = Arc<Mutex<dyn FnMut(&Reply) + Send>>;

fn emit(out: &Out, r: Reply) {
    if let Ok(mut f) = out.lock() {
        f(&r);
    }
}

pub fn run(opts: ScanOptions, sock: &Path, out: Out) {
    let ctl = Arc::new(JobCtl::default());
    if let Ok(mut m) = jobs().lock() {
        m.insert(opts.job.clone(), ctl.clone());
    }
    let who = opts.as_uid.map(Identity::of);
    if clamd::ping(sock) {
        run_clamd(&opts, sock, &out, &ctl, who.as_ref());
    } else {
        run_clamscan(&opts, &out, &ctl, who.as_ref());
    }
    if let Ok(mut m) = jobs().lock() {
        m.remove(&opts.job);
    }
}

fn run_clamd(
    opts: &ScanOptions,
    sock: &Path,
    out: &Out,
    ctl: &Arc<JobCtl>,
    who: Option<&Identity>,
) {
    let progress = |state: JobState, total: u64, done: u64, current: &str, found: u64| {
        Reply::Progress(ScanProgress {
            job: opts.job.clone(),
            state,
            total,
            done,
            current: current.to_string(),
            found,
            fallback: false,
        })
    };
    emit(out, progress(JobState::Counting, 0, 0, "", 0));
    let mut total = 0u64;
    let mut last = Instant::now();
    for _ in walk(opts, who) {
        total += 1;
        if ctl.cancelled.load(Ordering::SeqCst) {
            break;
        }
        if last.elapsed() > Duration::from_millis(500) {
            emit(out, progress(JobState::Counting, total, 0, "", 0));
            last = Instant::now();
        }
    }

    let done = Arc::new(AtomicU64::new(0));
    let found = Arc::new(AtomicU64::new(0));
    let errors = Arc::new(AtomicU64::new(0));
    let current = Arc::new(Mutex::new(String::new()));
    let (tx, rx) = mpsc::sync_channel::<PathBuf>(256);
    let rx = Arc::new(Mutex::new(rx));
    let sessions = opts.sessions.clamp(1, 32);
    let mut handles = Vec::new();
    for _ in 0..sessions {
        let rx = rx.clone();
        let out = out.clone();
        let ctl = ctl.clone();
        let done = done.clone();
        let found = found.clone();
        let errors = errors.clone();
        let current = current.clone();
        let sock = sock.to_path_buf();
        let job = opts.job.clone();
        handles.push(std::thread::spawn(move || {
            let mut sess = match Session::open(&sock) {
                Ok(s) => s,
                Err(e) => {
                    emit(
                        &out,
                        Reply::Error {
                            message: format!("clamd session failed: {e}"),
                        },
                    );
                    return;
                }
            };
            loop {
                let next = rx.lock().ok().and_then(|r| r.recv().ok());
                let Some(path) = next else { break };
                while ctl.paused.load(Ordering::SeqCst) && !ctl.cancelled.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(200));
                }
                if ctl.cancelled.load(Ordering::SeqCst) {
                    break;
                }
                if let Ok(mut c) = current.lock() {
                    *c = path.to_string_lossy().into_owned();
                }
                match scan_one(&mut sess, &path) {
                    Ok(Some((Verdict::Found(sig), dev, ino))) => {
                        found.fetch_add(1, Ordering::SeqCst);
                        emit(
                            &out,
                            Reply::Found {
                                job: job.clone(),
                                path: path.to_string_lossy().into_owned(),
                                signature: sig,
                                dev,
                                ino,
                            },
                        );
                    }
                    Ok(Some((Verdict::Clean, _, _))) => {}
                    // Gone since the walk: not scanned, not an error.
                    Ok(None) => continue,
                    Ok(Some((Verdict::Error(e), _, _))) | Err(e) => {
                        // Report why, for the first few. A count alone says nothing.
                        if errors.fetch_add(1, Ordering::SeqCst) < REPORTED_ERRORS {
                            emit(
                                &out,
                                Reply::Error {
                                    message: format!("{}: {e}", path.display()),
                                },
                            );
                        }
                        // A broken session (clamd restarted) gets reopened.
                        if let Ok(s) = Session::open(&sock) {
                            sess = s;
                        }
                    }
                }
                done.fetch_add(1, Ordering::SeqCst);
            }
        }));
    }

    let mut last = Instant::now();
    for path in walk(opts, who) {
        if ctl.cancelled.load(Ordering::SeqCst) {
            break;
        }
        if tx.send(path).is_err() {
            break;
        }
        if last.elapsed() > Duration::from_millis(250) {
            let state = if ctl.paused.load(Ordering::SeqCst) {
                JobState::Paused
            } else {
                JobState::Running
            };
            let cur = current.lock().map(|c| c.clone()).unwrap_or_default();
            emit(
                out,
                progress(
                    state,
                    total.max(done.load(Ordering::SeqCst)),
                    done.load(Ordering::SeqCst),
                    &cur,
                    found.load(Ordering::SeqCst),
                ),
            );
            last = Instant::now();
        }
    }
    drop(tx);
    for h in handles {
        let _ = h.join();
    }
    let cancelled = ctl.cancelled.load(Ordering::SeqCst);
    let d = done.load(Ordering::SeqCst);
    emit(
        out,
        progress(
            if cancelled {
                JobState::Cancelled
            } else {
                JobState::Done
            },
            total.max(d),
            d,
            "",
            found.load(Ordering::SeqCst),
        ),
    );
    emit(
        out,
        Reply::Done {
            job: opts.job.clone(),
            files: d,
            errors: errors.load(Ordering::SeqCst),
            cancelled,
        },
    );
}

/// Turn a path prefix into a clamscan --exclude-dir regex.
pub fn exclude_regex(prefix: &str) -> String {
    format!("^{}(/|$)", regex::escape(prefix.trim_end_matches('/')))
}

/// Parse "path: Sig.Name FOUND" lines from clamscan --infected.
pub fn parse_clamscan_line(line: &str) -> Option<(String, String)> {
    let body = line.strip_suffix(" FOUND")?;
    let (path, sig) = body.rsplit_once(": ")?;
    Some((path.to_string(), sig.to_string()))
}

fn run_clamscan(opts: &ScanOptions, out: &Out, ctl: &Arc<JobCtl>, who: Option<&Identity>) {
    // Paths a user may not read are dropped up front; clamscan itself runs
    // with the worker's read capability.
    let targets: Vec<&String> = opts
        .paths
        .iter()
        .filter(|p| who.is_none_or(|w| perm::can_read(Path::new(p), w)))
        .collect();
    let mut cmd = Command::new("clamscan");
    cmd.args(["--infected", "--no-summary", "--recursive", "--stdout"]);
    if opts.one_filesystem {
        cmd.arg("--cross-fs=no");
    }
    for p in opts.skip.iter().chain(&opts.exclusions) {
        cmd.arg(format!("--exclude-dir={}", exclude_regex(p)));
    }
    cmd.arg("--");
    cmd.args(targets);
    cmd.stdout(Stdio::piped())
        .stderr(Stdio::null())
        .stdin(Stdio::null());
    let progress = |state, done, found, cur: &str| {
        Reply::Progress(ScanProgress {
            job: opts.job.clone(),
            state,
            total: 0,
            done,
            current: cur.to_string(),
            found,
            fallback: true,
        })
    };
    emit(out, progress(JobState::Running, 0, 0, ""));
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            emit(
                out,
                Reply::Error {
                    message: format!("clamd is down and clamscan could not start: {e}"),
                },
            );
            emit(
                out,
                Reply::Done {
                    job: opts.job.clone(),
                    files: 0,
                    errors: 1,
                    cancelled: false,
                },
            );
            return;
        }
    };
    let mut found = 0;
    if let Some(stdout) = child.stdout.take() {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if ctl.cancelled.load(Ordering::SeqCst) {
                let _ = child.kill();
                break;
            }
            if let Some((path, sig)) = parse_clamscan_line(&line) {
                found += 1;
                let (dev, ino) = std::fs::symlink_metadata(&path)
                    .map(|m| {
                        use std::os::unix::fs::MetadataExt;
                        (m.dev(), m.ino())
                    })
                    .unwrap_or((0, 0));
                emit(
                    out,
                    Reply::Found {
                        job: opts.job.clone(),
                        path: path.clone(),
                        signature: sig,
                        dev,
                        ino,
                    },
                );
                emit(out, progress(JobState::Running, 0, found, &path));
            }
        }
    }
    let _ = child.wait();
    let cancelled = ctl.cancelled.load(Ordering::SeqCst);
    emit(
        out,
        progress(
            if cancelled {
                JobState::Cancelled
            } else {
                JobState::Done
            },
            0,
            found,
            "",
        ),
    );
    emit(
        out,
        Reply::Done {
            job: opts.job.clone(),
            files: 0,
            errors: 0,
            cancelled,
        },
    );
}

/// Rescan one file. Used before acting on any detection.
pub fn verdict(sock: &Path, path: &Path) -> Reply {
    let fd = match fsops::open_read(path) {
        Ok(fd) => fd,
        Err(e) => {
            return Reply::Error {
                message: format!("cannot open {}: {e}", path.display()),
            };
        }
    };
    let st = match fsops::stat_fd(&fd) {
        Ok(s) => s,
        Err(e) => {
            return Reply::Error {
                message: e.to_string(),
            };
        }
    };
    let path_s = path.to_string_lossy().into_owned();
    if clamd::ping(sock) {
        match Session::open(sock).and_then(|mut s| s.scan_fd(fd.as_fd())) {
            Ok(Verdict::Found(sig)) => Reply::Verdict {
                path: path_s,
                signature: Some(sig),
                dev: st.st_dev,
                ino: st.st_ino,
            },
            Ok(Verdict::Clean) => Reply::Verdict {
                path: path_s,
                signature: None,
                dev: st.st_dev,
                ino: st.st_ino,
            },
            Ok(Verdict::Error(e)) => Reply::Error { message: e },
            Err(e) => Reply::Error {
                message: e.to_string(),
            },
        }
    } else {
        let out = Command::new("clamscan")
            .args(["--infected", "--no-summary", "--stdout", "--"])
            .arg(path)
            .stdin(Stdio::null())
            .output();
        match out {
            Ok(o) => {
                let text = String::from_utf8_lossy(&o.stdout);
                let sig = text.lines().find_map(parse_clamscan_line).map(|(_, s)| s);
                Reply::Verdict {
                    path: path_s,
                    signature: sig,
                    dev: st.st_dev,
                    ino: st.st_ino,
                }
            }
            Err(e) => Reply::Error {
                message: format!("clamd is down and clamscan failed: {e}"),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamscan_lines() {
        assert_eq!(
            parse_clamscan_line("/home/u/a b.txt: Win.Test.EICAR_HDB-1 FOUND"),
            Some(("/home/u/a b.txt".into(), "Win.Test.EICAR_HDB-1".into()))
        );
        assert_eq!(parse_clamscan_line("/x: OK"), None);
    }

    #[test]
    fn exclude_regex_escapes() {
        assert_eq!(
            exclude_regex("/home/u/My.Games/"),
            r"^/home/u/My\.Games(/|$)"
        );
    }

    #[test]
    fn walk_honors_skips() {
        let d = std::env::temp_dir().join(format!("dbt-walk-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("keep")).unwrap();
        std::fs::create_dir_all(d.join("skip")).unwrap();
        std::fs::write(d.join("keep/a"), b"1").unwrap();
        std::fs::write(d.join("skip/b"), b"2").unwrap();
        std::os::unix::fs::symlink("/etc", d.join("link")).unwrap();
        let opts = ScanOptions {
            job: "t".into(),
            paths: vec![d.to_string_lossy().into_owned()],
            exclusions: vec![d.join("skip").to_string_lossy().into_owned()],
            one_filesystem: true,
            skip: vec![],
            sessions: 1,
            as_uid: None,
        };
        let files: Vec<PathBuf> = walk(&opts, None).collect();
        assert_eq!(files, vec![d.join("keep/a")]);
        std::fs::remove_dir_all(&d).unwrap();
    }
}
