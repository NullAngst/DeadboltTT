//! The runtime: two fanotify groups, a mount watcher, and the scorer.
//!
//! Content group: FAN_CLOSE_WRITE in classic mode, hands over a descriptor
//! plus a pidfd. We read three 4 KB samples with pread on that descriptor.
//! Structure group: FID + DFID_NAME + TARGET reporting for create, delete and
//! rename, so ransom notes and write-then-delete show up.

use crate::allowlist::Allowlist;
use crate::detect;
use crate::freeze::{self, Frozen};
use crate::procinfo::{self, ProcInfo};
use crate::score::{AppKey, Obs, Scorer, Verdict};
use crate::sys::{self, Event};
use deadbolt_common::types::{Incident, now};
use deadbolt_common::userdata::{self, UserData};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::FileExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

const SAMPLE: usize = 4096;

#[derive(Debug, Clone)]
pub struct Config {
    pub watch_paths: Vec<String>,
    /// Absolute prefixes never counted: user exclusions and the quarantine folder.
    pub exclude_prefixes: Vec<String>,
    pub threshold: u32,
    pub window_secs: u64,
    /// uids whose file work never counts (deadbolt-worker).
    pub ignore_uids: Vec<u32>,
}

pub enum ShieldEvent {
    Trip(Box<Trip>),
    NearMiss {
        app: String,
        exe: String,
        score: u32,
    },
    Overflow {
        total: u64,
    },
    Error(String),
}

pub struct Trip {
    pub incident: Incident,
    pub key: AppKey,
    pub frozen: Frozen,
}

#[derive(Debug, Clone, Default)]
pub struct MarkStatus {
    pub protected: Vec<String>,
    pub unprotected: Vec<String>,
}

struct Shared {
    cfg: RwLock<Config>,
    canaries: RwLock<HashSet<String>>,
    allow: Arc<Allowlist>,
    scorer: Mutex<Scorer>,
    userdata: UserData,
    overflow: AtomicU64,
    paused: AtomicBool,
    marks: Mutex<MarkStatus>,
    mount_fds: Mutex<HashMap<[i32; 2], File>>,
    marked_fs: Mutex<HashSet<[i32; 2]>>,
    pids: Mutex<HashMap<i32, (Instant, Option<ProcInfo>)>>,
    epoch: Instant,
    tx: Mutex<Sender<ShieldEvent>>,
}

#[derive(Clone)]
pub struct Monitor {
    sh: Arc<Shared>,
}

/// Paths the shield never counts, regardless of settings.
pub fn ignored(path: &str, cfg: &Config) -> bool {
    if cfg
        .exclude_prefixes
        .iter()
        .any(|p| path == p || path.starts_with(&format!("{}/", p.trim_end_matches('/'))))
    {
        return true;
    }
    let parts: Vec<&str> = path.split('/').collect();
    if parts
        .iter()
        .any(|c| matches!(*c, ".cache" | "node_modules" | "target" | ".git"))
    {
        return true;
    }
    if path.contains("/.local/share/Steam/") || path.contains("/.steam/") {
        return true;
    }
    // ~/.var/app/<id>/cache
    if let Some(i) = parts.iter().position(|c| *c == ".var")
        && parts.get(i + 1) == Some(&"app")
        && parts.get(i + 3) == Some(&"cache")
    {
        return true;
    }
    false
}

fn watched(path: &str, cfg: &Config) -> bool {
    cfg.watch_paths
        .iter()
        .any(|w| path == w || path.starts_with(&format!("{}/", w.trim_end_matches('/'))))
}

/// Decode the octal escapes mountinfo uses for spaces and friends.
pub fn unescape_mount(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\'
            && i + 4 <= b.len()
            && let Some(oct) = s.get(i + 1..i + 4)
            && let Ok(v) = u8::from_str_radix(oct, 8)
        {
            out.push(v);
            i += 4;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[derive(Debug, Clone, PartialEq)]
pub struct Mount {
    pub point: String,
    pub fstype: String,
    pub ro: bool,
}

pub fn parse_mountinfo(text: &str) -> Vec<Mount> {
    text.lines()
        .filter_map(|l| {
            let (left, right) = l.split_once(" - ")?;
            let lf: Vec<&str> = left.split(' ').collect();
            let rf: Vec<&str> = right.split(' ').collect();
            let point = unescape_mount(lf.get(4)?);
            let opts = lf.get(5)?;
            Some(Mount {
                point,
                fstype: rf.first()?.to_string(),
                ro: opts.split(',').any(|o| o == "ro"),
            })
        })
        .collect()
}

const PSEUDO_FS: &[&str] = &[
    "proc",
    "sysfs",
    "cgroup",
    "cgroup2",
    "devpts",
    "mqueue",
    "debugfs",
    "tracefs",
    "securityfs",
    "pstore",
    "bpf",
    "autofs",
    "fusectl",
    "configfs",
    "binfmt_misc",
    "hugetlbfs",
    "efivarfs",
    "nsfs",
    "devtmpfs",
    "rpc_pipefs",
    "squashfs",
];

/// Mounts that hold a watched path: the one containing each watch path, plus
/// every mount below it.
pub fn target_mounts(mounts: &[Mount], watch: &[String]) -> Vec<Mount> {
    let mut out: Vec<Mount> = Vec::new();
    for w in watch {
        let wp = w.trim_end_matches('/');
        let containing = mounts
            .iter()
            .filter(|m| {
                let mp = m.point.trim_end_matches('/');
                mp.is_empty() || wp == mp || wp.starts_with(&format!("{mp}/"))
            })
            .max_by_key(|m| m.point.len());
        let below = mounts
            .iter()
            .filter(|m| m.point.starts_with(&format!("{wp}/")));
        for m in containing.into_iter().chain(below) {
            if PSEUDO_FS.contains(&m.fstype.as_str()) || m.ro {
                continue;
            }
            if !out.iter().any(|o| o.point == m.point) {
                out.push(m.clone());
            }
        }
    }
    out
}

fn sample(file: &File) -> (Vec<u8>, Vec<u8>) {
    let len = file.metadata().map(|m| m.len()).unwrap_or(0);
    let mut head = vec![0u8; SAMPLE.min(len as usize)];
    let n = file.read_at(&mut head, 0).unwrap_or(0);
    head.truncate(n);
    let mut all = head.clone();
    if len > (SAMPLE * 3) as u64 {
        for off in [len / 2, len - SAMPLE as u64] {
            let mut b = vec![0u8; SAMPLE];
            let n = file.read_at(&mut b, off).unwrap_or(0);
            all.extend_from_slice(&b[..n]);
        }
    }
    (head, all)
}

fn fd_path(fd: &OwnedFd) -> Option<String> {
    use std::os::fd::AsRawFd;
    std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd()))
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

impl Monitor {
    pub fn new(
        cfg: Config,
        allow: Arc<Allowlist>,
        userdata: UserData,
        tx: Sender<ShieldEvent>,
    ) -> Monitor {
        let scorer = Scorer::new(cfg.threshold, cfg.window_secs);
        Monitor {
            sh: Arc::new(Shared {
                cfg: RwLock::new(cfg),
                canaries: RwLock::new(HashSet::new()),
                allow,
                scorer: Mutex::new(scorer),
                userdata,
                overflow: AtomicU64::new(0),
                paused: AtomicBool::new(false),
                marks: Mutex::new(MarkStatus::default()),
                mount_fds: Mutex::new(HashMap::new()),
                marked_fs: Mutex::new(HashSet::new()),
                pids: Mutex::new(HashMap::new()),
                epoch: Instant::now(),
                tx: Mutex::new(tx),
            }),
        }
    }

    pub fn set_config(&self, cfg: Config) {
        if let Ok(mut s) = self.sh.scorer.lock() {
            s.threshold = cfg.threshold;
            s.window_ms = cfg.window_secs * 1000;
        }
        if let Ok(mut c) = self.sh.cfg.write() {
            *c = cfg;
        }
    }

    pub fn set_canaries(&self, paths: impl IntoIterator<Item = String>) {
        if let Ok(mut c) = self.sh.canaries.write() {
            *c = paths.into_iter().collect();
        }
    }

    pub fn set_paused(&self, p: bool) {
        self.sh.paused.store(p, Ordering::SeqCst);
    }

    pub fn reset(&self, key: &AppKey) {
        if let Ok(mut s) = self.sh.scorer.lock() {
            s.reset(key);
        }
    }

    pub fn marks(&self) -> MarkStatus {
        self.sh.marks.lock().map(|m| m.clone()).unwrap_or_default()
    }

    pub fn overflow_count(&self) -> u64 {
        self.sh.overflow.load(Ordering::SeqCst)
    }

    /// Start both fanotify groups and the mount watcher. Needs CAP_SYS_ADMIN.
    pub fn start(&self) -> std::io::Result<()> {
        let base = sys::FAN_CLOEXEC
            | sys::FAN_CLASS_NOTIF
            | sys::FAN_UNLIMITED_QUEUE
            | sys::FAN_UNLIMITED_MARKS;
        let content = Arc::new(sys::fanotify_init(
            base | sys::FAN_REPORT_PIDFD,
            (libc::O_RDONLY | libc::O_LARGEFILE | libc::O_CLOEXEC | libc::O_NOATIME) as u32,
        )?);
        let structure = Arc::new(sys::fanotify_init(
            base | sys::FAN_REPORT_DFID_NAME_TARGET | sys::FAN_REPORT_PIDFD,
            (libc::O_RDONLY | libc::O_CLOEXEC) as u32,
        )?);

        self.remark(&content, &structure);

        let me = self.clone();
        let c2 = content.clone();
        std::thread::Builder::new()
            .name("shield-content".into())
            .spawn(move || me.loop_events(&c2, true))?;
        let me = self.clone();
        let s2 = structure.clone();
        std::thread::Builder::new()
            .name("shield-structure".into())
            .spawn(move || me.loop_events(&s2, false))?;
        let me = self.clone();
        std::thread::Builder::new()
            .name("shield-mounts".into())
            .spawn(move || {
                let mut last = String::new();
                loop {
                    std::thread::sleep(Duration::from_secs(5));
                    let now_info =
                        std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
                    if now_info != last {
                        last = now_info;
                        me.remark(&content, &structure);
                    }
                    if let Ok(mut s) = me.sh.scorer.lock() {
                        s.gc(me.sh.epoch.elapsed().as_millis() as u64);
                    }
                    if let Ok(mut p) = me.sh.pids.lock() {
                        p.retain(|_, (t, _)| t.elapsed() < Duration::from_secs(10));
                    }
                }
            })?;
        Ok(())
    }

    fn remark(&self, content: &OwnedFd, structure: &OwnedFd) {
        let watch = self
            .sh
            .cfg
            .read()
            .map(|c| c.watch_paths.clone())
            .unwrap_or_default();
        let info = std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
        let targets = target_mounts(&parse_mountinfo(&info), &watch);
        let mut status = MarkStatus::default();
        for m in targets {
            let p = PathBuf::from(&m.point);
            let fsid = match sys::fsid_of(&p) {
                Ok(f) => f,
                Err(e) => {
                    status
                        .unprotected
                        .push(format!("{} ({}): {e}", m.point, m.fstype));
                    continue;
                }
            };
            let already = self
                .sh
                .marked_fs
                .lock()
                .map(|s| s.contains(&fsid))
                .unwrap_or(false);
            if already {
                status.protected.push(m.point.clone());
                continue;
            }
            let r1 = sys::fanotify_mark(
                content.as_fd(),
                sys::FAN_MARK_ADD | sys::FAN_MARK_FILESYSTEM,
                sys::FAN_CLOSE_WRITE,
                &p,
            );
            let r2 = sys::fanotify_mark(
                structure.as_fd(),
                sys::FAN_MARK_ADD | sys::FAN_MARK_FILESYSTEM,
                sys::FAN_CREATE | sys::FAN_DELETE | sys::FAN_RENAME | sys::FAN_MODIFY,
                &p,
            );
            match (r1, r2) {
                (Ok(()), Ok(())) => {
                    if let Ok(f) = File::open(&p)
                        && let Ok(mut fds) = self.sh.mount_fds.lock()
                    {
                        fds.insert(fsid, f);
                    }
                    if let Ok(mut s) = self.sh.marked_fs.lock() {
                        s.insert(fsid);
                    }
                    status.protected.push(m.point.clone());
                }
                (a, b) => {
                    let why = a
                        .err()
                        .or(b.err())
                        .map(|e| e.to_string())
                        .unwrap_or_default();
                    status
                        .unprotected
                        .push(format!("{} ({}): {why}", m.point, m.fstype));
                }
            }
        }
        if let Ok(mut s) = self.sh.marks.lock() {
            *s = status;
        }
    }

    fn send(&self, ev: ShieldEvent) {
        if let Ok(tx) = self.sh.tx.lock() {
            let _ = tx.send(ev);
        }
    }

    fn loop_events(&self, fd: &OwnedFd, content: bool) {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match sys::read_events(fd.as_fd(), &mut buf) {
                Ok(evs) => {
                    for ev in evs {
                        if ev.mask & sys::FAN_Q_OVERFLOW != 0 {
                            let total = self.sh.overflow.fetch_add(1, Ordering::SeqCst) + 1;
                            tracing::warn!("fanotify queue overflow, events were lost");
                            self.send(ShieldEvent::Overflow { total });
                            continue;
                        }
                        if content {
                            self.on_content(ev);
                        } else {
                            self.on_structure(ev);
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => {
                    self.send(ShieldEvent::Error(format!("fanotify read failed: {e}")));
                    std::thread::sleep(Duration::from_secs(1));
                }
            }
        }
    }

    fn proc(&self, pid: i32) -> Option<ProcInfo> {
        let mut stale = None;
        if let Ok(p) = self.sh.pids.lock()
            && let Some((t, info)) = p.get(&pid)
        {
            if t.elapsed() < Duration::from_secs(2) {
                return info.clone();
            }
            stale = info.clone();
        }
        // A writer that already exited keeps what we learned while it ran.
        let info = procinfo::info(pid).or(stale);
        if let Ok(mut p) = self.sh.pids.lock() {
            if p.len() > 8192 {
                p.clear();
            }
            p.insert(pid, (Instant::now(), info.clone()));
        }
        info
    }

    /// Common gate: paused, own uid, allowlisted.
    fn who(&self, pid: i32) -> Option<ProcInfo> {
        if self.sh.paused.load(Ordering::SeqCst) || pid <= 0 {
            return None;
        }
        let info = self.proc(pid)?;
        let skip_uid = self
            .sh
            .cfg
            .read()
            .map(|c| c.ignore_uids.contains(&info.uid))
            .unwrap_or(false);
        if skip_uid || self.sh.allow.is_allowed(&info.exe) {
            return None;
        }
        Some(info)
    }

    fn is_canary(&self, path: &str) -> bool {
        self.sh
            .canaries
            .read()
            .map(|c| c.contains(path))
            .unwrap_or(false)
    }

    fn on_content(&self, ev: Event) {
        let Some(fd) = ev.fd else { return };
        let Some(path) = fd_path(&fd) else { return };
        let cfg = match self.sh.cfg.read() {
            Ok(c) => c.clone(),
            Err(_) => return,
        };
        let canary = self.is_canary(&path);
        if !canary && (!watched(&path, &cfg) || ignored(&path, &cfg)) {
            return;
        }
        let Some(info) = self.who(ev.pid) else { return };
        let obs = if canary {
            Obs::Canary { path }
        } else {
            let Some(ext) = userdata::extension(&path) else {
                return;
            };
            if !self.sh.userdata.contains(&ext) {
                return;
            }
            let file = File::from(fd);
            let (head, all) = sample(&file);
            Obs::Content {
                header_ok: detect::header_matches(&ext, &head),
                entropy: detect::entropy(&all),
                path,
                ext,
            }
        };
        self.feed(info, ev.pidfd, obs);
    }

    fn resolve_dir(&self, fid: &sys::Fid) -> Option<String> {
        let fds = self.sh.mount_fds.lock().ok()?;
        let mount = fds.get(&fid.fsid)?;
        let fd = sys::open_by_handle(mount.as_fd(), fid).ok()?;
        fd_path(&fd)
    }

    fn on_structure(&self, ev: Event) {
        // MODIFY arrives while the writer is still alive. Short-lived writers
        // (one openssl per file from a script) are often gone by CLOSE_WRITE,
        // so this is where their /proc details get cached. FID mode, so no
        // descriptor is opened for these.
        if ev.mask & sys::FAN_MODIFY != 0 {
            if ev.pid > 0 {
                let _ = self.proc(ev.pid);
            }
            if ev.mask & (sys::FAN_CREATE | sys::FAN_DELETE | sys::FAN_RENAME) == 0 {
                return;
            }
        }
        let cfg = match self.sh.cfg.read() {
            Ok(c) => c.clone(),
            Err(_) => return,
        };
        let named = |kind: u8| {
            ev.records
                .iter()
                .find(|r| r.kind == kind)
                .and_then(|r| Some((self.resolve_dir(&r.fid)?, r.name.clone()?)))
        };
        let obs = if ev.mask & sys::FAN_RENAME != 0 {
            let (Some((od, on)), Some((nd, nn))) = (
                named(sys::INFO_OLD_DFID_NAME),
                named(sys::INFO_NEW_DFID_NAME),
            ) else {
                return;
            };
            let old = format!("{od}/{on}");
            let new = format!("{nd}/{nn}");
            if self.is_canary(&old) {
                Obs::Canary { path: old }
            } else {
                if !watched(&new, &cfg) || ignored(&new, &cfg) {
                    return;
                }
                let counts =
                    userdata::extension(&on).is_some_and(|e| self.sh.userdata.contains(&e));
                if !counts {
                    return;
                }
                Obs::Renamed { old, new }
            }
        } else {
            let Some((dir, name)) = named(sys::INFO_DFID_NAME) else {
                return;
            };
            let full = format!("{dir}/{name}");
            if self.is_canary(&full) {
                Obs::Canary { path: full }
            } else {
                if !watched(&full, &cfg) || ignored(&full, &cfg) {
                    return;
                }
                if !userdata::extension(&name).is_some_and(|e| self.sh.userdata.contains(&e)) {
                    return;
                }
                if ev.mask & sys::FAN_CREATE != 0 {
                    Obs::Created { dir, name }
                } else if ev.mask & sys::FAN_DELETE != 0 {
                    Obs::Deleted { dir, name }
                } else {
                    return;
                }
            }
        };
        let Some(info) = self.who(ev.pid) else { return };
        self.feed(info, ev.pidfd, obs);
    }

    fn feed(&self, info: ProcInfo, pidfd: Option<OwnedFd>, obs: Obs) {
        let key = AppKey {
            cgroup: info.cgroup.clone(),
            exe: info.exe.clone(),
        };
        let t = self.sh.epoch.elapsed().as_millis() as u64;
        let (verdict, explain) = match self.sh.scorer.lock() {
            Ok(mut s) => {
                let v = s.observe(&key, t, obs);
                let e = if matches!(v, Verdict::Trip { .. }) {
                    Some(s.explain(&key))
                } else {
                    None
                };
                (v, e)
            }
            Err(_) => return,
        };
        match verdict {
            Verdict::Quiet => {}
            Verdict::NearMiss { score } => self.send(ShieldEvent::NearMiss {
                app: procinfo::app_name(&info.cgroup, &info.exe),
                exe: info.exe,
                score,
            }),
            Verdict::Trip { score } => {
                // Confirm the pid we read /proc for is still that program, if it is alive.
                let pidfd = pidfd.or_else(|| sys::pidfd_open(info.pid).ok());
                if pidfd.as_ref().is_some_and(|f| sys::pidfd_alive(f.as_fd()))
                    && procinfo::exe(info.pid).is_some_and(|e| e != info.exe)
                {
                    self.reset(&key);
                    return;
                }
                let (mut signals, files) = explain.unwrap_or_default();
                match freeze::freeze(info.pid, info.ppid, pidfd, &info.cgroup) {
                    Ok(frozen) => {
                        if frozen.root_pid != info.pid {
                            signals.push(format!(
                                "also froze the script driving it: {} (pid {})",
                                procinfo::exe(frozen.root_pid).unwrap_or_default(),
                                frozen.root_pid
                            ));
                        }
                        let user =
                            nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(info.uid))
                                .ok()
                                .flatten()
                                .map(|u| u.name)
                                .unwrap_or_else(|| info.uid.to_string());
                        let incident = Incident {
                            id: uuid::Uuid::new_v4().to_string(),
                            time: now(),
                            app: procinfo::app_name(&info.cgroup, &info.exe),
                            exe: info.exe.clone(),
                            pid: info.pid,
                            uid: info.uid,
                            user,
                            cgroup: info.cgroup.clone(),
                            freeze_method: frozen.method.as_str().into(),
                            score,
                            signals,
                            files,
                            binary_signature: None,
                            state: "frozen".into(),
                        };
                        self.send(ShieldEvent::Trip(Box::new(Trip {
                            incident,
                            key,
                            frozen,
                        })));
                    }
                    Err(e) => {
                        self.send(ShieldEvent::Error(format!(
                            "could not freeze {}: {e}",
                            info.exe
                        )));
                        self.reset(&key);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Config {
        Config {
            watch_paths: vec!["/home".into(), "/srv".into(), "/mnt".into()],
            exclude_prefixes: vec!["/var/lib/deadbolt/quarantine".into(), "/home/u/VMs".into()],
            threshold: 100,
            window_secs: 20,
            ignore_uids: vec![],
        }
    }

    #[test]
    fn ignore_rules() {
        let c = cfg();
        assert!(ignored("/home/u/.cache/x.jpg", &c));
        assert!(ignored("/home/u/proj/node_modules/a.js", &c));
        assert!(ignored("/home/u/.local/share/Steam/steamapps/x.db", &c));
        assert!(ignored("/home/u/.var/app/org.gimp.GIMP/cache/x.png", &c));
        assert!(ignored("/home/u/VMs/disk.qcow2", &c));
        assert!(!ignored("/home/u/Documents/a.docx", &c));
        assert!(!ignored("/home/u/VMsx/disk.qcow2", &c));
    }

    #[test]
    fn watch_rules() {
        let c = cfg();
        assert!(watched("/home/u/a", &c));
        assert!(!watched("/homeless/a", &c));
        assert!(!watched("/usr/bin/x", &c));
    }

    #[test]
    fn mountinfo_parse_and_targets() {
        let text = "\
22 1 8:2 / / rw,relatime shared:1 - ext4 /dev/sda2 rw
30 22 8:3 / /home rw,relatime shared:2 - btrfs /dev/sda3 rw
31 22 0:5 / /proc rw - proc proc rw
40 22 8:17 / /mnt/usb\\040drive rw - vfat /dev/sdb1 rw
41 22 0:50 / /mnt/nas rw - nfs4 nas:/x rw
42 22 7:0 / /mnt/iso ro - iso9660 /dev/loop0 ro
";
        let m = parse_mountinfo(text);
        assert_eq!(m.len(), 6);
        assert_eq!(m[3].point, "/mnt/usb drive");
        let t = target_mounts(&m, &["/home".into(), "/srv".into(), "/mnt".into()]);
        let pts: Vec<&str> = t.iter().map(|m| m.point.as_str()).collect();
        assert_eq!(pts, vec!["/home", "/", "/mnt/usb drive", "/mnt/nas"]);
    }
}
