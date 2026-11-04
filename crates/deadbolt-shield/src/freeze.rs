//! Freezing, thawing and killing a suspicious app.
//!
//! If the offender owns its app scope outright, one write to cgroup.freeze
//! stops the whole tree. If its cgroup also holds things that must keep
//! running (a terminal, the session scope, a service), SIGSTOP goes to the
//! offender and its descendants through pidfds instead.

use crate::procinfo;
use crate::sys;
use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::path::PathBuf;

const CGROUP_ROOT: &str = "/sys/fs/cgroup";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Cgroup,
    SigStop,
}

impl Method {
    pub fn as_str(self) -> &'static str {
        match self {
            Method::Cgroup => "cgroup",
            Method::SigStop => "sigstop",
        }
    }
}

#[derive(Debug)]
pub struct Frozen {
    pub method: Method,
    pub cgroup: String,
    pub root_pid: i32,
    /// Every process we stopped, held by pidfd so a recycled PID is never signalled.
    pub procs: Vec<(i32, OwnedFd)>,
}

fn cgroup_dir(cg: &str) -> PathBuf {
    PathBuf::from(CGROUP_ROOT).join(cg.trim_start_matches('/'))
}

fn is_app_scope(cg: &str) -> bool {
    let leaf = cg.rsplit('/').next().unwrap_or("");
    leaf.starts_with("app-") && leaf.ends_with(".scope")
}

fn cgroup_procs(cg: &str) -> Vec<i32> {
    std::fs::read_to_string(cgroup_dir(cg).join("cgroup.procs"))
        .map(|t| t.lines().filter_map(|l| l.trim().parse().ok()).collect())
        .unwrap_or_default()
}

/// Decide the method: cgroup freeze only when every process in the scope is
/// the offender or one of its descendants.
pub fn choose_method(cg: &str, tree: &[i32], members: &[i32]) -> Method {
    if is_app_scope(cg) && !members.is_empty() && members.iter().all(|p| tree.contains(p)) {
        Method::Cgroup
    } else {
        Method::SigStop
    }
}

fn refuse(pid: i32, cg: &str) -> io::Result<()> {
    let me = std::process::id() as i32;
    if pid <= 1 || pid == me {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "refusing to freeze init or Deadbolt",
        ));
    }
    if cg.contains("/deadbolt") || cg.ends_with("init.scope") {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "refusing to freeze a Deadbolt or init cgroup",
        ));
    }
    Ok(())
}

/// Script-driven ransomware runs one short process per file from a shell or
/// interpreter loop. Freezing only the short process lets the loop carry on,
/// so walk up and include parents that are interpreters (bash, python, ...),
/// at most three levels, never init and never across users.
pub fn driver_root(pid: i32) -> i32 {
    let uid = procinfo::uid(pid);
    let mut root = pid;
    for _ in 0..3 {
        let Some(parent) = procinfo::ppid(root) else {
            break;
        };
        if parent <= 1 || procinfo::uid(parent) != uid {
            break;
        }
        let Some(exe) = procinfo::exe(parent) else {
            break;
        };
        if !crate::allowlist::is_interpreter(&exe) {
            break;
        }
        root = parent;
    }
    root
}

/// Freeze the offender, or, when it already exited (one short process per
/// file), the interpreter that keeps launching it. `ppid` is the parent we
/// saw while the offender was alive.
pub fn freeze(pid: i32, ppid: i32, pidfd: Option<OwnedFd>, cg: &str) -> io::Result<Frozen> {
    refuse(pid, cg)?;
    let alive = pidfd.as_ref().is_some_and(|f| sys::pidfd_alive(f.as_fd()));
    let start = if alive {
        pid
    } else {
        let exe = procinfo::exe(ppid).unwrap_or_default();
        if ppid <= 1 || !crate::allowlist::is_interpreter(&exe) {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "the process exited before it could be frozen and nothing is driving it",
            ));
        }
        ppid
    };
    let root = driver_root(start);
    refuse(root, cg)?;
    let pidfd = match pidfd {
        Some(f) if alive && root == pid => f,
        _ => sys::pidfd_open(root)?,
    };
    let pid = root;
    let tree = procinfo::tree(pid);
    let members = cgroup_procs(cg);
    match choose_method(cg, &tree, &members) {
        Method::Cgroup => {
            std::fs::write(cgroup_dir(cg).join("cgroup.freeze"), b"1")?;
            let mut procs = vec![(pid, pidfd)];
            for p in members {
                if p != pid
                    && let Ok(fd) = sys::pidfd_open(p)
                {
                    procs.push((p, fd));
                }
            }
            Ok(Frozen {
                method: Method::Cgroup,
                cgroup: cg.to_string(),
                root_pid: pid,
                procs,
            })
        }
        Method::SigStop => {
            sys::pidfd_send_signal(pidfd.as_fd(), libc::SIGSTOP)?;
            let mut procs = vec![(pid, pidfd)];
            // Walk again for anything forked mid-walk.
            for _ in 0..5 {
                let mut added = 0;
                for p in procinfo::tree(pid) {
                    if procs.iter().any(|(q, _)| *q == p) {
                        continue;
                    }
                    if let Ok(fd) = sys::pidfd_open(p)
                        && sys::pidfd_send_signal(fd.as_fd(), libc::SIGSTOP).is_ok()
                    {
                        procs.push((p, fd));
                        added += 1;
                    }
                }
                if added == 0 {
                    break;
                }
            }
            Ok(Frozen {
                method: Method::SigStop,
                cgroup: cg.to_string(),
                root_pid: pid,
                procs,
            })
        }
    }
}

pub fn thaw(f: &Frozen) -> io::Result<()> {
    match f.method {
        Method::Cgroup => std::fs::write(cgroup_dir(&f.cgroup).join("cgroup.freeze"), b"0"),
        Method::SigStop => {
            for (_, fd) in &f.procs {
                let _ = sys::pidfd_send_signal(fd.as_fd(), libc::SIGCONT);
            }
            Ok(())
        }
    }
}

pub fn kill(f: &Frozen) -> io::Result<()> {
    if f.method == Method::Cgroup {
        let k = cgroup_dir(&f.cgroup).join("cgroup.kill");
        if k.exists() && std::fs::write(&k, b"1").is_ok() {
            return Ok(());
        }
    }
    for (_, fd) in &f.procs {
        let _ = sys::pidfd_send_signal(fd.as_fd(), libc::SIGKILL);
    }
    // A cgroup-frozen task still dies on SIGKILL. Thaw anyway so nothing lingers.
    if f.method == Method::Cgroup {
        let _ = std::fs::write(cgroup_dir(&f.cgroup).join("cgroup.freeze"), b"0");
    }
    Ok(())
}

pub fn alive(f: &Frozen) -> bool {
    f.procs
        .first()
        .is_some_and(|(_, fd)| sys::pidfd_alive(fd.as_fd()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_choice() {
        let cg = "/user.slice/user-1000.slice/app.slice/app-evil@x.scope";
        assert_eq!(choose_method(cg, &[10, 11], &[10, 11]), Method::Cgroup);
        // Konsole case: the scope also holds the terminal.
        assert_eq!(choose_method(cg, &[10, 11], &[5, 10, 11]), Method::SigStop);
        assert_eq!(
            choose_method("/user.slice/session-2.scope", &[10], &[10]),
            Method::SigStop
        );
    }

    #[test]
    fn refuses_self() {
        assert!(refuse(std::process::id() as i32, "/x").is_err());
        assert!(refuse(1, "/x").is_err());
        assert!(refuse(500, "/system.slice/deadboltd.service").is_err());
    }
}
