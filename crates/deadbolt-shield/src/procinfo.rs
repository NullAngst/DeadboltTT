//! Reading /proc for a process: executable, cgroup, owner, parent.

use std::fs;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcInfo {
    pub pid: i32,
    pub exe: String,
    pub cgroup: String,
    pub uid: u32,
    pub comm: String,
    pub cmdline: Vec<String>,
    /// Parent at the time we looked, so a process that already exited can
    /// still be traced to the script that started it.
    pub ppid: i32,
}

pub fn exe(pid: i32) -> Option<String> {
    let p = fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    let s = p.to_string_lossy().into_owned();
    Some(s.strip_suffix(" (deleted)").unwrap_or(&s).to_string())
}

/// The cgroup v2 path, "/user.slice/user-1000.slice/.../app-x.scope".
pub fn cgroup(pid: i32) -> Option<String> {
    let text = fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    parse_cgroup(&text)
}

pub fn parse_cgroup(text: &str) -> Option<String> {
    text.lines()
        .find_map(|l| l.strip_prefix("0::"))
        .map(|s| s.trim().to_string())
}

pub fn uid(pid: i32) -> Option<u32> {
    let text = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    parse_status_uid(&text)
}

pub fn parse_status_uid(text: &str) -> Option<u32> {
    text.lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|v| v.parse().ok())
}

/// Parent pid from /proc/<pid>/stat. The comm field can hold spaces and
/// parens, so parse after the last ')'.
pub fn ppid(pid: i32) -> Option<i32> {
    let text = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    parse_stat_ppid(&text)
}

pub fn parse_stat_ppid(text: &str) -> Option<i32> {
    let after = &text[text.rfind(')')? + 1..];
    let mut it = after.split_whitespace();
    let _state = it.next()?;
    it.next()?.parse().ok()
}

pub fn comm(pid: i32) -> String {
    fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

pub fn cmdline(pid: i32) -> Vec<String> {
    fs::read(format!("/proc/{pid}/cmdline"))
        .map(|b| {
            b.split(|&c| c == 0)
                .filter(|s| !s.is_empty())
                .take(64)
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect()
        })
        .unwrap_or_default()
}

pub fn info(pid: i32) -> Option<ProcInfo> {
    Some(ProcInfo {
        pid,
        exe: exe(pid)?,
        cgroup: cgroup(pid).unwrap_or_default(),
        uid: uid(pid)?,
        comm: comm(pid),
        cmdline: cmdline(pid),
        ppid: ppid(pid).unwrap_or(0),
    })
}

/// Every pid on the system with its parent.
pub fn all_parents() -> Vec<(i32, i32)> {
    let Ok(rd) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    rd.filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().to_str()?.parse::<i32>().ok())
        .filter_map(|pid| Some((pid, ppid(pid)?)))
        .collect()
}

/// `root` and all of its descendants.
pub fn tree(root: i32) -> Vec<i32> {
    descendants_of(root, &all_parents())
}

pub fn descendants_of(root: i32, pairs: &[(i32, i32)]) -> Vec<i32> {
    let mut out = vec![root];
    let mut i = 0;
    while i < out.len() {
        let cur = out[i];
        for &(pid, parent) in pairs {
            if parent == cur && !out.contains(&pid) {
                out.push(pid);
            }
        }
        i += 1;
    }
    out
}

/// Name for an app from its cgroup scope, e.g. "app-org.kde.konsole@abc.scope" -> "org.kde.konsole".
pub fn app_name(cgroup: &str, exe: &str) -> String {
    let leaf = cgroup.rsplit('/').next().unwrap_or("");
    if let Some(rest) = leaf
        .strip_prefix("app-")
        .and_then(|r| r.strip_suffix(".scope"))
    {
        let rest = rest.split('@').next().unwrap_or(rest);
        let rest = rest.strip_prefix("flatpak-").unwrap_or(rest);
        // app-<launcher>-<name>-<random> on some launchers
        if !rest.is_empty() {
            return rest.to_string();
        }
    }
    exe.rsplit('/').next().unwrap_or(exe).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses() {
        assert_eq!(
            parse_cgroup("0::/user.slice/user-1000.slice/app.slice/app-gimp.scope\n").as_deref(),
            Some("/user.slice/user-1000.slice/app.slice/app-gimp.scope")
        );
        assert_eq!(
            parse_status_uid("Name:\tx\nUid:\t1000\t1000\t1000\t1000\n"),
            Some(1000)
        );
        assert_eq!(parse_stat_ppid("123 (we ird) name) S 77 123 123"), Some(77));
    }

    #[test]
    fn tree_walk() {
        let pairs = [(2, 1), (3, 2), (4, 2), (5, 9), (6, 3)];
        let mut t = descendants_of(2, &pairs);
        t.sort();
        assert_eq!(t, vec![2, 3, 4, 6]);
    }

    #[test]
    fn names() {
        assert_eq!(
            app_name("/u/app-org.gimp.GIMP@1a2b.scope", "/usr/bin/gimp"),
            "org.gimp.GIMP"
        );
        assert_eq!(
            app_name("/user.slice/session-3.scope", "/usr/bin/foo"),
            "foo"
        );
    }

    #[test]
    fn self_info() {
        let me = info(std::process::id() as i32).unwrap();
        assert!(!me.exe.is_empty());
    }
}
