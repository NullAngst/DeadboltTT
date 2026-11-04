//! "Could this uid read that file?" Used so a scan request can never be
//! turned into a way of probing files the caller cannot read.

use nix::unistd::{Gid, Group, Uid, User, getgrouplist};
use std::ffi::CString;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct Identity {
    pub uid: u32,
    pub gids: Vec<u32>,
}

impl Identity {
    pub fn of(uid: u32) -> Identity {
        let mut gids = Vec::new();
        if let Ok(Some(u)) = User::from_uid(Uid::from_raw(uid)) {
            gids.push(u.gid.as_raw());
            if let Ok(name) = CString::new(u.name.as_str())
                && let Ok(list) = getgrouplist(&name, u.gid)
            {
                gids.extend(list.into_iter().map(Gid::as_raw));
            }
        }
        gids.sort_unstable();
        gids.dedup();
        Identity { uid, gids }
    }

    pub fn is_root(&self) -> bool {
        self.uid == 0
    }
}

fn allows(mode: u32, owner: u32, group: u32, who: &Identity, want: u32) -> bool {
    if who.is_root() {
        return true;
    }
    let bits = if owner == who.uid {
        (mode >> 6) & 7
    } else if who.gids.contains(&group) {
        (mode >> 3) & 7
    } else {
        mode & 7
    };
    bits & want == want
}

/// Read permission on the file, and search permission on every parent directory.
pub fn can_read(path: &Path, who: &Identity) -> bool {
    if who.is_root() {
        return true;
    }
    let Ok(m) = std::fs::symlink_metadata(path) else {
        return false;
    };
    let need = if m.is_dir() { 4 | 1 } else { 4 };
    if !allows(m.mode(), m.uid(), m.gid(), who, need) {
        return false;
    }
    let mut cur = path.parent();
    while let Some(dir) = cur {
        let Ok(dm) = std::fs::metadata(dir) else {
            return false;
        };
        if !allows(dm.mode(), dm.uid(), dm.gid(), who, 1) {
            return false;
        }
        cur = dir.parent();
    }
    true
}

pub fn user_name(uid: u32) -> String {
    User::from_uid(Uid::from_raw(uid))
        .ok()
        .flatten()
        .map(|u| u.name)
        .unwrap_or_else(|| uid.to_string())
}

pub fn uid_of(name: &str) -> Option<u32> {
    User::from_name(name).ok().flatten().map(|u| u.uid.as_raw())
}

pub fn gid_of_group(name: &str) -> Option<u32> {
    Group::from_name(name)
        .ok()
        .flatten()
        .map(|g| g.gid.as_raw())
}

/// Every regular login user with a home under /home, plus root.
pub fn login_homes() -> Vec<(u32, String)> {
    let mut out = Vec::new();
    let Ok(text) = std::fs::read_to_string("/etc/passwd") else {
        return out;
    };
    for line in text.lines() {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() < 7 {
            continue;
        }
        let Ok(uid) = f[2].parse::<u32>() else {
            continue;
        };
        let home = f[5];
        let shell = f[6];
        if (1000..60000).contains(&uid)
            && home.starts_with("/home/")
            && !shell.ends_with("nologin")
            && !shell.ends_with("false")
            && Path::new(home).is_dir()
        {
            out.push((uid, home.to_string()));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_bits() {
        let me = Identity {
            uid: 1000,
            gids: vec![100],
        };
        assert!(allows(0o600, 1000, 0, &me, 4));
        assert!(!allows(0o600, 0, 0, &me, 4));
        assert!(allows(0o640, 0, 100, &me, 4));
        assert!(allows(0o604, 0, 0, &me, 4));
        assert!(!allows(0o640, 0, 5, &me, 4));
    }

    #[test]
    fn root_reads_all() {
        assert!(can_read(
            Path::new("/etc/shadow"),
            &Identity {
                uid: 0,
                gids: vec![]
            }
        ));
    }

    #[test]
    fn nobody_cannot_read_shadow() {
        let nobody = Identity {
            uid: 65534,
            gids: vec![65534],
        };
        assert!(!can_read(Path::new("/etc/shadow"), &nobody));
    }
}
