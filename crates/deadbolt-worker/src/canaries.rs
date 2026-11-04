//! Planting and removing canary files in each user's XDG folders.

use crate::fsops;
use deadbolt_common::canary;
use nix::sys::stat::{Mode, fchmod};
use nix::unistd::{Gid, Uid, User, fchown};
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

fn add_hidden(folder: &Path, names: &[&str], uid: u32, gid: u32) -> io::Result<()> {
    let hidden = folder.join(".hidden");
    let existing = std::fs::read_to_string(&hidden).unwrap_or_default();
    let missing: Vec<&&str> = names
        .iter()
        .filter(|n| !existing.lines().any(|l| l == **n))
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    if std::fs::symlink_metadata(&hidden).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(io::Error::other(".hidden is a symlink, leaving it alone"));
    }
    let created = !hidden.exists();
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&hidden)?;
    if !existing.is_empty() && !existing.ends_with('\n') {
        f.write_all(b"\n")?;
    }
    for n in missing {
        f.write_all(n.as_bytes())?;
        f.write_all(b"\n")?;
    }
    if created {
        let _ = fchown(&f, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)));
    }
    Ok(())
}

/// Plant the decoys in every existing XDG folder of each home. Returns every
/// canary path, already present or new.
pub fn plant(homes: &[(u32, String)]) -> Vec<String> {
    let mut all = Vec::new();
    for (uid, home) in homes {
        let gid = User::from_uid(Uid::from_raw(*uid))
            .ok()
            .flatten()
            .map(|u| u.gid.as_raw())
            .unwrap_or(*uid);
        let dirs = std::fs::read_to_string(format!("{home}/.config/user-dirs.dirs")).ok();
        let mut folders = canary::xdg_folders(home, dirs.as_deref());
        folders.sort();
        folders.dedup();
        for folder in folders {
            let fp = Path::new(&folder);
            if !fp.is_dir() {
                continue;
            }
            let Ok(dir) = fsops::open_dir(fp) else {
                continue;
            };
            let mut names = Vec::new();
            for (name, bytes) in canary::FILES {
                let path = fp.join(name);
                names.push(*name);
                if path.exists() {
                    all.push(path.to_string_lossy().into_owned());
                    continue;
                }
                let n = OsString::from(*name);
                let Ok(fd) = fsops::create_excl(&dir, &n, 0o600) else {
                    continue;
                };
                let mut f = File::from(fd);
                if f.write_all(bytes).is_err() || f.sync_all().is_err() {
                    continue;
                }
                let _ = fchown(&f, Some(Uid::from_raw(*uid)), Some(Gid::from_raw(gid)));
                let _ = fchmod(&f, Mode::from_bits_truncate(0o644));
                all.push(path.to_string_lossy().into_owned());
            }
            if let Err(e) = add_hidden(fp, &names, *uid, gid) {
                tracing::warn!("{}: {e}", fp.display());
            }
        }
    }
    all
}

/// Remove canaries listed in `paths` and their .hidden entries.
pub fn remove(paths: &[String]) {
    let names: Vec<&str> = canary::FILES.iter().map(|(n, _)| *n).collect();
    for p in paths {
        let path = Path::new(p);
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !names.contains(&name) {
            continue;
        }
        if let Ok(fd) = fsops::open_read(path)
            && let Ok(st) = fsops::stat_fd(&fd)
        {
            let _ = fsops::unlink_if_same(path, st.st_dev, st.st_ino);
        }
        if let Some(folder) = path.parent() {
            let hidden = folder.join(".hidden");
            if let Ok(text) = std::fs::read_to_string(&hidden) {
                let kept: Vec<&str> = text.lines().filter(|l| !names.contains(l)).collect();
                if kept.is_empty() {
                    let _ = std::fs::remove_file(&hidden);
                } else {
                    let _ = std::fs::write(&hidden, format!("{}\n", kept.join("\n")));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plant_and_remove() {
        let home = std::env::temp_dir().join(format!("dbt-canary-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(home.join("Documents")).unwrap();
        std::fs::write(home.join("Documents/.hidden"), "mine").unwrap();
        let h = home.to_string_lossy().into_owned();
        let uid = nix::unistd::getuid().as_raw();
        let paths = plant(&[(uid, h.clone())]);
        assert_eq!(paths.len(), 4);
        let hidden = std::fs::read_to_string(home.join("Documents/.hidden")).unwrap();
        assert!(hidden.starts_with("mine\n"));
        assert!(hidden.contains("0000-budget.xlsx"));
        // Planting again changes nothing.
        assert_eq!(plant(&[(uid, h)]).len(), 4);
        remove(&paths);
        assert!(!home.join("Documents/0000-budget.xlsx").exists());
        assert_eq!(
            std::fs::read_to_string(home.join("Documents/.hidden")).unwrap(),
            "mine\n"
        );
        std::fs::remove_dir_all(&home).unwrap();
    }
}
