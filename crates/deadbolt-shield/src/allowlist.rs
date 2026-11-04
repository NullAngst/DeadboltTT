//! Shield allowlist. An entry matches an executable path plus its SHA-256,
//! and the binary must be root-owned and not writable by anyone else, so
//! malware cannot drop itself at ~/.local/bin/borg and walk through.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::Command;
use std::sync::Mutex;

/// Allowlisted out of the box, resolved against PATH at startup.
pub const DEFAULT_NAMES: &[&str] = &[
    "dpkg",
    "apt",
    "apt-get",
    "rpm",
    "dnf",
    "zypper",
    "borg",
    "restic",
    "rsync",
    "rclone",
    "git",
    "gcc",
    "g++",
    "cc",
    "c++",
    "clang",
    "clang++",
    "ld",
    "ld.bfd",
    "ld.gold",
    "ld.lld",
    "rustc",
    "make",
    "ninja",
    "tar",
    "gzip",
    "xz",
    "zstd",
    "7z",
    "7za",
    "7zz",
    "gpg",
    "age",
    "cryptsetup",
    "ffmpeg",
    "bzip2",
    "pigz",
];

/// Never allowlisted, even if asked. Allowing one allows every script.
pub fn is_interpreter(exe: &str) -> bool {
    let base = exe.rsplit('/').next().unwrap_or(exe);
    let stripped = base.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    matches!(
        stripped,
        "python"
            | "perl"
            | "bash"
            | "sh"
            | "dash"
            | "zsh"
            | "fish"
            | "ksh"
            | "mksh"
            | "node"
            | "nodejs"
            | "ruby"
            | "java"
            | "lua"
            | "luajit"
            | "php"
            | "deno"
            | "bun"
            | "tclsh"
            | "wish"
            | "pwsh"
            | "osascript"
            | "busybox"
            | "env"
            | "awk"
            | "gawk"
            | "mawk"
    )
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Entry {
    pub path: String,
    pub sha256: String,
    #[serde(default)]
    pub package: String,
    #[serde(default)]
    pub builtin: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum AllowError {
    #[error("{0} is an interpreter. Allowing it would allow every script on the system")]
    Interpreter(String),
    #[error("{0} is not owned by root or is writable by other users, so it cannot be allowlisted")]
    Unsafe(String),
    #[error("cannot read {0}: {1}")]
    Io(String, std::io::Error),
}

pub fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

/// Root-owned, and neither the file nor its directory writable by group or others.
pub fn safely_owned(path: &Path) -> bool {
    let ok = |p: &Path| {
        std::fs::metadata(p)
            .map(|m| m.uid() == 0 && m.mode() & 0o022 == 0)
            .unwrap_or(false)
    };
    ok(path) && path.parent().is_some_and(ok)
}

/// Which package owns a file, via dpkg -S or rpm -qf.
pub fn owning_package(path: &str) -> Option<String> {
    if let Ok(out) = Command::new("dpkg").args(["-S", "--", path]).output()
        && out.status.success()
    {
        let s = String::from_utf8_lossy(&out.stdout);
        return s.split(':').next().map(|p| p.trim().to_string());
    }
    if let Ok(out) = Command::new("rpm").args(["-qf", "--", path]).output()
        && out.status.success()
    {
        return Some(String::from_utf8_lossy(&out.stdout).trim().to_string());
    }
    None
}

pub fn which(name: &str) -> Option<String> {
    let path = std::env::var_os("PATH").unwrap_or_else(|| "/usr/sbin:/usr/bin:/sbin:/bin".into());
    for dir in std::env::split_paths(&path) {
        let p = dir.join(name);
        if p.is_file() {
            let real = std::fs::canonicalize(&p).unwrap_or(p);
            return Some(real.to_string_lossy().into_owned());
        }
    }
    None
}

/// (path, dev, ino, mtime, size)
type FileVersion = (String, u64, u64, i64, u64);

#[derive(Default)]
pub struct Allowlist {
    entries: Mutex<Vec<Entry>>,
    /// (path, dev, ino, mtime, size) -> sha256, so hashing happens once per file version.
    cache: Mutex<HashMap<FileVersion, String>>,
}

impl Allowlist {
    pub fn load(file: &Path) -> Allowlist {
        let entries: Vec<Entry> = std::fs::read(file)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        Allowlist {
            entries: Mutex::new(entries),
            cache: Mutex::new(HashMap::new()),
        }
    }

    pub fn save(&self, file: &Path) -> std::io::Result<()> {
        let e = self
            .entries
            .lock()
            .map_err(|_| std::io::Error::other("poisoned"))?;
        let tmp = file.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(&*e)?)?;
        std::fs::rename(tmp, file)
    }

    pub fn entries(&self) -> Vec<Entry> {
        self.entries.lock().map(|e| e.clone()).unwrap_or_default()
    }

    /// Add the default tools that exist on this system and are not listed yet.
    pub fn seed_defaults(&self) {
        for name in DEFAULT_NAMES {
            if let Some(p) = which(name) {
                let _ = self.add(&p, true);
            }
        }
    }

    fn hash_cached(&self, path: &str) -> Option<String> {
        let m = std::fs::metadata(path).ok()?;
        let k = (path.to_string(), m.dev(), m.ino(), m.mtime(), m.size());
        if let Ok(c) = self.cache.lock()
            && let Some(h) = c.get(&k)
        {
            return Some(h.clone());
        }
        let h = sha256_file(Path::new(path)).ok()?;
        if let Ok(mut c) = self.cache.lock() {
            if c.len() > 4096 {
                c.clear();
            }
            c.insert(k, h.clone());
        }
        Some(h)
    }

    pub fn is_allowed(&self, exe: &str) -> bool {
        if is_interpreter(exe) || !safely_owned(Path::new(exe)) {
            return false;
        }
        let Ok(entries) = self.entries.lock() else {
            return false;
        };
        let Some(e) = entries.iter().find(|e| e.path == exe) else {
            return false;
        };
        let want = e.sha256.clone();
        drop(entries);
        self.hash_cached(exe).is_some_and(|h| h == want)
    }

    pub fn add(&self, exe: &str, builtin: bool) -> Result<(), AllowError> {
        if is_interpreter(exe) {
            return Err(AllowError::Interpreter(exe.into()));
        }
        if !safely_owned(Path::new(exe)) {
            return Err(AllowError::Unsafe(exe.into()));
        }
        let sha = sha256_file(Path::new(exe)).map_err(|e| AllowError::Io(exe.into(), e))?;
        let package = owning_package(exe).unwrap_or_default();
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| AllowError::Unsafe(exe.into()))?;
        entries.retain(|e| e.path != exe);
        entries.push(Entry {
            path: exe.into(),
            sha256: sha,
            package,
            builtin,
        });
        Ok(())
    }

    pub fn remove(&self, exe: &str) -> bool {
        self.entries
            .lock()
            .map(|mut e| {
                let n = e.len();
                e.retain(|x| x.path != exe);
                e.len() != n
            })
            .unwrap_or(false)
    }

    /// After a dpkg or rpm run: re-hash every entry. A changed hash is kept
    /// only if the file still belongs to the same package. Returns removed paths.
    pub fn rehash_after_package_change(&self) -> Vec<String> {
        let mut removed = Vec::new();
        let Ok(mut entries) = self.entries.lock() else {
            return removed;
        };
        entries.retain_mut(|e| {
            let Ok(h) = sha256_file(Path::new(&e.path)) else {
                removed.push(e.path.clone());
                return false;
            };
            if h == e.sha256 {
                return true;
            }
            match owning_package(&e.path) {
                Some(pkg) if !e.package.is_empty() && pkg == e.package => {
                    e.sha256 = h;
                    true
                }
                _ => {
                    removed.push(e.path.clone());
                    false
                }
            }
        });
        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interpreters_refused() {
        for i in [
            "/usr/bin/python3",
            "/usr/bin/python3.12",
            "/bin/bash",
            "/usr/bin/node",
            "/usr/bin/perl5.38",
        ] {
            assert!(is_interpreter(i), "{i}");
        }
        for ok in ["/usr/bin/borg", "/usr/bin/gzip", "/usr/bin/7z"] {
            assert!(!is_interpreter(ok), "{ok}");
        }
    }

    #[test]
    fn user_owned_binary_not_allowed() {
        let a = Allowlist::default();
        let dir = std::env::temp_dir().join(format!("dbt-allow-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("borg");
        std::fs::write(&f, b"fake").unwrap();
        // World-writable binary: must never pass, even when the test runs as root.
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(a.add(f.to_str().unwrap(), false).is_err());
        assert!(!a.is_allowed(f.to_str().unwrap()));
        let _ = std::fs::remove_dir_all(dir);
    }
}
