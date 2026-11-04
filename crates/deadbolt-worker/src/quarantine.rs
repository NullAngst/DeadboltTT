//! Quarantine store: /var/lib/deadbolt/quarantine, root:root 0700, mounted
//! noexec,nosuid,nodev. Each item is <uuid>.cq (original bytes XORed with a
//! random 32-byte key, mode 0400) and <uuid>.json (metadata).

use crate::fsops;
use deadbolt_common::types::{QuarantineItem, Source, now};
use nix::sys::stat::{Mode, fchmod, futimens};
use nix::sys::time::TimeSpec;
use nix::unistd::{Gid, Uid, fchown};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

pub struct Store {
    pub dir: PathBuf,
}

fn xor(buf: &mut [u8], key: &[u8; 32], offset: u64) {
    for (i, b) in buf.iter_mut().enumerate() {
        *b ^= key[((offset + i as u64) % 32) as usize];
    }
}

fn valid_id(id: &str) -> bool {
    uuid::Uuid::parse_str(id).is_ok() && id.len() == 36
}

fn decode_key(hexkey: &str) -> io::Result<[u8; 32]> {
    let v = hex::decode(hexkey).map_err(|_| io::Error::other("bad key in metadata"))?;
    v.try_into()
        .map_err(|_| io::Error::other("bad key length in metadata"))
}

impl Store {
    pub fn new(dir: impl Into<PathBuf>) -> Store {
        Store { dir: dir.into() }
    }

    fn paths(&self, id: &str) -> (PathBuf, PathBuf) {
        (
            self.dir.join(format!("{id}.cq")),
            self.dir.join(format!("{id}.json")),
        )
    }

    fn write_private(&self, name: &str, data: &[u8], mode: u32) -> io::Result<()> {
        let dir = fsops::open_dir(&self.dir)?;
        let tmp = OsString::from(format!("{name}.tmp"));
        let fd = fsops::create_excl(&dir, &tmp, 0o600)?;
        let mut f = File::from(fd);
        f.write_all(data)?;
        f.sync_all()?;
        let _ = fchown(&f, Some(Uid::from_raw(0)), Some(Gid::from_raw(0)));
        fchmod(&f, Mode::from_bits_truncate(mode)).map_err(io::Error::from)?;
        drop(f);
        std::fs::rename(self.dir.join(&tmp), self.dir.join(name))
    }

    /// Move a file in. Steps: open with no symlinks and fstat, stream it
    /// scrambled to a temp file and fsync, rename into place, verify SHA-256,
    /// then unlink the original only if it is still the scanned inode.
    pub fn quarantine(
        &self,
        path: &Path,
        signature: &str,
        source: Source,
        expect: Option<(u64, u64)>,
    ) -> io::Result<QuarantineItem> {
        let src = fsops::open_read(path)?;
        let st = fsops::stat_fd(&src)?;
        if !fsops::is_regular(&st) {
            return Err(io::Error::other("not a regular file"));
        }
        if let Some((dev, ino)) = expect
            && (st.st_dev != dev || st.st_ino != ino)
        {
            return Err(io::Error::other(
                "the file changed after it was scanned, refusing to move it",
            ));
        }
        let id = uuid::Uuid::new_v4().to_string();
        let mut key = [0u8; 32];
        rand::rng().fill_bytes(&mut key);

        let dir = fsops::open_dir(&self.dir)?;
        let tmp = OsString::from(format!("{id}.cq.tmp"));
        let out_fd = fsops::create_excl(&dir, &tmp, 0o600)?;
        let mut out = File::from(out_fd);
        let mut input = File::from(src);
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 1 << 16];
        let mut off = 0u64;
        loop {
            let n = input.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            xor(&mut buf[..n], &key, off);
            out.write_all(&buf[..n])?;
            off += n as u64;
        }
        out.sync_all()?;
        let _ = fchown(&out, Some(Uid::from_raw(0)), Some(Gid::from_raw(0)));
        fchmod(&out, Mode::from_bits_truncate(0o400)).map_err(io::Error::from)?;
        drop(out);
        let (cq, _) = self.paths(&id);
        std::fs::rename(self.dir.join(&tmp), &cq)?;
        let sha = hex::encode(hasher.finalize());

        // Verify what landed on disk matches what we read.
        if self.hash_item(&cq, &key)? != sha {
            let _ = std::fs::remove_file(&cq);
            return Err(io::Error::other(
                "quarantine copy did not verify, original left in place",
            ));
        }

        let item = QuarantineItem {
            id: id.clone(),
            original_path: path.to_string_lossy().into_owned(),
            owner: st.st_uid,
            group: st.st_gid,
            mode: st.st_mode & 0o7777,
            mtime: st.st_mtime,
            size: off,
            sha256: sha,
            signature: signature.to_string(),
            source,
            date: now(),
            key: hex::encode(key),
        };
        self.write_private(
            &format!("{id}.json"),
            &serde_json::to_vec_pretty(&item)?,
            0o400,
        )?;

        if let Err(e) = fsops::unlink_if_same(path, st.st_dev, st.st_ino) {
            // Keep the copy; report that the original is still there.
            return Err(io::Error::other(format!(
                "copied to quarantine as {id} but could not remove the original: {e}"
            )));
        }
        Ok(item)
    }

    fn hash_item(&self, cq: &Path, key: &[u8; 32]) -> io::Result<String> {
        let mut f = File::open(cq)?;
        let mut h = Sha256::new();
        let mut buf = vec![0u8; 1 << 16];
        let mut off = 0u64;
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            xor(&mut buf[..n], key, off);
            h.update(&buf[..n]);
            off += n as u64;
        }
        Ok(hex::encode(h.finalize()))
    }

    pub fn list(&self) -> io::Result<Vec<QuarantineItem>> {
        let mut out = Vec::new();
        for e in std::fs::read_dir(&self.dir)? {
            let e = e?;
            let name = e.file_name().to_string_lossy().into_owned();
            let Some(id) = name.strip_suffix(".json") else {
                continue;
            };
            if !valid_id(id) {
                continue;
            }
            let data = std::fs::read(e.path())?;
            if data.len() > 64 * 1024 {
                continue;
            }
            if let Ok(item) = serde_json::from_slice::<QuarantineItem>(&data) {
                out.push(item);
            }
        }
        out.sort_by_key(|i| std::cmp::Reverse(i.date));
        Ok(out)
    }

    pub fn get(&self, id: &str) -> io::Result<QuarantineItem> {
        if !valid_id(id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "bad quarantine id",
            ));
        }
        let (_, js) = self.paths(id);
        let data = std::fs::read(js)?;
        serde_json::from_slice(&data).map_err(io::Error::other)
    }

    /// Restore to the original path or `to`. Never overwrites. Owner, mode and
    /// mtime come back; the execute bit stays off unless asked.
    pub fn restore(&self, id: &str, to: Option<&Path>, restore_exec: bool) -> io::Result<PathBuf> {
        let item = self.get(id)?;
        let key = decode_key(&item.key)?;
        let dest = to
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from(&item.original_path));
        if !dest.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "restore path must be absolute",
            ));
        }
        let (dir, name) = fsops::open_parent(&dest)?;
        let fd = fsops::create_excl(&dir, &name, 0o600).map_err(|e| {
            if e.kind() == io::ErrorKind::AlreadyExists {
                io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "a file already exists at the restore path",
                )
            } else {
                e
            }
        })?;
        let mut out = File::from(fd);
        let (cq, js) = self.paths(id);
        let mut input = File::open(&cq)?;
        let mut h = Sha256::new();
        let mut buf = vec![0u8; 1 << 16];
        let mut off = 0u64;
        loop {
            let n = input.read(&mut buf)?;
            if n == 0 {
                break;
            }
            xor(&mut buf[..n], &key, off);
            h.update(&buf[..n]);
            out.write_all(&buf[..n])?;
            off += n as u64;
        }
        out.sync_all()?;
        if hex::encode(h.finalize()) != item.sha256 {
            drop(out);
            let _ = nix::unistd::unlinkat(
                &dir,
                name.as_os_str(),
                nix::unistd::UnlinkatFlags::NoRemoveDir,
            );
            return Err(io::Error::other(
                "restored data did not match the recorded hash",
            ));
        }
        let mut mode = item.mode & 0o7777;
        if !restore_exec {
            mode &= !0o111;
        }
        // Never restore setuid/setgid.
        mode &= !0o6000;
        fchown(
            &out,
            Some(Uid::from_raw(item.owner)),
            Some(Gid::from_raw(item.group)),
        )
        .map_err(io::Error::from)?;
        fchmod(&out, Mode::from_bits_truncate(mode)).map_err(io::Error::from)?;
        let t = TimeSpec::new(item.mtime, 0);
        let _ = futimens(&out, &t, &t);
        drop(out);
        std::fs::remove_file(&cq)?;
        std::fs::remove_file(&js)?;
        Ok(dest)
    }

    pub fn delete(&self, id: &str) -> io::Result<()> {
        if !valid_id(id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "bad quarantine id",
            ));
        }
        let (cq, js) = self.paths(id);
        let r1 = std::fs::remove_file(&cq);
        let r2 = std::fs::remove_file(&js);
        r1.or(r2)
    }

    pub fn purge(&self, older_than_days: u32) -> io::Result<u64> {
        if older_than_days == 0 {
            return Ok(0);
        }
        let cut = now() - i64::from(older_than_days) * 86_400;
        let mut n = 0;
        for item in self.list()? {
            if item.date < cut && self.delete(&item.id).is_ok() {
                n += 1;
            }
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("dbt-q-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn quarantine_and_restore_round_trip() {
        let base = tmpdir("rt");
        let qdir = base.join("q");
        std::fs::create_dir_all(&qdir).unwrap();
        let store = Store::new(&qdir);
        let f = base.join("evil.sh");
        std::fs::write(&f, b"#!/bin/sh\necho pwned\n").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
        let m = std::fs::metadata(&f).unwrap();
        let item = store
            .quarantine(&f, "Test.Sig", Source::Manual, Some((m.dev(), m.ino())))
            .unwrap();
        assert!(!f.exists());
        let cq = qdir.join(format!("{}.cq", item.id));
        let stored = std::fs::read(&cq).unwrap();
        assert_ne!(stored, b"#!/bin/sh\necho pwned\n");
        assert_eq!(std::fs::metadata(&cq).unwrap().mode() & 0o777, 0o400);
        assert_eq!(store.list().unwrap().len(), 1);

        let back = store.restore(&item.id, None, false).unwrap();
        assert_eq!(std::fs::read(&back).unwrap(), b"#!/bin/sh\necho pwned\n");
        assert_eq!(std::fs::metadata(&back).unwrap().mode() & 0o777, 0o644);
        assert!(store.list().unwrap().is_empty());
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn restore_never_overwrites() {
        let base = tmpdir("ow");
        let qdir = base.join("q");
        std::fs::create_dir_all(&qdir).unwrap();
        let store = Store::new(&qdir);
        let f = base.join("a.bin");
        std::fs::write(&f, b"one").unwrap();
        let item = store.quarantine(&f, "S", Source::Manual, None).unwrap();
        std::fs::write(&f, b"two").unwrap();
        assert!(store.restore(&item.id, None, false).is_err());
        assert_eq!(std::fs::read(&f).unwrap(), b"two");
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn changed_inode_is_not_moved() {
        let base = tmpdir("ino");
        let qdir = base.join("q");
        std::fs::create_dir_all(&qdir).unwrap();
        let store = Store::new(&qdir);
        let f = base.join("a.bin");
        std::fs::write(&f, b"x").unwrap();
        let m = std::fs::metadata(&f).unwrap();
        assert!(
            store
                .quarantine(&f, "S", Source::Manual, Some((m.dev(), m.ino() + 7)))
                .is_err()
        );
        assert!(f.exists());
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn bad_ids_rejected() {
        let store = Store::new("/nonexistent");
        assert!(store.get("../../etc/passwd").is_err());
        assert!(store.delete("x").is_err());
    }
}
