//! Descriptor-based file operations. Every action on a file resolves its path
//! with openat2 + RESOLVE_NO_SYMLINKS and then works through descriptors, so a
//! symlink swapped in mid-operation gets nothing.

use nix::fcntl::{AT_FDCWD, OFlag, OpenHow, ResolveFlag, openat2};
use nix::sys::stat::{FileStat, Mode, fstat, fstatat};
use nix::unistd::{UnlinkatFlags, unlinkat};
use std::ffi::OsString;
use std::io;
use std::os::fd::OwnedFd;
use std::path::Path;

fn how(flags: OFlag, mode: Mode) -> OpenHow {
    OpenHow::new()
        .flags(flags | OFlag::O_CLOEXEC)
        .mode(mode)
        .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS | ResolveFlag::RESOLVE_NO_MAGICLINKS)
}

fn err(e: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(e as i32)
}

/// Open for reading, no symlinks anywhere in the path. Tries O_NOATIME first,
/// which needs ownership or CAP_FOWNER, and falls back without it.
pub fn open_read(path: &Path) -> io::Result<OwnedFd> {
    let base = OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK;
    match openat2(AT_FDCWD, path, how(base | OFlag::O_NOATIME, Mode::empty())) {
        Ok(fd) => Ok(fd),
        Err(nix::errno::Errno::EPERM) => {
            openat2(AT_FDCWD, path, how(base, Mode::empty())).map_err(err)
        }
        Err(e) => Err(err(e)),
    }
}

pub fn open_dir(path: &Path) -> io::Result<OwnedFd> {
    openat2(
        AT_FDCWD,
        path,
        how(
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW,
            Mode::empty(),
        ),
    )
    .map_err(err)
}

/// Parent directory descriptor and the final name.
pub fn open_parent(path: &Path) -> io::Result<(OwnedFd, OsString)> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    Ok((open_dir(parent)?, name.to_os_string()))
}

/// Create a new file in `dir`, refusing to overwrite anything.
pub fn create_excl(dir: &OwnedFd, name: &OsString, mode: u32) -> io::Result<OwnedFd> {
    openat2(
        dir,
        name.as_os_str(),
        how(
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW,
            Mode::from_bits_truncate(mode),
        ),
    )
    .map_err(err)
}

pub fn stat_fd(fd: &OwnedFd) -> io::Result<FileStat> {
    fstat(fd).map_err(err)
}

/// Remove `path` only if it is still the inode we checked.
pub fn unlink_if_same(path: &Path, dev: u64, ino: u64) -> io::Result<()> {
    let (dir, name) = open_parent(path)?;
    let st = fstatat(
        &dir,
        name.as_os_str(),
        nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
    )
    .map_err(err)?;
    if st.st_dev != dev || st.st_ino != ino {
        return Err(io::Error::other(
            "the file changed after it was scanned, refusing to remove it",
        ));
    }
    unlinkat(&dir, name.as_os_str(), UnlinkatFlags::NoRemoveDir).map_err(err)
}

pub fn is_regular(st: &FileStat) -> bool {
    (st.st_mode & libc::S_IFMT) == libc::S_IFREG
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn symlinks_refused_and_inode_checked() {
        let dir = std::env::temp_dir().join(format!("dbt-fsops-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let real = dir.join("real.txt");
        std::fs::write(&real, b"hello").unwrap();
        let link = dir.join("link.txt");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(open_read(&link).is_err());
        assert!(open_read(&real).is_ok());
        let m = std::fs::metadata(&real).unwrap();
        assert!(unlink_if_same(&real, m.dev(), m.ino() + 1).is_err());
        assert!(real.exists());
        unlink_if_same(&real, m.dev(), m.ino()).unwrap();
        assert!(!real.exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
