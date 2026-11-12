//! Descriptor-based file operations. Every action on a file resolves its path
//! with no symlinks in any component and then works through descriptors, so a
//! symlink swapped in mid-operation gets nothing.
//!
//! The rule is enforced by openat2 + RESOLVE_NO_SYMLINKS where it is
//! available. systemd's RestrictSUIDSGID=yes answers openat2 with ENOSYS,
//! since seccomp cannot see the mode inside struct open_how, and kernels before
//! 5.6 lack it. Then the path is walked one component at a time with
//! openat(O_NOFOLLOW), which enforces the same rule and which the setuid filter
//! can inspect.

use nix::errno::Errno;
use nix::fcntl::{AT_FDCWD, OFlag, OpenHow, ResolveFlag, openat, openat2};
use nix::sys::stat::{FileStat, Mode, SFlag, fstat, fstatat};
use nix::unistd::{UnlinkatFlags, unlinkat};
use std::ffi::{OsStr, OsString};
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Component, Path};

fn how(flags: OFlag, mode: Mode) -> OpenHow {
    OpenHow::new()
        .flags(flags | OFlag::O_CLOEXEC)
        .mode(mode)
        .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS | ResolveFlag::RESOLVE_NO_MAGICLINKS)
}

fn err(e: Errno) -> io::Error {
    io::Error::from_raw_os_error(e as i32)
}

/// Open `path` relative to `dir` with no symlink in any component.
fn open_nofollow<Fd: AsFd>(dir: Fd, path: &Path, flags: OFlag, mode: Mode) -> nix::Result<OwnedFd> {
    match openat2(dir.as_fd(), path, how(flags, mode)) {
        Err(Errno::ENOSYS) => walk_open(dir.as_fd(), path, flags, mode),
        r => r,
    }
}

/// One `openat(O_NOFOLLOW)` per component. Directories on the way are opened
/// O_PATH, which needs only search permission. A symlink anywhere gives ELOOP,
/// as RESOLVE_NO_SYMLINKS does; ".." is allowed, as it is there.
fn walk_open(dir: BorrowedFd<'_>, path: &Path, flags: OFlag, mode: Mode) -> nix::Result<OwnedFd> {
    let comps: Vec<Component<'_>> = path.components().collect();
    let Some((last, parents)) = comps.split_last() else {
        return Err(Errno::ENOENT);
    };
    let mut cur: Option<OwnedFd> = None;
    let walk = OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    for c in parents {
        let next = match c {
            Component::RootDir => openat(AT_FDCWD, "/", walk, Mode::empty())?,
            Component::CurDir => continue,
            Component::ParentDir => step(base(&cur, dir), OsStr::new(".."), walk, Mode::empty())?,
            Component::Normal(n) => step(base(&cur, dir), n, walk, Mode::empty())?,
            Component::Prefix(_) => return Err(Errno::EINVAL),
        };
        cur = Some(next);
    }
    let fl = flags | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    match last {
        Component::RootDir => openat(AT_FDCWD, "/", fl, mode),
        Component::CurDir => openat(base(&cur, dir), ".", fl, mode),
        Component::ParentDir => openat(base(&cur, dir), "..", fl, mode),
        Component::Normal(n) => step(base(&cur, dir), n, fl, mode),
        Component::Prefix(_) => Err(Errno::EINVAL),
    }
}

fn base<'a>(cur: &'a Option<OwnedFd>, dir: BorrowedFd<'a>) -> BorrowedFd<'a> {
    cur.as_ref().map_or(dir, |f| f.as_fd())
}

/// openat on one name. O_PATH|O_NOFOLLOW on a symlink opens the link itself
/// and O_DIRECTORY then reports ENOTDIR; report ELOOP for a symlink instead,
/// so both resolution paths give the same error.
fn step(base: BorrowedFd<'_>, name: &OsStr, flags: OFlag, mode: Mode) -> nix::Result<OwnedFd> {
    openat(base, name, flags, mode).map_err(|e| {
        if e == Errno::ENOTDIR
            && fstatat(base, name, nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW).is_ok_and(|st| {
                SFlag::from_bits_truncate(st.st_mode) & SFlag::S_IFMT == SFlag::S_IFLNK
            })
        {
            Errno::ELOOP
        } else {
            e
        }
    })
}

/// Open for reading, no symlinks anywhere in the path. Tries O_NOATIME first,
/// which needs ownership or CAP_FOWNER, and falls back without it.
pub fn open_read(path: &Path) -> io::Result<OwnedFd> {
    let base = OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK;
    match open_nofollow(AT_FDCWD, path, base | OFlag::O_NOATIME, Mode::empty()) {
        Ok(fd) => Ok(fd),
        Err(Errno::EPERM) => open_nofollow(AT_FDCWD, path, base, Mode::empty()).map_err(err),
        Err(e) => Err(err(e)),
    }
}

pub fn open_dir(path: &Path) -> io::Result<OwnedFd> {
    open_nofollow(
        AT_FDCWD,
        path,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW,
        Mode::empty(),
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
    open_nofollow(
        dir,
        Path::new(name.as_os_str()),
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW,
        Mode::from_bits_truncate(mode),
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

    /// The path RestrictSUIDSGID=yes forces: same rule, one component at a time.
    #[test]
    fn walk_open_matches_openat2_rules() {
        let dir = std::env::temp_dir().join(format!("dbt-walk-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("real/sub")).unwrap();
        std::fs::write(dir.join("real/sub/f.txt"), b"hi").unwrap();
        std::os::unix::fs::symlink(dir.join("real"), dir.join("linkdir")).unwrap();
        std::os::unix::fs::symlink(dir.join("real/sub/f.txt"), dir.join("real/sub/l.txt")).unwrap();
        let rd = OFlag::O_RDONLY;
        let open = |p: &Path| walk_open(AT_FDCWD, p, rd, Mode::empty());
        assert!(open(&dir.join("real/sub/f.txt")).is_ok());
        assert!(open(&dir.join("real/sub/../sub/f.txt")).is_ok());
        assert_eq!(open(&dir.join("real/sub/l.txt")).unwrap_err(), Errno::ELOOP);
        assert_eq!(
            open(&dir.join("linkdir/sub/f.txt")).unwrap_err(),
            Errno::ELOOP
        );
        assert_eq!(open(&dir.join("real/nope.txt")).unwrap_err(), Errno::ENOENT);
        // Relative to a directory descriptor, as create_excl uses it.
        let d = walk_open(
            AT_FDCWD,
            &dir.join("real/sub"),
            OFlag::O_RDONLY | OFlag::O_DIRECTORY,
            Mode::empty(),
        )
        .unwrap();
        let cf = OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL;
        assert!(
            walk_open(
                d.as_fd(),
                Path::new("new.txt"),
                cf,
                Mode::from_bits_truncate(0o600)
            )
            .is_ok()
        );
        assert_eq!(
            walk_open(
                d.as_fd(),
                Path::new("new.txt"),
                cf,
                Mode::from_bits_truncate(0o600)
            )
            .unwrap_err(),
            Errno::EEXIST
        );
        assert!(
            walk_open(
                AT_FDCWD,
                Path::new("/"),
                OFlag::O_RDONLY | OFlag::O_DIRECTORY,
                Mode::empty()
            )
            .is_ok()
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
