//! The only module in Deadbolt allowed to use `unsafe`. It wraps the
//! syscalls the standard library and nix do not cover in the form we need:
//! fanotify_init/fanotify_mark with FID and PIDFD reporting, event parsing,
//! open_by_handle_at, statfs fsid, pidfd_open and pidfd_send_signal.
#![allow(unsafe_code)]

use std::ffi::{CStr, CString};
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;

// fanotify_init flags
pub const FAN_CLOEXEC: u32 = 0x0000_0001;
pub const FAN_CLASS_NOTIF: u32 = 0x0000_0000;
pub const FAN_CLASS_CONTENT: u32 = 0x0000_0004;
pub const FAN_UNLIMITED_QUEUE: u32 = 0x0000_0010;
pub const FAN_UNLIMITED_MARKS: u32 = 0x0000_0020;
pub const FAN_REPORT_PIDFD: u32 = 0x0000_0080;
pub const FAN_REPORT_FID: u32 = 0x0000_0200;
pub const FAN_REPORT_DIR_FID: u32 = 0x0000_0400;
pub const FAN_REPORT_NAME: u32 = 0x0000_0800;
pub const FAN_REPORT_TARGET_FID: u32 = 0x0000_1000;
pub const FAN_REPORT_DFID_NAME_TARGET: u32 =
    FAN_REPORT_DIR_FID | FAN_REPORT_NAME | FAN_REPORT_FID | FAN_REPORT_TARGET_FID;

// event mask bits
pub const FAN_MODIFY: u64 = 0x0000_0002;
pub const FAN_CLOSE_WRITE: u64 = 0x0000_0008;
pub const FAN_MOVED_FROM: u64 = 0x0000_0040;
pub const FAN_MOVED_TO: u64 = 0x0000_0080;
pub const FAN_CREATE: u64 = 0x0000_0100;
pub const FAN_DELETE: u64 = 0x0000_0200;
pub const FAN_Q_OVERFLOW: u64 = 0x0000_4000;
pub const FAN_RENAME: u64 = 0x1000_0000;
pub const FAN_ONDIR: u64 = 0x4000_0000;

// fanotify_mark flags
pub const FAN_MARK_ADD: u32 = 0x0000_0001;
pub const FAN_MARK_REMOVE: u32 = 0x0000_0002;
pub const FAN_MARK_FILESYSTEM: u32 = 0x0000_0100;

// info record types
pub const INFO_FID: u8 = 1;
pub const INFO_DFID_NAME: u8 = 2;
pub const INFO_DFID: u8 = 3;
pub const INFO_PIDFD: u8 = 4;
pub const INFO_OLD_DFID_NAME: u8 = 10;
pub const INFO_NEW_DFID_NAME: u8 = 12;

const METADATA_LEN: usize = 24;
const METADATA_VERSION: u8 = 3;
const FAN_NOFD: i32 = -1;

/// A file handle as reported by fanotify, with the filesystem it belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Fid {
    pub fsid: [i32; 2],
    pub handle_type: i32,
    pub handle: Vec<u8>,
}

#[derive(Debug)]
pub struct InfoRecord {
    pub kind: u8,
    pub fid: Fid,
    pub name: Option<String>,
}

/// One parsed fanotify event. Descriptors are owned and close on drop.
#[derive(Debug)]
pub struct Event {
    pub mask: u64,
    pub pid: i32,
    pub fd: Option<OwnedFd>,
    pub pidfd: Option<OwnedFd>,
    pub records: Vec<InfoRecord>,
}

pub fn fanotify_init(flags: u32, event_f_flags: u32) -> io::Result<OwnedFd> {
    // SAFETY: fanotify_init takes two integer arguments and returns a new
    // descriptor or -1. On success we take sole ownership of that descriptor.
    let fd = unsafe { libc::fanotify_init(flags, event_f_flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is a fresh, valid descriptor returned by the kernel and owned by no one else.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

pub fn fanotify_mark(fd: BorrowedFd<'_>, flags: u32, mask: u64, path: &Path) -> io::Result<()> {
    let c = CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
    // SAFETY: fd is a valid fanotify descriptor borrowed for the call, c is a
    // NUL-terminated string that outlives the call, AT_FDCWD is a valid dirfd.
    let r = unsafe { libc::fanotify_mark(fd.as_raw_fd(), flags, mask, libc::AT_FDCWD, c.as_ptr()) };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn take_fd(raw: i32) -> Option<OwnedFd> {
    if raw >= 0 {
        // SAFETY: the kernel installed this descriptor into our table for this
        // event and hands ownership to the reader. Each event's fd is taken once.
        Some(unsafe { OwnedFd::from_raw_fd(raw) })
    } else {
        None
    }
}

/// Read and parse whatever events are queued. Blocks if the descriptor is blocking.
pub fn read_events(fd: BorrowedFd<'_>, buf: &mut [u8]) -> io::Result<Vec<Event>> {
    // SAFETY: buf is a valid, writable slice of buf.len() bytes for the whole call.
    let n = unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(parse_events(&buf[..n as usize]))
}

/// Parse a buffer of events. Takes ownership of every descriptor it finds,
/// including those in malformed tails, so nothing leaks.
pub fn parse_events(data: &[u8]) -> Vec<Event> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + METADATA_LEN <= data.len() {
        let m = &data[off..];
        let event_len = u32::from_ne_bytes([m[0], m[1], m[2], m[3]]) as usize;
        let vers = m[4];
        let metadata_len = u16::from_ne_bytes([m[6], m[7]]) as usize;
        let mask = u64::from_ne_bytes(m[8..16].try_into().unwrap_or([0; 8]));
        let fd = i32::from_ne_bytes(m[16..20].try_into().unwrap_or([0; 4]));
        let pid = i32::from_ne_bytes(m[20..24].try_into().unwrap_or([0; 4]));
        let fd = if fd == FAN_NOFD { None } else { take_fd(fd) };
        if vers != METADATA_VERSION
            || event_len < METADATA_LEN
            || metadata_len < METADATA_LEN
            || off + event_len > data.len()
        {
            break;
        }
        let mut ev = Event {
            mask,
            pid,
            fd,
            pidfd: None,
            records: Vec::new(),
        };
        let mut r = off + metadata_len;
        let end = off + event_len;
        while r + 4 <= end {
            let kind = data[r];
            let len = u16::from_ne_bytes([data[r + 2], data[r + 3]]) as usize;
            if len < 4 || r + len > end {
                break;
            }
            let rec = &data[r..r + len];
            match kind {
                INFO_PIDFD if len >= 8 => {
                    let raw = i32::from_ne_bytes([rec[4], rec[5], rec[6], rec[7]]);
                    ev.pidfd = take_fd(raw);
                }
                INFO_FID | INFO_DFID | INFO_DFID_NAME | INFO_OLD_DFID_NAME | INFO_NEW_DFID_NAME
                    if len >= 4 + 8 + 8 =>
                {
                    let fsid = [
                        i32::from_ne_bytes([rec[4], rec[5], rec[6], rec[7]]),
                        i32::from_ne_bytes([rec[8], rec[9], rec[10], rec[11]]),
                    ];
                    let hb = u32::from_ne_bytes([rec[12], rec[13], rec[14], rec[15]]) as usize;
                    let ht = i32::from_ne_bytes([rec[16], rec[17], rec[18], rec[19]]);
                    let hstart = 20;
                    if hstart + hb <= len {
                        let handle = rec[hstart..hstart + hb].to_vec();
                        let name = if matches!(
                            kind,
                            INFO_DFID_NAME | INFO_OLD_DFID_NAME | INFO_NEW_DFID_NAME
                        ) {
                            CStr::from_bytes_until_nul(&rec[hstart + hb..])
                                .ok()
                                .map(|c| c.to_string_lossy().into_owned())
                        } else {
                            None
                        };
                        ev.records.push(InfoRecord {
                            kind,
                            fid: Fid {
                                fsid,
                                handle_type: ht,
                                handle,
                            },
                            name,
                        });
                    }
                }
                _ => {}
            }
            r += len;
        }
        out.push(ev);
        off += event_len;
    }
    out
}

/// Filesystem id of the filesystem holding `path`, as fanotify reports it.
pub fn fsid_of(path: &Path) -> io::Result<[i32; 2]> {
    let c = CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
    // SAFETY: an all-zero statfs is a valid value for this plain C struct.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: c is NUL terminated and lives through the call, st is a valid out pointer.
    let r = unsafe { libc::statfs(c.as_ptr(), &mut st) };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    const _: () = assert!(std::mem::size_of::<libc::fsid_t>() == 8);
    // SAFETY: fsid_t is two c_ints with private fields; the size check above
    // guarantees the transmute to [i32; 2] reads exactly those 8 bytes.
    let v: [i32; 2] = unsafe { std::mem::transmute(st.f_fsid) };
    Ok(v)
}

/// Open the object a file handle refers to with O_PATH. Needs CAP_DAC_READ_SEARCH.
pub fn open_by_handle(mount_fd: BorrowedFd<'_>, fid: &Fid) -> io::Result<OwnedFd> {
    // struct file_handle { u32 handle_bytes; i32 handle_type; u8 f_handle[]; }
    let mut buf = Vec::with_capacity(8 + fid.handle.len());
    buf.extend_from_slice(&(fid.handle.len() as u32).to_ne_bytes());
    buf.extend_from_slice(&fid.handle_type.to_ne_bytes());
    buf.extend_from_slice(&fid.handle);
    // u32 alignment for the struct header.
    let mut aligned: Vec<u32> = vec![0; buf.len().div_ceil(4)];
    // SAFETY: aligned has at least buf.len() bytes; we copy bytes into it, no overlap.
    unsafe {
        std::ptr::copy_nonoverlapping(buf.as_ptr(), aligned.as_mut_ptr().cast::<u8>(), buf.len());
    }
    // SAFETY: mount_fd is valid for the call, aligned points to a properly laid out
    // and aligned struct file_handle that outlives the call.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_open_by_handle_at,
            mount_fd.as_raw_fd(),
            aligned.as_mut_ptr(),
            libc::O_PATH | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is a fresh descriptor the kernel just gave us.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

pub fn pidfd_open(pid: i32) -> io::Result<OwnedFd> {
    // SAFETY: pidfd_open takes a pid and flags and returns a new descriptor or -1.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is a fresh descriptor the kernel just gave us.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

/// Signal the exact process a pidfd refers to. Never hits a recycled PID.
pub fn pidfd_send_signal(pidfd: BorrowedFd<'_>, sig: i32) -> io::Result<()> {
    // SAFETY: pidfd is a valid descriptor for the call; null siginfo and zero
    // flags are the documented defaults.
    let r = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            sig,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// true while the process behind the pidfd still exists.
pub fn pidfd_alive(pidfd: BorrowedFd<'_>) -> bool {
    pidfd_send_signal(pidfd, 0).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(event_len: u32, mask: u64, fd: i32, pid: i32) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&event_len.to_ne_bytes());
        v.push(METADATA_VERSION);
        v.push(0);
        v.extend_from_slice(&(METADATA_LEN as u16).to_ne_bytes());
        v.extend_from_slice(&mask.to_ne_bytes());
        v.extend_from_slice(&fd.to_ne_bytes());
        v.extend_from_slice(&pid.to_ne_bytes());
        v
    }

    #[test]
    fn parses_dfid_name_record() {
        let handle = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let name = b"note.txt\0";
        let rec_len = 4 + 8 + 8 + handle.len() + name.len();
        let mut rec = vec![INFO_DFID_NAME, 0];
        rec.extend_from_slice(&(rec_len as u16).to_ne_bytes());
        rec.extend_from_slice(&7i32.to_ne_bytes());
        rec.extend_from_slice(&9i32.to_ne_bytes());
        rec.extend_from_slice(&(handle.len() as u32).to_ne_bytes());
        rec.extend_from_slice(&1i32.to_ne_bytes());
        rec.extend_from_slice(&handle);
        rec.extend_from_slice(name);
        let mut data = meta((METADATA_LEN + rec.len()) as u32, FAN_CREATE, FAN_NOFD, 42);
        data.extend_from_slice(&rec);
        let evs = parse_events(&data);
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].pid, 42);
        assert!(evs[0].fd.is_none());
        assert_eq!(evs[0].records.len(), 1);
        assert_eq!(evs[0].records[0].fid.fsid, [7, 9]);
        assert_eq!(evs[0].records[0].name.as_deref(), Some("note.txt"));
    }

    #[test]
    fn truncated_buffer_is_ignored() {
        let mut data = meta(100, FAN_CREATE, FAN_NOFD, 1);
        data.truncate(30);
        assert!(parse_events(&data).is_empty());
    }

    #[test]
    fn fsid_of_root_works() {
        assert!(fsid_of(Path::new("/")).is_ok());
    }

    #[test]
    fn pidfd_on_self() {
        let fd = pidfd_open(std::process::id() as i32).unwrap();
        assert!(pidfd_alive(std::os::fd::AsFd::as_fd(&fd)));
    }
}
