//! Minimal clamd client over its local socket, using clamd's own protocol:
//! `zPING`, `zVERSION`, `zRELOAD`, and `zIDSESSION` + `zFILDES` with the
//! descriptor passed by SCM_RIGHTS, so clamd never needs read access to the file.

use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};
use std::io::{IoSlice, Read, Write};
use std::os::fd::{AsRawFd, BorrowedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

const MAX_REPLY: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Clean,
    Found(String),
    Error(String),
}

#[derive(Debug, thiserror::Error)]
pub enum ClamdError {
    #[error("cannot reach clamd: {0}")]
    Io(#[from] std::io::Error),
    #[error("cannot pass descriptor to clamd: {0}")]
    Send(#[from] nix::Error),
    #[error("clamd sent a malformed reply: {0}")]
    Protocol(String),
}

fn connect(sock: &Path, timeout: Duration) -> Result<UnixStream, ClamdError> {
    let s = UnixStream::connect(sock)?;
    s.set_read_timeout(Some(timeout))?;
    s.set_write_timeout(Some(Duration::from_secs(10)))?;
    Ok(s)
}

/// Read until NUL. Replies to z-commands are NUL terminated.
fn read_reply(s: &mut UnixStream) -> Result<String, ClamdError> {
    let mut out = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = s.read(&mut byte)?;
        if n == 0 {
            break;
        }
        if byte[0] == 0 {
            break;
        }
        out.push(byte[0]);
        if out.len() > MAX_REPLY {
            return Err(ClamdError::Protocol("reply too long".into()));
        }
    }
    String::from_utf8(out).map_err(|_| ClamdError::Protocol("reply is not UTF-8".into()))
}

fn simple(sock: &Path, cmd: &str) -> Result<String, ClamdError> {
    let mut s = connect(sock, Duration::from_secs(30))?;
    s.write_all(format!("z{cmd}\0").as_bytes())?;
    read_reply(&mut s)
}

pub fn ping(sock: &Path) -> bool {
    matches!(simple(sock, "PING"), Ok(r) if r == "PONG")
}

/// "ClamAV 1.4.6/27450/Tue Nov  3 08:23:01 2026"
pub fn version(sock: &Path) -> Result<String, ClamdError> {
    simple(sock, "VERSION")
}

pub fn reload(sock: &Path) -> Result<String, ClamdError> {
    simple(sock, "RELOAD")
}

/// Parse one scan reply line, with or without the "N: " session prefix.
pub fn parse_verdict(line: &str) -> Verdict {
    let line = line.trim_end();
    let body = match line.split_once(": ") {
        Some((pfx, rest)) if pfx.chars().all(|c| c.is_ascii_digit()) => rest,
        _ => line,
    };
    // body: "fd[10]: OK" | "fd[10]: Sig.Name FOUND" | "fd[10]: reason ERROR"
    let detail = match body.split_once(": ") {
        Some((_, d)) => d,
        None => body,
    };
    if detail == "OK" {
        Verdict::Clean
    } else if let Some(sig) = detail.strip_suffix(" FOUND") {
        Verdict::Found(sig.trim().to_string())
    } else if let Some(err) = detail.strip_suffix(" ERROR") {
        Verdict::Error(err.trim().to_string())
    } else {
        Verdict::Error(format!("unexpected reply: {detail}"))
    }
}

/// One IDSESSION. Scan files one descriptor at a time, in order.
pub struct Session {
    stream: UnixStream,
}

impl Session {
    pub fn open(sock: &Path) -> Result<Session, ClamdError> {
        // A single file can take a while (large archives).
        let mut stream = connect(sock, Duration::from_secs(600))?;
        stream.write_all(b"zIDSESSION\0")?;
        Ok(Session { stream })
    }

    pub fn scan_fd(&mut self, fd: BorrowedFd<'_>) -> Result<Verdict, ClamdError> {
        // clamd wants the command first, then the descriptor riding on a
        // single dummy byte, the same way clamdscan sends it.
        self.stream.write_all(b"zFILDES\0")?;
        let dummy = [0u8; 1];
        let iov = [IoSlice::new(&dummy)];
        let fds = [fd.as_raw_fd()];
        let cmsg = [ControlMessage::ScmRights(&fds)];
        sendmsg::<()>(
            self.stream.as_raw_fd(),
            &iov,
            &cmsg,
            MsgFlags::empty(),
            None,
        )?;
        let reply = read_reply(&mut self.stream)?;
        if reply.is_empty() {
            return Err(ClamdError::Protocol("clamd closed the session".into()));
        }
        Ok(parse_verdict(&reply))
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.stream.write_all(b"zEND\0");
    }
}

/// Engine version and signature date out of a VERSION reply.
pub fn split_version(reply: &str) -> (String, Option<String>) {
    let mut parts = reply.trim().splitn(3, '/');
    let engine = parts
        .next()
        .unwrap_or("")
        .trim_start_matches("ClamAV ")
        .to_string();
    let _db = parts.next();
    let date = parts.next().map(|s| s.to_string());
    (engine, date)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdicts() {
        assert_eq!(parse_verdict("1: fd[10]: OK"), Verdict::Clean);
        assert_eq!(
            parse_verdict("2: fd[11]: Win.Test.EICAR_HDB-1 FOUND"),
            Verdict::Found("Win.Test.EICAR_HDB-1".into())
        );
        assert_eq!(
            parse_verdict("fd[11]: Can't open file ERROR"),
            Verdict::Error("Can't open file".into())
        );
        assert!(matches!(parse_verdict("garbage"), Verdict::Error(_)));
    }

    #[test]
    fn version_split() {
        let (e, d) = split_version("ClamAV 1.4.6/27450/Tue Nov  3 08:23:01 2026");
        assert_eq!(e, "1.4.6");
        assert_eq!(d.as_deref(), Some("Tue Nov  3 08:23:01 2026"));
    }
}
