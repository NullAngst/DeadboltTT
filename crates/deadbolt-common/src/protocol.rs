//! Daemon to worker protocol: one JSON object per line over
//! `/run/deadbolt-worker/worker.sock`. The worker only accepts peers with uid 0.

use crate::types::{QuarantineItem, ScanProgress, Source};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, Write};

/// Longest line either side accepts. Anything longer is a protocol error.
pub const MAX_LINE: usize = 1 << 20;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanOptions {
    pub job: String,
    pub paths: Vec<String>,
    pub exclusions: Vec<String>,
    pub one_filesystem: bool,
    pub skip: Vec<String>,
    pub sessions: u32,
    /// uid the scan runs on behalf of. None means system scan (polkit scan-system passed).
    pub as_uid: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case")]
pub enum Request {
    Ping,
    /// Walk and scan. Replies with a stream of Progress/Found lines, then Done.
    Scan(ScanOptions),
    Control {
        job: String,
        /// pause, resume, cancel
        command: String,
    },
    /// Rescan one file. Replies Verdict.
    ScanFile {
        path: String,
    },
    Quarantine {
        path: String,
        signature: String,
        source: Source,
        /// Device and inode seen when the file was flagged. The move refuses if they changed.
        dev: Option<u64>,
        ino: Option<u64>,
    },
    Delete {
        path: String,
        dev: Option<u64>,
        ino: Option<u64>,
    },
    QuarantineList,
    Restore {
        id: String,
        to: Option<String>,
        restore_exec: bool,
    },
    QuarantineDelete {
        id: String,
    },
    Purge {
        older_than_days: u32,
    },
    PlantCanaries {
        homes: Vec<(u32, String)>,
    },
    RemoveCanaries,
    StartupItems,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Reply {
    Ok,
    Error {
        message: String,
    },
    Progress(ScanProgress),
    Found {
        job: String,
        path: String,
        signature: String,
        dev: u64,
        ino: u64,
    },
    Done {
        job: String,
        files: u64,
        errors: u64,
        cancelled: bool,
    },
    Verdict {
        path: String,
        /// None means clean.
        signature: Option<String>,
        dev: u64,
        ino: u64,
    },
    Quarantined {
        item: QuarantineItem,
    },
    Items {
        items: Vec<QuarantineItem>,
    },
    Restored {
        path: String,
    },
    Purged {
        removed: u64,
    },
    Canaries {
        paths: Vec<String>,
    },
    Startup {
        items: Vec<StartupItem>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StartupItem {
    /// autostart, xdg-autostart, systemd-user, cron
    pub kind: String,
    pub name: String,
    pub file: String,
    /// The program it launches, if one could be found.
    pub target: String,
    pub owner: String,
}

pub fn write_line<W: Write, T: Serialize>(w: &mut W, value: &T) -> std::io::Result<()> {
    let mut s = serde_json::to_string(value).map_err(std::io::Error::other)?;
    s.push('\n');
    w.write_all(s.as_bytes())?;
    w.flush()
}

/// Read one line, capped at MAX_LINE. Ok(None) on clean EOF.
pub fn read_line<R: BufRead, T: for<'de> Deserialize<'de>>(
    r: &mut R,
) -> std::io::Result<Option<T>> {
    let mut buf = Vec::new();
    let n = std::io::Read::take(&mut *r, MAX_LINE as u64 + 1).read_until(b'\n', &mut buf)?;
    if n == 0 {
        return Ok(None);
    }
    if buf.len() > MAX_LINE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "protocol line too long",
        ));
    }
    serde_json::from_slice(&buf)
        .map(Some)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn round_trip() {
        let mut out = Vec::new();
        write_line(&mut out, &Request::ScanFile { path: "/x".into() }).unwrap();
        let mut r = Cursor::new(out);
        let back: Request = read_line(&mut r).unwrap().unwrap();
        assert!(matches!(back, Request::ScanFile { path } if path == "/x"));
        let eof: Option<Request> = read_line(&mut r).unwrap();
        assert!(eof.is_none());
    }

    #[test]
    fn oversized_line_rejected() {
        let big = vec![b'a'; MAX_LINE + 10];
        let mut r = Cursor::new(big);
        let res: std::io::Result<Option<Request>> = read_line(&mut r);
        assert!(res.is_err());
    }
}
