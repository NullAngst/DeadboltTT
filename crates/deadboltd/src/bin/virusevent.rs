//! VirusEvent hook. clamd runs this as the clamav user on every detection,
//! with the path and signature in CLAM_VIRUSEVENT_FILENAME and
//! CLAM_VIRUSEVENT_VIRUSNAME. It forwards them to the daemon and exits. The
//! daemon rescans the file itself before acting on it.
#![forbid(unsafe_code)]

use std::io::Write;
use std::os::unix::net::UnixStream;
use std::time::Duration;

fn main() {
    let path = std::env::var("CLAM_VIRUSEVENT_FILENAME").unwrap_or_default();
    let sig = std::env::var("CLAM_VIRUSEVENT_VIRUSNAME").unwrap_or_default();
    if path.is_empty() || sig.is_empty() || path.len() > 4000 || sig.len() > 256 {
        return;
    }
    if path.contains(['\t', '\n']) || sig.contains(['\t', '\n']) {
        return;
    }
    let Ok(mut s) = UnixStream::connect(deadbolt_common::paths::EVENTS_SOCK) else {
        return;
    };
    let _ = s.set_write_timeout(Some(Duration::from_secs(2)));
    let _ = s.write_all(format!("{path}\t{sig}\n").as_bytes());
}
