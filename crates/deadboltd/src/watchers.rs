//! Background loops: real-time hits, package changes, signature changes,
//! USB drives, retention.

use crate::app::{IFACE_STATUS, Shared};
use crate::units;
use deadbolt_common::paths;
use deadbolt_common::settings::UsbMode;
use deadbolt_common::types::Source;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncSeekExt, BufReader};
use tokio::net::UnixListener;

/// One line from the VirusEvent hook: "<path>\t<signature>\n", length-capped.
pub fn parse_event(line: &str) -> Option<(String, String)> {
    if line.len() > 4096 {
        return None;
    }
    let (p, s) = line.trim_end_matches('\n').split_once('\t')?;
    if !p.starts_with('/')
        || p.contains('\0')
        || s.is_empty()
        || s.len() > 256
        || s.contains(['\t', '\n'])
    {
        return None;
    }
    Some((p.to_string(), s.to_string()))
}

/// The VirusEvent hook socket. Only the clamav user is accepted.
pub async fn events_socket(app: Shared) {
    let _ = std::fs::remove_file(paths::EVENTS_SOCK);
    let listener = match UnixListener::bind(paths::EVENTS_SOCK) {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("cannot bind {}: {e}", paths::EVENTS_SOCK);
            return;
        }
    };
    // Anyone may connect; peer credentials decide. clamav only.
    let _ = std::fs::set_permissions(
        paths::EVENTS_SOCK,
        std::os::unix::fs::PermissionsExt::from_mode(0o666),
    );
    let clamav = deadbolt_common::perm::uid_of(paths::CLAMAV_USER);
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let ok = stream
            .peer_cred()
            .ok()
            .is_some_and(|c| Some(c.uid()) == clamav);
        if !ok {
            tracing::warn!("rejected a virus-event connection from a non-clamav peer");
            continue;
        }
        let app = app.clone();
        tokio::spawn(async move {
            let mut buf = Vec::new();
            let mut s = stream.take(4097);
            if s.read_to_end(&mut buf).await.is_err() {
                return;
            }
            if let Some((p, sig)) = parse_event(&String::from_utf8_lossy(&buf)) {
                app.realtime_hit(p, sig).await;
            }
        });
    }
}

/// clamonacc --log lines: "<path>: <Signature> FOUND".
pub fn parse_onaccess(line: &str) -> Option<(String, String)> {
    let body = line.trim_end().strip_suffix(" FOUND")?;
    let (p, s) = body.rsplit_once(": ")?;
    let p = p.trim();
    // clamonacc prefixes some lines with a timestamp and " -> ".
    let p = p.rsplit_once(" -> ").map(|(_, x)| x).unwrap_or(p);
    if !p.starts_with('/') {
        return None;
    }
    Some((p.to_string(), s.trim().to_string()))
}

/// Tail clamonacc's log. With --fdpass, clamd only sees a descriptor, so the
/// log is where the real path shows up.
pub async fn tail_onaccess(app: Shared) {
    let mut pos: u64 = std::fs::metadata(paths::ONACCESS_LOG)
        .map(|m| m.len())
        .unwrap_or(0);
    let mut ino: u64 = std::fs::metadata(paths::ONACCESS_LOG)
        .map(|m| m.ino())
        .unwrap_or(0);
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let Ok(meta) = std::fs::metadata(paths::ONACCESS_LOG) else {
            continue;
        };
        if meta.ino() != ino || meta.len() < pos {
            ino = meta.ino();
            pos = 0;
        }
        if meta.len() == pos {
            continue;
        }
        let Ok(mut f) = tokio::fs::File::open(paths::ONACCESS_LOG).await else {
            continue;
        };
        if f.seek(std::io::SeekFrom::Start(pos)).await.is_err() {
            continue;
        }
        let mut r = BufReader::new(f.take(4 << 20));
        let mut line = String::new();
        while let Ok(n) = r.read_line(&mut line).await {
            if n == 0 {
                break;
            }
            pos += n as u64;
            if let Some((p, s)) = parse_onaccess(&line) {
                app.realtime_hit(p, s).await;
            }
            line.clear();
        }
    }
}

fn pkg_db_stamp() -> i64 {
    [
        "/var/lib/dpkg/status",
        "/var/lib/rpm/rpmdb.sqlite",
        "/var/lib/rpm/Packages",
        "/usr/lib/sysimage/rpm/rpmdb.sqlite",
    ]
    .iter()
    .filter_map(|p| std::fs::metadata(p).ok())
    .map(|m| m.mtime())
    .max()
    .unwrap_or(0)
}

/// After every dpkg or rpm transaction: re-check requirements, re-hash the
/// allowlist, and re-mask distro clamd units an upgrade brought back.
pub async fn package_watch(app: Shared) {
    let mut last = pkg_db_stamp();
    loop {
        tokio::time::sleep(Duration::from_secs(10)).await;
        let now = pkg_db_stamp();
        if now == last {
            continue;
        }
        // Let the transaction finish.
        tokio::time::sleep(Duration::from_secs(5)).await;
        last = pkg_db_stamp();
        app.refresh_requirements().await;
        let removed = app.allow.rehash_after_package_change();
        if !removed.is_empty() {
            app.history.log(
                "shield",
                "Allowlist entries removed after a package change",
                &removed.join(", "),
            );
        }
        let _ = app.allow.save(Path::new(paths::ALLOWLIST_FILE));
        let setup = app.persist.lock().map(|p| p.setup_done).unwrap_or(false);
        if setup && units::distro_units_back().await {
            app.history.log(
                "protection",
                "A package upgrade re-enabled the distro ClamAV units, masking them again",
                "",
            );
            app.emit(IFACE_STATUS, "ProtectionChanged", &serde_json::json!({"note": "Distro ClamAV units were re-enabled by an upgrade. Deadbolt masked them again."})).await;
            units::take_over_clamd().await;
        }
        app.refresh_signatures().await;
        app.status_changed().await;
    }
}

/// When freshclam updates the database, tell clamd to reload right away.
pub async fn signature_watch(app: Shared) {
    let dir = Path::new("/var/lib/clamav");
    let mut last = crate::profiles::signature_time(dir);
    let mut ticks = 0u32;
    loop {
        tokio::time::sleep(Duration::from_secs(30)).await;
        ticks += 1;
        let now = crate::profiles::signature_time(dir);
        if now != last {
            last = now;
            let _ = deadbolt_common::clamd::reload(Path::new(paths::CLAMD_SOCK));
            app.history.log("update", "Signatures updated", "");
            app.refresh_signatures().await;
            app.status_changed().await;
        } else if ticks.is_multiple_of(120) {
            // Hourly: age moves even when nothing changes.
            app.refresh_signatures().await;
            app.status_changed().await;
        }
    }
}

/// Daily: roll up old history.
pub async fn retention(app: Shared) {
    loop {
        let days = app.settings().history.retention_days;
        let n = app.history.retain(days);
        if n > 0 {
            tracing::info!("rolled up {n} history rows older than {days} days");
        }
        tokio::time::sleep(Duration::from_secs(86_400)).await;
    }
}

#[zbus::proxy(
    interface = "org.freedesktop.UDisks2.Block",
    default_service = "org.freedesktop.UDisks2"
)]
trait Block {
    #[zbus(property)]
    fn drive(&self) -> zbus::Result<zbus::OwnedObjectPath>;
}

#[zbus::proxy(
    interface = "org.freedesktop.UDisks2.Drive",
    default_service = "org.freedesktop.UDisks2"
)]
trait Drive {
    #[zbus(property)]
    fn removable(&self) -> zbus::Result<bool>;
    #[zbus(property)]
    fn connection_bus(&self) -> zbus::Result<String>;
}

#[zbus::proxy(
    interface = "org.freedesktop.UDisks2.Filesystem",
    default_service = "org.freedesktop.UDisks2"
)]
trait Filesystem {
    #[zbus(property)]
    fn mount_points(&self) -> zbus::Result<Vec<Vec<u8>>>;
}

async fn removable(conn: &zbus::Connection, obj: &str) -> bool {
    let Ok(b) = BlockProxy::builder(conn)
        .path(obj.to_string())
        .build()
        .await
    else {
        return false;
    };
    let Ok(drive) = b.drive().await else {
        return false;
    };
    if drive.as_str() == "/" {
        return false;
    }
    let Ok(d) = DriveProxy::builder(conn).path(drive).build().await else {
        return false;
    };
    d.removable().await.unwrap_or(false) || d.connection_bus().await.is_ok_and(|b| b == "usb")
}

/// Offer a scan when a removable drive mounts, through udisks2 signals.
pub async fn usb_watch(app: Shared) {
    use futures_util::StreamExt;
    let Ok(conn) = zbus::Connection::system().await else {
        return;
    };
    let rule = zbus::MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .sender("org.freedesktop.UDisks2")
        .interface("org.freedesktop.DBus.Properties")
        .member("PropertiesChanged")
        .arg(0, "org.freedesktop.UDisks2.Filesystem")
        .build();
    let Ok(rule) = rule else { return };
    let Ok(mut stream) = zbus::MessageStream::for_match_rule(rule, &conn, None).await else {
        return;
    };
    let mut seen: Vec<String> = Vec::new();
    while let Some(Ok(msg)) = stream.next().await {
        let Some(obj) = msg.header().path().map(|p| p.to_string()) else {
            continue;
        };
        let Ok(fs) = FilesystemProxy::builder(&conn)
            .path(obj.clone())
            .build()
            .await
        else {
            continue;
        };
        let mps: Vec<String> = fs
            .mount_points()
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|b| {
                String::from_utf8_lossy(&b)
                    .trim_end_matches('\0')
                    .to_string()
            })
            .collect();
        let Some(mp) = mps.first().cloned() else {
            seen.retain(|o| *o != obj);
            continue;
        };
        if seen.contains(&obj) || !removable(&conn, &obj).await {
            continue;
        }
        seen.push(obj);
        match app.settings().usb.autoscan {
            UsbMode::Never => {}
            UsbMode::Ask => {
                app.emit(
                    IFACE_STATUS,
                    "UsbMounted",
                    &serde_json::json!({"mount": mp}),
                )
                .await;
            }
            UsbMode::Always => {
                let skip = paths::FULL_SCAN_SKIP
                    .iter()
                    .map(|s| s.to_string())
                    .collect();
                let _ = app
                    .start_scan(0, vec![mp.clone()], skip, "usb", Source::Scheduled, None)
                    .await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_lines() {
        assert_eq!(
            parse_event("/home/u/x.exe\tWin.Test\n"),
            Some(("/home/u/x.exe".into(), "Win.Test".into()))
        );
        assert_eq!(parse_event("fd[10]\tWin.Test\n"), None);
        assert_eq!(parse_event("/x\t\n"), None);
        assert_eq!(parse_event(&format!("/x\t{}\n", "a".repeat(300))), None);
    }

    #[test]
    fn onaccess_lines() {
        assert_eq!(
            parse_onaccess("/home/u/Downloads/eicar.com: Win.Test.EICAR_HDB-1 FOUND\n"),
            Some((
                "/home/u/Downloads/eicar.com".into(),
                "Win.Test.EICAR_HDB-1".into()
            ))
        );
        assert_eq!(parse_onaccess("ClamInotif: watching '/home'"), None);
    }
}
