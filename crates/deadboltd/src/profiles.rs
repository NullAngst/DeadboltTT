//! Scan presets and signature status.

use deadbolt_common::paths;
use deadbolt_common::settings::Settings;
use std::path::Path;

fn browser_extension_dirs(home: &str) -> Vec<String> {
    let mut out = Vec::new();
    let globs: [(&str, &str); 6] = [
        (".mozilla/firefox", "extensions"),
        (
            ".var/app/org.mozilla.firefox/.mozilla/firefox",
            "extensions",
        ),
        (".config/google-chrome", "Extensions"),
        (".config/chromium", "Extensions"),
        (".config/BraveSoftware/Brave-Browser", "Extensions"),
        (".config/vivaldi", "Extensions"),
    ];
    for (base, leaf) in globs {
        let b = Path::new(home).join(base);
        let Ok(rd) = std::fs::read_dir(&b) else {
            continue;
        };
        for e in rd.filter_map(|e| e.ok()) {
            let p = e.path().join(leaf);
            if p.is_dir() {
                out.push(p.to_string_lossy().into_owned());
            }
        }
    }
    out
}

pub fn quick(homes: &[String]) -> Vec<String> {
    let mut v: Vec<String> = vec!["/tmp".into(), "/var/tmp".into()];
    for h in homes {
        for sub in [
            "Downloads",
            "Desktop",
            ".local/bin",
            ".config/autostart",
            ".config/systemd/user",
        ] {
            v.push(format!("{h}/{sub}"));
        }
        v.extend(browser_extension_dirs(h));
    }
    v.retain(|p| Path::new(p).exists());
    v
}

pub struct Preset {
    pub paths: Vec<String>,
    pub skip: Vec<String>,
    /// true when every target belongs to the caller (no scan-system needed).
    pub system: bool,
}

/// Resolve a preset. `home` is the caller's home for a user scan; `None`
/// means a system scan covering every home.
pub fn resolve(profile: &str, s: &Settings, home: Option<&str>) -> Option<Preset> {
    let homes: Vec<String> = match home {
        Some(h) => vec![h.to_string()],
        None => {
            let mut h: Vec<String> = deadbolt_common::perm::login_homes()
                .into_iter()
                .map(|(_, h)| h)
                .collect();
            if Path::new("/root").is_dir() {
                h.push("/root".into());
            }
            h
        }
    };
    let skip: Vec<String> = paths::FULL_SCAN_SKIP
        .iter()
        .map(|s| s.to_string())
        .collect();
    Some(match profile {
        "quick" => Preset {
            paths: quick(&homes),
            skip,
            system: home.is_none(),
        },
        "home" => Preset {
            paths: if home.is_some() {
                homes
            } else {
                vec!["/home".into(), "/root".into()]
            },
            skip,
            system: home.is_none(),
        },
        "full" => Preset {
            paths: vec!["/".into()],
            skip,
            system: true,
        },
        "custom" => Preset {
            paths: s.scan.custom_paths.clone(),
            skip,
            system: true,
        },
        _ => return None,
    })
}

/// Newest signature database file in /var/lib/clamav, as unix time.
pub fn signature_time(dir: &Path) -> Option<i64> {
    use std::os::unix::fs::MetadataExt;
    std::fs::read_dir(dir)
        .ok()?
        .filter_map(|e| e.ok())
        .filter(|e| {
            let n = e.file_name();
            let n = n.to_string_lossy();
            n.ends_with(".cvd") || n.ends_with(".cld") || n.ends_with(".cud")
        })
        .filter_map(|e| e.metadata().ok().map(|m| m.mtime()))
        .max()
}

/// Is a newer clamav package waiting? apt and dnf only; others report false.
pub async fn engine_outdated(pm: &str) -> bool {
    match pm {
        "apt" => {
            let out = tokio::process::Command::new("apt-cache")
                .args(["policy", "clamav-daemon"])
                .env("LC_ALL", "C")
                .output()
                .await;
            let Ok(o) = out else { return false };
            let text = String::from_utf8_lossy(&o.stdout);
            let get = |k: &str| {
                text.lines()
                    .find_map(|l| l.trim().strip_prefix(k))
                    .map(|s| s.trim().to_string())
            };
            match (get("Installed:"), get("Candidate:")) {
                (Some(i), Some(c)) => i != "(none)" && c != "(none)" && i != c,
                _ => false,
            }
        }
        "dnf" => tokio::process::Command::new("dnf")
            .args(["-q", "check-update", "clamd"])
            .output()
            .await
            .is_ok_and(|o| o.status.code() == Some(100)),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets() {
        let s = Settings::default();
        assert!(resolve("full", &s, None).unwrap().system);
        assert_eq!(resolve("full", &s, None).unwrap().paths, vec!["/"]);
        let full = resolve("full", &s, None).unwrap();
        assert!(full.skip.contains(&"/proc".to_string()));
        assert!(full.skip.contains(&paths::QUARANTINE_DIR.to_string()));
        assert!(!resolve("home", &s, Some("/home/z")).unwrap().system);
        assert!(resolve("bogus", &s, None).is_none());
    }
}
