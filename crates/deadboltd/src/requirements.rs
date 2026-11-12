//! System requirements check: every backend tool, its version, its service,
//! plus kernel features. Deadbolt shows the install command; it never runs it.

use deadbolt_common::paths;
use deadbolt_common::types::{KernelCheck, Requirement, RequirementsReport};
use deadbolt_shield::sys;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;
use tokio::process::Command;

pub const BUILTIN: &str = include_str!("../../../data/packages.toml");

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tool {
    pub name: String,
    pub binary: String,
    #[serde(default)]
    pub version: Vec<String>,
    pub required: bool,
    pub feature: String,
    #[serde(default)]
    pub service: String,
    #[serde(default)]
    pub packages: HashMap<String, String>,
    #[serde(default)]
    pub hint: String,
    #[serde(default)]
    pub only: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Packages {
    pub tool: Vec<Tool>,
}

pub fn load() -> Packages {
    let text =
        std::fs::read_to_string(paths::PACKAGES_TOML).unwrap_or_else(|_| BUILTIN.to_string());
    toml::from_str(&text)
        .unwrap_or_else(|_| toml::from_str(BUILTIN).unwrap_or(Packages { tool: Vec::new() }))
}

pub fn which(bin: &str) -> Option<String> {
    let path = std::env::var_os("PATH")
        .unwrap_or_else(|| "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into());
    std::env::split_paths(&path)
        .chain(["/usr/sbin", "/sbin"].map(Into::into))
        .map(|d| d.join(bin))
        .find(|p| p.is_file())
        .map(|p| p.to_string_lossy().into_owned())
}

/// apt, dnf, zypper or pacman, from /etc/os-release and what is installed.
pub fn package_manager(os_release: &str) -> String {
    let field = |k: &str| {
        os_release
            .lines()
            .find_map(|l| l.strip_prefix(k))
            .map(|v| v.trim_matches('"').to_ascii_lowercase())
            .unwrap_or_default()
    };
    let ids = format!("{} {}", field("ID="), field("ID_LIKE="));
    let by_id = [
        ("debian", "apt"),
        ("ubuntu", "apt"),
        ("fedora", "dnf"),
        ("rhel", "dnf"),
        ("centos", "dnf"),
        ("suse", "zypper"),
        ("opensuse", "zypper"),
        ("arch", "pacman"),
    ];
    for (id, pm) in by_id {
        if ids
            .split_whitespace()
            .any(|w| w == id || w.starts_with(&format!("{id}-")))
            && which(pm).is_some()
        {
            return pm.into();
        }
    }
    for pm in ["apt", "dnf", "zypper", "pacman"] {
        if which(pm).is_some() {
            return pm.into();
        }
    }
    String::new()
}

pub fn install_command(pm: &str, pkgs: &[String]) -> String {
    if pkgs.is_empty() {
        return String::new();
    }
    let verb = match pm {
        "apt" => "sudo apt install",
        "dnf" => "sudo dnf install",
        "zypper" => "sudo zypper install",
        "pacman" => "sudo pacman -S",
        _ => return format!("install: {}", pkgs.join(" ")),
    };
    format!("{verb} {}", pkgs.join(" "))
}

async fn version_of(bin: &str, args: &[String]) -> String {
    if args.is_empty() {
        return String::new();
    }
    let run = Command::new(bin)
        .args(args)
        .stdin(std::process::Stdio::null())
        .env("LC_ALL", "C")
        .output();
    match tokio::time::timeout(Duration::from_secs(5), run).await {
        Ok(Ok(o)) => {
            let text = if o.stdout.is_empty() {
                o.stderr
            } else {
                o.stdout
            };
            String::from_utf8_lossy(&text)
                .lines()
                .find(|l| !l.trim().is_empty())
                .unwrap_or("")
                .trim()
                .chars()
                .take(80)
                .collect()
        }
        _ => String::new(),
    }
}

pub fn kernel_release() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .unwrap_or_default()
        .trim()
        .to_string()
}

pub fn kernel_at_least(release: &str, major: u32, minor: u32) -> bool {
    let mut it = release
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty());
    let ma: u32 = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let mi: u32 = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    (ma, mi) >= (major, minor)
}

/// Kernel probes. These need root, which the daemon has.
pub fn kernel_checks() -> Vec<KernelCheck> {
    let rel = kernel_release();
    let mut v = Vec::new();
    let probe = |flags: u32| sys::fanotify_init(sys::FAN_CLOEXEC | flags, libc::O_RDONLY as u32);
    let notif = probe(sys::FAN_CLASS_NOTIF);
    v.push(KernelCheck {
        name: "fanotify".into(),
        ok: notif.is_ok(),
        detail: match &notif {
            Ok(_) => "CONFIG_FANOTIFY available".into(),
            Err(e) => format!("fanotify unavailable: {e}"),
        },
        required: true,
    });
    let perm = probe(sys::FAN_CLASS_CONTENT);
    v.push(KernelCheck {
        name: "fanotify access permissions".into(),
        ok: perm.is_ok(),
        detail: if perm.is_ok() {
            "CONFIG_FANOTIFY_ACCESS_PERMISSIONS available, real-time can block".into()
        } else {
            "missing: real-time protection is notify-only".into()
        },
        required: false,
    });
    let fid =
        probe(sys::FAN_CLASS_NOTIF | sys::FAN_REPORT_DFID_NAME_TARGET | sys::FAN_REPORT_PIDFD);
    v.push(KernelCheck {
        name: "fanotify rename events".into(),
        ok: fid.is_ok() && kernel_at_least(&rel, 5, 17),
        detail: format!("kernel {rel}, needs 5.17 or newer for the ransomware shield"),
        required: true,
    });
    let cg2 = Path::new("/sys/fs/cgroup/cgroup.controllers").exists();
    v.push(KernelCheck {
        name: "cgroup v2".into(),
        ok: cg2,
        detail: if cg2 {
            "mounted at /sys/fs/cgroup".into()
        } else {
            "not mounted, freezing falls back to SIGSTOP".into()
        },
        required: false,
    });
    let userns = std::fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone")
        .map(|s| s.trim() == "1")
        .ok();
    if let Some(on) = userns {
        v.push(KernelCheck {
            name: "unprivileged user namespaces".into(),
            ok: !on,
            detail: if on {
                "enabled: a process in a user namespace can dodge OpenSnitch path matching".into()
            } else {
                "disabled".into()
            },
            required: false,
        });
    }
    if let Ok(list) = std::fs::read_to_string("/sys/kernel/security/apparmor/profiles") {
        v.push(apparmor_check(&list));
    }
    v
}

/// Debian, Ubuntu and openSUSE confine /usr/sbin/clamd to the distro's own
/// config and socket paths, so Deadbolt's clamd runs under its own profile
/// (AppArmorProfile= in deadbolt-clamd.service). If that profile is not
/// loaded, the unit falls back to the distro profile and clamd exits.
/// `list` is /sys/kernel/security/apparmor/profiles, one "name (mode)" per line.
pub fn apparmor_check(list: &str) -> KernelCheck {
    let name_of = |l: &str| l.rsplit_once(" (").map_or(l, |(n, _)| n).trim().to_string();
    let names: Vec<String> = list.lines().map(name_of).collect();
    let loaded = names.iter().any(|n| n == "deadbolt-clamd");
    let distro = names
        .iter()
        .any(|n| n != "deadbolt-clamd" && (n == "clamd" || n.ends_with("/clamd")));
    KernelCheck {
        name: "AppArmor profile deadbolt-clamd".into(),
        ok: loaded,
        detail: if loaded {
            "loaded".into()
        } else {
            "not loaded, clamd cannot start: sudo apparmor_parser -r /etc/apparmor.d/deadbolt-clamd"
                .into()
        },
        required: distro,
    }
}

pub fn blocking_supported(checks: &[KernelCheck]) -> bool {
    checks
        .iter()
        .any(|c| c.name == "fanotify access permissions" && c.ok)
}

pub async fn check() -> RequirementsReport {
    let os = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    let pm = package_manager(&os);
    let pkgs = load();
    let mut rows = Vec::new();
    let mut missing = Vec::new();
    for t in pkgs.tool {
        if !t.only.is_empty() && !t.only.contains(&pm) {
            continue;
        }
        let found = which(&t.binary);
        let version = match &found {
            Some(b) => version_of(b, &t.version).await,
            None => String::new(),
        };
        let running = if t.service.is_empty() {
            None
        } else {
            Some(crate::units::is_active(&t.service).await)
        };
        let package = t.packages.get(&pm).cloned().unwrap_or_default();
        if found.is_none() && !package.is_empty() && !missing.contains(&package) {
            missing.push(package.clone());
        }
        let install_hint = if found.is_some() {
            String::new()
        } else if !t.hint.is_empty() {
            t.hint.clone()
        } else {
            install_command(&pm, std::slice::from_ref(&package))
        };
        rows.push(Requirement {
            tool: t.name,
            required: t.required,
            installed: found.is_some(),
            version,
            feature: t.feature,
            package,
            install_hint,
            running,
        });
    }
    let missing_required = rows
        .iter()
        .any(|r| r.required && (!r.installed || r.running == Some(false)));
    RequirementsReport {
        install_command: install_command(&pm, &missing),
        package_manager: pm,
        rows,
        kernel: kernel_checks(),
        missing_required,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_parses() {
        let p: Packages = toml::from_str(BUILTIN).unwrap();
        assert!(p.tool.iter().any(|t| t.name == "clamd" && t.required));
        assert!(p.tool.iter().any(|t| t.name == "lynis" && !t.required));
        for t in &p.tool {
            assert!(!t.packages.is_empty(), "{} has no packages", t.name);
        }
    }

    #[test]
    fn install_cmd() {
        let c = install_command("apt", &["clamav-daemon".into(), "lynis".into()]);
        assert_eq!(c, "sudo apt install clamav-daemon lynis");
        assert_eq!(install_command("apt", &[]), "");
        assert_eq!(install_command("pacman", &["x".into()]), "sudo pacman -S x");
    }

    #[test]
    fn kernel_versions() {
        assert!(kernel_at_least("6.18.44-fc-v233", 5, 17));
        assert!(kernel_at_least("5.17.0", 5, 17));
        assert!(!kernel_at_least("5.15.0-91-generic", 5, 17));
    }

    #[test]
    fn apparmor_profiles() {
        let c = apparmor_check("/usr/sbin/clamd (enforce)\ndeadbolt-clamd (enforce)\n");
        assert!(c.ok && c.required);
        let c = apparmor_check("/usr/sbin/clamd (enforce)\n/usr/bin/freshclam (enforce)\n");
        assert!(!c.ok && c.required);
        let c = apparmor_check("clamd (complain)\n");
        assert!(!c.ok && c.required);
        let c = apparmor_check("firefox (unconfined)\n");
        assert!(!c.ok && !c.required);
    }
}
