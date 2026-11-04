//! `/etc/deadbolt/deadbolt.toml`, parsed into typed structs.
//! Unknown keys are rejected so a typo never silently does nothing.

use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ThreatAction {
    Ask,
    Quarantine,
    Delete,
    ReportOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Sensitivity {
    Low,
    Normal,
    High,
}

impl Sensitivity {
    /// Score that freezes an app. Normal is the spec's 100.
    pub fn threshold(self) -> u32 {
        match self {
            Sensitivity::Low => 150,
            Sensitivity::Normal => 100,
            Sensitivity::High => 70,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UsbMode {
    Ask,
    Always,
    Never,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Settings {
    pub actions: Actions,
    pub realtime: Realtime,
    pub scan: Scan,
    pub schedules: Vec<Schedule>,
    pub shield: Shield,
    pub quarantine: Quarantine,
    pub network: Network,
    pub usb: Usb,
    pub history: History,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Actions {
    pub realtime: ThreatAction,
    pub manual: ThreatAction,
    pub scheduled: ThreatAction,
    /// Only Quarantine or Delete are valid here.
    pub ransomware: ThreatAction,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Realtime {
    pub enabled: bool,
    pub include_paths: Vec<String>,
    pub exclude_paths: Vec<String>,
    pub max_file_mb: u32,
    /// false means root processes are scanned too (the shipped default).
    pub exclude_root: bool,
    /// Block the open at kernel level when the kernel supports it.
    pub prevention: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Scan {
    pub detect_pua: bool,
    pub max_file_mb: u32,
    pub max_scan_mb: u32,
    pub max_recursion: u32,
    pub scan_archive: bool,
    pub alert_encrypted: bool,
    pub one_filesystem: bool,
    pub max_threads: u32,
    pub exclusions: Vec<String>,
    pub custom_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Schedule {
    pub profile: String,
    pub on_calendar: String,
    pub enabled: bool,
    #[serde(default = "yes")]
    pub skip_on_battery: bool,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Shield {
    pub enabled: bool,
    pub sensitivity: Sensitivity,
    pub watch_paths: Vec<String>,
    pub ignore: Vec<String>,
    pub window_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Quarantine {
    /// 0 means off. Allowed: 0, 7, 14, 30, 90.
    pub auto_delete_days: u32,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Network {
    /// Hardening toggle: reject anything running from /tmp, /var/tmp, /dev/shm, memfd.
    pub deny_tmp: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Usb {
    pub autoscan: UsbMode,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct History {
    pub retention_days: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            actions: Actions::default(),
            realtime: Realtime::default(),
            scan: Scan::default(),
            schedules: vec![Schedule {
                profile: "quick".into(),
                on_calendar: "Sun *-*-* 03:00:00".into(),
                enabled: true,
                skip_on_battery: true,
            }],
            shield: Shield::default(),
            quarantine: Quarantine::default(),
            network: Network::default(),
            usb: Usb::default(),
            history: History::default(),
        }
    }
}

impl Default for Actions {
    fn default() -> Self {
        Actions {
            realtime: ThreatAction::Quarantine,
            manual: ThreatAction::Ask,
            scheduled: ThreatAction::Quarantine,
            ransomware: ThreatAction::Quarantine,
        }
    }
}

impl Default for Realtime {
    fn default() -> Self {
        Realtime {
            enabled: true,
            include_paths: ["/home", "/tmp", "/var/tmp", "/opt", "/usr/local", "/srv"]
                .map(String::from)
                .to_vec(),
            exclude_paths: Vec::new(),
            max_file_mb: 25,
            exclude_root: false,
            prevention: true,
        }
    }
}

impl Default for Scan {
    fn default() -> Self {
        Scan {
            detect_pua: false,
            max_file_mb: 100,
            max_scan_mb: 400,
            max_recursion: 17,
            scan_archive: true,
            alert_encrypted: false,
            one_filesystem: true,
            max_threads: 4,
            exclusions: Vec::new(),
            custom_paths: Vec::new(),
        }
    }
}

impl Default for Shield {
    fn default() -> Self {
        Shield {
            enabled: true,
            sensitivity: Sensitivity::Normal,
            watch_paths: ["/home", "/srv", "/mnt"].map(String::from).to_vec(),
            ignore: Vec::new(),
            window_secs: 20,
        }
    }
}

impl Default for Quarantine {
    fn default() -> Self {
        Quarantine {
            auto_delete_days: 30,
        }
    }
}

impl Default for Usb {
    fn default() -> Self {
        Usb {
            autoscan: UsbMode::Ask,
        }
    }
}

impl Default for History {
    fn default() -> Self {
        History {
            retention_days: 180,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SettingsError {
    #[error("cannot read settings: {0}")]
    Io(#[from] std::io::Error),
    #[error("settings file is invalid: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("setting is out of range: {0}")]
    Invalid(String),
}

impl Settings {
    pub fn load(path: &Path) -> Result<Settings, SettingsError> {
        match std::fs::read_to_string(path) {
            Ok(text) => Settings::parse(&text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Settings::default()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn parse(text: &str) -> Result<Settings, SettingsError> {
        if text.len() > 1 << 20 {
            return Err(SettingsError::Invalid(
                "settings file larger than 1 MiB".into(),
            ));
        }
        let s: Settings = toml::from_str(text)?;
        s.validate()?;
        Ok(s)
    }

    pub fn to_toml(&self) -> String {
        let body = toml::to_string_pretty(self).unwrap_or_default();
        format!("# Deadbolt settings. Edited by the app; hand edits are fine.\n{body}")
    }

    pub fn validate(&self) -> Result<(), SettingsError> {
        let bad = |m: &str| Err(SettingsError::Invalid(m.into()));
        if matches!(
            self.actions.ransomware,
            ThreatAction::Ask | ThreatAction::ReportOnly
        ) {
            return bad("actions.ransomware must be quarantine or delete");
        }
        if matches!(self.actions.realtime, ThreatAction::Ask)
            || matches!(self.actions.scheduled, ThreatAction::Ask)
        {
            return bad("ask is only valid for actions.manual");
        }
        if ![0, 7, 14, 30, 90].contains(&self.quarantine.auto_delete_days) {
            return bad("quarantine.auto_delete_days must be 0, 7, 14, 30 or 90");
        }
        if self.realtime.include_paths.iter().any(|p| p == "/") {
            return bad("realtime.include_paths cannot contain /, ClamAV refuses it");
        }
        for p in self
            .realtime
            .include_paths
            .iter()
            .chain(&self.realtime.exclude_paths)
            .chain(&self.scan.exclusions)
            .chain(&self.scan.custom_paths)
            .chain(&self.shield.watch_paths)
        {
            if !p.starts_with('/') || p.contains('\n') || p.contains('\0') {
                return Err(SettingsError::Invalid(format!(
                    "not an absolute path: {p:?}"
                )));
            }
        }
        if self.scan.max_threads == 0 || self.scan.max_threads > 64 {
            return bad("scan.max_threads must be 1 to 64");
        }
        if self.shield.window_secs == 0 || self.shield.window_secs > 600 {
            return bad("shield.window_secs must be 1 to 600");
        }
        for s in &self.schedules {
            if !matches!(s.profile.as_str(), "quick" | "home" | "full" | "custom") {
                return Err(SettingsError::Invalid(format!(
                    "unknown schedule profile {:?}",
                    s.profile
                )));
            }
            if !s
                .on_calendar
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || " *-:,./~".contains(c))
            {
                return bad("schedule on_calendar has characters systemd does not use");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_validate_and_round_trip() {
        let s = Settings::default();
        s.validate().unwrap();
        let back = Settings::parse(&s.to_toml()).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let err = Settings::parse("[realtime]\nenabeld = true\n").unwrap_err();
        assert!(matches!(err, SettingsError::Parse(_)));
    }

    #[test]
    fn root_include_rejected() {
        let mut s = Settings::default();
        s.realtime.include_paths.push("/".into());
        assert!(s.validate().is_err());
    }

    #[test]
    fn ransomware_ask_rejected() {
        let mut s = Settings::default();
        s.actions.ransomware = ThreatAction::Ask;
        assert!(s.validate().is_err());
    }

    #[test]
    fn weekly_quick_scan_is_default() {
        let s = Settings::default();
        assert_eq!(s.schedules[0].profile, "quick");
        assert_eq!(s.schedules[0].on_calendar, "Sun *-*-* 03:00:00");
    }
}
