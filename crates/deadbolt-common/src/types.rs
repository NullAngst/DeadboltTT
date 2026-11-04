//! Types that cross process boundaries. Over D-Bus they travel as JSON
//! strings so the Python GUI and the Rust clients share one shape.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Source {
    Manual,
    Realtime,
    Scheduled,
    Ransomware,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Manual => "manual",
            Source::Realtime => "realtime",
            Source::Scheduled => "scheduled",
            Source::Ransomware => "ransomware",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Level {
    Green,
    Amber,
    Red,
}

/// What the dashboard and tray show.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Status {
    pub level: Level,
    /// One line of reason, already worded for the banner.
    pub reason: String,
    /// Fix button: "update-signatures", "enable-realtime", "requirements", "start-daemon" or "".
    pub fix: String,
    pub realtime: RealtimeState,
    pub shield: ShieldState,
    pub signatures: SignatureState,
    pub last_scan: Option<ScanSummary>,
    pub quarantine_count: u64,
    pub network_blocks: u64,
    pub paused_until: Option<i64>,
    pub setup_done: bool,
    pub overflow_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealtimeState {
    pub enabled: bool,
    pub running: bool,
    /// "blocking" or "notify-only"
    pub mode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShieldState {
    pub enabled: bool,
    pub running: bool,
    pub protected: Vec<String>,
    pub unprotected: Vec<String>,
    pub canaries: u64,
    pub frozen: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureState {
    pub engine: String,
    /// Unix time of the newest signature database, if known.
    pub updated: Option<i64>,
    pub age_days: Option<u32>,
    pub engine_outdated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Detection {
    pub path: String,
    pub signature: String,
    pub source: Source,
    /// What was done: "quarantined", "deleted", "reported", "pending", "failed: ..."
    pub action: String,
    pub quarantine_id: Option<String>,
    pub time: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum JobState {
    Counting,
    Running,
    Paused,
    Cancelled,
    Done,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgress {
    pub job: String,
    pub state: JobState,
    pub total: u64,
    pub done: u64,
    pub current: String,
    pub found: u64,
    /// true when running through clamscan because clamd is down.
    pub fallback: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScanSummary {
    pub job: String,
    pub profile: String,
    pub source: Source,
    pub started: i64,
    pub finished: i64,
    pub files: u64,
    pub errors: u64,
    pub detections: Vec<Detection>,
    pub state: JobState,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct QuarantineItem {
    pub id: String,
    pub original_path: String,
    pub owner: u32,
    pub group: u32,
    pub mode: u32,
    pub mtime: i64,
    pub size: u64,
    pub sha256: String,
    pub signature: String,
    pub source: Source,
    pub date: i64,
    /// XOR key, hex. Never shown in the GUI.
    #[serde(default)]
    pub key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Incident {
    pub id: String,
    pub time: i64,
    pub app: String,
    pub exe: String,
    pub pid: i32,
    pub uid: u32,
    pub user: String,
    pub cgroup: String,
    /// "cgroup" or "sigstop"
    pub freeze_method: String,
    pub score: u32,
    pub signals: Vec<String>,
    pub files: Vec<String>,
    /// Signature name if clamd knew the binary.
    pub binary_signature: Option<String>,
    /// "frozen", "killed", "allowed-once", "allowed-always", "gone"
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Requirement {
    pub tool: String,
    pub required: bool,
    pub installed: bool,
    pub version: String,
    pub feature: String,
    /// Package name for this system's package manager.
    pub package: String,
    pub install_hint: String,
    pub running: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequirementsReport {
    pub package_manager: String,
    pub rows: Vec<Requirement>,
    pub kernel: Vec<KernelCheck>,
    /// One command installing every missing package, empty when nothing is missing.
    pub install_command: String,
    pub missing_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelCheck {
    pub name: String,
    pub ok: bool,
    pub detail: String,
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HistoryEvent {
    pub id: i64,
    pub time: i64,
    /// scan, detection, action, block, shield, protection, update, setup
    pub kind: String,
    pub summary: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NetApp {
    pub name: String,
    pub icon: String,
    /// Absolute executable path, Flatpak app id, or the .exe for Wine apps.
    pub target: String,
    /// "native", "flatpak" or "wine"
    pub kind: String,
    pub blocked: bool,
    pub allow_lan: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Connection {
    pub proto: String,
    pub local: String,
    pub peer: String,
    pub process: String,
    pub pid: i32,
}

pub fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}
