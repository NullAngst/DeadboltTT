//! Every fixed path Deadbolt uses, in one place.

pub const ETC_DIR: &str = "/etc/deadbolt";
pub const SETTINGS_FILE: &str = "/etc/deadbolt/deadbolt.toml";
pub const CLAMD_CONF: &str = "/etc/deadbolt/clamd.conf";

pub const LIB_DIR: &str = "/var/lib/deadbolt";
pub const QUARANTINE_DIR: &str = "/var/lib/deadbolt/quarantine";
pub const INCIDENT_DIR: &str = "/var/lib/deadbolt/incidents";
pub const HISTORY_DB: &str = "/var/lib/deadbolt/history.db";
pub const ALLOWLIST_FILE: &str = "/var/lib/deadbolt/allowlist.json";
pub const CANARY_INDEX: &str = "/var/lib/deadbolt/canaries.json";
/// Same list, one path per line, for packaging scripts.
pub const CANARY_LIST: &str = "/var/lib/deadbolt/canaries.txt";
pub const STATE_FILE: &str = "/var/lib/deadbolt/state.json";

pub const LOG_DIR: &str = "/var/log/deadbolt";
pub const ONACCESS_LOG: &str = "/var/log/deadbolt/onaccess.log";

pub const LIBEXEC_DIR: &str = "/usr/libexec/deadbolt";
pub const VIRUSEVENT_HOOK: &str = "/usr/libexec/deadbolt/virusevent";

/// Runtime directory of deadboltd (RuntimeDirectory=deadbolt).
pub const RUN_DIR: &str = "/run/deadbolt";
/// The VirusEvent hook writes here. Peer credentials are checked: clamav only.
pub const EVENTS_SOCK: &str = "/run/deadbolt/events.sock";
/// Runtime directory of deadbolt-worker, mode 0700, owned by deadbolt-worker.
pub const WORKER_RUN_DIR: &str = "/run/deadbolt-worker";
/// The worker's job socket. The worker accepts only peers with uid 0.
pub const WORKER_SOCK: &str = "/run/deadbolt-worker/worker.sock";
/// Runtime directory of deadbolt-clamd, owned by clamav.
pub const CLAMD_RUN_DIR: &str = "/run/deadbolt-clamd";
pub const CLAMD_SOCK: &str = "/run/deadbolt-clamd/clamd.ctl";

pub const OPENSNITCH_RULES_DIR: &str = "/etc/opensnitchd/rules";
pub const OPENSNITCH_CONFIG: &str = "/etc/opensnitchd/default-config.json";
pub const OPENSNITCH_LOG: &str = "/var/log/opensnitchd.log";

pub const DATA_DIR: &str = "/usr/share/deadbolt";
pub const PACKAGES_TOML: &str = "/usr/share/deadbolt/packages.toml";
pub const USER_DATA_EXTENSIONS: &str = "/usr/share/deadbolt/user-data-extensions.txt";
pub const SHIELD_TEST: &str = "/usr/share/deadbolt/tools/deadbolt-shield-test";

pub const WORKER_USER: &str = "deadbolt-worker";
pub const CLAMAV_USER: &str = "clamav";

/// Paths a Full scan never enters.
pub const FULL_SCAN_SKIP: &[&str] = &["/proc", "/sys", "/dev", "/run", QUARANTINE_DIR];
