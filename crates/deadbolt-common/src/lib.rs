//! Shared pieces for every Deadbolt binary: paths, D-Bus names, settings,
//! wire types, the worker protocol and the clamd client.

pub mod canary;
pub mod clamd;
pub mod exitcode;
pub mod paths;
pub mod perm;
pub mod protocol;
pub mod settings;
pub mod types;
pub mod userdata;

pub use settings::Settings;

/// Well-known bus name of the daemon.
pub const BUS_NAME: &str = "io.github.nullangst.Deadbolt1";
/// The one object the daemon exports.
pub const OBJECT_PATH: &str = "/io/github/nullangst/Deadbolt1";
/// Interface name prefix. Interfaces are `<prefix>.Status`, `<prefix>.Scan`, ...
pub const IFACE_PREFIX: &str = "io.github.nullangst.Deadbolt1";
/// polkit action id prefix.
pub const POLKIT_PREFIX: &str = "io.github.nullangst.deadbolt";

/// The polkit actions declared in `data/polkit/io.github.nullangst.deadbolt.policy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Scan,
    ScanSystem,
    QuarantineManage,
    ShieldDecide,
    ShieldDecideOther,
    Settings,
    Network,
    ProtectionToggle,
}

impl Action {
    pub const ALL: [Action; 8] = [
        Action::Scan,
        Action::ScanSystem,
        Action::QuarantineManage,
        Action::ShieldDecide,
        Action::ShieldDecideOther,
        Action::Settings,
        Action::Network,
        Action::ProtectionToggle,
    ];

    pub fn suffix(self) -> &'static str {
        match self {
            Action::Scan => "scan",
            Action::ScanSystem => "scan-system",
            Action::QuarantineManage => "quarantine-manage",
            Action::ShieldDecide => "shield-decide",
            Action::ShieldDecideOther => "shield-decide-other",
            Action::Settings => "settings",
            Action::Network => "network",
            Action::ProtectionToggle => "protection-toggle",
        }
    }

    pub fn id(self) -> String {
        format!("{POLKIT_PREFIX}.{}", self.suffix())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_file_declares_every_action() {
        let policy = include_str!("../../../data/polkit/io.github.nullangst.deadbolt.policy");
        for a in Action::ALL {
            let needle = format!("id=\"{}\"", a.id());
            assert!(
                policy.contains(&needle),
                "policy file is missing {}",
                a.id()
            );
        }
    }
}
