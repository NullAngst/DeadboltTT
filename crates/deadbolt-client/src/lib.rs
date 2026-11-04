//! D-Bus client for deadboltd. Every call is a JSON string over the system
//! bus; this crate turns them back into the shared types.
#![forbid(unsafe_code)]

use deadbolt_common::types::*;
use deadbolt_common::{BUS_NAME, IFACE_PREFIX, OBJECT_PATH};
use futures_util::StreamExt;
use serde::de::DeserializeOwned;
use tokio::sync::mpsc;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("cannot reach the system bus: {0}")]
    Bus(String),
    #[error("{0}")]
    Daemon(String),
    #[error("bad reply from deadboltd: {0}")]
    Decode(String),
}

impl ClientError {
    /// true when deadboltd is not running.
    pub fn daemon_down(&self) -> bool {
        match self {
            ClientError::Daemon(m) | ClientError::Bus(m) => {
                m.contains("ServiceUnknown")
                    || m.contains("NameHasNoOwner")
                    || m.contains("was not provided")
            }
            _ => false,
        }
    }
}

fn daemon_err(e: zbus::Error) -> ClientError {
    match e {
        zbus::Error::MethodError(name, msg, _) => {
            ClientError::Daemon(format!("{}: {}", name.as_str(), msg.unwrap_or_default()))
        }
        other => ClientError::Daemon(other.to_string()),
    }
}

pub type Result<T> = std::result::Result<T, ClientError>;

#[derive(Clone)]
pub struct Client {
    conn: zbus::Connection,
}

/// A signal from the daemon: interface short name, member, JSON body.
#[derive(Debug, Clone)]
pub struct Signal {
    pub iface: String,
    pub member: String,
    pub json: String,
}

impl Client {
    pub async fn connect() -> Result<Client> {
        let conn = zbus::Connection::system()
            .await
            .map_err(|e| ClientError::Bus(e.to_string()))?;
        Ok(Client { conn })
    }

    async fn raw<B, R>(&self, iface: &str, method: &str, body: &B) -> Result<R>
    where
        B: serde::Serialize + zbus::DynamicType,
        R: for<'d> serde::Deserialize<'d> + zbus::Type,
    {
        let iface = format!("{IFACE_PREFIX}.{iface}");
        let p = zbus::Proxy::new(&self.conn, BUS_NAME, OBJECT_PATH, iface.as_str())
            .await
            .map_err(daemon_err)?;
        p.call(method, body).await.map_err(daemon_err)
    }

    async fn json<B, T>(&self, iface: &str, method: &str, body: &B) -> Result<T>
    where
        B: serde::Serialize + zbus::DynamicType,
        T: DeserializeOwned,
    {
        let s: String = self.raw(iface, method, body).await?;
        serde_json::from_str(&s).map_err(|e| ClientError::Decode(e.to_string()))
    }

    // Status
    pub async fn status(&self) -> Result<Status> {
        self.json("Status", "GetStatus", &()).await
    }
    pub async fn requirements(&self, refresh: bool) -> Result<RequirementsReport> {
        self.json("Status", "Requirements", &(refresh,)).await
    }
    pub async fn version(&self) -> Result<String> {
        self.raw("Status", "Version", &()).await
    }

    // Scan
    pub async fn scan(&self, paths: &[String], profile: &str, source: &str) -> Result<String> {
        let list = serde_json::to_string(paths).map_err(|e| ClientError::Decode(e.to_string()))?;
        self.raw("Scan", "Start", &(list, profile, source)).await
    }
    pub async fn scan_control(&self, job: &str, what: &str) -> Result<()> {
        let m = match what {
            "pause" => "Pause",
            "resume" => "Resume",
            _ => "Cancel",
        };
        self.raw("Scan", m, &(job,)).await
    }
    pub async fn scan_result(&self, job: &str) -> Result<serde_json::Value> {
        self.json("Scan", "Result", &(job,)).await
    }
    pub async fn scan_jobs(&self) -> Result<serde_json::Value> {
        self.json("Scan", "Jobs", &()).await
    }
    pub async fn scan_act(&self, job: &str, path: &str, action: &str) -> Result<Detection> {
        self.json("Scan", "Act", &(job, path, action)).await
    }

    // Quarantine
    pub async fn quarantine_list(&self) -> Result<Vec<QuarantineItem>> {
        self.json("Quarantine", "List", &()).await
    }
    pub async fn quarantine_restore(
        &self,
        id: &str,
        to: &str,
        exec: bool,
        exclude: bool,
    ) -> Result<String> {
        self.raw("Quarantine", "Restore", &(id, to, exec, exclude))
            .await
    }
    pub async fn quarantine_delete(&self, id: &str) -> Result<()> {
        self.raw("Quarantine", "Delete", &(id,)).await
    }
    pub async fn quarantine_purge(&self, days: u32) -> Result<u64> {
        self.raw("Quarantine", "Purge", &(days.min(i32::MAX as u32) as i32,))
            .await
    }

    // Shield
    pub async fn incidents(&self) -> Result<Vec<Incident>> {
        self.json("Shield", "Incidents", &()).await
    }
    pub async fn frozen(&self) -> Result<Vec<Incident>> {
        self.json("Shield", "Frozen", &()).await
    }
    pub async fn decide(&self, id: &str, choice: &str) -> Result<Incident> {
        self.json("Shield", "Decide", &(id, choice)).await
    }
    pub async fn canaries(&self) -> Result<serde_json::Value> {
        self.json("Shield", "Canaries", &()).await
    }
    pub async fn allowlist(&self) -> Result<serde_json::Value> {
        self.json("Shield", "Allowlist", &()).await
    }
    pub async fn recovery(&self, id: &str) -> Result<serde_json::Value> {
        self.json("Shield", "Recovery", &(id,)).await
    }

    // Network
    pub async fn net_available(&self) -> Result<bool> {
        self.raw("Network", "Available", &()).await
    }
    pub async fn net_apps(&self) -> Result<Vec<NetApp>> {
        self.json("Network", "Apps", &()).await
    }
    pub async fn net_rules(&self) -> Result<serde_json::Value> {
        self.json("Network", "Rules", &()).await
    }
    pub async fn net_set(
        &self,
        name: &str,
        kind: &str,
        target: &str,
        blocked: bool,
        lan: bool,
    ) -> Result<()> {
        self.raw("Network", "SetBlocked", &(name, kind, target, blocked, lan))
            .await
    }
    pub async fn net_connections(&self) -> Result<Vec<Connection>> {
        self.json("Network", "Connections", &()).await
    }
    pub async fn net_recent(&self) -> Result<Vec<String>> {
        self.json("Network", "RecentlyBlocked", &()).await
    }
    pub async fn net_drop(&self, target: &str) -> Result<u32> {
        self.raw("Network", "DropConnections", &(target,)).await
    }

    // Settings
    pub async fn settings(&self) -> Result<deadbolt_common::Settings> {
        self.json("Settings", "Get", &()).await
    }
    pub async fn set_settings(&self, s: &deadbolt_common::Settings) -> Result<Vec<String>> {
        let body = serde_json::to_string(s).map_err(|e| ClientError::Decode(e.to_string()))?;
        self.json("Settings", "Set", &(body,)).await
    }
    pub async fn pause(&self, minutes: u32) -> Result<()> {
        self.raw("Settings", "Pause", &(minutes.min(i32::MAX as u32) as i32,))
            .await
    }
    pub async fn resume(&self) -> Result<()> {
        self.raw("Settings", "Resume", &()).await
    }
    pub async fn update_signatures(&self) -> Result<String> {
        self.raw("Settings", "UpdateSignatures", &()).await
    }
    pub async fn history(&self, filter: &serde_json::Value) -> Result<Vec<HistoryEvent>> {
        self.json("Settings", "History", &(filter.to_string(),))
            .await
    }
    pub async fn history_csv(&self, filter: &serde_json::Value) -> Result<String> {
        self.raw("Settings", "HistoryCsv", &(filter.to_string(),))
            .await
    }
    pub async fn setup_step(&self, step: &str) -> Result<serde_json::Value> {
        self.json("Settings", "SetupStep", &(step,)).await
    }
    pub async fn startup_items(&self) -> Result<serde_json::Value> {
        self.json("Settings", "StartupItems", &()).await
    }
    pub async fn run_tool(&self, tool: &str) -> Result<String> {
        self.raw("Settings", "RunTool", &(tool,)).await
    }

    /// Every signal the daemon emits, forwarded into a channel.
    pub async fn signals(&self) -> Result<mpsc::Receiver<Signal>> {
        let rule = zbus::MatchRule::builder()
            .msg_type(zbus::message::Type::Signal)
            .sender(BUS_NAME)
            .path(OBJECT_PATH)
            .build()
            .map_err(|e| ClientError::Bus(e.to_string()))?;
        let mut stream = zbus::MessageStream::for_match_rule(rule, &self.conn, None)
            .await
            .map_err(|e| ClientError::Bus(e.to_string()))?;
        let (tx, rx) = mpsc::channel(256);
        tokio::spawn(async move {
            while let Some(Ok(msg)) = stream.next().await {
                let h = msg.header();
                let iface = h
                    .interface()
                    .map(|i| i.as_str().rsplit('.').next().unwrap_or("").to_string())
                    .unwrap_or_default();
                let member = h
                    .member()
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default();
                let json: String = msg.body().deserialize().unwrap_or_default();
                if tx
                    .send(Signal {
                        iface,
                        member,
                        json,
                    })
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        Ok(rx)
    }
}

/// The EICAR test string, assembled at runtime so this source file is not
/// itself flagged by a scanner.
pub fn eicar() -> String {
    let parts = [
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}$",
        "EICAR-STANDARD-ANTIVIRUS-TEST-",
        "FILE!$H+H*",
    ];
    parts.concat()
}
