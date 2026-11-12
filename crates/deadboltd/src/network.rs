//! Per-app network blocking through OpenSnitch rule files. Rules are
//! generated from structs and serialized with serde_json, never string-built.
//! Deadbolt only touches files named *deadbolt-* in the rules folder.

use deadbolt_common::paths;
use deadbolt_common::types::{Connection, NetApp, now};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Private, loopback and link-local ranges, as one regexp on dest.ip.
pub const LAN_REGEX: &str = r"^(127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[01])\.|::1$|[fF][eE]80:|[fF][cCdD][0-9a-fA-F]{2}:)";
pub const TMP_REGEX: &str = r"^(/tmp/|/var/tmp/|/dev/shm/|/memfd:)";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Operator {
    #[serde(rename = "type")]
    pub kind: String,
    pub operand: String,
    pub sensitive: bool,
    pub data: String,
    #[serde(default)]
    pub list: Vec<Operator>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Rule {
    pub created: String,
    pub updated: String,
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub precedence: bool,
    #[serde(default)]
    pub nolog: bool,
    pub action: String,
    pub duration: String,
    pub operator: Operator,
}

fn op(kind: &str, operand: &str, data: &str) -> Operator {
    Operator {
        kind: kind.into(),
        operand: operand.into(),
        sensitive: false,
        data: data.into(),
        list: Vec::new(),
    }
}

fn stamp() -> String {
    time::OffsetDateTime::from_unix_timestamp(now())
        .ok()
        .and_then(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_default()
}

/// A short, stable, filename-safe id for an app target.
pub fn slug(name: &str, target: &str) -> String {
    let base: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    let base: String = base.chars().take(40).collect();
    let h = hex::encode(&Sha256::digest(target.as_bytes())[..4]);
    format!("{}-{h}", if base.is_empty() { "app" } else { &base })
}

/// The matcher for an app, by kind.
pub fn app_matcher(kind: &str, target: &str) -> Result<Operator, String> {
    match kind {
        "native" => {
            if !target.starts_with('/') || target.contains('\0') || !Path::new(target).is_file() {
                return Err(format!("{target} is not an existing absolute path"));
            }
            Ok(op("simple", "process.path", target))
        }
        "flatpak" => {
            let ok = target.split('.').count() >= 2
                && target
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-');
            if !ok {
                return Err(format!("{target} is not a valid Flatpak app id"));
            }
            Ok(op("simple", "process.env.FLATPAK_ID", target))
        }
        "wine" => {
            let exe = target.rsplit(['/', '\\']).next().unwrap_or(target);
            if !exe.to_ascii_lowercase().ends_with(".exe") || exe.len() < 5 {
                return Err(format!("{target} is not a Windows .exe"));
            }
            let re = format!(r"(?i)(^|[\\/\s]){}($|\s|\x22)", regex::escape(exe));
            Ok(op("regexp", "process.command", &re))
        }
        _ => Err(format!("unknown app kind {kind}")),
    }
}

pub fn block_rule(name: &str, kind: &str, target: &str) -> Result<(String, Rule), String> {
    let m = app_matcher(kind, target)?;
    let file = if kind == "wine" {
        format!("100-deadbolt-block-wine-{}", slug(name, target))
    } else {
        format!("100-deadbolt-block-{}", slug(name, target))
    };
    let t = stamp();
    Ok((
        file.clone(),
        Rule {
            created: t.clone(),
            updated: t,
            name: file,
            description: format!("Deadbolt: block {name} ({kind}: {target})"),
            enabled: true,
            precedence: false,
            nolog: false,
            action: "deny".into(),
            duration: "always".into(),
            operator: m,
        },
    ))
}

pub fn lan_rule(name: &str, kind: &str, target: &str) -> Result<(String, Rule), String> {
    let m = app_matcher(kind, target)?;
    let file = format!("000-deadbolt-allow-lan-{}", slug(name, target));
    let t = stamp();
    let mut list = op("list", "list", "");
    list.list = vec![m, op("regexp", "dest.ip", LAN_REGEX)];
    Ok((
        file.clone(),
        Rule {
            created: t.clone(),
            updated: t,
            name: file,
            description: format!("Deadbolt: allow {name} on the local network"),
            enabled: true,
            precedence: true,
            nolog: false,
            action: "allow".into(),
            duration: "always".into(),
            operator: list,
        },
    ))
}

pub fn deny_tmp_rule() -> (String, Rule) {
    let t = stamp();
    let file = "050-deadbolt-deny-tmp".to_string();
    (
        file.clone(),
        Rule {
            created: t.clone(),
            updated: t,
            name: file,
            description: "Deadbolt: reject network access for programs run from temp folders"
                .into(),
            enabled: true,
            precedence: true,
            nolog: false,
            action: "reject".into(),
            duration: "always".into(),
            operator: op("regexp", "process.path", TMP_REGEX),
        },
    )
}

pub struct Rules {
    pub dir: PathBuf,
}

impl Rules {
    pub fn new() -> Rules {
        Rules {
            dir: paths::OPENSNITCH_RULES_DIR.into(),
        }
    }

    pub fn available(&self) -> bool {
        self.dir.is_dir()
    }

    pub fn write(&self, file: &str, rule: &Rule) -> std::io::Result<()> {
        use std::io::Write;
        if !file.contains("deadbolt-") || file.contains('/') {
            return Err(std::io::Error::other(
                "refusing to write a rule not named *deadbolt-*",
            ));
        }
        // No trailing newline yet: to_vec_pretty does not add one.
        let data = serde_json::to_vec_pretty(rule)?;
        // Temp name without .json so opensnitchd never loads a half-written file.
        let tmp = self.dir.join(format!(".{file}.tmp"));
        let dest = self.dir.join(format!("{file}.json"));
        std::fs::write(&tmp, data)?;
        std::fs::rename(tmp, &dest)?;
        // opensnitchd's rules watcher reloads on fsnotify Write and Remove
        // only. A rename arrives as Create and is ignored, so the rule would
        // sit unloaded until opensnitchd restarts. Appending the newline is a
        // Write on a file that is already complete, valid JSON either way.
        std::fs::OpenOptions::new()
            .append(true)
            .open(&dest)?
            .write_all(b"\n")
    }

    pub fn remove(&self, file: &str) -> std::io::Result<()> {
        if !file.contains("deadbolt-") || file.contains('/') {
            return Err(std::io::Error::other(
                "refusing to remove a rule not named *deadbolt-*",
            ));
        }
        match std::fs::remove_file(self.dir.join(format!("{file}.json"))) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            r => r,
        }
    }

    pub fn ours(&self) -> Vec<(String, Rule)> {
        let Ok(rd) = std::fs::read_dir(&self.dir) else {
            return Vec::new();
        };
        let mut out: Vec<(String, Rule)> = rd
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                let stem = name.strip_suffix(".json")?.to_string();
                if !stem.contains("deadbolt-") {
                    return None;
                }
                let data = std::fs::read(e.path()).ok()?;
                if data.len() > 64 * 1024 {
                    return None;
                }
                Some((stem, serde_json::from_slice(&data).ok()?))
            })
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    pub fn set_blocked(
        &self,
        name: &str,
        kind: &str,
        target: &str,
        blocked: bool,
        allow_lan: bool,
    ) -> Result<(), String> {
        let (bf, br) = block_rule(name, kind, target)?;
        let (lf, lr) = lan_rule(name, kind, target)?;
        if blocked {
            self.write(&bf, &br).map_err(|e| e.to_string())?;
        } else {
            self.remove(&bf).map_err(|e| e.to_string())?;
        }
        if blocked && allow_lan {
            self.write(&lf, &lr).map_err(|e| e.to_string())?;
        } else {
            self.remove(&lf).map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    pub fn set_deny_tmp(&self, on: bool) -> Result<(), String> {
        let (f, r) = deny_tmp_rule();
        if on {
            self.write(&f, &r).map_err(|e| e.to_string())
        } else {
            self.remove(&f).map_err(|e| e.to_string())
        }
    }

    /// Mark apps blocked or LAN-allowed from the rules on disk.
    pub fn annotate(&self, apps: &mut [NetApp]) {
        let rules = self.ours();
        for a in apps.iter_mut() {
            let Ok((bf, _)) = block_rule(&a.name, &a.kind, &a.target) else {
                continue;
            };
            let Ok((lf, _)) = lan_rule(&a.name, &a.kind, &a.target) else {
                continue;
            };
            a.blocked = rules.iter().any(|(f, _)| *f == bf);
            a.allow_lan = rules.iter().any(|(f, _)| *f == lf);
        }
    }
}

/// Leave the OpenSnitch daemon quiet: allow by default, no UI address, so it
/// never waits on a UI. Returns the new JSON. Only used when opensnitch-ui
/// is not installed, and only after the user saw the preview.
pub fn quiet_config(current: &str) -> Result<String, String> {
    let mut v: serde_json::Value = serde_json::from_str(current)
        .map_err(|e| format!("cannot parse OpenSnitch config: {e}"))?;
    let obj = v
        .as_object_mut()
        .ok_or("OpenSnitch config is not an object")?;
    obj.insert(
        "DefaultAction".into(),
        serde_json::Value::String("allow".into()),
    );
    let server = obj
        .entry("Server")
        .or_insert_with(|| serde_json::Value::Object(Default::default()));
    if let Some(s) = server.as_object_mut() {
        s.insert("Address".into(), serde_json::Value::String(String::new()));
    }
    serde_json::to_string_pretty(&v).map_err(|e| e.to_string())
}

// ---- app list from .desktop files ----

fn desktop_value<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let mut in_entry = false;
    for l in text.lines() {
        let l = l.trim();
        if l.starts_with('[') {
            in_entry = l == "[Desktop Entry]";
            continue;
        }
        if in_entry
            && let Some(v) = l
                .strip_prefix(key)
                .and_then(|r| r.trim_start().strip_prefix('='))
        {
            return Some(v.trim());
        }
    }
    None
}

fn resolve_bin(word: &str) -> Option<String> {
    let w = word.trim_matches(|c| c == '"' || c == '\'');
    if w.starts_with('/') {
        return std::fs::canonicalize(w)
            .ok()
            .map(|p| p.to_string_lossy().into_owned());
    }
    crate::requirements::which(w)
        .and_then(|p| std::fs::canonicalize(p).ok())
        .map(|p| p.to_string_lossy().into_owned())
}

pub fn parse_desktop(text: &str) -> Option<NetApp> {
    if desktop_value(text, "Type") != Some("Application")
        || desktop_value(text, "NoDisplay") == Some("true")
    {
        return None;
    }
    let name = desktop_value(text, "Name")?.to_string();
    let icon = desktop_value(text, "Icon").unwrap_or("").to_string();
    let exec = desktop_value(text, "Exec")?;
    if let Some(id) = desktop_value(text, "X-Flatpak") {
        return Some(NetApp {
            name,
            icon,
            target: id.to_string(),
            kind: "flatpak".into(),
            blocked: false,
            allow_lan: false,
        });
    }
    let words: Vec<&str> = exec.split_whitespace().collect();
    if let Some(exe) = words.iter().find(|w| {
        w.to_ascii_lowercase()
            .trim_matches(|c| c == '"' || c == '\'')
            .ends_with(".exe")
    }) {
        return Some(NetApp {
            name,
            icon,
            target: exe.trim_matches(|c| c == '"' || c == '\'').to_string(),
            kind: "wine".into(),
            blocked: false,
            allow_lan: false,
        });
    }
    let first = words.iter().find(|w| !w.contains('=') && **w != "env")?;
    let target = resolve_bin(first)?;
    Some(NetApp {
        name,
        icon,
        target,
        kind: "native".into(),
        blocked: false,
        allow_lan: false,
    })
}

pub fn list_apps(home: Option<&str>) -> Vec<NetApp> {
    let mut dirs: Vec<PathBuf> = vec![
        "/usr/share/applications".into(),
        "/usr/local/share/applications".into(),
        "/var/lib/flatpak/exports/share/applications".into(),
    ];
    if let Some(h) = home {
        dirs.push(Path::new(h).join(".local/share/applications"));
        dirs.push(Path::new(h).join(".local/share/flatpak/exports/share/applications"));
    }
    let mut apps: Vec<NetApp> = Vec::new();
    for d in dirs {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.filter_map(|e| e.ok()) {
            let p = e.path();
            if p.extension().is_none_or(|x| x != "desktop") {
                continue;
            }
            let Ok(m) = std::fs::metadata(&p) else {
                continue;
            };
            if m.len() > 256 * 1024 {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&p) else {
                continue;
            };
            if let Some(a) = parse_desktop(&text)
                && !apps.iter().any(|x| x.target == a.target)
            {
                apps.push(a);
            }
        }
    }
    apps.sort_by_key(|a| a.name.to_lowercase());
    apps
}

// ---- connections ----

/// Parse `ss -tupnH` output.
pub fn parse_ss(text: &str) -> Vec<Connection> {
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 6 {
                return None;
            }
            let users = f[6..].join(" ");
            let (process, pid) = users
                .split_once("((\"")
                .and_then(|(_, r)| {
                    let (name, rest) = r.split_once('"')?;
                    let pid = rest
                        .split("pid=")
                        .nth(1)?
                        .split(|c: char| !c.is_ascii_digit())
                        .next()?
                        .parse()
                        .ok()?;
                    Some((name.to_string(), pid))
                })
                .unwrap_or_default();
            Some(Connection {
                proto: f[0].into(),
                local: f[4].into(),
                peer: f[5].into(),
                process,
                pid,
            })
        })
        .collect()
}

pub async fn connections() -> Vec<Connection> {
    let out = tokio::process::Command::new("ss")
        .args(["-tupnH"])
        .env("LC_ALL", "C")
        .stdin(std::process::Stdio::null())
        .output()
        .await;
    match out {
        Ok(o) => parse_ss(&String::from_utf8_lossy(&o.stdout)),
        Err(_) => Vec::new(),
    }
}

/// Kill a set of sockets with `ss -K`, matching each by both endpoints.
/// The filter is an argument vector built from parsed addresses, never a shell string.
pub async fn drop_connections(conns: &[Connection]) -> usize {
    let mut n = 0;
    for c in conns {
        let split = |a: &str| {
            a.rsplit_once(':')
                .map(|(h, p)| (h.trim_matches(['[', ']']).to_string(), p.to_string()))
        };
        let (Some((lh, lp)), Some((ph, pp))) = (split(&c.local), split(&c.peer)) else {
            continue;
        };
        let lh = lh.split('%').next().unwrap_or(&lh).to_string();
        let ph = ph.split('%').next().unwrap_or(&ph).to_string();
        let args = [
            "-K",
            "src",
            lh.as_str(),
            "sport",
            "=",
            &format!(":{lp}"),
            "dst",
            ph.as_str(),
            "dport",
            "=",
            &format!(":{pp}"),
        ];
        // ss -K needs CAP_NET_ADMIN, which deadboltd does not hold. Run it in a
        // transient unit instead of widening the daemon's capabilities.
        let ok = tokio::process::Command::new("systemd-run")
            .args(["--wait", "--quiet", "--collect", "--", "ss"])
            .args(args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await
            .is_ok_and(|s| s.success());
        if ok {
            n += 1;
        }
    }
    n
}

/// Last lines from the OpenSnitch log that look like a block.
pub fn recently_blocked(log: &str, max: usize) -> Vec<String> {
    log.lines()
        .rev()
        .filter(|l| {
            let low = l.to_ascii_lowercase();
            low.contains("deadbolt-")
                || low.contains(" deny")
                || low.contains("reject")
                || low.contains("dropped")
        })
        .take(max)
        .map(|l| l.chars().take(300).collect())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_rule_shape() {
        let (f, r) = block_rule("GIMP", "native", "/bin/sh").unwrap();
        assert!(f.starts_with("100-deadbolt-block-gimp-"));
        assert_eq!(r.action, "deny");
        assert!(!r.precedence);
        assert_eq!(r.operator.operand, "process.path");
        let js = serde_json::to_value(&r).unwrap();
        assert_eq!(js["operator"]["type"], "simple");
    }

    #[test]
    fn lan_sorts_before_block() {
        let (l, r) = lan_rule("GIMP", "native", "/bin/sh").unwrap();
        let (b, _) = block_rule("GIMP", "native", "/bin/sh").unwrap();
        assert!(l < b);
        assert!(r.precedence);
        assert_eq!(r.operator.list.len(), 2);
    }

    #[test]
    fn wine_regex_is_escaped() {
        let m = app_matcher("wine", "C:\\Games\\My.Game (x86).exe").unwrap();
        assert!(m.data.contains(r"My\.Game \(x86\)\.exe"));
        let re = regex::Regex::new(&m.data).unwrap();
        assert!(re.is_match(r"C:\Games\My.Game (x86).exe -windowed"));
        assert!(!re.is_match(r"C:\Games\Other.exe"));
        assert!(!re.is_match(r"C:\Games\MyxGame (x86).exe"));
    }

    #[test]
    fn bad_targets_rejected() {
        assert!(app_matcher("native", "relative/bin").is_err());
        assert!(app_matcher("native", "/does/not/exist").is_err());
        assert!(app_matcher("flatpak", "evil\"; rm").is_err());
        assert!(app_matcher("wine", "notexe.txt").is_err());
    }

    #[test]
    fn lan_regex_works() {
        let re = regex::Regex::new(LAN_REGEX).unwrap();
        for ip in [
            "192.168.1.5",
            "10.0.0.1",
            "172.20.3.4",
            "127.0.0.1",
            "fe80::1",
            "fd12:3456::1",
        ] {
            assert!(re.is_match(ip), "{ip}");
        }
        for ip in ["8.8.8.8", "172.32.0.1", "2001:db8::1"] {
            assert!(!re.is_match(ip), "{ip}");
        }
    }

    #[test]
    fn desktop_parsing() {
        let gimp = "[Desktop Entry]\nType=Application\nName=GIMP\nExec=sh %U\nIcon=gimp\n[Desktop Action new]\nName=Other\n";
        let a = parse_desktop(gimp).unwrap();
        assert_eq!(a.name, "GIMP");
        assert_eq!(a.kind, "native");
        let fp = "[Desktop Entry]\nType=Application\nName=GIMP\nExec=/usr/bin/flatpak run org.gimp.GIMP\nX-Flatpak=org.gimp.GIMP\n";
        assert_eq!(parse_desktop(fp).unwrap().kind, "flatpak");
        let wine = "[Desktop Entry]\nType=Application\nName=Game\nExec=env WINEPREFIX=/x wine \"C:\\\\G\\\\game.exe\"\n";
        assert_eq!(parse_desktop(wine).unwrap().kind, "wine");
    }

    #[test]
    fn ss_parsing() {
        let t = "tcp ESTAB 0 0 192.168.1.2:44222 140.82.112.3:443 users:((\"firefox\",pid=4242,fd=88))\n";
        let c = parse_ss(t);
        assert_eq!(c[0].process, "firefox");
        assert_eq!(c[0].pid, 4242);
        assert_eq!(c[0].peer, "140.82.112.3:443");
    }

    #[test]
    fn rule_files_are_complete_json_and_leave_no_temp() {
        let dir = std::env::temp_dir().join(format!("dbt-rules-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let rules = Rules { dir: dir.clone() };
        let (f, r) = block_rule("Sh", "native", "/bin/sh").unwrap();
        rules.write(&f, &r).unwrap();
        // Rewriting an existing rule goes through the same path.
        rules.write(&f, &r).unwrap();
        let text = std::fs::read_to_string(dir.join(format!("{f}.json"))).unwrap();
        assert!(text.ends_with("}\n") && !text.ends_with("\n\n"));
        assert_eq!(serde_json::from_str::<Rule>(&text).unwrap(), r);
        let names: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec![format!("{f}.json")]);
        assert!(rules.write("../escape", &r).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn quiet_config_edits_only_two_keys() {
        let cur = r#"{"Server":{"Address":"unix:///tmp/osui.sock","LogFile":"/var/log/opensnitchd.log"},"DefaultAction":"deny","Firewall":"nftables"}"#;
        let new: serde_json::Value = serde_json::from_str(&quiet_config(cur).unwrap()).unwrap();
        assert_eq!(new["DefaultAction"], "allow");
        assert_eq!(new["Server"]["Address"], "");
        assert_eq!(new["Server"]["LogFile"], "/var/log/opensnitchd.log");
        assert_eq!(new["Firewall"], "nftables");
    }
}
