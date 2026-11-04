//! polkit checks for D-Bus callers. Every daemon method calls one of these
//! before doing any work; the polkit_coverage test enforces it.

use deadbolt_common::Action;
use std::collections::HashMap;
use zbus::Variant;
use zbus::fdo;
use zbus::message::Header;

#[zbus::proxy(
    interface = "org.freedesktop.PolicyKit1.Authority",
    default_service = "org.freedesktop.PolicyKit1",
    default_path = "/org/freedesktop/PolicyKit1/Authority"
)]
pub trait Authority {
    #[allow(clippy::type_complexity)]
    fn check_authorization(
        &self,
        subject: &(&str, HashMap<&str, Variant<'_>>),
        action_id: &str,
        details: HashMap<&str, &str>,
        flags: u32,
        cancellation_id: &str,
    ) -> zbus::Result<(bool, bool, HashMap<String, String>)>;
}

const ALLOW_USER_INTERACTION: u32 = 1;

pub struct Caller {
    pub uid: u32,
    pub name: String,
}

pub async fn caller(conn: &zbus::Connection, hdr: &Header<'_>) -> fdo::Result<Caller> {
    let sender = hdr
        .sender()
        .ok_or_else(|| fdo::Error::AccessDenied("message has no sender".into()))?
        .to_string();
    let dbus = fdo::DBusProxy::new(conn).await?;
    let name = zbus::names::BusName::try_from(sender.as_str())
        .map_err(|e| fdo::Error::Failed(e.to_string()))?;
    let uid = dbus.get_connection_unix_user(name).await?;
    Ok(Caller { uid, name: sender })
}

/// Ask polkit whether the sender may perform `action`. Root always passes,
/// which is also what polkit itself answers for uid 0.
pub async fn check(
    conn: &zbus::Connection,
    hdr: &Header<'_>,
    action: Action,
) -> fdo::Result<Caller> {
    let who = caller(conn, hdr).await?;
    if who.uid == 0 {
        return Ok(who);
    }
    let authority = AuthorityProxy::new(conn).await?;
    let mut subj = HashMap::new();
    subj.insert("name", Variant::new(who.name.as_str()));
    let (authorized, challenge, _) = authority
        .check_authorization(
            &("system-bus-name", subj),
            &action.id(),
            HashMap::new(),
            ALLOW_USER_INTERACTION,
            "",
        )
        .await
        .map_err(|e| fdo::Error::AccessDenied(format!("polkit check failed: {e}")))?;
    if authorized {
        Ok(who)
    } else if challenge {
        Err(fdo::Error::AuthFailed(format!(
            "authentication required for {}",
            action.id()
        )))
    } else {
        Err(fdo::Error::AccessDenied(format!(
            "not authorized for {}",
            action.id()
        )))
    }
}
