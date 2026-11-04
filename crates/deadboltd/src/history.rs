//! Event log in SQLite at /var/lib/deadbolt/history.db. Rows older than the
//! retention period are rolled up into monthly counts.

use deadbolt_common::types::{HistoryEvent, now};
use rusqlite::{Connection, params};
use std::path::Path;
use std::sync::Mutex;

pub struct History {
    db: Mutex<Connection>,
}

#[derive(Debug, Default, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Filter {
    pub kind: String,
    pub text: String,
    pub since: i64,
    pub limit: u32,
}

impl History {
    pub fn open(path: &Path) -> rusqlite::Result<History> {
        let db = Connection::open(path)?;
        db.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS events(
               id INTEGER PRIMARY KEY, time INTEGER NOT NULL, kind TEXT NOT NULL,
               summary TEXT NOT NULL, detail TEXT NOT NULL);
             CREATE INDEX IF NOT EXISTS events_time ON events(time);
             CREATE TABLE IF NOT EXISTS rollup(
               month TEXT NOT NULL, kind TEXT NOT NULL, count INTEGER NOT NULL,
               PRIMARY KEY(month, kind));",
        )?;
        Ok(History { db: Mutex::new(db) })
    }

    pub fn memory() -> History {
        History::open(Path::new(":memory:")).unwrap_or_else(|_| {
            // An in-memory database cannot fail to open short of OOM.
            std::process::abort()
        })
    }

    pub fn log(&self, kind: &str, summary: &str, detail: &str) {
        let Ok(db) = self.db.lock() else { return };
        let _ = db.execute(
            "INSERT INTO events(time, kind, summary, detail) VALUES (?1, ?2, ?3, ?4)",
            params![now(), kind, summary, detail],
        );
    }

    pub fn query(&self, f: &Filter) -> Vec<HistoryEvent> {
        let Ok(db) = self.db.lock() else {
            return Vec::new();
        };
        let limit = if f.limit == 0 {
            500
        } else {
            f.limit.min(10_000)
        };
        let like = format!("%{}%", f.text.replace(['%', '_'], ""));
        let Ok(mut st) = db.prepare(
            "SELECT id, time, kind, summary, detail FROM events
             WHERE time >= ?1 AND (?2 = '' OR kind = ?2) AND (?3 = '%%' OR summary LIKE ?3 OR detail LIKE ?3)
             ORDER BY time DESC, id DESC LIMIT ?4",
        ) else {
            return Vec::new();
        };
        st.query_map(params![f.since, f.kind, like, limit], |r| {
            Ok(HistoryEvent {
                id: r.get(0)?,
                time: r.get(1)?,
                kind: r.get(2)?,
                summary: r.get(3)?,
                detail: r.get(4)?,
            })
        })
        .map(|rows| rows.filter_map(Result::ok).collect())
        .unwrap_or_default()
    }

    /// Roll up and delete rows older than `days`.
    pub fn retain(&self, days: u32) -> usize {
        let Ok(mut db) = self.db.lock() else { return 0 };
        let cut = now() - i64::from(days.max(1)) * 86_400;
        let Ok(tx) = db.transaction() else { return 0 };
        let _ = tx.execute(
            "INSERT INTO rollup(month, kind, count)
               SELECT strftime('%Y-%m', time, 'unixepoch'), kind, COUNT(*) FROM events WHERE time < ?1
               GROUP BY 1, 2
             ON CONFLICT(month, kind) DO UPDATE SET count = count + excluded.count",
            params![cut],
        );
        let n = tx
            .execute("DELETE FROM events WHERE time < ?1", params![cut])
            .unwrap_or(0);
        let _ = tx.commit();
        n
    }

    pub fn rollup(&self) -> Vec<(String, String, i64)> {
        let Ok(db) = self.db.lock() else {
            return Vec::new();
        };
        let Ok(mut st) = db.prepare("SELECT month, kind, count FROM rollup ORDER BY month DESC")
        else {
            return Vec::new();
        };
        st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .map(|rows| rows.filter_map(Result::ok).collect())
            .unwrap_or_default()
    }
}

pub fn to_csv(rows: &[HistoryEvent]) -> String {
    let esc = |s: &str| format!("\"{}\"", s.replace('"', "\"\""));
    let mut out = String::from("id,time,kind,summary,detail\n");
    for r in rows {
        out.push_str(&format!(
            "{},{},{},{},{}\n",
            r.id,
            r.time,
            esc(&r.kind),
            esc(&r.summary),
            esc(&r.detail)
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_query_filter() {
        let h = History::memory();
        h.log("detection", "Threat found in a.pdf", "/home/u/a.pdf");
        h.log("scan", "Quick scan finished", "");
        assert_eq!(h.query(&Filter::default()).len(), 2);
        let f = Filter {
            kind: "scan".into(),
            ..Default::default()
        };
        assert_eq!(h.query(&f).len(), 1);
        let f = Filter {
            text: "a.pdf".into(),
            ..Default::default()
        };
        assert_eq!(h.query(&f).len(), 1);
    }

    #[test]
    fn csv_escapes() {
        let rows = vec![HistoryEvent {
            id: 1,
            time: 2,
            kind: "k".into(),
            summary: "say \"hi\"".into(),
            detail: "a,b".into(),
        }];
        assert!(to_csv(&rows).contains("\"say \"\"hi\"\"\",\"a,b\""));
    }
}
