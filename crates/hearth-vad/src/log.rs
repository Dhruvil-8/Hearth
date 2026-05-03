use anyhow::Result;
use chrono::Utc;
use rusqlite::{params, Connection};
use std::sync::{Arc, Mutex};

/// VAD event logger — writes allow/block events to a separate SQLite database.
pub struct VadLog {
    conn: Arc<Mutex<Connection>>,
}

impl VadLog {
    /// Create a new VAD event log, initializing the database schema.
    pub fn new(db_path: &str) -> Result<Self> {
        let conn = if db_path == ":memory:" {
            Connection::open_in_memory()?
        } else {
            if let Some(parent) = std::path::Path::new(db_path).parent() {
                std::fs::create_dir_all(parent).ok();
            }
            Connection::open(db_path)?
        };

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS vad_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                destination_ip TEXT NOT NULL,
                duration_ms INTEGER,
                speech_score REAL,
                detail TEXT
            );",
        )?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Log a VAD event (ALLOWED or BLOCKED).
    pub fn log_event(
        &self,
        event_type: &str,
        destination_ip: &str,
        duration_ms: Option<i64>,
        speech_score: Option<f64>,
        detail: Option<&str>,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO vad_events (timestamp, event_type, destination_ip, duration_ms, speech_score, detail)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                Utc::now().to_rfc3339(),
                event_type,
                destination_ip,
                duration_ms,
                speech_score,
                detail,
            ],
        )?;
        Ok(())
    }

    /// Get recent VAD events within the last N hours.
    pub fn get_events(&self, hours: u32) -> Result<Vec<VadEvent>> {
        let conn = self.conn.lock().unwrap();
        let cutoff = Utc::now() - chrono::Duration::hours(hours as i64);
        let mut stmt = conn.prepare(
            "SELECT id, timestamp, event_type, destination_ip, duration_ms, speech_score, detail
             FROM vad_events WHERE timestamp > ?1 ORDER BY timestamp DESC",
        )?;
        let events = stmt
            .query_map(params![cutoff.to_rfc3339()], |row| {
                Ok(VadEvent {
                    id: row.get(0)?,
                    timestamp: row.get(1)?,
                    event_type: row.get(2)?,
                    destination_ip: row.get(3)?,
                    duration_ms: row.get(4)?,
                    speech_score: row.get(5)?,
                    detail: row.get(6)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(events)
    }

    /// Get today's stats (allowed count, blocked count).
    pub fn get_today_stats(&self) -> Result<(u32, u32)> {
        let conn = self.conn.lock().unwrap();
        let today = Utc::now().date_naive().and_hms_opt(0, 0, 0).unwrap();
        let today_utc = chrono::DateTime::<Utc>::from_naive_utc_and_offset(today, Utc);
        let allowed: i32 = conn.query_row(
            "SELECT COUNT(*) FROM vad_events WHERE event_type='ALLOWED' AND timestamp > ?1",
            params![today_utc.to_rfc3339()],
            |r| r.get(0),
        )?;
        let blocked: i32 = conn.query_row(
            "SELECT COUNT(*) FROM vad_events WHERE event_type='BLOCKED' AND timestamp > ?1",
            params![today_utc.to_rfc3339()],
            |r| r.get(0),
        )?;
        Ok((allowed as u32, blocked as u32))
    }
}

/// A single VAD event record.
#[derive(Debug, serde::Serialize)]
pub struct VadEvent {
    pub id: i64,
    pub timestamp: String,
    pub event_type: String,
    pub destination_ip: String,
    pub duration_ms: Option<i64>,
    pub speech_score: Option<f64>,
    pub detail: Option<String>,
}
