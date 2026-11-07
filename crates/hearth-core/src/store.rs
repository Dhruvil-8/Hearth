use crate::types::{
    Anomaly, AnomalyKind, Device, DevicePort, DeviceProfile, DnsQueryLog, DnsStats,
    ThreatIntelEntry, TrafficSample,
};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use std::sync::{Arc, Mutex};

/// SQLite-backed persistent storage for all Hearth data.
///
/// Thread-safe via `Arc<Mutex<Connection>>`. All public methods acquire the lock.
pub struct Store {
    conn: Arc<Mutex<Connection>>,
}

impl Clone for Store {
    fn clone(&self) -> Self {
        Store {
            conn: Arc::clone(&self.conn),
        }
    }
}

impl Store {
    /// Open or create the SQLite database and run schema migrations.
    pub fn new(db_path: &str) -> Result<Self> {
        let conn = if db_path == ":memory:" {
            Connection::open_in_memory().context("Failed to open in-memory SQLite")?
        } else {
            // Ensure parent directory exists
            if let Some(parent) = std::path::Path::new(db_path).parent() {
                std::fs::create_dir_all(parent).ok();
            }
            Connection::open(db_path)
                .with_context(|| format!("Failed to open SQLite database: {}", db_path))?
        };

        // Enable WAL mode for better concurrency
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;

        let store = Store {
            conn: Arc::new(Mutex::new(conn)),
        };
        store.run_migrations()?;
        Ok(store)
    }

    /// Run all schema migrations.
    fn run_migrations(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS devices (
                mac TEXT PRIMARY KEY,
                ip TEXT NOT NULL,
                vendor TEXT,
                label TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                is_quarantined INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS traffic_samples (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                bytes_sent INTEGER NOT NULL,
                bytes_recv INTEGER NOT NULL,
                destinations TEXT NOT NULL,
                FOREIGN KEY (mac) REFERENCES devices(mac)
            );

            CREATE TABLE IF NOT EXISTS device_profiles (
                mac TEXT PRIMARY KEY,
                baseline_bytes_sent_per_hour_mean REAL NOT NULL,
                baseline_bytes_sent_per_hour_stddev REAL NOT NULL,
                known_destinations TEXT NOT NULL,
                active_hours TEXT NOT NULL,
                profile_built_at TEXT NOT NULL,
                observation_hours INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS anomalies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac TEXT NOT NULL,
                detected_at TEXT NOT NULL,
                kind TEXT NOT NULL,
                detail TEXT NOT NULL,
                resolved INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS device_ports (
                mac TEXT NOT NULL,
                port INTEGER NOT NULL,
                service TEXT NOT NULL,
                is_insecure INTEGER NOT NULL DEFAULT 0,
                discovered_at TEXT NOT NULL,
                PRIMARY KEY (mac, port)
            );

            CREATE TABLE IF NOT EXISTS threat_intel_ips (
                ip TEXT PRIMARY KEY,
                feed TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                confidence INTEGER NOT NULL,
                description TEXT NOT NULL,
                last_updated TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS blocked_domains (
                domain TEXT PRIMARY KEY,
                list_source TEXT NOT NULL,
                added_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS dns_queries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                client_ip TEXT NOT NULL,
                client_mac TEXT,
                domain TEXT NOT NULL,
                query_type TEXT NOT NULL,
                is_blocked INTEGER NOT NULL DEFAULT 0,
                block_reason TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_samples_mac_time ON traffic_samples(mac, timestamp);
            CREATE INDEX IF NOT EXISTS idx_anomalies_mac ON anomalies(mac);
            CREATE INDEX IF NOT EXISTS idx_ports_mac ON device_ports(mac);
            CREATE INDEX IF NOT EXISTS idx_threat_ips ON threat_intel_ips(ip);
            CREATE INDEX IF NOT EXISTS idx_blocked_domains ON blocked_domains(domain);
            CREATE INDEX IF NOT EXISTS idx_dns_queries_time ON dns_queries(timestamp);
            CREATE INDEX IF NOT EXISTS idx_dns_queries_domain ON dns_queries(domain);
            ",
        )
        .context("Failed to run database migrations")?;

        // Safely add is_quarantined if older database exists without it
        let _ = conn.execute(
            "ALTER TABLE devices ADD COLUMN is_quarantined INTEGER NOT NULL DEFAULT 0;",
            [],
        );

        Ok(())
    }

    /// Insert or update a device record.
    pub fn upsert_device(&self, device: &Device) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO devices (mac, ip, vendor, label, first_seen, last_seen, is_quarantined)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(mac) DO UPDATE SET
                ip = excluded.ip,
                vendor = COALESCE(excluded.vendor, devices.vendor),
                label = COALESCE(excluded.label, devices.label),
                first_seen = devices.first_seen,
                last_seen = excluded.last_seen,
                is_quarantined = COALESCE(devices.is_quarantined, excluded.is_quarantined)",
            params![
                device.mac,
                device.ip.to_string(),
                device.vendor,
                device.label,
                device.first_seen.to_rfc3339(),
                device.last_seen.to_rfc3339(),
                device.is_quarantined as i32,
            ],
        )?;
        Ok(())
    }

    /// Insert a new traffic sample, serializing destinations to JSON.
    pub fn insert_sample(&self, sample: &TrafficSample) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let destinations_json = serde_json::to_string(&sample.top_destinations)?;
        conn.execute(
            "INSERT INTO traffic_samples (mac, timestamp, bytes_sent, bytes_recv, destinations)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                sample.mac,
                sample.timestamp.to_rfc3339(),
                sample.bytes_sent as i64,
                sample.bytes_recv as i64,
                destinations_json,
            ],
        )?;
        Ok(())
    }

    /// Get all known devices, ordered by last_seen descending.
    pub fn get_all_devices(&self) -> Result<Vec<Device>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt =
            conn.prepare("SELECT mac, ip, vendor, label, first_seen, last_seen, is_quarantined FROM devices ORDER BY last_seen DESC")?;
        let devices = stmt
            .query_map([], |row| {
                let ip_str: String = row.get(1)?;
                let first_seen_str: String = row.get(4)?;
                let last_seen_str: String = row.get(5)?;
                let is_quarantined: i32 = row.get(6).unwrap_or(0);
                Ok(Device {
                    mac: row.get(0)?,
                    ip: ip_str
                        .parse()
                        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
                    vendor: row.get(2)?,
                    label: row.get(3)?,
                    first_seen: DateTime::parse_from_rfc3339(&first_seen_str)
                        .unwrap_or_default()
                        .with_timezone(&Utc),
                    last_seen: DateTime::parse_from_rfc3339(&last_seen_str)
                        .unwrap_or_default()
                        .with_timezone(&Utc),
                    is_quarantined: is_quarantined != 0,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(devices)
    }

    /// Get traffic samples for a specific device within the last N hours.
    pub fn get_samples_for_device(&self, mac: &str, hours: u32) -> Result<Vec<TrafficSample>> {
        let conn = self.conn.lock().unwrap();
        let cutoff = Utc::now() - chrono::Duration::hours(hours as i64);
        let mut stmt = conn.prepare(
            "SELECT id, mac, timestamp, bytes_sent, bytes_recv, destinations
             FROM traffic_samples
             WHERE mac = ?1 AND timestamp > ?2
             ORDER BY timestamp ASC",
        )?;
        let samples = stmt
            .query_map(params![mac, cutoff.to_rfc3339()], |row| {
                let ts_str: String = row.get(2)?;
                let dest_json: String = row.get(5)?;
                Ok(TrafficSample {
                    id: Some(row.get(0)?),
                    mac: row.get(1)?,
                    timestamp: DateTime::parse_from_rfc3339(&ts_str)
                        .unwrap_or_default()
                        .with_timezone(&Utc),
                    bytes_sent: row.get::<_, i64>(3)? as u64,
                    bytes_recv: row.get::<_, i64>(4)? as u64,
                    top_destinations: serde_json::from_str(&dest_json).unwrap_or_default(),
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(samples)
    }

    /// Get recent traffic samples across all devices within the last N hours.
    pub fn get_recent_samples(&self, hours: u32) -> Result<Vec<TrafficSample>> {
        let conn = self.conn.lock().unwrap();
        let cutoff = Utc::now() - chrono::Duration::hours(hours as i64);
        let mut stmt = conn.prepare(
            "SELECT id, mac, timestamp, bytes_sent, bytes_recv, destinations
             FROM traffic_samples
             WHERE timestamp > ?1
             ORDER BY timestamp ASC",
        )?;
        let samples = stmt
            .query_map(params![cutoff.to_rfc3339()], |row| {
                let ts_str: String = row.get(2)?;
                let dest_json: String = row.get(5)?;
                Ok(TrafficSample {
                    id: Some(row.get(0)?),
                    mac: row.get(1)?,
                    timestamp: DateTime::parse_from_rfc3339(&ts_str)
                        .unwrap_or_default()
                        .with_timezone(&Utc),
                    bytes_sent: row.get::<_, i64>(3)? as u64,
                    bytes_recv: row.get::<_, i64>(4)? as u64,
                    top_destinations: serde_json::from_str(&dest_json).unwrap_or_default(),
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(samples)
    }

    /// Get the device profile for a given MAC address.
    pub fn get_profile(&self, mac: &str) -> Result<Option<DeviceProfile>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT mac, baseline_bytes_sent_per_hour_mean, baseline_bytes_sent_per_hour_stddev,
                    known_destinations, active_hours, profile_built_at, observation_hours
             FROM device_profiles WHERE mac = ?1",
        )?;
        let mut rows = stmt.query_map(params![mac], |row| {
            let known_dest_json: String = row.get(3)?;
            let active_hours_json: String = row.get(4)?;
            let built_at_str: String = row.get(5)?;
            Ok(DeviceProfile {
                mac: row.get(0)?,
                baseline_bytes_sent_per_hour_mean: row.get(1)?,
                baseline_bytes_sent_per_hour_stddev: row.get(2)?,
                known_destinations: serde_json::from_str(&known_dest_json).unwrap_or_default(),
                active_hours: serde_json::from_str(&active_hours_json).unwrap_or_default(),
                profile_built_at: DateTime::parse_from_rfc3339(&built_at_str)
                    .unwrap_or_default()
                    .with_timezone(&Utc),
                observation_hours: row.get(6)?,
            })
        })?;
        match rows.next() {
            Some(Ok(profile)) => Ok(Some(profile)),
            Some(Err(e)) => Err(e.into()),
            None => Ok(None),
        }
    }

    /// Insert or update a device profile.
    pub fn upsert_profile(&self, profile: &DeviceProfile) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let known_dest_json = serde_json::to_string(&profile.known_destinations)?;
        let active_hours_json = serde_json::to_string(&profile.active_hours)?;
        conn.execute(
            "INSERT OR REPLACE INTO device_profiles
             (mac, baseline_bytes_sent_per_hour_mean, baseline_bytes_sent_per_hour_stddev,
              known_destinations, active_hours, profile_built_at, observation_hours)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                profile.mac,
                profile.baseline_bytes_sent_per_hour_mean,
                profile.baseline_bytes_sent_per_hour_stddev,
                known_dest_json,
                active_hours_json,
                profile.profile_built_at.to_rfc3339(),
                profile.observation_hours,
            ],
        )?;
        Ok(())
    }

    /// Insert a new anomaly, returning the new row ID.
    pub fn insert_anomaly(&self, anomaly: &Anomaly) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO anomalies (mac, detected_at, kind, detail, resolved)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                anomaly.mac,
                anomaly.detected_at.to_rfc3339(),
                anomaly.kind.to_string(),
                anomaly.detail,
                anomaly.resolved as i32,
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Get all unresolved anomalies.
    pub fn get_unresolved_anomalies(&self) -> Result<Vec<Anomaly>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, mac, detected_at, kind, detail, resolved
             FROM anomalies WHERE resolved = 0
             ORDER BY detected_at DESC",
        )?;
        let anomalies = stmt
            .query_map([], |row| {
                let ts_str: String = row.get(2)?;
                let kind_str: String = row.get(3)?;
                Ok(Anomaly {
                    id: Some(row.get(0)?),
                    mac: row.get(1)?,
                    detected_at: DateTime::parse_from_rfc3339(&ts_str)
                        .unwrap_or_default()
                        .with_timezone(&Utc),
                    kind: kind_str.parse().unwrap_or(AnomalyKind::ExcessiveUpload),
                    detail: row.get(4)?,
                    resolved: row.get::<_, i32>(5)? != 0,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(anomalies)
    }

    /// Get all anomalies for a specific device.
    pub fn get_anomalies_for_device(&self, mac: &str) -> Result<Vec<Anomaly>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, mac, detected_at, kind, detail, resolved
             FROM anomalies WHERE mac = ?1
             ORDER BY detected_at DESC",
        )?;
        let anomalies = stmt
            .query_map(params![mac], |row| {
                let ts_str: String = row.get(2)?;
                let kind_str: String = row.get(3)?;
                Ok(Anomaly {
                    id: Some(row.get(0)?),
                    mac: row.get(1)?,
                    detected_at: DateTime::parse_from_rfc3339(&ts_str)
                        .unwrap_or_default()
                        .with_timezone(&Utc),
                    kind: kind_str.parse().unwrap_or(AnomalyKind::ExcessiveUpload),
                    detail: row.get(4)?,
                    resolved: row.get::<_, i32>(5)? != 0,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(anomalies)
    }

    /// Mark an anomaly as resolved.
    pub fn resolve_anomaly(&self, id: i64) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE anomalies SET resolved = 1 WHERE id = ?1",
            params![id],
        )?;
        Ok(())
    }

    /// Delete traffic samples older than N days.
    pub fn prune_old_samples(&self, days: u32) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let cutoff = Utc::now() - chrono::Duration::days(days as i64);
        let deleted = conn.execute(
            "DELETE FROM traffic_samples WHERE timestamp < ?1",
            params![cutoff.to_rfc3339()],
        )?;
        tracing::info!(
            "Pruned {} old traffic samples (older than {} days)",
            deleted,
            days
        );
        Ok(())
    }

    /// Count anomalies for a given MAC address.
    pub fn count_anomalies_for_device(&self, mac: &str) -> Result<u32> {
        let conn = self.conn.lock().unwrap();
        let count: i32 = conn.query_row(
            "SELECT COUNT(*) FROM anomalies WHERE mac = ?1 AND resolved = 0",
            params![mac],
            |row| row.get(0),
        )?;
        Ok(count as u32)
    }

    /// Get the sum of bytes sent/recv for a device in the last N hours.
    pub fn get_device_bytes_last_hours(&self, mac: &str, hours: u32) -> Result<(u64, u64)> {
        let conn = self.conn.lock().unwrap();
        let cutoff = Utc::now() - chrono::Duration::hours(hours as i64);
        let result = conn.query_row(
            "SELECT COALESCE(SUM(bytes_sent), 0), COALESCE(SUM(bytes_recv), 0)
             FROM traffic_samples
             WHERE mac = ?1 AND timestamp > ?2",
            params![mac, cutoff.to_rfc3339()],
            |row| {
                let sent: i64 = row.get(0)?;
                let recv: i64 = row.get(1)?;
                Ok((sent as u64, recv as u64))
            },
        )?;
        Ok(result)
    }

    /// Get total bytes sent today across all devices.
    pub fn get_total_bytes_sent_today(&self) -> Result<u64> {
        let conn = self.conn.lock().unwrap();
        let today_start = Utc::now().date_naive().and_hms_opt(0, 0, 0).unwrap();
        let today_start_utc: DateTime<Utc> = DateTime::from_naive_utc_and_offset(today_start, Utc);
        let result: i64 = conn.query_row(
            "SELECT COALESCE(SUM(bytes_sent), 0) FROM traffic_samples WHERE timestamp > ?1",
            params![today_start_utc.to_rfc3339()],
            |row| row.get(0),
        )?;
        Ok(result as u64)
    }

    /// Get the MAC (or label) of the most active device today.
    pub fn get_most_active_device_today(&self) -> Result<Option<String>> {
        let conn = self.conn.lock().unwrap();
        let today_start = Utc::now().date_naive().and_hms_opt(0, 0, 0).unwrap();
        let today_start_utc: DateTime<Utc> = DateTime::from_naive_utc_and_offset(today_start, Utc);
        let result = conn.query_row(
            "SELECT t.mac, d.label FROM traffic_samples t
             LEFT JOIN devices d ON t.mac = d.mac
             WHERE t.timestamp > ?1
             GROUP BY t.mac
             ORDER BY SUM(t.bytes_sent + t.bytes_recv) DESC
             LIMIT 1",
            params![today_start_utc.to_rfc3339()],
            |row| {
                let mac: String = row.get(0)?;
                let label: Option<String> = row.get(1)?;
                Ok(label.unwrap_or(mac))
            },
        );
        match result {
            Ok(name) => Ok(Some(name)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Check if a device MAC is already known.
    pub fn device_exists(&self, mac: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT 1 FROM devices WHERE mac = ?1 LIMIT 1")?;
        let exists = stmt.exists(params![mac])?;
        Ok(exists)
    }

    /// Retrieve a single device by MAC address.
    pub fn get_device(&self, mac: &str) -> Result<Option<Device>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT mac, ip, vendor, label, first_seen, last_seen, is_quarantined FROM devices WHERE mac = ?1",
        )?;
        let mut rows = stmt.query_map(params![mac], |row| {
            let ip_str: String = row.get(1)?;
            let first_seen_str: String = row.get(4)?;
            let last_seen_str: String = row.get(5)?;
            let is_quarantined: i32 = row.get(6).unwrap_or(0);
            Ok(Device {
                mac: row.get(0)?,
                ip: ip_str
                    .parse()
                    .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
                vendor: row.get(2)?,
                label: row.get(3)?,
                first_seen: DateTime::parse_from_rfc3339(&first_seen_str)
                    .unwrap_or_default()
                    .with_timezone(&Utc),
                last_seen: DateTime::parse_from_rfc3339(&last_seen_str)
                    .unwrap_or_default()
                    .with_timezone(&Utc),
                is_quarantined: is_quarantined != 0,
            })
        })?;

        if let Some(res) = rows.next() {
            Ok(Some(res?))
        } else {
            Ok(None)
        }
    }

    /// Insert or update an open port for a device.
    pub fn upsert_device_port(&self, port: &DevicePort) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO device_ports (mac, port, service, is_insecure, discovered_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(mac, port) DO UPDATE SET
                service = excluded.service,
                is_insecure = excluded.is_insecure,
                discovered_at = excluded.discovered_at",
            params![
                port.mac,
                port.port as i32,
                port.service,
                port.is_insecure as i32,
                port.discovered_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    /// Get all open ports for a specific device.
    pub fn get_ports_for_device(&self, mac: &str) -> Result<Vec<DevicePort>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT mac, port, service, is_insecure, discovered_at FROM device_ports WHERE mac = ?1 ORDER BY port ASC",
        )?;
        let ports = stmt
            .query_map(params![mac], |row| {
                let disc_str: String = row.get(4)?;
                Ok(DevicePort {
                    mac: row.get(0)?,
                    port: row.get::<_, i32>(1)? as u16,
                    service: row.get(2)?,
                    is_insecure: row.get::<_, i32>(3)? != 0,
                    discovered_at: DateTime::parse_from_rfc3339(&disc_str)
                        .unwrap_or_default()
                        .with_timezone(&Utc),
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ports)
    }

    /// Get all discovered insecure ports across the network.
    pub fn get_all_insecure_ports(&self) -> Result<Vec<DevicePort>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT mac, port, service, is_insecure, discovered_at FROM device_ports WHERE is_insecure = 1 ORDER BY discovered_at DESC",
        )?;
        let ports = stmt
            .query_map([], |row| {
                let disc_str: String = row.get(4)?;
                Ok(DevicePort {
                    mac: row.get(0)?,
                    port: row.get::<_, i32>(1)? as u16,
                    service: row.get(2)?,
                    is_insecure: true,
                    discovered_at: DateTime::parse_from_rfc3339(&disc_str)
                        .unwrap_or_default()
                        .with_timezone(&Utc),
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ports)
    }

    /// Check if an unresolved anomaly of the same kind already exists for this device within the last N hours.
    pub fn has_recent_unresolved_anomaly(&self, mac: &str, kind: &AnomalyKind, hours: i64) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let cutoff = (Utc::now() - chrono::Duration::hours(hours)).to_rfc3339();
        let mut stmt = conn.prepare(
            "SELECT 1 FROM anomalies WHERE mac = ?1 AND kind = ?2 AND resolved = 0 AND detected_at > ?3 LIMIT 1",
        )?;
        let exists = stmt.exists(params![mac, kind.to_string(), cutoff])?;
        Ok(exists)
    }

    /// Update quarantine status for a device.
    pub fn set_device_quarantine(&self, mac: &str, quarantined: bool) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE devices SET is_quarantined = ?1 WHERE mac = ?2",
            params![quarantined as i32, mac],
        )?;
        Ok(())
    }

    /// Check if a device is currently quarantined.
    pub fn is_device_quarantined(&self, mac: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT is_quarantined FROM devices WHERE mac = ?1")?;
        let is_q: Option<i32> = stmt.query_row(params![mac], |row| row.get(0)).ok();
        Ok(is_q.unwrap_or(0) != 0)
    }

    /// Get all quarantined devices.
    pub fn get_quarantined_devices(&self) -> Result<Vec<Device>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT mac, ip, vendor, label, first_seen, last_seen, is_quarantined FROM devices WHERE is_quarantined = 1",
        )?;
        let devices = stmt
            .query_map([], |row| {
                let ip_str: String = row.get(1)?;
                let first_seen_str: String = row.get(4)?;
                let last_seen_str: String = row.get(5)?;
                Ok(Device {
                    mac: row.get(0)?,
                    ip: ip_str
                        .parse()
                        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
                    vendor: row.get(2)?,
                    label: row.get(3)?,
                    first_seen: DateTime::parse_from_rfc3339(&first_seen_str)
                        .unwrap_or_default()
                        .with_timezone(&Utc),
                    last_seen: DateTime::parse_from_rfc3339(&last_seen_str)
                        .unwrap_or_default()
                        .with_timezone(&Utc),
                    is_quarantined: true,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(devices)
    }

    /// Bulk upsert threat intelligence IPs within a transaction.
    pub fn upsert_threat_intel_ips(&self, entries: &[ThreatIntelEntry]) -> Result<usize> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        let mut count = 0;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO threat_intel_ips (ip, feed, threat_type, confidence, description, last_updated)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(ip) DO UPDATE SET
                    feed = excluded.feed,
                    threat_type = excluded.threat_type,
                    confidence = excluded.confidence,
                    description = excluded.description,
                    last_updated = excluded.last_updated",
            )?;

            for entry in entries {
                stmt.execute(params![
                    entry.ip,
                    entry.feed,
                    entry.threat_type,
                    entry.confidence as i32,
                    entry.description,
                    entry.last_updated.to_rfc3339(),
                ])?;
                count += 1;
            }
        }
        tx.commit()?;
        Ok(count)
    }

    /// Check if an IP is flagged in the threat intelligence database.
    pub fn is_ip_malicious(&self, ip: &str) -> Result<Option<ThreatIntelEntry>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT ip, feed, threat_type, confidence, description, last_updated FROM threat_intel_ips WHERE ip = ?1 LIMIT 1",
        )?;
        let mut rows = stmt.query_map(params![ip], |row| {
            let last_updated_str: String = row.get(5)?;
            Ok(ThreatIntelEntry {
                ip: row.get(0)?,
                feed: row.get(1)?,
                threat_type: row.get(2)?,
                confidence: row.get::<_, i32>(3)? as u8,
                description: row.get(4)?,
                last_updated: DateTime::parse_from_rfc3339(&last_updated_str)
                    .unwrap_or_default()
                    .with_timezone(&Utc),
            })
        })?;

        if let Some(res) = rows.next() {
            Ok(Some(res?))
        } else {
            Ok(None)
        }
    }

    /// Retrieve summary statistics for threat intelligence.
    pub fn get_threat_intel_stats(&self) -> Result<(usize, Vec<ThreatIntelEntry>)> {
        let conn = self.conn.lock().unwrap();
        let total: i64 = conn.query_row(
            "SELECT COUNT(*) FROM threat_intel_ips",
            [],
            |row| row.get(0),
        )?;

        let mut stmt = conn.prepare(
            "SELECT ip, feed, threat_type, confidence, description, last_updated FROM threat_intel_ips ORDER BY last_updated DESC LIMIT 50",
        )?;
        let recent = stmt
            .query_map([], |row| {
                let last_updated_str: String = row.get(5)?;
                Ok(ThreatIntelEntry {
                    ip: row.get(0)?,
                    feed: row.get(1)?,
                    threat_type: row.get(2)?,
                    confidence: row.get::<_, i32>(3)? as u8,
                    description: row.get(4)?,
                    last_updated: DateTime::parse_from_rfc3339(&last_updated_str)
                        .unwrap_or_default()
                        .with_timezone(&Utc),
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok((total as usize, recent))
    }

    /// Bulk upsert blocked domains within a transaction.
    pub fn upsert_blocked_domains(&self, domains: &[String], list_source: &str) -> Result<usize> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        let now = Utc::now().to_rfc3339();
        let mut count = 0;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO blocked_domains (domain, list_source, added_at)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(domain) DO UPDATE SET
                    list_source = excluded.list_source,
                    added_at = excluded.added_at",
            )?;

            for domain in domains {
                stmt.execute(params![domain.to_lowercase(), list_source, now])?;
                count += 1;
            }
        }
        tx.commit()?;
        Ok(count)
    }

    /// Check if a domain (or any of its parent zones) is blocked.
    pub fn is_domain_blocked(&self, domain: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let domain_lower = domain.to_lowercase().trim_end_matches('.').to_string();

        let mut stmt = conn.prepare("SELECT 1 FROM blocked_domains WHERE domain = ?1 LIMIT 1")?;
        if stmt.exists(params![domain_lower])? {
            return Ok(true);
        }

        // Check wildcard / parent domains e.g. "sub.example.com" -> "example.com"
        let parts: Vec<&str> = domain_lower.split('.').collect();
        if parts.len() > 2 {
            for i in 1..parts.len() - 1 {
                let parent = parts[i..].join(".");
                if stmt.exists(params![parent])? {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    /// Log a DNS query observation.
    pub fn insert_dns_query(&self, log: &DnsQueryLog) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO dns_queries (timestamp, client_ip, client_mac, domain, query_type, is_blocked, block_reason)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                log.timestamp.to_rfc3339(),
                log.client_ip.to_string(),
                log.client_mac,
                log.domain,
                log.query_type,
                log.is_blocked as i32,
                log.block_reason,
            ],
        )?;
        Ok(())
    }

    /// Retrieve recent DNS queries.
    pub fn get_recent_dns_queries(&self, limit: usize) -> Result<Vec<DnsQueryLog>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, timestamp, client_ip, client_mac, domain, query_type, is_blocked, block_reason
             FROM dns_queries ORDER BY id DESC LIMIT ?1",
        )?;
        let queries = stmt
            .query_map(params![limit as i64], |row| {
                let ts_str: String = row.get(1)?;
                let ip_str: String = row.get(2)?;
                Ok(DnsQueryLog {
                    id: Some(row.get(0)?),
                    timestamp: DateTime::parse_from_rfc3339(&ts_str)
                        .unwrap_or_default()
                        .with_timezone(&Utc),
                    client_ip: ip_str
                        .parse()
                        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
                    client_mac: row.get(3)?,
                    domain: row.get(4)?,
                    query_type: row.get(5)?,
                    is_blocked: row.get::<_, i32>(6)? != 0,
                    block_reason: row.get(7)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(queries)
    }

    /// Get summary stats for DNS sinkhole.
    pub fn get_dns_stats(&self) -> Result<DnsStats> {
        let conn = self.conn.lock().unwrap();
        let total_queries: i64 = conn
            .query_row("SELECT COUNT(*) FROM dns_queries", [], |row| row.get(0))
            .unwrap_or(0);
        let blocked_queries: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM dns_queries WHERE is_blocked = 1",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);
        let total_blocked_domains: i64 = conn
            .query_row("SELECT COUNT(*) FROM blocked_domains", [], |row| row.get(0))
            .unwrap_or(0);
        let last_query_time: Option<String> = conn
            .query_row(
                "SELECT timestamp FROM dns_queries ORDER BY id DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .ok();

        Ok(DnsStats {
            total_queries: total_queries as u64,
            blocked_queries: blocked_queries as u64,
            total_blocked_domains: total_blocked_domains as usize,
            last_query_time: last_query_time.and_then(|ts| {
                DateTime::parse_from_rfc3339(&ts)
                    .ok()
                    .map(|dt| dt.with_timezone(&Utc))
            }),
        })
    }
}
