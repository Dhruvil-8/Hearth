use crate::capture::DeviceSnapshot;
use crate::store::Store;
use crate::types::{Anomaly, AnomalyKind, DeviceProfile};
use chrono::Utc;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Stats engine — builds profiles and detects anomalies.
pub struct StatsEngine {
    store: Arc<Store>,
    anomaly_tx: mpsc::Sender<Anomaly>,
}

impl StatsEngine {
    pub fn new(store: Arc<Store>, anomaly_tx: mpsc::Sender<Anomaly>) -> Self {
        Self { store, anomaly_tx }
    }

    pub async fn process_new_samples(&self, snapshots: &[DeviceSnapshot]) -> anyhow::Result<()> {
        for snap in snapshots {
            let _ = self.rebuild_profile(&snap.mac).await;
            let _ = self.detect_anomalies(snap).await;
        }
        Ok(())
    }

    async fn rebuild_profile(&self, mac: &str) -> anyhow::Result<()> {
        let samples = self.store.get_samples_for_device(mac, 168)?;
        if samples.is_empty() {
            return Ok(());
        }

        let mut hours_seen: HashSet<i64> = HashSet::new();
        let mut hourly_bytes: HashMap<u8, Vec<u64>> = HashMap::new();
        let mut all_dests: HashSet<String> = HashSet::new();
        let mut active_hrs: HashSet<u8> = HashSet::new();

        for s in &samples {
            hours_seen.insert(s.timestamp.timestamp() / 3600);
            let h = s
                .timestamp
                .format("%H")
                .to_string()
                .parse::<u8>()
                .unwrap_or(0);
            hourly_bytes.entry(h).or_default().push(s.bytes_sent);
            if s.bytes_sent > 0 {
                active_hrs.insert(h);
            }
            for d in &s.top_destinations {
                if !is_private_ip(&d.ip) {
                    all_dests.insert(d.ip.to_string());
                }
            }
        }

        let obs = hours_seen.len() as u32;
        let avgs: Vec<f64> = hourly_bytes
            .values()
            .map(|v| v.iter().sum::<u64>() as f64 / v.len().max(1) as f64)
            .collect();
        let mean = if avgs.is_empty() {
            0.0
        } else {
            avgs.iter().sum::<f64>() / avgs.len() as f64
        };
        let stddev = if avgs.len() < 2 {
            0.0
        } else {
            (avgs.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (avgs.len() - 1) as f64).sqrt()
        };

        let mut ah: Vec<u8> = active_hrs.into_iter().collect();
        ah.sort();

        self.store.upsert_profile(&DeviceProfile {
            mac: mac.to_string(),
            baseline_bytes_sent_per_hour_mean: mean,
            baseline_bytes_sent_per_hour_stddev: stddev,
            known_destinations: all_dests.into_iter().collect(),
            active_hours: ah,
            profile_built_at: Utc::now(),
            observation_hours: obs,
        })?;
        Ok(())
    }

    async fn detect_anomalies(&self, snap: &DeviceSnapshot) -> anyhow::Result<()> {
        let profile = match self.store.get_profile(&snap.mac)? {
            Some(p) if p.observation_hours >= 72 => p,
            _ => return Ok(()),
        };

        // ExcessiveUpload
        let thresh = profile.baseline_bytes_sent_per_hour_mean
            + 3.0 * profile.baseline_bytes_sent_per_hour_stddev;
        if thresh > 0.0 && snap.bytes_sent as f64 > thresh {
            self.emit(Anomaly {
                id: None,
                mac: snap.mac.clone(),
                detected_at: Utc::now(),
                kind: AnomalyKind::ExcessiveUpload,
                detail: format!(
                    "Uploaded {} bytes — {:.1}x above baseline",
                    snap.bytes_sent,
                    snap.bytes_sent as f64 / profile.baseline_bytes_sent_per_hour_mean.max(1.0)
                ),
                resolved: false,
            })
            .await?;
        }

        // NewDestination
        let known: HashSet<&str> = profile
            .known_destinations
            .iter()
            .map(|s| s.as_str())
            .collect();
        for (ip, _) in &snap.destinations {
            if !is_private_ip(ip) && !known.contains(ip.to_string().as_str()) {
                self.emit(Anomaly {
                    id: None,
                    mac: snap.mac.clone(),
                    detected_at: Utc::now(),
                    kind: AnomalyKind::NewDestination,
                    detail: format!("New destination: {}", ip),
                    resolved: false,
                })
                .await?;
            }
        }

        // UnusualHour
        let h = Utc::now()
            .format("%H")
            .to_string()
            .parse::<u8>()
            .unwrap_or(0);
        if !profile.active_hours.contains(&h) && (snap.bytes_sent + snap.bytes_recv) > 1000 {
            self.emit(Anomaly {
                id: None,
                mac: snap.mac.clone(),
                detected_at: Utc::now(),
                kind: AnomalyKind::UnusualHour,
                detail: format!("Active at {}:00 — outside normal hours", h),
                resolved: false,
            })
            .await?;
        }

        Ok(())
    }

    async fn emit(&self, a: Anomaly) -> anyhow::Result<()> {
        tracing::warn!("ANOMALY [{}] {}: {}", a.kind, a.mac, a.detail);
        let id = self.store.insert_anomaly(&a)?;
        let mut stored = a;
        stored.id = Some(id);
        let _ = self.anomaly_tx.send(stored).await;
        Ok(())
    }
}

/// Weekly digest.
#[derive(Debug, Clone, serde::Serialize)]
pub struct WeeklyDigest {
    pub period_start: chrono::DateTime<Utc>,
    pub period_end: chrono::DateTime<Utc>,
    pub total_anomalies: u32,
    pub most_active_device: Option<String>,
    pub top_destinations_by_country: Vec<(String, u64)>,
    pub new_devices_seen: Vec<crate::types::Device>,
    pub highlights: Vec<String>,
}

pub fn generate_weekly_digest(store: &Store) -> anyhow::Result<WeeklyDigest> {
    let now = Utc::now();
    let start = now - chrono::Duration::days(7);
    let samples = store.get_recent_samples(168)?;
    let devices = store.get_all_devices()?;
    let anomalies = store.get_unresolved_anomalies()?;

    let mut dev_bytes: HashMap<String, u64> = HashMap::new();
    let mut country_bytes: HashMap<String, u64> = HashMap::new();
    for s in &samples {
        *dev_bytes.entry(s.mac.clone()).or_default() += s.bytes_sent + s.bytes_recv;
        for d in &s.top_destinations {
            if let Some(ref c) = d.country {
                *country_bytes.entry(c.clone()).or_default() += d.bytes;
            }
        }
    }

    let most_active = dev_bytes.iter().max_by_key(|(_, b)| *b).map(|(m, _)| {
        devices
            .iter()
            .find(|d| d.mac == *m)
            .and_then(|d| d.label.clone())
            .unwrap_or_else(|| m.clone())
    });

    let mut top_c: Vec<(String, u64)> = country_bytes.into_iter().collect();
    top_c.sort_by(|a, b| b.1.cmp(&a.1));
    top_c.truncate(5);

    let new_devs: Vec<_> = devices
        .iter()
        .filter(|d| d.first_seen >= start)
        .cloned()
        .collect();

    let mut highlights = Vec::new();
    for a in anomalies.iter().take(5) {
        let lbl = devices
            .iter()
            .find(|d| d.mac == a.mac)
            .and_then(|d| d.label.clone())
            .unwrap_or_else(|| a.mac.clone());
        let h = match &a.kind {
            AnomalyKind::ExcessiveUpload => format!(
                "{} had excessive uploads on {}",
                lbl,
                a.detected_at.format("%A at %-I%P")
            ),
            AnomalyKind::NewDestination => format!("{} connected to a new server", lbl),
            AnomalyKind::UnusualHour => format!("{} was active at unusual hours", lbl),
            AnomalyKind::VoiceLeakSuspected => format!("{} may have leaked audio", lbl),
        };
        highlights.push(h);
    }

    Ok(WeeklyDigest {
        period_start: start,
        period_end: now,
        total_anomalies: anomalies.len() as u32,
        most_active_device: most_active,
        top_destinations_by_country: top_c,
        new_devices_seen: new_devs,
        highlights,
    })
}

fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}
