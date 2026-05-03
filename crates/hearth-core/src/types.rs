use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// A discovered device on the local network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    /// MAC address in "AA:BB:CC:DD:EE:FF" format
    pub mac: String,
    /// IP address observed for this device
    pub ip: IpAddr,
    /// Vendor name from OUI lookup (e.g. "Philips Lighting BV")
    pub vendor: Option<String>,
    /// User-assigned friendly name, from config
    pub label: Option<String>,
    /// Timestamp when this device was first observed
    pub first_seen: DateTime<Utc>,
    /// Timestamp when this device was last observed
    pub last_seen: DateTime<Utc>,
}

/// One traffic observation — written to DB every 60 seconds per device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficSample {
    /// Database row ID (None for new records)
    pub id: Option<i64>,
    /// MAC address of the device
    pub mac: String,
    /// Timestamp of the sample
    pub timestamp: DateTime<Utc>,
    /// Bytes sent by this device in the sample window
    pub bytes_sent: u64,
    /// Bytes received by this device in the sample window
    pub bytes_recv: u64,
    /// Top 5 destinations by bytes
    pub top_destinations: Vec<Destination>,
}

/// A destination observed in traffic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Destination {
    /// Destination IP address
    pub ip: IpAddr,
    /// Resolved domain name from reverse DNS
    pub domain: Option<String>,
    /// Country code from GeoIP lookup (e.g. "US", "RU")
    pub country: Option<String>,
    /// Total bytes sent to this destination
    pub bytes: u64,
}

/// Anomaly flag produced by the stats engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anomaly {
    /// Database row ID (None for new records)
    pub id: Option<i64>,
    /// MAC address of the device that triggered the anomaly
    pub mac: String,
    /// When the anomaly was detected
    pub detected_at: DateTime<Utc>,
    /// Type of anomaly
    pub kind: AnomalyKind,
    /// Human-readable explanation
    pub detail: String,
    /// Whether the anomaly has been resolved/acknowledged
    pub resolved: bool,
}

/// Types of anomalies the stats engine can detect.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AnomalyKind {
    /// bytes_sent > 3σ above baseline
    ExcessiveUpload,
    /// IP never seen before for this device
    NewDestination,
    /// Traffic outside device's normal active hours
    UnusualHour,
    /// hearth-vad detected upload without wake word
    VoiceLeakSuspected,
}

impl std::fmt::Display for AnomalyKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnomalyKind::ExcessiveUpload => write!(f, "ExcessiveUpload"),
            AnomalyKind::NewDestination => write!(f, "NewDestination"),
            AnomalyKind::UnusualHour => write!(f, "UnusualHour"),
            AnomalyKind::VoiceLeakSuspected => write!(f, "VoiceLeakSuspected"),
        }
    }
}

impl std::str::FromStr for AnomalyKind {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ExcessiveUpload" => Ok(AnomalyKind::ExcessiveUpload),
            "NewDestination" => Ok(AnomalyKind::NewDestination),
            "UnusualHour" => Ok(AnomalyKind::UnusualHour),
            "VoiceLeakSuspected" => Ok(AnomalyKind::VoiceLeakSuspected),
            _ => Err(anyhow::anyhow!("Unknown AnomalyKind: {}", s)),
        }
    }
}

/// Device profile — built from 72h of observation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceProfile {
    /// MAC address
    pub mac: String,
    /// Mean bytes sent per hour over observation window
    pub baseline_bytes_sent_per_hour_mean: f64,
    /// Standard deviation of bytes sent per hour
    pub baseline_bytes_sent_per_hour_stddev: f64,
    /// Known destination IP strings
    pub known_destinations: Vec<String>,
    /// Hours (0-23) when device is normally active
    pub active_hours: Vec<u8>,
    /// When this profile was last built
    pub profile_built_at: DateTime<Utc>,
    /// Total hours of observation — must be >= 72 for mature profile
    pub observation_hours: u32,
}

/// Runtime config, loaded from hearth.toml.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Network interface to capture on (e.g. "eth0", "wlan0")
    pub interface: String,
    /// Port for the web dashboard (default 7777)
    #[serde(default = "default_dashboard_port")]
    pub dashboard_port: u16,
    /// Path to SQLite database file
    #[serde(default = "default_db_path")]
    pub db_path: String,
    /// Path to OUI CSV database for vendor lookup
    #[serde(default = "default_oui_db_path")]
    pub oui_db_path: String,
    /// Path to GeoLite2 MMDB database for country lookup
    #[serde(default = "default_geoip_db_path")]
    pub geoip_db_path: String,
    /// Per-device configuration
    #[serde(default)]
    pub devices: Vec<DeviceConfig>,
}

/// Per-device configuration from hearth.toml.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceConfig {
    /// MAC address of the device
    pub mac: String,
    /// Friendly label for the device
    pub label: String,
    /// Optional hard limit for upload per hour in MB
    pub max_upload_per_hour_mb: Option<f64>,
    /// Optional block hours range, e.g. ["23:00", "06:00"]
    pub block_hours: Option<[String; 2]>,
    /// Optional list of allowed domains — if set, all other destinations are blocked
    #[serde(default)]
    pub allow_domains: Option<Vec<String>>,
}

fn default_dashboard_port() -> u16 {
    7777
}

fn default_db_path() -> String {
    if cfg!(windows) {
        "./hearth.db".to_string()
    } else {
        "/var/lib/hearth/hearth.db".to_string()
    }
}

fn default_oui_db_path() -> String {
    if cfg!(windows) {
        "./oui.csv".to_string()
    } else {
        "/var/lib/hearth/oui.csv".to_string()
    }
}

fn default_geoip_db_path() -> String {
    if cfg!(windows) {
        "./GeoLite2-Country.mmdb".to_string()
    } else {
        "/var/lib/hearth/GeoLite2-Country.mmdb".to_string()
    }
}
