use crate::types::Config;
use anyhow::{Context, Result};
use std::path::Path;

/// Load and parse the Hearth configuration from a TOML file.
///
/// Falls back to sensible defaults for optional fields.
pub fn load_config(path: &str) -> Result<Config> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read config file: {}", path))?;
    let config: Config =
        toml::from_str(&contents).with_context(|| format!("Failed to parse config: {}", path))?;
    Ok(config)
}

/// Create a default config suitable for development/testing.
pub fn default_config() -> Config {
    Config {
        interface: detect_default_interface(),
        dashboard_port: 7777,
        subnet: None,
        api_key: None,
        gateway_ip: None,
        gateway_mac: None,
        db_path: if cfg!(windows) {
            "./hearth.db".to_string()
        } else {
            "/var/lib/hearth/hearth.db".to_string()
        },
        oui_db_path: if cfg!(windows) {
            "./oui.csv".to_string()
        } else {
            "/var/lib/hearth/oui.csv".to_string()
        },
        geoip_db_path: if cfg!(windows) {
            "./GeoLite2-Country.mmdb".to_string()
        } else {
            "/var/log/hearth/GeoLite2-Country.mmdb".to_string()
        },
        pcap_capture_enabled: true,
        captures_dir: if cfg!(windows) {
            "./captures".to_string()
        } else {
            "/var/log/hearth/captures".to_string()
        },
        fleet: Default::default(),
        notifications: Default::default(),
        threat_intel: Default::default(),
        dns: Default::default(),
        ai_analyst: Default::default(),
        devices: Vec::new(),
    }
}

/// Helper to generate or load a secure persistent API key when none is specified.
fn get_or_generate_api_key() -> String {
    if let Ok(env_key) = std::env::var("HEARTH_API_KEY") {
        let trimmed = env_key.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }

    let key_file = Path::new("./.hearth_api_key");
    if key_file.exists() {
        if let Ok(saved) = std::fs::read_to_string(key_file) {
            let trimmed = saved.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }

    // Generate high-entropy key from timestamp, PID and memory layout
    let seed = format!(
        "{}:{}:{:p}:{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
        std::process::id(),
        &key_file,
        std::time::Instant::now().elapsed().as_nanos()
    );
    let key = crate::ja3::md5_hex(seed.as_bytes());
    if let Err(e) = std::fs::write(key_file, &key) {
        tracing::warn!("Failed to persist auto-generated API key to {:?}: {}", key_file, e);
    }
    tracing::warn!(
        "[SECURITY NOTICE] No API key specified in configuration. Auto-generated administrative API key: '{}' (Saved to ./.hearth_api_key)",
        key
    );
    key
}

/// Try to load config from path, falling back to defaults if file doesn't exist.
pub fn load_or_default(path: &str) -> Config {
    let mut config = if Path::new(path).exists() {
        match load_config(path) {
            Ok(config) => {
                tracing::info!("Loaded config from {}", path);
                config
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to load config from {}: {}. Using defaults.",
                    path,
                    e
                );
                default_config()
            }
        }
    } else {
        tracing::info!("Config file not found at {}. Using defaults.", path);
        default_config()
    };

    if config.api_key.as_deref().unwrap_or("").trim().is_empty() {
        config.api_key = Some(get_or_generate_api_key());
    }

    config
}

/// Auto-detect the primary network interface name.
fn detect_default_interface() -> String {
    #[cfg(windows)]
    {
        // On Windows, pnet uses adapter names like "\\Device\\NPF_{GUID}"
        // Try to find the first non-loopback interface
        use pnet::datalink;
        if let Some(iface) = datalink::interfaces()
            .into_iter()
            .find(|i| i.is_up() && !i.is_loopback() && !i.ips.is_empty())
        {
            return iface.name;
        }
        "Ethernet".to_string()
    }
    #[cfg(not(windows))]
    {
        use pnet::datalink;
        if let Some(iface) = datalink::interfaces()
            .into_iter()
            .find(|i| i.is_up() && !i.is_loopback() && !i.ips.is_empty())
        {
            return iface.name;
        }
        "eth0".to_string()
    }
}
