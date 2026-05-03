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
            "/var/lib/hearth/GeoLite2-Country.mmdb".to_string()
        },
        devices: Vec::new(),
    }
}

/// Try to load config from path, falling back to defaults if file doesn't exist.
pub fn load_or_default(path: &str) -> Config {
    if Path::new(path).exists() {
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
    }
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
