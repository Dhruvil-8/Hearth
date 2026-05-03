use chrono::{DateTime, NaiveTime, Utc};
use hearth_core::store::Store;
use hearth_core::types::Config;
use serde::Serialize;
use std::net::IpAddr;
use std::sync::Arc;

/// Rule enforcement engine — evaluates config rules and generates nftables commands.
pub struct RulesEngine {
    config: Config,
    store: Arc<Store>,
}

/// An action to be applied via nftables.
#[derive(Debug, Clone, Serialize)]
pub struct RuleAction {
    pub mac: String,
    pub action: ActionKind,
    pub reason: String,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Types of enforcement actions.
#[derive(Debug, Clone, Serialize)]
pub enum ActionKind {
    BlockOutbound { destination: Option<IpAddr> },
    RateLimit { max_bytes_per_second: u64 },
    AllowOnly { domains: Vec<String> },
}

impl RulesEngine {
    /// Create a new rules engine with the given config and store.
    pub fn new(config: Config, store: Arc<Store>) -> Self {
        Self { config, store }
    }

    /// Evaluate all device rules and return actions to apply.
    /// Called every 60 seconds.
    pub async fn evaluate(&self) -> anyhow::Result<Vec<RuleAction>> {
        let mut actions = Vec::new();
        let now = Utc::now();

        for dev_cfg in &self.config.devices {
            // Check block_hours rule
            if let Some(ref hours) = dev_cfg.block_hours {
                if is_within_block_hours(&hours[0], &hours[1], &now) {
                    actions.push(RuleAction {
                        mac: dev_cfg.mac.clone(),
                        action: ActionKind::BlockOutbound { destination: None },
                        reason: format!("Blocked during hours {} — {}", hours[0], hours[1]),
                        expires_at: None,
                    });
                    continue; // Don't apply other rules if fully blocked
                }
            }

            // Check max_upload_per_hour_mb rule
            if let Some(max_mb) = dev_cfg.max_upload_per_hour_mb {
                let (sent, _) = self.store.get_device_bytes_last_hours(&dev_cfg.mac, 1)?;
                let sent_mb = sent as f64 / (1024.0 * 1024.0);
                if sent_mb > max_mb {
                    let limit_bps = (max_mb * 1024.0 * 1024.0 / 3600.0) as u64;
                    actions.push(RuleAction {
                        mac: dev_cfg.mac.clone(),
                        action: ActionKind::RateLimit {
                            max_bytes_per_second: limit_bps,
                        },
                        reason: format!(
                            "Upload limit exceeded: {:.1} MB > {:.0} MB/hr",
                            sent_mb, max_mb
                        ),
                        expires_at: None,
                    });
                }
            }

            // Check allow_domains rule
            if let Some(ref domains) = dev_cfg.allow_domains {
                if !domains.is_empty() {
                    actions.push(RuleAction {
                        mac: dev_cfg.mac.clone(),
                        action: ActionKind::AllowOnly {
                            domains: domains.clone(),
                        },
                        reason: format!("Only allowed: {}", domains.join(", ")),
                        expires_at: None,
                    });
                }
            }
        }

        Ok(actions)
    }

    /// Apply rule actions by generating nftables commands.
    /// On Linux: shells out to `nft`. On other platforms: logs only.
    pub fn apply(&self, actions: &[RuleAction]) -> anyhow::Result<()> {
        if actions.is_empty() {
            return Ok(());
        }

        let mut commands = Vec::new();

        // Always flush and reapply from scratch
        commands.push("nft flush chain inet hearth forward".to_string());

        for action in actions {
            let cmd = match &action.action {
                ActionKind::BlockOutbound { destination: None } => {
                    format!(
                        "nft add rule inet hearth forward ether saddr {} drop",
                        action.mac
                    )
                }
                ActionKind::BlockOutbound {
                    destination: Some(ip),
                } => {
                    format!(
                        "nft add rule inet hearth forward ether saddr {} ip daddr {} drop",
                        action.mac, ip
                    )
                }
                ActionKind::RateLimit {
                    max_bytes_per_second,
                } => {
                    let kbps = max_bytes_per_second / 1024;
                    format!(
                        "nft add rule inet hearth forward ether saddr {} limit rate {} kbytes/second accept",
                        action.mac, kbps.max(1)
                    )
                }
                ActionKind::AllowOnly { domains: _ } => {
                    // Domain-based filtering would need DNS-based resolution
                    // For now, log the intent
                    format!(
                        "# Allow-only rule for {} — requires DNS resolution",
                        action.mac
                    )
                }
            };
            commands.push(cmd);
        }

        // Execute commands
        #[cfg(target_os = "linux")]
        {
            for cmd in &commands {
                if cmd.starts_with('#') {
                    continue;
                }
                tracing::info!("nftables: {}", cmd);
                let output = std::process::Command::new("sh").arg("-c").arg(cmd).output();
                match output {
                    Ok(o) if o.status.success() => {}
                    Ok(o) => tracing::error!(
                        "nft command failed: {}",
                        String::from_utf8_lossy(&o.stderr)
                    ),
                    Err(e) => tracing::error!("Failed to execute nft: {}", e),
                }
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            for cmd in &commands {
                tracing::info!("[DRY RUN] nftables: {}", cmd);
            }
        }

        Ok(())
    }

    /// Generate nftables commands as strings (for testing).
    pub fn generate_commands(&self, actions: &[RuleAction]) -> Vec<String> {
        let mut commands = vec!["nft flush chain inet hearth forward".to_string()];
        for action in actions {
            let cmd = match &action.action {
                ActionKind::BlockOutbound { destination: None } => {
                    format!(
                        "nft add rule inet hearth forward ether saddr {} drop",
                        action.mac
                    )
                }
                ActionKind::BlockOutbound {
                    destination: Some(ip),
                } => {
                    format!(
                        "nft add rule inet hearth forward ether saddr {} ip daddr {} drop",
                        action.mac, ip
                    )
                }
                ActionKind::RateLimit {
                    max_bytes_per_second,
                } => {
                    format!("nft add rule inet hearth forward ether saddr {} limit rate {} kbytes/second accept",
                        action.mac, max_bytes_per_second / 1024)
                }
                ActionKind::AllowOnly { .. } => format!("# allow-only for {}", action.mac),
            };
            commands.push(cmd);
        }
        commands
    }
}

/// Check if the current time is within a block hours range.
fn is_within_block_hours(start: &str, end: &str, now: &DateTime<Utc>) -> bool {
    let start_time = match NaiveTime::parse_from_str(start, "%H:%M") {
        Ok(t) => t,
        Err(_) => return false,
    };
    let end_time = match NaiveTime::parse_from_str(end, "%H:%M") {
        Ok(t) => t,
        Err(_) => return false,
    };
    let current_time = now.time();

    if start_time <= end_time {
        // Same-day range (e.g., 09:00 — 17:00)
        current_time >= start_time && current_time < end_time
    } else {
        // Overnight range (e.g., 23:00 — 06:00)
        current_time >= start_time || current_time < end_time
    }
}

/// Initialize the hearth nftables table (Linux only).
pub fn init_nftables() -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let cmds = [
            "nft add table inet hearth",
            "nft add chain inet hearth forward { type filter hook forward priority 0 \\; }",
        ];
        for cmd in &cmds {
            tracing::info!("nftables init: {}", cmd);
            std::process::Command::new("sh")
                .arg("-c")
                .arg(cmd)
                .output()?;
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        tracing::info!("[DRY RUN] nftables initialization skipped (not Linux)");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_hours_overnight() {
        // 23:00 — 06:00 should block at midnight
        let midnight = chrono::NaiveDate::from_ymd_opt(2025, 1, 1)
            .unwrap()
            .and_hms_opt(0, 30, 0)
            .unwrap();
        let midnight_utc = DateTime::<Utc>::from_naive_utc_and_offset(midnight, Utc);
        assert!(is_within_block_hours("23:00", "06:00", &midnight_utc));
    }

    #[test]
    fn test_block_hours_daytime() {
        let noon = chrono::NaiveDate::from_ymd_opt(2025, 1, 1)
            .unwrap()
            .and_hms_opt(12, 0, 0)
            .unwrap();
        let noon_utc = DateTime::<Utc>::from_naive_utc_and_offset(noon, Utc);
        assert!(!is_within_block_hours("23:00", "06:00", &noon_utc));
    }

    #[test]
    fn test_generate_block_command() {
        let config = Config {
            interface: "eth0".into(),
            dashboard_port: 7777,
            db_path: ":memory:".into(),
            oui_db_path: "".into(),
            geoip_db_path: "".into(),
            devices: vec![],
        };
        let store = Arc::new(Store::new(":memory:").unwrap());
        let engine = RulesEngine::new(config, store);

        let actions = vec![RuleAction {
            mac: "AA:BB:CC:DD:EE:FF".into(),
            action: ActionKind::BlockOutbound { destination: None },
            reason: "Test".into(),
            expires_at: None,
        }];

        let cmds = engine.generate_commands(&actions);
        assert_eq!(cmds.len(), 2);
        assert!(cmds[0].contains("flush"));
        assert!(cmds[1].contains("AA:BB:CC:DD:EE:FF"));
        assert!(cmds[1].contains("drop"));
    }
}
