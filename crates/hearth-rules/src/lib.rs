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
    Quarantine,
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

        // Apply strict quarantine isolation rules
        if let Ok(quarantined) = self.store.get_quarantined_devices() {
            for q_dev in quarantined {
                actions.push(RuleAction {
                    mac: q_dev.mac.clone(),
                    action: ActionKind::Quarantine,
                    reason: "Emergency device quarantine isolation active".to_string(),
                    expires_at: None,
                });
            }
        }

        Ok(actions)
    }

    /// Apply rule actions by generating and executing nftables commands.
    /// Executes `nft` directly with parameterized arguments (no shell interpreter invocation to prevent injection).
    pub fn apply(&self, actions: &[RuleAction]) -> anyhow::Result<()> {
        if actions.is_empty() {
            return Ok(());
        }

        let mut nft_arg_lists: Vec<Vec<String>> = Vec::new();

        // Always flush forward and input chains and reapply from scratch
        nft_arg_lists.push(vec![
            "flush".into(),
            "chain".into(),
            "inet".into(),
            "hearth".into(),
            "forward".into(),
        ]);
        nft_arg_lists.push(vec![
            "flush".into(),
            "chain".into(),
            "inet".into(),
            "hearth".into(),
            "input".into(),
        ]);

        for action in actions {
            // Strict MAC address format validation to prevent injection
            if !is_valid_mac(&action.mac) {
                tracing::error!("Invalid MAC address format in rule action: '{}'", action.mac);
                continue;
            }

            match &action.action {
                ActionKind::BlockOutbound { destination: None } | ActionKind::Quarantine => {
                    // Drop transit forwarding traffic
                    nft_arg_lists.push(vec![
                        "add".into(),
                        "rule".into(),
                        "inet".into(),
                        "hearth".into(),
                        "forward".into(),
                        "ether".into(),
                        "saddr".into(),
                        action.mac.clone(),
                        "drop".into(),
                    ]);
                    // Drop incoming packets destined to Hearth daemon / host
                    nft_arg_lists.push(vec![
                        "add".into(),
                        "rule".into(),
                        "inet".into(),
                        "hearth".into(),
                        "input".into(),
                        "ether".into(),
                        "saddr".into(),
                        action.mac.clone(),
                        "drop".into(),
                    ]);
                }
                ActionKind::BlockOutbound {
                    destination: Some(ip),
                } => {
                    nft_arg_lists.push(vec![
                        "add".into(),
                        "rule".into(),
                        "inet".into(),
                        "hearth".into(),
                        "forward".into(),
                        "ether".into(),
                        "saddr".into(),
                        action.mac.clone(),
                        "ip".into(),
                        "daddr".into(),
                        ip.to_string(),
                        "drop".into(),
                    ]);
                }
                ActionKind::RateLimit {
                    max_bytes_per_second,
                } => {
                    let kbps = (max_bytes_per_second / 1024).max(1);
                    nft_arg_lists.push(vec![
                        "add".into(),
                        "rule".into(),
                        "inet".into(),
                        "hearth".into(),
                        "forward".into(),
                        "ether".into(),
                        "saddr".into(),
                        action.mac.clone(),
                        "limit".into(),
                        "rate".into(),
                        format!("{}/kbytes/second", kbps),
                        "accept".into(),
                    ]);
                }
                ActionKind::AllowOnly { domains } => {
                    use std::net::ToSocketAddrs;
                    tracing::info!(
                        "Enforcing AllowOnly domain rules for {} ({} domains)",
                        action.mac,
                        domains.len()
                    );
                    // Allow DNS resolution (UDP & TCP 53) ONLY to local private subnets (RFC 1918)
                    // Prevents WAN egress tunneling over port 53 while allowing local DNS sinkhole
                    for private_net in &["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"] {
                        nft_arg_lists.push(vec![
                            "add".into(),
                            "rule".into(),
                            "inet".into(),
                            "hearth".into(),
                            "forward".into(),
                            "ether".into(),
                            "saddr".into(),
                            action.mac.clone(),
                            "ip".into(),
                            "daddr".into(),
                            (*private_net).into(),
                            "udp".into(),
                            "dport".into(),
                            "53".into(),
                            "accept".into(),
                        ]);
                        nft_arg_lists.push(vec![
                            "add".into(),
                            "rule".into(),
                            "inet".into(),
                            "hearth".into(),
                            "forward".into(),
                            "ether".into(),
                            "saddr".into(),
                            action.mac.clone(),
                            "ip".into(),
                            "daddr".into(),
                            (*private_net).into(),
                            "tcp".into(),
                            "dport".into(),
                            "53".into(),
                            "accept".into(),
                        ]);
                    }

                    // Resolve domains to IPs and permit them
                    for domain in domains {
                        if let Ok(addrs) = format!("{}:80", domain).to_socket_addrs() {
                            for socket_addr in addrs {
                                let ip = socket_addr.ip();
                                nft_arg_lists.push(vec![
                                    "add".into(),
                                    "rule".into(),
                                    "inet".into(),
                                    "hearth".into(),
                                    "forward".into(),
                                    "ether".into(),
                                    "saddr".into(),
                                    action.mac.clone(),
                                    "ip".into(),
                                    "daddr".into(),
                                    ip.to_string(),
                                    "accept".into(),
                                ]);
                            }
                        }
                    }

                    // Default drop all other forward traffic from this restricted MAC
                    nft_arg_lists.push(vec![
                        "add".into(),
                        "rule".into(),
                        "inet".into(),
                        "hearth".into(),
                        "forward".into(),
                        "ether".into(),
                        "saddr".into(),
                        action.mac.clone(),
                        "drop".into(),
                    ]);
                }
            }
        }

        // Execute commands directly without shell
        #[cfg(target_os = "linux")]
        {
            for args in &nft_arg_lists {
                tracing::info!("Executing nft: {:?}", args);
                let output = std::process::Command::new("nft").args(args).output();
                match output {
                    Ok(o) if o.status.success() => {}
                    Ok(o) => tracing::error!(
                        "nft command {:?} failed: {}",
                        args,
                        String::from_utf8_lossy(&o.stderr)
                    ),
                    Err(e) => tracing::error!("Failed to execute nft {:?}: {}", args, e),
                }
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            for args in &nft_arg_lists {
                tracing::info!("[DRY RUN] nft {:?}", args);
            }
        }

        Ok(())
    }

    /// Generate nftables commands as strings (for testing).
    pub fn generate_commands(&self, actions: &[RuleAction]) -> Vec<String> {
        let mut commands = vec![
            "nft flush chain inet hearth forward".to_string(),
            "nft flush chain inet hearth input".to_string(),
        ];
        for action in actions {
            match &action.action {
                ActionKind::BlockOutbound { destination: None } => {
                    commands.push(format!(
                        "nft add rule inet hearth forward ether saddr {} drop",
                        action.mac
                    ));
                    commands.push(format!(
                        "nft add rule inet hearth input ether saddr {} drop",
                        action.mac
                    ));
                }
                ActionKind::Quarantine => {
                    commands.push(format!(
                        "nft add rule inet hearth forward ether saddr {} drop",
                        action.mac
                    ));
                    commands.push(format!(
                        "nft add rule inet hearth input ether saddr {} drop",
                        action.mac
                    ));
                }
                ActionKind::BlockOutbound {
                    destination: Some(ip),
                } => {
                    commands.push(format!(
                        "nft add rule inet hearth forward ether saddr {} ip daddr {} drop",
                        action.mac, ip
                    ));
                }
                ActionKind::RateLimit {
                    max_bytes_per_second,
                } => {
                    commands.push(format!(
                        "nft add rule inet hearth forward ether saddr {} limit rate {} kbytes/second accept",
                        action.mac, max_bytes_per_second / 1024
                    ));
                }
                ActionKind::AllowOnly { domains } => {
                    commands.push(format!(
                        "nft add rule inet hearth forward ether saddr {} drop # allow-only: {}",
                        action.mac,
                        domains.join(", ")
                    ));
                }
            }
        }
        commands
    }

    /// Immediately quarantine a device by MAC address and reapply firewall rules.
    pub async fn quarantine_device(&self, mac: &str) -> anyhow::Result<()> {
        self.store.set_device_quarantine(mac, true)?;
        let actions = self.evaluate().await?;
        self.apply(&actions)?;
        tracing::warn!("[QUARANTINE] Device {} has been isolated at the firewall", mac);
        Ok(())
    }

    /// Remove quarantine isolation for a device and restore normal access.
    pub async fn unquarantine_device(&self, mac: &str) -> anyhow::Result<()> {
        self.store.set_device_quarantine(mac, false)?;
        let actions = self.evaluate().await?;
        self.apply(&actions)?;
        tracing::info!("[UNQUARANTINE] Device {} quarantine removed at firewall", mac);
        Ok(())
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

/// Validate MAC address format (e.g. 00:11:22:33:44:55 or 00-11-22-33-44-55) to prevent command injection.
pub fn is_valid_mac(mac: &str) -> bool {
    let parts: Vec<&str> = if mac.contains(':') {
        mac.split(':').collect()
    } else if mac.contains('-') {
        mac.split('-').collect()
    } else {
        return false;
    };

    if parts.len() != 6 {
        return false;
    }

    parts.iter().all(|part| part.len() == 2 && part.chars().all(|c| c.is_ascii_hexdigit()))
}

/// Initialize the hearth nftables table (Linux only).
pub fn init_nftables() -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let commands: [&[&str]; 3] = [
            &["add", "table", "inet", "hearth"],
            &["add", "chain", "inet", "hearth", "forward", "{ type filter hook forward priority 0 ; }"],
            &["add", "chain", "inet", "hearth", "input", "{ type filter hook input priority 0 ; }"],
        ];
        for args in &commands {
            tracing::info!("nftables init: nft {:?}", args);
            let status = std::process::Command::new("nft")
                .args(*args)
                .status()?;
            if !status.success() {
                tracing::warn!("nft init command failed with status: {}", status);
            }
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
            subnet: None,
            api_key: None,
            gateway_ip: None,
            gateway_mac: None,
            db_path: ":memory:".into(),
            oui_db_path: "".into(),
            geoip_db_path: "".into(),
            notifications: Default::default(),
            threat_intel: Default::default(),
            dns: Default::default(),
            ai_analyst: Default::default(),
            pcap_capture_enabled: true,
            captures_dir: "./captures".into(),
            fleet: Default::default(),
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
        assert_eq!(cmds.len(), 4);
        assert!(cmds[0].contains("flush"));
        assert!(cmds[1].contains("flush"));
        assert!(cmds[2].contains("AA:BB:CC:DD:EE:FF") && cmds[2].contains("forward"));
        assert!(cmds[3].contains("AA:BB:CC:DD:EE:FF") && cmds[3].contains("input"));
    }

    #[test]
    fn test_generate_quarantine_command() {
        let config = Config {
            interface: "eth0".into(),
            dashboard_port: 7777,
            subnet: None,
            api_key: None,
            gateway_ip: None,
            gateway_mac: None,
            db_path: ":memory:".into(),
            oui_db_path: "".into(),
            geoip_db_path: "".into(),
            notifications: Default::default(),
            threat_intel: Default::default(),
            dns: Default::default(),
            ai_analyst: Default::default(),
            pcap_capture_enabled: true,
            captures_dir: "./captures".into(),
            fleet: Default::default(),
            devices: vec![],
        };
        let store = Arc::new(Store::new(":memory:").unwrap());
        let engine = RulesEngine::new(config, store);

        let actions = vec![RuleAction {
            mac: "11:22:33:44:55:66".into(),
            action: ActionKind::Quarantine,
            reason: "Emergency isolation".into(),
            expires_at: None,
        }];

        let cmds = engine.generate_commands(&actions);
        assert_eq!(cmds.len(), 4);
        assert!(cmds[2].contains("11:22:33:44:55:66") && cmds[2].contains("forward"));
        assert!(cmds[3].contains("11:22:33:44:55:66") && cmds[3].contains("input"));
    }

    #[test]
    fn test_is_valid_mac() {
        assert!(is_valid_mac("00:11:22:33:44:55"));
        assert!(is_valid_mac("AA:BB:CC:DD:EE:FF"));
        assert!(is_valid_mac("aa-bb-cc-dd-ee-ff"));
        // Invalid formats / potential injection
        assert!(!is_valid_mac("00:11:22:33:44"));
        assert!(!is_valid_mac("00:11:22:33:44:55:66"));
        assert!(!is_valid_mac("00:11:22:33:44:GG"));
        assert!(!is_valid_mac("00:11:22:33:44:55; rm -rf /"));
        assert!(!is_valid_mac("eth0"));
    }
}
