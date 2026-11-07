use crate::store::Store;
use crate::types::{Anomaly, AnomalyKind};
use anyhow::Result;
use chrono::Utc;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::Sender;
use tracing::{error, info, warn};

/// Guard to detect ARP poisoning and Man-in-the-Middle (MITM) attacks on the local network.
pub struct ArpGuard {
    store: Arc<Store>,
    anomaly_tx: Sender<Anomaly>,
    /// Track IP -> MAC mapping history
    ip_mac_history: tokio::sync::Mutex<HashMap<IpAddr, (String, chrono::DateTime<Utc>)>>,
    /// Known gateway IP address
    gateway_ip: tokio::sync::Mutex<Option<IpAddr>>,
    /// Known gateway MAC address
    gateway_mac: tokio::sync::Mutex<Option<String>>,
}

impl ArpGuard {
    pub fn new(store: Arc<Store>, anomaly_tx: Sender<Anomaly>) -> Self {
        Self {
            store,
            anomaly_tx,
            ip_mac_history: tokio::sync::Mutex::new(HashMap::new()),
            gateway_ip: tokio::sync::Mutex::new(None),
            gateway_mac: tokio::sync::Mutex::new(None),
        }
    }

    /// Check if a MAC address belongs to the known default gateway.
    pub async fn is_known_gateway_mac(&self, mac: &str) -> bool {
        let normalized = mac.to_uppercase();
        let gw_lock = self.gateway_mac.lock().await;
        if let Some(ref gw) = *gw_lock {
            gw == &normalized
        } else {
            false
        }
    }

    /// Process a freshly parsed ARP table snapshot `(IP, MAC)` pairs.
    pub async fn inspect_arp_table(&self, arp_entries: &[(IpAddr, String)]) -> Result<Vec<Anomaly>> {
        let mut detected_anomalies = Vec::new();
        let mut history = self.ip_mac_history.lock().await;
        let mut gateway_ip_lock = self.gateway_ip.lock().await;
        let mut gateway_mac_lock = self.gateway_mac.lock().await;

        for (ip, mac) in arp_entries {
            let normalized_mac = mac.to_uppercase();
            // Skip invalid or broadcast MACs
            if normalized_mac == "00:00:00:00:00:00"
                || normalized_mac == "FF:FF:FF:FF:FF:FF"
                || normalized_mac.is_empty()
            {
                continue;
            }

            // Check if this IP matches the established gateway IP, or if not yet set, candidate .1 or .254
            let is_gateway_candidate = match *gateway_ip_lock {
                Some(existing_ip) => *ip == existing_ip,
                None => match ip {
                    IpAddr::V4(v4) => {
                        let octets = v4.octets();
                        octets[3] == 1 || octets[3] == 254
                    }
                    _ => false,
                },
            };

            if is_gateway_candidate {
                if let Some(existing_gw_mac) = &*gateway_mac_lock {
                    if existing_gw_mac != &normalized_mac {
                        let anomaly = Anomaly {
                            id: None,
                            mac: normalized_mac.clone(),
                            detected_at: Utc::now(),
                            kind: AnomalyKind::ArpSpoofing,
                            detail: format!(
                                "CRITICAL: Gateway {} MAC changed from {} to {}! Possible ARP Poisoning / MITM attack!",
                                ip, existing_gw_mac, normalized_mac
                            ),
                            resolved: false,
                        };
                        detected_anomalies.push(anomaly);
                    }
                } else {
                    // Lock in baseline gateway IP and MAC to prevent flapping between multiple router IPs
                    *gateway_ip_lock = Some(*ip);
                    *gateway_mac_lock = Some(normalized_mac.clone());
                    info!("Recorded baseline gateway: {} -> {}", ip, normalized_mac);
                }
            }

            // Check if this IP was previously mapped to a different MAC address
            if let Some((old_mac, last_seen)) = history.get(ip) {
                if old_mac != &normalized_mac {
                    let elapsed = Utc::now().signed_duration_since(*last_seen);
                    // If the MAC changed in less than 30 minutes, flag as ARP spoofing
                    if elapsed.num_minutes() < 30 {
                        let already_flagged = self
                            .store
                            .has_recent_unresolved_anomaly(&normalized_mac, &AnomalyKind::ArpSpoofing, 1)
                            .unwrap_or(false);

                        if !already_flagged {
                            let anomaly = Anomaly {
                                id: None,
                                mac: normalized_mac.clone(),
                                detected_at: Utc::now(),
                                kind: AnomalyKind::ArpSpoofing,
                                detail: format!(
                                    "CRITICAL: IP {} rapidly changed hardware address from {} to {}! Suspected ARP Spoofing.",
                                    ip, old_mac, normalized_mac
                                ),
                                resolved: false,
                            };
                            detected_anomalies.push(anomaly);
                        }
                    }
                }
            }

            // Update history
            history.insert(*ip, (normalized_mac, Utc::now()));
        }

        // Emit and persist detected anomalies
        for anomaly in &detected_anomalies {
            warn!("{}", anomaly.detail);
            let _ = self.store.insert_anomaly(anomaly);
            let _ = self.anomaly_tx.send(anomaly.clone()).await;
        }

        Ok(detected_anomalies)
    }

    /// Spawn a periodic background monitor for ARP cache inspection.
    pub fn start_monitor(self: Arc<Self>, interval_secs: u64) {
        tokio::spawn(async move {
            info!("Anti-ARP Spoofing Guard background task active (interval: {}s)", interval_secs);
            let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
            loop {
                interval.tick().await;
                // Query system ARP table
                let arp_map = crate::discovery::NetworkScanner::read_arp_cache();
                let entries: Vec<(IpAddr, String)> = arp_map.into_iter().collect();

                if !entries.is_empty() {
                    if let Err(e) = self.inspect_arp_table(&entries).await {
                        error!("ARP guard inspection error: {}", e);
                    }
                }
            }
        });
    }
}
