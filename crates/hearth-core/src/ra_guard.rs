use crate::store::Store;
use crate::types::{Anomaly, AnomalyKind};
use anyhow::Result;
use chrono::Utc;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::mpsc::Sender;
use tracing::info;

/// Guard to detect rogue IPv6 routers attempting SLAAC gateway/DNS hijacking (RFC 6105 RA-Guard).
pub struct RaGuard {
    store: Arc<Store>,
    anomaly_tx: Sender<Anomaly>,
    /// Authorized IPv6 router MAC addresses
    authorized_routers: tokio::sync::Mutex<HashSet<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterAdvertInfo {
    pub hop_limit: u8,
    pub managed_flag: bool,
    pub other_flag: bool,
    pub router_lifetime_secs: u16,
    pub source_mac: Option<String>,
    pub prefixes: Vec<String>,
}

impl RaGuard {
    pub fn new(store: Arc<Store>, anomaly_tx: Sender<Anomaly>) -> Self {
        Self {
            store,
            anomaly_tx,
            authorized_routers: tokio::sync::Mutex::new(HashSet::new()),
        }
    }

    /// Authorize a known legitimate IPv6 router MAC.
    pub async fn authorize_router(&self, mac: &str) {
        let mut set = self.authorized_routers.lock().await;
        set.insert(mac.to_uppercase());
        info!("Authorized IPv6 default router: {}", mac);
    }

    /// Parse an ICMPv6 payload starting with Type (byte 0).
    pub fn parse_router_advert(payload: &[u8]) -> Option<RouterAdvertInfo> {
        // ICMPv6 RA base header is 16 bytes: Type (1), Code (1), Checksum (2),
        // HopLimit (1), Flags (1), Lifetime (2), Reachable (4), Retrans (4)
        if payload.len() < 16 {
            return None;
        }

        let icmp6_type = payload[0];
        let icmp6_code = payload[1];
        if icmp6_type != 134 || icmp6_code != 0 {
            return None; // Not a Router Advertisement
        }

        let hop_limit = payload[4];
        let flags = payload[5];
        let managed_flag = (flags & 0x80) != 0;
        let other_flag = (flags & 0x40) != 0;
        let lifetime = ((payload[6] as u16) << 8) | (payload[7] as u16);

        let mut source_mac = None;
        let mut prefixes = Vec::new();

        let mut idx = 16;
        while idx + 2 <= payload.len() {
            let opt_type = payload[idx];
            let opt_len = (payload[idx + 1] as usize) * 8; // Length in 8-octet units
            if opt_len == 0 || idx + opt_len > payload.len() {
                break;
            }

            match opt_type {
                // Option 1: Source Link-Layer Address (MAC)
                1 if opt_len >= 8 => {
                    let mac_bytes = &payload[idx + 2..idx + 8];
                    source_mac = Some(
                        mac_bytes
                            .iter()
                            .map(|b| format!("{:02X}", b))
                            .collect::<Vec<_>>()
                            .join(":"),
                    );
                }
                // Option 3: Prefix Information
                3 if opt_len >= 32 => {
                    let prefix_len = payload[idx + 2];
                    let prefix_bytes = &payload[idx + 16..idx + 32];
                    let mut b16 = [0u8; 16];
                    b16.copy_from_slice(prefix_bytes);
                    let ipv6 = std::net::Ipv6Addr::from(b16);
                    prefixes.push(format!("{}/{}", ipv6, prefix_len));
                }
                _ => {}
            }
            idx += opt_len;
        }

        Some(RouterAdvertInfo {
            hop_limit,
            managed_flag,
            other_flag,
            router_lifetime_secs: lifetime,
            source_mac,
            prefixes,
        })
    }

    /// Inspect an ICMPv6 packet received on the LAN.
    pub async fn inspect_icmpv6(
        &self,
        sender_mac: &str,
        sender_ip: IpAddr,
        payload: &[u8],
    ) -> Result<Option<Anomaly>> {
        let info = match Self::parse_router_advert(payload) {
            Some(i) => i,
            None => return Ok(None),
        };

        // If lifetime == 0, router is not advertising itself as default gateway
        if info.router_lifetime_secs == 0 {
            return Ok(None);
        }

        let norm_mac = sender_mac.to_uppercase();
        let mut auth = self.authorized_routers.lock().await;

        if auth.is_empty() {
            auth.insert(norm_mac.clone());
            info!("Recorded initial authorized IPv6 router: {} ({})", norm_mac, sender_ip);
            return Ok(None);
        }

        if !auth.contains(&norm_mac) {
            let detail = format!(
                "CRITICAL: Unauthorized Rogue IPv6 Router Advertisement detected! MAC: {} (IP: {}). Lifetime: {}s, Prefixes: {:?}. Suspected IPv6 SLAAC Gateway Hijack / MITM attack!",
                norm_mac, sender_ip, info.router_lifetime_secs, info.prefixes
            );

            let anomaly = Anomaly {
                id: None,
                mac: norm_mac.clone(),
                detected_at: Utc::now(),
                kind: AnomalyKind::RogueIpv6Router,
                detail,
                resolved: false,
            };

            let already_flagged = self
                .store
                .has_recent_unresolved_anomaly(&norm_mac, &AnomalyKind::RogueIpv6Router, 1)
                .unwrap_or(false);

            if !already_flagged {
                if let Ok(id) = self.store.insert_anomaly(&anomaly) {
                    let mut stored = anomaly.clone();
                    stored.id = Some(id);
                    let _ = self.anomaly_tx.send(stored).await;
                }
            }

            return Ok(Some(anomaly));
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_router_advert() {
        let mut packet = vec![0u8; 48];
        packet[0] = 134; // Type: Router Advertisement
        packet[1] = 0;   // Code: 0
        packet[4] = 64;  // Hop Limit: 64
        packet[5] = 0x80;// Managed flag
        packet[6] = 0x07;// Lifetime: 1800s (0x0708)
        packet[7] = 0x08;

        // Option 1: Source MAC (length = 1 * 8 = 8 bytes)
        packet[16] = 1;  // Type: Source Link Layer
        packet[17] = 1;  // Length: 1 (8 bytes)
        packet[18] = 0xAA;
        packet[19] = 0xBB;
        packet[20] = 0xCC;
        packet[21] = 0xDD;
        packet[22] = 0xEE;
        packet[23] = 0xFF;

        let parsed = RaGuard::parse_router_advert(&packet).expect("Failed to parse RA");
        assert_eq!(parsed.hop_limit, 64);
        assert!(parsed.managed_flag);
        assert!(!parsed.other_flag);
        assert_eq!(parsed.router_lifetime_secs, 1800);
        assert_eq!(parsed.source_mac, Some("AA:BB:CC:DD:EE:FF".to_string()));
    }
}

