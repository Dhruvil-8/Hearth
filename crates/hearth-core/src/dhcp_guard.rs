use crate::store::Store;
use crate::types::{Anomaly, AnomalyKind};
use anyhow::Result;
use chrono::Utc;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use tokio::sync::mpsc::Sender;
use tracing::info;

/// DHCP Guard to detect rogue DHCP servers attempting to hijack default gateways or DNS on the LAN.
pub struct DhcpGuard {
    store: Arc<Store>,
    anomaly_tx: Sender<Anomaly>,
    /// Authorized DHCP server IPs (e.g. gateway router)
    authorized_servers: std::sync::Mutex<HashSet<IpAddr>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpPacketInfo {
    pub op: u8,
    pub message_type: Option<u8>, // 1=Discover, 2=Offer, 3=Request, 5=Ack
    pub server_ip: Option<IpAddr>,
    pub offered_ip: Option<IpAddr>,
    pub router_ip: Option<IpAddr>,
    pub dns_servers: Vec<IpAddr>,
}

impl DhcpGuard {
    pub fn new(store: Arc<Store>, anomaly_tx: Sender<Anomaly>) -> Self {
        Self {
            store,
            anomaly_tx,
            authorized_servers: std::sync::Mutex::new(HashSet::new()),
        }
    }

    /// Authorize a known DHCP server IP address.
    pub fn authorize_server(&self, ip: IpAddr) {
        if let Ok(mut set) = self.authorized_servers.lock() {
            set.insert(ip);
            info!("Authorized DHCP server: {}", ip);
        }
    }

    /// Parse a raw BOOTP/DHCP payload (RFC 2131).
    pub fn parse_dhcp_payload(payload: &[u8]) -> Option<DhcpPacketInfo> {
        if payload.len() < 240 {
            return None;
        }

        let op = payload[0];
        let yiaddr = Ipv4Addr::new(payload[16], payload[17], payload[18], payload[19]);
        let siaddr = Ipv4Addr::new(payload[20], payload[21], payload[22], payload[23]);

        // Check magic cookie: [99, 130, 83, 99] at offset 236
        if payload[236..240] != [99, 130, 83, 99] {
            return None;
        }

        let mut message_type = None;
        let mut server_id = if siaddr != Ipv4Addr::UNSPECIFIED {
            Some(IpAddr::V4(siaddr))
        } else {
            None
        };
        let mut router_ip = None;
        let mut dns_servers = Vec::new();

        let mut idx = 240;
        while idx < payload.len() {
            let opt = payload[idx];
            if opt == 255 {
                // End option
                break;
            }
            if opt == 0 {
                // Pad option
                idx += 1;
                continue;
            }
            if idx + 1 >= payload.len() {
                break;
            }
            let len = payload[idx + 1] as usize;
            idx += 2;
            if idx + len > payload.len() {
                break;
            }

            match opt {
                53 if len >= 1 => {
                    message_type = Some(payload[idx]);
                }
                54 if len >= 4 => {
                    server_id = Some(IpAddr::V4(Ipv4Addr::new(
                        payload[idx],
                        payload[idx + 1],
                        payload[idx + 2],
                        payload[idx + 3],
                    )));
                }
                3 if len >= 4 => {
                    router_ip = Some(IpAddr::V4(Ipv4Addr::new(
                        payload[idx],
                        payload[idx + 1],
                        payload[idx + 2],
                        payload[idx + 3],
                    )));
                }
                6 => {
                    let mut d_idx = 0;
                    while d_idx + 4 <= len {
                        dns_servers.push(IpAddr::V4(Ipv4Addr::new(
                            payload[idx + d_idx],
                            payload[idx + d_idx + 1],
                            payload[idx + d_idx + 2],
                            payload[idx + d_idx + 3],
                        )));
                        d_idx += 4;
                    }
                }
                _ => {}
            }
            idx += len;
        }

        Some(DhcpPacketInfo {
            op,
            message_type,
            server_ip: server_id,
            offered_ip: if yiaddr != Ipv4Addr::UNSPECIFIED {
                Some(IpAddr::V4(yiaddr))
            } else {
                None
            },
            router_ip,
            dns_servers,
        })
    }

    /// Inspect a DHCP packet received on the network.
    /// If an unauthorized DHCP server is detected offering leases, emits a RogueDhcp anomaly.
    pub fn inspect_dhcp(
        &self,
        sender_ip: IpAddr,
        sender_mac: &str,
        payload: &[u8],
    ) -> Result<Option<Anomaly>> {
        let info = match Self::parse_dhcp_payload(payload) {
            Some(i) => i,
            None => return Ok(None),
        };

        // Only inspect server responses: BOOTREPLY (op == 2) or Offer/Ack (type 2 or 5)
        let is_server_response = info.op == 2
            || info.message_type == Some(2)
            || info.message_type == Some(5);

        if !is_server_response {
            return Ok(None);
        }

        let effective_server_ip = info.server_ip.unwrap_or(sender_ip);

        let mut auth_servers = match self.authorized_servers.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        // If no authorized server is known yet, assume the first seen responding server is the legitimate gateway
        if auth_servers.is_empty() {
            auth_servers.insert(effective_server_ip);
            info!(
                "Recorded initial authorized DHCP server: {} (MAC: {})",
                effective_server_ip, sender_mac
            );
            return Ok(None);
        }

        // Check if the server is unauthorized
        if !auth_servers.contains(&effective_server_ip) {
            let msg_type_str = match info.message_type {
                Some(2) => "DHCPOFFER",
                Some(5) => "DHCPACK",
                _ => "BOOTREPLY",
            };

            let router_info = match info.router_ip {
                Some(r) => format!(", Rogue Gateway Offered: {}", r),
                None => String::new(),
            };

            let detail = format!(
                "CRITICAL: Unauthorized Rogue DHCP Server detected! Server IP: {} (MAC: {}). Sent {} offering client IP: {:?}{}. Suspected LAN Traffic Hijack / MITM attack!",
                effective_server_ip, sender_mac, msg_type_str, info.offered_ip, router_info
            );

            let anomaly = Anomaly {
                id: None,
                mac: sender_mac.to_string(),
                detected_at: Utc::now(),
                kind: AnomalyKind::RogueDhcp,
                detail,
                resolved: false,
            };

            let already_flagged = self
                .store
                .has_recent_unresolved_anomaly(sender_mac, &AnomalyKind::RogueDhcp, 1)
                .unwrap_or(false);

            if !already_flagged {
                if let Ok(id) = self.store.insert_anomaly(&anomaly) {
                    let mut stored = anomaly.clone();
                    stored.id = Some(id);
                    let _ = self.anomaly_tx.try_send(stored);
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
    fn test_parse_dhcp_offer() {
        let mut packet = vec![0u8; 300];
        packet[0] = 2; // BOOTREPLY
        // yiaddr: 192.168.1.150
        packet[16] = 192;
        packet[17] = 168;
        packet[18] = 1;
        packet[19] = 150;
        // Magic cookie: 99, 130, 83, 99
        packet[236] = 99;
        packet[237] = 130;
        packet[238] = 83;
        packet[239] = 99;

        // Option 53: DHCP Message Type = 2 (DHCPOFFER)
        packet[240] = 53;
        packet[241] = 1;
        packet[242] = 2;

        // Option 54: Server Identifier = 192.168.1.200
        packet[243] = 54;
        packet[244] = 4;
        packet[245] = 192;
        packet[246] = 168;
        packet[247] = 1;
        packet[248] = 200;

        // Option 3: Router = 192.168.1.200
        packet[249] = 3;
        packet[250] = 4;
        packet[251] = 192;
        packet[252] = 168;
        packet[253] = 1;
        packet[254] = 200;

        // End option
        packet[255] = 255;

        let parsed = DhcpGuard::parse_dhcp_payload(&packet).expect("Failed to parse DHCP");
        assert_eq!(parsed.op, 2);
        assert_eq!(parsed.message_type, Some(2));
        assert_eq!(parsed.server_ip, Some("192.168.1.200".parse().unwrap()));
        assert_eq!(parsed.offered_ip, Some("192.168.1.150".parse().unwrap()));
        assert_eq!(parsed.router_ip, Some("192.168.1.200".parse().unwrap()));
    }
}

