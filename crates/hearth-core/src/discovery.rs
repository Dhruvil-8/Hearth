use crate::oui::OuiDb;
use crate::store::Store;
use crate::types::{Anomaly, AnomalyKind, Device};
use anyhow::Result;
use chrono::Utc;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::timeout;

/// Active network scanner for subnet device discovery and inventory.
pub struct NetworkScanner {
    store: Arc<Store>,
    oui_db: Arc<OuiDb>,
    anomaly_tx: Option<mpsc::Sender<Anomaly>>,
}

impl NetworkScanner {
    pub fn new(
        store: Arc<Store>,
        oui_db: Arc<OuiDb>,
        anomaly_tx: Option<mpsc::Sender<Anomaly>>,
    ) -> Self {
        Self {
            store,
            oui_db,
            anomaly_tx,
        }
    }

    /// Auto-detect the local IPv4 subnet base (e.g. "192.168.1").
    pub fn detect_local_subnet(&self) -> Option<[u8; 3]> {
        for iface in pnet::datalink::interfaces() {
            if iface.is_loopback() || !iface.is_up() {
                continue;
            }
            for ip_net in iface.ips {
                if let IpAddr::V4(v4) = ip_net.ip() {
                    if !v4.is_loopback() && !v4.is_link_local() {
                        let octets = v4.octets();
                        return Some([octets[0], octets[1], octets[2]]);
                    }
                }
            }
        }
        None
    }

    /// Send quick asynchronous probes across a /24 subnet to trigger ARP resolution.
    pub async fn ping_sweep_subnet(&self, base: [u8; 3]) {
        let mut tasks = Vec::with_capacity(254);
        for host in 1..255 {
            let target_ip = Ipv4Addr::new(base[0], base[1], base[2], host);
            // Probe common ports with very short timeout to induce ARP request from OS
            tasks.push(tokio::spawn(async move {
                let addr = SocketAddr::new(IpAddr::V4(target_ip), 80);
                let _ = timeout(Duration::from_millis(150), TcpStream::connect(addr)).await;
            }));
        }

        for task in tasks {
            let _ = task.await;
        }
        // Small pause to allow OS ARP table to settle
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    /// Read and parse the operating system's ARP neighbor table.
    pub fn read_arp_cache() -> HashMap<IpAddr, String> {
        let mut neighbors = HashMap::new();

        #[cfg(target_os = "windows")]
        {
            if let Ok(output) = std::process::Command::new("arp").arg("-a").output() {
                let text = String::from_utf8_lossy(&output.stdout);
                for line in text.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        if let Ok(ip) = parts[0].parse::<IpAddr>() {
                            let mac_raw = parts[1].replace('-', ":").to_uppercase();
                            if is_valid_unicast_mac(&mac_raw) && !is_multicast_or_broadcast(&ip) {
                                neighbors.insert(ip, mac_raw);
                            }
                        }
                    }
                }
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            // On Linux, read /proc/net/arp directly
            if let Ok(content) = std::fs::read_to_string("/proc/net/arp") {
                for line in content.lines().skip(1) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 4 {
                        if let Ok(ip) = parts[0].parse::<IpAddr>() {
                            let mac_raw = parts[3].to_uppercase();
                            if is_valid_unicast_mac(&mac_raw) && !is_multicast_or_broadcast(&ip) {
                                neighbors.insert(ip, mac_raw);
                            }
                        }
                    }
                }
            } else if let Ok(output) = std::process::Command::new("arp").arg("-a").output() {
                let text = String::from_utf8_lossy(&output.stdout);
                for line in text.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 4 {
                        let ip_str = parts[1].trim_matches(|c| c == '(' || c == ')');
                        if let Ok(ip) = ip_str.parse::<IpAddr>() {
                            let mac_raw = parts[3].to_uppercase();
                            if is_valid_unicast_mac(&mac_raw) && !is_multicast_or_broadcast(&ip) {
                                neighbors.insert(ip, mac_raw);
                            }
                        }
                    }
                }
            }
        }

        neighbors
    }

    /// Perform a full active discovery sweep across the network.
    pub async fn discover_network(&self, explicit_subnet: Option<&str>) -> Result<Vec<Device>> {
        let base = if let Some(sub) = explicit_subnet {
            parse_subnet_base(sub)
        } else {
            self.detect_local_subnet()
        };

        if let Some(base_octets) = base {
            tracing::info!(
                "Performing active discovery sweep on {}.{}.{}.0/24...",
                base_octets[0],
                base_octets[1],
                base_octets[2]
            );
            self.ping_sweep_subnet(base_octets).await;
        }

        let arp_entries = Self::read_arp_cache();
        tracing::info!("ARP scan identified {} local devices", arp_entries.len());

        let iot_names = discover_iot_friendly_names().await;
        if !iot_names.is_empty() {
            tracing::info!(
                "Discovered {} friendly IoT names via mDNS/SSDP",
                iot_names.len()
            );
        }

        let mut discovered_devices = Vec::new();
        let now = Utc::now();

        for (ip, mac) in arp_entries {
            let vendor = self.oui_db.lookup(&mac);
            let already_known = self.store.device_exists(&mac).unwrap_or(false);

            let hostname = async_dns_lookup(ip).await;
            let label = iot_names.get(&ip).cloned().or(hostname);

            if already_known {
                if let Ok(Some(existing)) = self.store.get_device(&mac) {
                    if existing.label.is_none() && label.is_some() {
                        let mut updated = existing;
                        updated.label = label.clone();
                        let _ = self.store.upsert_device(&updated);
                    }
                }
            }

            let device = Device {
                mac: mac.clone(),
                ip,
                vendor: vendor.clone(),
                label,
                first_seen: now,
                last_seen: now,
                is_quarantined: false,
            };

            let _ = self.store.upsert_device(&device);
            discovered_devices.push(device);

            // If device is newly discovered on the network, trigger an alert!
            if !already_known {
                let vendor_info = vendor
                    .as_deref()
                    .unwrap_or("Unknown Vendor");
                let detail = format!(
                    "New device joined network: {} (IP: {}, Vendor: {})",
                    mac, ip, vendor_info
                );

                let anomaly = Anomaly {
                    id: None,
                    mac: mac.clone(),
                    detected_at: now,
                    kind: AnomalyKind::NewDevice,
                    detail,
                    resolved: false,
                };

                if let Ok(id) = self.store.insert_anomaly(&anomaly) {
                    if let Some(tx) = &self.anomaly_tx {
                        let mut stored = anomaly;
                        stored.id = Some(id);
                        let _ = tx.send(stored).await;
                    }
                }
            }
        }

        Ok(discovered_devices)
    }
}

/// Helper to parse "192.168.1.0/24" into [192, 168, 1].
fn parse_subnet_base(subnet_str: &str) -> Option<[u8; 3]> {
    let clean = subnet_str.split('/').next()?;
    let parts: Vec<&str> = clean.split('.').collect();
    if parts.len() >= 3 {
        let o0 = parts[0].parse::<u8>().ok()?;
        let o1 = parts[1].parse::<u8>().ok()?;
        let o2 = parts[2].parse::<u8>().ok()?;
        Some([o0, o1, o2])
    } else {
        None
    }
}

/// Helper to check if MAC is a valid unicast physical address.
fn is_valid_unicast_mac(mac: &str) -> bool {
    let parts: Vec<&str> = mac.split(':').collect();
    if parts.len() != 6 {
        return false;
    }
    // Ignore all zeros or all FFs
    if mac == "00:00:00:00:00:00" || mac == "FF:FF:FF:FF:FF:FF" {
        return false;
    }
    // Check multicast bit (least significant bit of first octet)
    if let Ok(first_octet) = u8::from_str_radix(parts[0], 16) {
        (first_octet & 0x01) == 0
    } else {
        false
    }
}

/// Helper to filter out multicast and broadcast IP addresses.
fn is_multicast_or_broadcast(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_multicast() || v4.is_broadcast() || v4.octets()[3] == 255,
        IpAddr::V6(v6) => v6.is_multicast(),
    }
}

/// Best-effort asynchronous reverse DNS lookup with a tight timeout to prevent Tokio worker starvation.
async fn async_dns_lookup(ip: IpAddr) -> Option<String> {
    let lookup_handle = tokio::task::spawn_blocking(move || {
        dns_lookup::lookup_addr(&ip).ok().filter(|h| h != &ip.to_string())
    });
    match tokio::time::timeout(Duration::from_millis(200), lookup_handle).await {
        Ok(Ok(Some(name))) => Some(name),
        _ => None,
    }
}

/// Query mDNS and SSDP on the local network to discover friendly device names.
pub async fn discover_iot_friendly_names() -> HashMap<IpAddr, String> {
    let mut names = HashMap::new();

    // 1. SSDP / UPnP Discovery (239.255.255.250:1900)
    if let Ok(socket) = tokio::net::UdpSocket::bind("0.0.0.0:0").await {
        let _ = socket.set_broadcast(true);
        let ssdp_msg = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n";
        let target: SocketAddr = "239.255.255.250:1900".parse().unwrap();
        let _ = socket.send_to(ssdp_msg.as_bytes(), target).await;

        let mut buf = [0u8; 1500];
        let timeout_fut = tokio::time::sleep(Duration::from_millis(500));
        tokio::pin!(timeout_fut);

        loop {
            tokio::select! {
                _ = &mut timeout_fut => break,
                res = socket.recv_from(&mut buf) => {
                    if let Ok((len, src)) = res {
                        if let Ok(text) = std::str::from_utf8(&buf[..len]) {
                            if let Some(friendly) = parse_ssdp_friendly_name(text) {
                                names.insert(src.ip(), friendly);
                            }
                        }
                    } else {
                        break;
                    }
                }
            }
        }
    }

    // 2. mDNS Discovery (224.0.0.251:5353)
    if let Ok(socket) = tokio::net::UdpSocket::bind("0.0.0.0:0").await {
        let _ = socket.set_broadcast(true);
        let mdns_query = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x09, b'_', b's', b'e', b'r', b'v', b'i', b'c', b'e', b's',
            0x07, b'_', b'd', b'n', b's', b'-', b's', b'd',
            0x04, b'_', b'u', b'd', b'p',
            0x05, b'l', b'o', b'c', b'a', b'l',
            0x00, 0x00, 0x0C, 0x00, 0x01,
        ];

        let target: SocketAddr = "224.0.0.251:5353".parse().unwrap();
        let _ = socket.send_to(&mdns_query, target).await;

        let mut buf = [0u8; 1500];
        let timeout_fut = tokio::time::sleep(Duration::from_millis(500));
        tokio::pin!(timeout_fut);

        loop {
            tokio::select! {
                _ = &mut timeout_fut => break,
                res = socket.recv_from(&mut buf) => {
                    if let Ok((len, src)) = res {
                        if let Some(friendly) = parse_mdns_friendly_name(&buf[..len]) {
                            names.entry(src.ip()).or_insert(friendly);
                        }
                    } else {
                        break;
                    }
                }
            }
        }
    }

    names
}

/// Extract friendly name from SSDP response headers.
pub fn parse_ssdp_friendly_name(response: &str) -> Option<String> {
    for line in response.lines() {
        let line_lower = line.to_lowercase();
        if line_lower.starts_with("server:") {
            let val = line[7..].trim();
            // Look for known IoT brand signatures in SERVER header
            if val.contains("Sonos") {
                return Some("Sonos Speaker".to_string());
            } else if val.contains("Roku") {
                return Some("Roku Streaming Player".to_string());
            } else if val.contains("IpBridge") || val.contains("Philips") {
                return Some("Philips Hue Bridge".to_string());
            } else if val.contains("EPSON") || val.contains("HP") || val.contains("Canon") || val.contains("Brother") {
                return Some(val.split_whitespace().next().unwrap_or("Network Printer").to_string());
            } else if val.contains("Samsung") {
                return Some("Samsung Smart Device".to_string());
            } else if val.contains("LG") {
                return Some("LG Smart Device".to_string());
            }
        }
    }
    None
}

/// Extract friendly name from raw mDNS response payload.
pub fn parse_mdns_friendly_name(payload: &[u8]) -> Option<String> {
    // Scan payload for ASCII labels matching common IoT signatures
    let text = String::from_utf8_lossy(payload);
    for word in text.split(|c: char| !c.is_alphanumeric() && c != '-' && c != '_') {
        let lower = word.to_lowercase();
        if lower.contains("googlecast") || lower.contains("chromecast") {
            return Some("Google Chromecast / Nest".to_string());
        } else if lower.contains("airplay") || lower.contains("appletv") {
            return Some("Apple AirPlay Device".to_string());
        } else if lower.contains("spotify") {
            return Some("Spotify Connect Device".to_string());
        } else if lower.contains("hue") {
            return Some("Philips Hue Light".to_string());
        } else if lower.contains("printer") {
            return Some("Network Printer".to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ssdp_friendly_name() {
        let sonos_resp = "HTTP/1.1 200 OK\r\nSERVER: Linux/4.9 UPnP/1.0 Sonos/76.2-47270 (ZPS22)\r\nST: ssdp:all\r\n\r\n";
        assert_eq!(parse_ssdp_friendly_name(sonos_resp), Some("Sonos Speaker".to_string()));

        let roku_resp = "HTTP/1.1 200 OK\r\nSERVER: Roku/11.5.0 UPnP/1.0\r\n\r\n";
        assert_eq!(parse_ssdp_friendly_name(roku_resp), Some("Roku Streaming Player".to_string()));

        let hue_resp = "HTTP/1.1 200 OK\r\nSERVER: Linux/3.14.0 UPnP/1.0 IpBridge/1.50.0\r\n\r\n";
        assert_eq!(parse_ssdp_friendly_name(hue_resp), Some("Philips Hue Bridge".to_string()));
    }

    #[test]
    fn test_parse_mdns_friendly_name() {
        let sample_chromecast = b"\x00\x00\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00\x0fLiving-Room-TV\x0b_googlecast\x04_tcp\x05local\x00";
        assert_eq!(parse_mdns_friendly_name(sample_chromecast), Some("Google Chromecast / Nest".to_string()));

        let sample_airplay = b"\x00\x00\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00\x0fBedroom-Speaker\x08_airplay\x04_tcp\x05local\x00";
        assert_eq!(parse_mdns_friendly_name(sample_airplay), Some("Apple AirPlay Device".to_string()));
    }
}
