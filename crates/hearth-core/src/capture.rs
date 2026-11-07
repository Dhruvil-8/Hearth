use pnet::datalink::{self, Channel::Ethernet, Config as PnetConfig};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use crate::types::Anomaly;

/// A snapshot of a single device's traffic within a 60-second window.
#[derive(Debug, Clone)]
pub struct DeviceSnapshot {
    /// MAC address of the device
    pub mac: String,
    /// Most recently observed IP address
    pub ip: IpAddr,
    /// Total bytes where this MAC is the source
    pub bytes_sent: u64,
    /// Total bytes where this MAC is the destination
    pub bytes_recv: u64,
    /// (destination IP, bytes) pairs
    pub destinations: Vec<(IpAddr, u64)>,
}

/// Internal accumulator for building device snapshots.
#[derive(Debug)]
struct DeviceAccum {
    ip: IpAddr,
    bytes_sent: u64,
    bytes_recv: u64,
    destinations: HashMap<IpAddr, u64>,
}

/// Format a MAC address from raw bytes.
fn format_mac(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}

/// Start the packet capture loop on the given network interface.
pub fn start_capture(
    interface_name: &str,
    tx: mpsc::Sender<Vec<DeviceSnapshot>>,
    anomaly_tx: Option<mpsc::Sender<Anomaly>>,
    canary_engine: Option<std::sync::Arc<crate::canary::CanaryEngine>>,
    ra_guard: Option<std::sync::Arc<crate::ra_guard::RaGuard>>,
    dhcp_guard: Option<std::sync::Arc<crate::dhcp_guard::DhcpGuard>>,
    pcap_buffer: Option<std::sync::Arc<crate::pcap::PcapRingBuffer>>,
    store: Option<std::sync::Arc<crate::store::Store>>,
) -> anyhow::Result<()> {
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.name == interface_name)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Network interface '{}' not found. Available: {}",
                interface_name,
                datalink::interfaces()
                    .iter()
                    .map(|i| i.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })?;

    tracing::info!(
        "Starting packet capture on interface: {} ({})",
        interface.name,
        interface
            .ips
            .iter()
            .map(|ip| ip.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );

    let config = PnetConfig {
        promiscuous: true,
        ..Default::default()
    };

    let (_, mut rx) = match datalink::channel(&interface, config) {
        Ok(Ethernet(tx_chan, rx_chan)) => (tx_chan, rx_chan),
        Ok(_) => return Err(anyhow::anyhow!("Unsupported channel type for interface")),
        Err(e) => {
            return Err(anyhow::anyhow!(
                "Failed to open capture channel on '{}': {}. \
                 On Windows, ensure Npcap is installed. \
                 On Linux, ensure CAP_NET_RAW capability.",
                interface_name,
                e
            ))
        }
    };

    let window_duration = Duration::from_secs(60);
    let mut window_start = Instant::now();
    let mut devices: HashMap<String, DeviceAccum> = HashMap::new();
    let canary_engine = canary_engine.unwrap_or_else(|| std::sync::Arc::new(crate::canary::CanaryEngine::new()));

    loop {
        match rx.next() {
            Ok(packet) => {
                if let Some(eth) = EthernetPacket::new(packet) {
                    let src_mac = format_mac(&eth.get_source().octets());
                    let dst_mac = format_mac(&eth.get_destination().octets());
                    let frame_len = packet.len() as u64;

                    // Push raw packet into circular PCAP ring buffer for zero-day incident digital forensics
                    if let Some(ref pcap_buf) = pcap_buffer {
                        pcap_buf.push(crate::pcap::RawCapturedPacket {
                            timestamp: std::time::SystemTime::now(),
                            src_mac: src_mac.clone(),
                            dst_mac: dst_mac.clone(),
                            raw_bytes: packet.to_vec(),
                        });
                    }

                    // Extract IP layer info
                    let (src_ip, dst_ip) = match eth.get_ethertype() {
                        EtherTypes::Ipv4 => {
                            if let Some(ipv4) = Ipv4Packet::new(eth.payload()) {
                                if let Some(ref a_tx) = anomaly_tx {
                                    if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                                        if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                                            // Passive OS Fingerprinting via TCP SYN flags (SYN=1, ACK=0)
                                            let is_syn_only = (tcp.get_flags() & 0x12) == 0x02;
                                            if is_syn_only {
                                                if let Some(os) = crate::os_fingerprint::OsFingerprinter::classify_syn(
                                                    ipv4.get_ttl(),
                                                    tcp.get_window(),
                                                    true,
                                                ) {
                                                    if let Some(ref st) = store {
                                                        let _ = st.update_device_os_guess(&src_mac, &os.to_string());
                                                    }
                                                }
                                            }

                                            // Zero-Day Deception: Check lateral movement / worm propagation against sensitive ports & canaries
                                            if let Some(canary_anomaly) = canary_engine.inspect_lateral_traffic(
                                                &src_mac,
                                                IpAddr::V4(ipv4.get_source()),
                                                IpAddr::V4(ipv4.get_destination()),
                                                tcp.get_destination(),
                                            ) {
                                                let _ = a_tx.try_send(canary_anomaly);
                                            }

                                            if let Some(anomaly) = crate::ja3::inspect_tls_traffic(
                                                tcp.payload(),
                                                &src_mac,
                                                IpAddr::V4(ipv4.get_source()),
                                            ) {
                                                let _ = a_tx.try_send(anomaly);
                                            }
                                        }
                                    } else if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
                                        if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                                            // Zero-Day Deception: Check UDP lateral movement / worm probes
                                            if let Some(canary_anomaly) = canary_engine.inspect_lateral_traffic(
                                                &src_mac,
                                                IpAddr::V4(ipv4.get_source()),
                                                IpAddr::V4(ipv4.get_destination()),
                                                udp.get_destination(),
                                            ) {
                                                let _ = a_tx.try_send(canary_anomaly);
                                            }

                                            if (udp.get_source() == 67 || udp.get_destination() == 68)
                                                && udp.payload().len() >= 240
                                            {
                                                if let Some(ref dg) = dhcp_guard {
                                                    let _ = dg.inspect_dhcp(IpAddr::V4(ipv4.get_source()), &src_mac, udp.payload());
                                                } else if let Some(info) = crate::dhcp_guard::DhcpGuard::parse_dhcp_payload(udp.payload()) {
                                                    if info.op == 2 || info.message_type == Some(2) || info.message_type == Some(5) {
                                                        if let Some(rogue_router) = info.router_ip {
                                                            if rogue_router != IpAddr::V4(ipv4.get_source()) {
                                                                let detail = format!(
                                                                    "CRITICAL: Rogue DHCP Server detected via passive capture! Server IP: {} (MAC: {}). Offering alternate gateway: {}. Suspected LAN Traffic Hijack!",
                                                                    ipv4.get_source(), src_mac, rogue_router
                                                                );
                                                                let _ = a_tx.try_send(Anomaly {
                                                                    id: None,
                                                                    mac: src_mac.clone(),
                                                                    detected_at: chrono::Utc::now(),
                                                                    kind: crate::types::AnomalyKind::RogueDhcp,
                                                                    detail,
                                                                    resolved: false,
                                                                });
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                (
                                    IpAddr::V4(ipv4.get_source()),
                                    IpAddr::V4(ipv4.get_destination()),
                                )
                            } else {
                                continue;
                            }
                        }
                        EtherTypes::Ipv6 => {
                            if let Some(ipv6) = Ipv6Packet::new(eth.payload()) {
                                if let Some(ref a_tx) = anomaly_tx {
                                    if ipv6.get_next_header() == IpNextHeaderProtocols::Tcp {
                                        if let Some(tcp) = TcpPacket::new(ipv6.payload()) {
                                            let is_syn_only = (tcp.get_flags() & 0x12) == 0x02;
                                            if is_syn_only {
                                                if let Some(os) = crate::os_fingerprint::OsFingerprinter::classify_syn(
                                                    ipv6.get_hop_limit(),
                                                    tcp.get_window(),
                                                    true,
                                                ) {
                                                    if let Some(ref st) = store {
                                                        let _ = st.update_device_os_guess(&src_mac, &os.to_string());
                                                    }
                                                }
                                            }

                                            if let Some(anomaly) = crate::ja3::inspect_tls_traffic(
                                                tcp.payload(),
                                                &src_mac,
                                                IpAddr::V6(ipv6.get_source()),
                                            ) {
                                                let _ = a_tx.try_send(anomaly);
                                            }
                                        }
                                    } else if ipv6.get_next_header() == IpNextHeaderProtocols::Icmpv6 {
                                        if let Some(ref rag) = ra_guard {
                                            let _ = rag.inspect_icmpv6(&src_mac, IpAddr::V6(ipv6.get_source()), ipv6.payload());
                                        } else if let Some(ra_info) = crate::ra_guard::RaGuard::parse_router_advert(ipv6.payload()) {
                                            if ra_info.router_lifetime_secs > 0 {
                                                tracing::info!("Observed active IPv6 Router Advertisement from MAC {} (prefixes: {:?})", src_mac, ra_info.prefixes);
                                            }
                                        }
                                    }
                                }
                                (
                                    IpAddr::V6(ipv6.get_source()),
                                    IpAddr::V6(ipv6.get_destination()),
                                )
                            } else {
                                continue;
                            }
                        }
                        _ => continue, // Skip non-IP frames (ARP, etc.)
                    };

                    // Record bytes_sent for source device
                    let src_entry =
                        devices
                            .entry(src_mac.clone())
                            .or_insert_with(|| DeviceAccum {
                                ip: src_ip,
                                bytes_sent: 0,
                                bytes_recv: 0,
                                destinations: HashMap::new(),
                            });
                    src_entry.ip = src_ip;
                    src_entry.bytes_sent += frame_len;
                    *src_entry.destinations.entry(dst_ip).or_insert(0) += frame_len;

                    // Record bytes_recv for destination device
                    let dst_entry = devices.entry(dst_mac).or_insert_with(|| DeviceAccum {
                        ip: dst_ip,
                        bytes_sent: 0,
                        bytes_recv: 0,
                        destinations: HashMap::new(),
                    });
                    dst_entry.bytes_recv += frame_len;
                }
            }
            Err(e) => {
                tracing::warn!("Packet capture error (continuing): {}", e);
            }
        }

        // Check if the 60-second window has elapsed
        if window_start.elapsed() >= window_duration {
            let snapshots: Vec<DeviceSnapshot> = devices
                .drain()
                .map(|(mac, accum)| {
                    // Sort destinations by bytes and take top 5
                    let mut dest_vec: Vec<(IpAddr, u64)> =
                        accum.destinations.into_iter().collect();
                    dest_vec.sort_by(|a, b| b.1.cmp(&a.1));
                    dest_vec.truncate(5);

                    DeviceSnapshot {
                        mac,
                        ip: accum.ip,
                        bytes_sent: accum.bytes_sent,
                        bytes_recv: accum.bytes_recv,
                        destinations: dest_vec,
                    }
                })
                .collect();

            if !snapshots.is_empty() {
                tracing::trace!(
                    "Window complete: {} devices, {} total bytes",
                    snapshots.len(),
                    snapshots
                        .iter()
                        .map(|s| s.bytes_sent + s.bytes_recv)
                        .sum::<u64>()
                );
                if let Err(e) = tx.blocking_send(snapshots) {
                    tracing::error!("Failed to send snapshots to main loop: {}", e);
                    break;
                }
            }

            window_start = Instant::now();
        }
    }

    Ok(())
}

/// Start a demo capture loop that generates synthetic traffic data.
/// Useful for testing on systems without packet capture capability.
pub fn start_demo_capture(
    tx: mpsc::Sender<Vec<DeviceSnapshot>>,
    _anomaly_tx: Option<mpsc::Sender<Anomaly>>,
) -> anyhow::Result<()> {
    use std::net::Ipv4Addr;

    tracing::info!("Starting DEMO capture mode (synthetic data)");

    let demo_devices = [
        ("AA:BB:CC:DD:EE:01", "192.168.1.100", "Samsung TV"),
        ("AA:BB:CC:DD:EE:02", "192.168.1.101", "Echo Dot"),
        ("AA:BB:CC:DD:EE:03", "192.168.1.102", "Philips Hue Bridge"),
        ("AA:BB:CC:DD:EE:04", "192.168.1.103", "iPhone"),
        ("AA:BB:CC:DD:EE:05", "192.168.1.104", "Laptop"),
    ];

    let destinations = [
        ("142.250.80.46", "google.com"),       // Google
        ("31.13.71.36", "facebook.com"),       // Facebook
        ("54.239.26.128", "alexa.amazon.com"), // Amazon
        ("104.16.51.111", "cloudflare.com"),   // Cloudflare
        ("151.101.1.140", "reddit.com"),       // Reddit
    ];

    loop {
        std::thread::sleep(Duration::from_secs(60));

        let snapshots: Vec<DeviceSnapshot> = demo_devices
            .iter()
            .map(|(mac, ip, _label)| {
                let base_sent = (rand_u64() % 50000) + 1000;
                let base_recv = (rand_u64() % 200000) + 5000;

                let dest_count = (rand_u64() % 3) as usize + 1;
                let dests: Vec<(IpAddr, u64)> = destinations
                    .iter()
                    .take(dest_count)
                    .map(|(ip_str, _)| {
                        let ip: IpAddr = ip_str.parse().unwrap();
                        (ip, (rand_u64() % 10000) + 100)
                    })
                    .collect();

                DeviceSnapshot {
                    mac: mac.to_string(),
                    ip: IpAddr::V4(ip.parse::<Ipv4Addr>().unwrap()),
                    bytes_sent: base_sent,
                    bytes_recv: base_recv,
                    destinations: dests,
                }
            })
            .collect();

        tracing::trace!("Demo: generated {} device snapshots", snapshots.len());
        if let Err(e) = tx.blocking_send(snapshots) {
            tracing::error!("Demo capture channel closed: {}", e);
            break;
        }
    }

    Ok(())
}

/// Simple pseudo-random u64 using system time for demo mode.
fn rand_u64() -> u64 {
    use std::time::SystemTime;
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos() as u64;
    // xorshift-like mixing
    let mut x = nanos;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    x
}
