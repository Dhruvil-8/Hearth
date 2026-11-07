use crate::types::{Anomaly, AnomalyKind};
use chrono::Utc;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Sensitive lateral movement and worm propagation ports.
/// If an unprivileged IoT or rogue device on the LAN initiates connections to these ports,
/// it indicates automated zero-day worm propagation (e.g. Mirai, WannaCry, EternalBlue, Reaper).
pub const SENSITIVE_LATERAL_PORTS: &[u16] = &[
    23,   // Telnet (Mirai / Mozi / IoT Botnet brute-force)
    445,  // SMB / CIFS (WannaCry / EternalBlue / PsExec)
    139,  // NetBIOS-SSN
    135,  // MSRPC (Remote procedure call exploits)
    3389, // RDP
    5555, // Android Debug Bridge (ADB worm / cryptominer)
    5985, // WinRM HTTP
    5986, // WinRM HTTPS
    1433, // MS SQL Server
];

/// Deception and Canary Trap Engine for Zero-Day Lateral Movement Defense.
pub struct CanaryEngine {
    /// In-memory tracker of recent alerts per (source_mac, port) to prevent alert storms
    recent_alerts: Mutex<HashMap<(String, u16), Instant>>,
    /// Designated dark / canary IPs on the local subnet (any traffic to these trips alarm)
    canary_ips: Mutex<HashSet<IpAddr>>,
}

impl Default for CanaryEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl CanaryEngine {
    /// Create a new Canary deception engine.
    pub fn new() -> Self {
        Self {
            recent_alerts: Mutex::new(HashMap::new()),
            canary_ips: Mutex::new(HashSet::new()),
        }
    }

    /// Register a dark / unassigned canary IP address on the local subnet.
    pub fn register_canary_ip(&self, ip: IpAddr) {
        if let Ok(mut set) = self.canary_ips.lock() {
            set.insert(ip);
        }
    }

    /// Register multiple dark / unassigned canary IP addresses on the local subnet.
    pub fn register_canary_ips<I: IntoIterator<Item = IpAddr>>(&self, ips: I) {
        if let Ok(mut set) = self.canary_ips.lock() {
            set.extend(ips);
        }
    }

    /// Check if an IP address is registered as a deception canary.
    pub fn is_canary_ip(&self, ip: &IpAddr) -> bool {
        if let Ok(set) = self.canary_ips.lock() {
            set.contains(ip)
        } else {
            false
        }
    }

    /// Inspect an observed local TCP SYN or UDP connection attempt for lateral zero-day propagation.
    pub fn inspect_lateral_traffic(
        &self,
        src_mac: &str,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        dst_port: u16,
    ) -> Option<Anomaly> {
        // Only inspect internal LAN traffic (private source to private destination)
        if !is_private_ip(&src_ip) || !is_private_ip(&dst_ip) {
            return None;
        }

        // Ignore traffic from self to self
        if src_ip == dst_ip {
            return None;
        }

        let is_canary_target = self.is_canary_ip(&dst_ip);
        let is_sensitive_port = SENSITIVE_LATERAL_PORTS.contains(&dst_port);

        if !is_canary_target && !is_sensitive_port {
            return None;
        }

        // Throttle repeated alerts for the same device and port (5 minute cooldown)
        let now = Instant::now();
        {
            let mut recent = self.recent_alerts.lock().ok()?;
            // Purge expired entries older than 5 minutes
            recent.retain(|_, time| now.duration_since(*time) < Duration::from_secs(300));

            if let Some(prev) = recent.get(&(src_mac.to_string(), dst_port)) {
                if now.duration_since(*prev) < Duration::from_secs(300) {
                    return None;
                }
            }
            recent.insert((src_mac.to_string(), dst_port), now);
        }

        let detail = if is_canary_target {
            format!(
                "CRITICAL: Zero-day lateral movement canary trap tripped! Host {} (IP: {}) contacted dark/unassigned honeypot IP: {} on port {}. Suspected internal worm scanning / network reconnaissance.",
                src_mac, src_ip, dst_ip, dst_port
            )
        } else {
            let port_desc = match dst_port {
                23 => "Telnet (suspected Mirai/IoT botnet worm)",
                445 => "SMB/CIFS (suspected EternalBlue/WannaCry/ransomware propagation)",
                135 | 139 => "NetBIOS/MSRPC (suspected Windows RPC exploit)",
                3389 => "RDP (suspected remote desktop brute-force)",
                5555 => "ADB (suspected Android debug worm/miner)",
                _ => "High-risk administrative lateral movement service",
            };
            format!(
                "CRITICAL: Zero-day lateral movement / worm propagation attempt detected! Host {} (IP: {}) targeted sensitive internal port {} [{}] on destination {}. Autonomous quarantine recommended.",
                src_mac, src_ip, dst_port, port_desc, dst_ip
            )
        };

        Some(Anomaly {
            id: None,
            mac: src_mac.to_string(),
            detected_at: Utc::now(),
            kind: AnomalyKind::CanaryTripDetected,
            detail,
            resolved: false,
        })
    }
}

/// Helper to determine if an IP address is a private LAN address (RFC 1918 / RFC 4193).
fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unicast_link_local()
                || ((v6.segments()[0] & 0xfe00) == 0xfc00)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canary_engine_sensitive_port_detection() {
        let canary = CanaryEngine::new();
        let src_mac = "AA:BB:CC:DD:EE:11";
        let src_ip = "192.168.1.50".parse().unwrap();
        let dst_ip = "192.168.1.100".parse().unwrap();

        // Safe port (e.g. standard HTTP 80 or HTTPS 443) should not trigger canary
        assert!(canary.inspect_lateral_traffic(src_mac, src_ip, dst_ip, 80).is_none());
        assert!(canary.inspect_lateral_traffic(src_mac, src_ip, dst_ip, 443).is_none());

        // Sensitive SMB port 445 (WannaCry / lateral movement) MUST trigger
        let anomaly = canary.inspect_lateral_traffic(src_mac, src_ip, dst_ip, 445);
        assert!(anomaly.is_some());
        let a = anomaly.unwrap();
        assert_eq!(a.kind, AnomalyKind::CanaryTripDetected);
        assert!(a.detail.contains("445"));
        assert!(a.detail.contains("SMB/CIFS"));

        // Second immediate attempt should be rate-limited
        assert!(canary.inspect_lateral_traffic(src_mac, src_ip, dst_ip, 445).is_none());
    }

    #[test]
    fn test_canary_engine_dark_ip_trap() {
        let canary = CanaryEngine::new();
        let dark_ip: IpAddr = "192.168.1.240".parse().unwrap();
        canary.register_canary_ip(dark_ip);

        let src_mac = "11:22:33:44:55:66";
        let src_ip = "192.168.1.10".parse().unwrap();

        // Any traffic to dark canary IP trips the honeypot
        let anomaly = canary.inspect_lateral_traffic(src_mac, src_ip, dark_ip, 8080);
        assert!(anomaly.is_some());
        let a = anomaly.unwrap();
        assert_eq!(a.kind, AnomalyKind::CanaryTripDetected);
        assert!(a.detail.contains("dark/unassigned honeypot IP"));
    }
}

