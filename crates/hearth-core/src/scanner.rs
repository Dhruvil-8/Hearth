use crate::store::Store;
use crate::types::{Anomaly, AnomalyKind, DevicePort};
use anyhow::Result;
use chrono::Utc;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::timeout;

/// Definition of a target port to check during vulnerability scans.
#[derive(Clone, Copy, Debug)]
pub struct TargetPort {
    pub port: u16,
    pub service: &'static str,
    pub is_insecure: bool,
    pub risk_description: Option<&'static str>,
}

/// Standard high-risk and administrative IoT ports.
pub const TARGET_PORTS: &[TargetPort] = &[
    TargetPort {
        port: 21,
        service: "FTP",
        is_insecure: true,
        risk_description: Some("Cleartext file transfer credentials"),
    },
    TargetPort {
        port: 22,
        service: "SSH",
        is_insecure: false,
        risk_description: None,
    },
    TargetPort {
        port: 23,
        service: "Telnet",
        is_insecure: true,
        risk_description: Some("Unencrypted remote shell; prime target for Mirai/IoT botnets"),
    },
    TargetPort {
        port: 80,
        service: "HTTP",
        is_insecure: false,
        risk_description: None,
    },
    TargetPort {
        port: 443,
        service: "HTTPS",
        is_insecure: false,
        risk_description: None,
    },
    TargetPort {
        port: 554,
        service: "RTSP",
        is_insecure: true,
        risk_description: Some("Real-Time Streaming Protocol; check for unauthenticated camera video feed"),
    },
    TargetPort {
        port: 1883,
        service: "MQTT",
        is_insecure: false,
        risk_description: None,
    },
    TargetPort {
        port: 8080,
        service: "HTTP-Alt",
        is_insecure: false,
        risk_description: None,
    },
    TargetPort {
        port: 8443,
        service: "HTTPS-Alt",
        is_insecure: false,
        risk_description: None,
    },
];

/// Port and vulnerability scanner for IoT and network hosts.
pub struct PortScanner {
    store: Arc<Store>,
    anomaly_tx: Option<mpsc::Sender<Anomaly>>,
    timeout_duration: Duration,
}

impl PortScanner {
    /// Create a new PortScanner instance.
    pub fn new(store: Arc<Store>, anomaly_tx: Option<mpsc::Sender<Anomaly>>) -> Self {
        Self {
            store,
            anomaly_tx,
            timeout_duration: Duration::from_millis(700),
        }
    }

    /// Scan a single IP for target ports asynchronously.
    pub async fn scan_host(&self, ip: IpAddr, mac: &str) -> Vec<DevicePort> {
        let mut discovered_ports = Vec::new();
        let now = Utc::now();

        for target in TARGET_PORTS {
            let addr = SocketAddr::new(ip, target.port);
            let conn_res = timeout(self.timeout_duration, TcpStream::connect(addr)).await;

            if let Ok(Ok(stream)) = conn_res {
                let banner = Self::grab_banner(stream, target.port, self.timeout_duration).await;
                let cve_warning = banner.as_deref().and_then(Self::evaluate_banner_vulnerability);
                let is_flagged_insecure = target.is_insecure || cve_warning.is_some();

                let port_record = DevicePort {
                    mac: mac.to_string(),
                    port: target.port,
                    service: target.service.to_string(),
                    is_insecure: is_flagged_insecure,
                    discovered_at: now,
                    banner: banner.clone(),
                };

                let _ = self.store.upsert_device_port(&port_record);
                discovered_ports.push(port_record);

                // If port is insecure or banner matches known critical CVE, emit a security anomaly
                if is_flagged_insecure {
                    let desc = if let Some(vuln) = cve_warning {
                        format!("CRITICAL Vulnerability Alert: {}", vuln)
                    } else {
                        target
                            .risk_description
                            .unwrap_or("Insecure unencrypted protocol detected")
                            .to_string()
                    };

                    let detail = if let Some(ref b) = banner {
                        format!(
                            "Open port {} ({}) on {} [Banner: '{}'] — {}",
                            target.port, target.service, ip, b, desc
                        )
                    } else {
                        format!(
                            "Insecure port {} ({}) is open on {} — {}",
                            target.port, target.service, ip, desc
                        )
                    };

                    // Check if already unresolved
                    let already_flagged = self
                        .store
                        .has_recent_unresolved_anomaly(mac, &AnomalyKind::InsecurePortOpen, 12)
                        .unwrap_or(false);

                    if !already_flagged {
                        let anomaly = Anomaly {
                            id: None,
                            mac: mac.to_string(),
                            detected_at: now,
                            kind: AnomalyKind::InsecurePortOpen,
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
            }
        }

        discovered_ports
    }

    /// Read service banner or HTTP server header asynchronously with timeout.
    async fn grab_banner(mut stream: TcpStream, port: u16, timeout_duration: Duration) -> Option<String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let probe: Option<&'static [u8]> = match port {
            80 | 8080 => Some(b"HEAD / HTTP/1.0\r\nHost: 127.0.0.1\r\nUser-Agent: Hearth/1.0\r\nConnection: close\r\n\r\n"),
            554 => Some(b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: Hearth/1.0\r\n\r\n"),
            _ => None,
        };

        if let Some(data) = probe {
            let _ = timeout(timeout_duration, stream.write_all(data)).await;
        }

        let mut buf = [0u8; 512];
        if let Ok(Ok(n)) = timeout(timeout_duration, stream.read(&mut buf)).await {
            if n > 0 {
                let raw_text = String::from_utf8_lossy(&buf[..n]);
                // If HTTP or RTSP, extract Server: header if present
                for line in raw_text.lines() {
                    let trimmed = line.trim();
                    if trimmed.to_ascii_lowercase().starts_with("server:") {
                        return Some(trimmed.to_string());
                    }
                }
                // Otherwise return first non-empty line (e.g. SSH identification or FTP/Telnet banner)
                if let Some(first_line) = raw_text.lines().find(|l| !l.trim().is_empty()) {
                    let cleaned = first_line.trim().to_string();
                    if cleaned.len() > 120 {
                        return Some(cleaned[..120].to_string());
                    }
                    return Some(cleaned);
                }
            }
        }
        None
    }

    /// Correlate service banner with known critical IoT CVE patterns and outdated daemon releases.
    pub fn evaluate_banner_vulnerability(banner: &str) -> Option<&'static str> {
        let b = banner.to_ascii_lowercase();
        if b.contains("openssh_7.") || b.contains("openssh_6.") || b.contains("openssh_5.") || b.contains("openssh_4.") {
            Some("Outdated OpenSSH release susceptible to CVE-2024-6387 (RegreSSHion) and Terrapin (CVE-2023-48795)")
        } else if b.contains("goahead") {
            Some("GoAhead-Webs embedded server — known remote code execution vulnerabilities in CGI handling")
        } else if b.contains("boa/0.9") {
            Some("Unmaintained Boa web server — vulnerable to arbitrary file disclosure and memory corruption")
        } else if b.contains("rompager") {
            Some("Allegro RomPager embedded server — vulnerable to Misfortune Cookie (CVE-2014-9222)")
        } else if b.contains("dropbear_201") {
            Some("Outdated Dropbear SSH daemon with known pre-authentication vulnerability vectors")
        } else {
            None
        }
    }

    /// Scan all currently known devices in the database.
    pub async fn scan_all(&self) -> Result<Vec<DevicePort>> {
        let devices = self.store.get_all_devices()?;
        let mut all_ports = Vec::new();

        for dev in devices {
            // Skip loopback or broadcast addresses
            if dev.ip.is_loopback() || dev.ip.is_unspecified() {
                continue;
            }
            tracing::info!("Scanning security ports for {} ({})", dev.ip, dev.mac);
            let ports = self.scan_host(dev.ip, &dev.mac).await;
            all_ports.extend(ports);
        }

        Ok(all_ports)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evaluate_banner_vulnerability_openssh() {
        let banner = "SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7";
        let vuln = PortScanner::evaluate_banner_vulnerability(banner);
        assert!(vuln.is_some());
        assert!(vuln.unwrap().contains("RegreSSHion"));
    }

    #[test]
    fn test_evaluate_banner_vulnerability_goahead() {
        let banner = "Server: GoAhead-Webs/2.5.0";
        let vuln = PortScanner::evaluate_banner_vulnerability(banner);
        assert!(vuln.is_some());
        assert!(vuln.unwrap().contains("GoAhead"));
    }

    #[test]
    fn test_evaluate_banner_clean() {
        let banner = "SSH-2.0-OpenSSH_9.6p1";
        let vuln = PortScanner::evaluate_banner_vulnerability(banner);
        assert!(vuln.is_none());
    }
}
