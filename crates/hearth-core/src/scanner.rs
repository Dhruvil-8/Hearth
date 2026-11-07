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
            let is_open = matches!(
                timeout(self.timeout_duration, TcpStream::connect(addr)).await,
                Ok(Ok(_stream))
            );

            if is_open {
                let port_record = DevicePort {
                    mac: mac.to_string(),
                    port: target.port,
                    service: target.service.to_string(),
                    is_insecure: target.is_insecure,
                    discovered_at: now,
                };

                let _ = self.store.upsert_device_port(&port_record);
                discovered_ports.push(port_record);

                // If port is insecure (e.g. Telnet or RTSP), emit a security anomaly
                if target.is_insecure {
                    let desc = target
                        .risk_description
                        .unwrap_or("Insecure unencrypted protocol detected");
                    let detail = format!(
                        "Insecure port {} ({}) is open on {} — {}",
                        target.port, target.service, ip, desc
                    );

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
