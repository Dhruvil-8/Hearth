use crate::types::{Anomaly, AnomalyKind, NotificationConfig};
use anyhow::Result;
use serde_json::json;
use std::time::Duration;

/// Asynchronous webhook dispatcher for security alerts and notifications.
#[derive(Clone, Debug)]
pub struct AlertDispatcher {
    client: reqwest::Client,
    config: NotificationConfig,
}

impl AlertDispatcher {
    /// Create a new alert dispatcher from the notification configuration.
    pub fn new(config: NotificationConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self { client, config }
    }

    /// Check if alerts are configured and enabled for a given anomaly kind.
    pub fn is_enabled_for(&self, kind: &AnomalyKind) -> bool {
        if self.config.webhook_url.is_none() && self.config.syslog_server.is_none() {
            return false;
        }
        match kind {
            AnomalyKind::NewDevice => self.config.notify_on_new_device,
            AnomalyKind::InsecurePortOpen => self.config.notify_on_vulnerability,
            AnomalyKind::MaliciousDest
            | AnomalyKind::MaliciousTlsFingerprint
            | AnomalyKind::DgaDomainDetected
            | AnomalyKind::DnsTunnelingExfiltration
            | AnomalyKind::CanaryTripDetected => self.config.notify_on_malicious_traffic,
            AnomalyKind::ArpSpoofing => self.config.notify_on_arp_spoofing,
            AnomalyKind::RogueDhcp | AnomalyKind::RogueIpv6Router => {
                self.config.notify_on_rogue_dhcp
            }
            _ => self.config.notify_on_anomaly,
        }
    }

    /// Sanitize text for inclusion in Syslog RFC 5424 structured data parameters.
    /// Escapes backslash, double quotes, and closing bracket per RFC 5424 Section 6.3.3,
    /// and replaces newlines to prevent Syslog Log Injection (CWE-117).
    fn sanitize_sd_param(input: &str) -> String {
        input
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace(']', "\\]")
            .replace(['\r', '\n'], " ")
    }

    /// Sanitize message body to prevent multiline log injection.
    fn sanitize_log_body(input: &str) -> String {
        input.replace(['\r', '\n'], " ")
    }

    /// Format an anomaly as a standard RFC 5424 Syslog message.
    pub fn format_syslog_rfc5424(anomaly: &Anomaly, device_label: Option<&str>) -> String {
        let severity = match anomaly.kind {
            AnomalyKind::MaliciousDest
            | AnomalyKind::ArpSpoofing
            | AnomalyKind::RogueDhcp
            | AnomalyKind::MaliciousTlsFingerprint
            | AnomalyKind::RogueIpv6Router
            | AnomalyKind::DgaDomainDetected
            | AnomalyKind::DnsTunnelingExfiltration
            | AnomalyKind::CanaryTripDetected => 2, // Critical
            AnomalyKind::InsecurePortOpen | AnomalyKind::ExcessiveUpload => 3, // Error
            _ => 4, // Warning
        };
        let pri = 16 * 8 + severity; // Facility 16 (local0)
        let timestamp = anomaly.detected_at.to_rfc3339();
        let raw_label = device_label.unwrap_or(&anomaly.mac);
        let safe_label = Self::sanitize_sd_param(raw_label);
        let safe_mac = Self::sanitize_sd_param(&anomaly.mac);
        let safe_detail = Self::sanitize_log_body(&anomaly.detail);

        format!(
            "<{}>1 {} hearth hearth-daemon - {} [security@hearth mac=\"{}\" kind=\"{}\" label=\"{}\"] {}",
            pri,
            timestamp,
            anomaly.kind,
            safe_mac,
            anomaly.kind,
            safe_label,
            safe_detail
        )
    }

    /// Format an anomaly as ArcSight Common Event Format (CEF) for SIEM ingest.
    pub fn format_cef(anomaly: &Anomaly, device_label: Option<&str>) -> String {
        let severity = match anomaly.kind {
            AnomalyKind::MaliciousDest
            | AnomalyKind::ArpSpoofing
            | AnomalyKind::RogueDhcp
            | AnomalyKind::MaliciousTlsFingerprint
            | AnomalyKind::RogueIpv6Router
            | AnomalyKind::DgaDomainDetected
            | AnomalyKind::DnsTunnelingExfiltration
            | AnomalyKind::CanaryTripDetected => 10,
            AnomalyKind::InsecurePortOpen | AnomalyKind::ExcessiveUpload => 7,
            _ => 4,
        };
        let raw_label = device_label.unwrap_or(&anomaly.mac);
        let safe_label = raw_label.replace(['|', '\r', '\n'], " ");
        let safe_detail = anomaly
            .detail
            .replace('\\', "\\\\")
            .replace('|', "\\|")
            .replace(['\r', '\n'], " ");
        let safe_mac = anomaly.mac.replace(['|', '\r', '\n'], " ");

        format!(
            "CEF:0|Hearth|HearthSecurity|0.1.0|{}|{}|{}|smac={} dhost={} msg={}",
            anomaly.kind,
            anomaly.kind,
            severity,
            safe_mac,
            safe_label,
            safe_detail
        )
    }

    /// Dispatch an anomaly alert asynchronously to the configured webhook and/or Syslog SIEM.
    pub async fn dispatch(&self, anomaly: &Anomaly, device_label: Option<&str>) -> Result<()> {
        if !self.is_enabled_for(&anomaly.kind) {
            return Ok(());
        }

        // 1. Dispatch to SIEM / Syslog collector via UDP if configured
        if let Some(ref syslog_server) = self.config.syslog_server {
            let msg = if self.config.syslog_format.eq_ignore_ascii_case("cef") {
                Self::format_cef(anomaly, device_label)
            } else {
                Self::format_syslog_rfc5424(anomaly, device_label)
            };

            if let Ok(socket) = tokio::net::UdpSocket::bind("0.0.0.0:0").await {
                let _ = socket.send_to(msg.as_bytes(), syslog_server).await;
            }
        }

        // 2. Dispatch to Webhook URL (Discord / Slack) if configured
        let webhook_url = match &self.config.webhook_url {
            Some(url) if !url.trim().is_empty() => url,
            _ => return Ok(()),
        };

        let label = device_label.unwrap_or(&anomaly.mac);
        let title = match anomaly.kind {
            AnomalyKind::NewDevice => "[Hearth INFO] New Device Discovered",
            AnomalyKind::InsecurePortOpen => "[Hearth WARN] Insecure Port / Vulnerability",
            AnomalyKind::ExcessiveUpload => "[Hearth WARN] Excessive Upload Spike",
            AnomalyKind::NewDestination => "[Hearth INFO] New External Destination",
            AnomalyKind::UnusualHour => "[Hearth INFO] Activity at Unusual Hours",
            AnomalyKind::VoiceLeakSuspected => "[Hearth WARN] Audio Leak Suspected",
            AnomalyKind::MaliciousDest => "[Hearth CRITICAL] Malicious C2 Traffic Detected",
            AnomalyKind::ArpSpoofing => "[Hearth CRITICAL] ARP Spoofing / MITM Attack Detected",
            AnomalyKind::RogueDhcp => "[Hearth CRITICAL] Rogue DHCP Server / LAN Hijack Detected",
            AnomalyKind::MaliciousTlsFingerprint => "[Hearth CRITICAL] Malicious JA3 TLS Fingerprint (C2 Botnet)",
            AnomalyKind::RogueIpv6Router => "[Hearth CRITICAL] Rogue IPv6 Router / SLAAC Hijack Detected",
            AnomalyKind::DgaDomainDetected => "[Hearth ZERO-DAY] Algorithmic DGA C2 Domain Detected",
            AnomalyKind::DnsTunnelingExfiltration => "[Hearth ZERO-DAY] DNS Tunneling Data Exfiltration Detected",
            AnomalyKind::CanaryTripDetected => "[Hearth ZERO-DAY] LAN Lateral Movement Canary Trap Tripped",
        };

        // Determine color code for rich embeds (Discord format)
        let color = match anomaly.kind {
            AnomalyKind::MaliciousDest
            | AnomalyKind::ArpSpoofing
            | AnomalyKind::RogueDhcp
            | AnomalyKind::MaliciousTlsFingerprint
            | AnomalyKind::RogueIpv6Router
            | AnomalyKind::DgaDomainDetected
            | AnomalyKind::DnsTunnelingExfiltration
            | AnomalyKind::CanaryTripDetected => 15158332, // Dark Crimson Red
            AnomalyKind::InsecurePortOpen | AnomalyKind::ExcessiveUpload => 15682620, // Red
            AnomalyKind::NewDevice | AnomalyKind::VoiceLeakSuspected => 16500772,     // Amber
            _ => 3447003,                                                          // Blue
        };

        let is_discord = webhook_url.contains("discord.com/api/webhooks");

        let body = if is_discord {
            json!({
                "username": "Hearth Security",
                "embeds": [{
                    "title": title,
                    "color": color,
                    "fields": [
                        { "name": "Device", "value": format!("`{}` ({})", anomaly.mac, label), "inline": true },
                        { "name": "Anomaly", "value": anomaly.kind.to_string(), "inline": true },
                        { "name": "Detail", "value": &anomaly.detail, "inline": false }
                    ],
                    "timestamp": anomaly.detected_at.to_rfc3339(),
                    "footer": { "text": "Hearth Local Network Intelligence" }
                }]
            })
        } else {
            // Slack / Generic Webhook format
            json!({
                "text": format!("{}: {} for {} — {}", title, anomaly.kind, label, anomaly.detail),
                "kind": anomaly.kind.to_string(),
                "mac": anomaly.mac,
                "label": label,
                "detail": anomaly.detail,
                "timestamp": anomaly.detected_at.to_rfc3339()
            })
        };

        match self.client.post(webhook_url).json(&body).send().await {
            Ok(resp) if resp.status().is_success() => {
                tracing::info!("Alert webhook dispatched successfully for [{}]", anomaly.kind);
            }
            Ok(resp) => {
                tracing::warn!(
                    "Webhook notification returned non-success status: {}",
                    resp.status()
                );
            }
            Err(e) => {
                tracing::warn!("Failed to dispatch webhook alert: {}", e);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_format_syslog_rfc5424() {
        let anomaly = Anomaly {
            id: Some(1),
            mac: "AA:BB:CC:DD:EE:FF".to_string(),
            detected_at: Utc::now(),
            kind: AnomalyKind::MaliciousDest,
            detail: "Connection to Feodo C2 botnet".to_string(),
            resolved: false,
        };

        let msg = AlertDispatcher::format_syslog_rfc5424(&anomaly, Some("Smart Plug"));
        assert!(msg.starts_with("<130>1")); // local0 (128) + 2 (Critical)
        assert!(msg.contains("hearth-daemon"));
        assert!(msg.contains("mac=\"AA:BB:CC:DD:EE:FF\""));
        assert!(msg.contains("label=\"Smart Plug\""));
        assert!(msg.contains("Connection to Feodo C2 botnet"));
    }

    #[test]
    fn test_format_cef() {
        let anomaly = Anomaly {
            id: Some(2),
            mac: "11:22:33:44:55:66".to_string(),
            detected_at: Utc::now(),
            kind: AnomalyKind::ArpSpoofing,
            detail: "Gateway MAC changed".to_string(),
            resolved: false,
        };

        let msg = AlertDispatcher::format_cef(&anomaly, Some("Gateway Router"));
        assert!(msg.starts_with("CEF:0|Hearth|HearthSecurity|0.1.0|ArpSpoofing|ArpSpoofing|10|"));
        assert!(msg.contains("smac=11:22:33:44:55:66"));
        assert!(msg.contains("dhost=Gateway Router"));
    }

    #[test]
    fn test_format_syslog_and_cef_sanitizes_crlf_and_special_chars() {
        let anomaly = Anomaly {
            id: Some(3),
            mac: "AA:BB:CC:DD:EE:FF".to_string(),
            detected_at: Utc::now(),
            kind: AnomalyKind::MaliciousDest,
            detail: "Injected detail\r\n<0>1 2026-01-01 FAKE LOG\nMore text|with|pipes".to_string(),
            resolved: false,
        };

        let malicious_label = "Smart Plug\"] <0>1 FAKE\r\nNEXT LINE";
        let syslog = AlertDispatcher::format_syslog_rfc5424(&anomaly, Some(malicious_label));
        // Verify no raw newlines in syslog message
        assert!(!syslog.contains('\r'));
        assert!(!syslog.contains('\n'));
        // Verify quotes and brackets were escaped in SD-PARAM
        assert!(syslog.contains(r#"label="Smart Plug\"\] <0>1 FAKE  NEXT LINE""#));

        let cef = AlertDispatcher::format_cef(&anomaly, Some(malicious_label));
        assert!(!cef.contains('\r'));
        assert!(!cef.contains('\n'));
        assert!(cef.contains(r#"msg=Injected detail  <0>1 2026-01-01 FAKE LOG More text\|with\|pipes"#));
    }
}
