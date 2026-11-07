use crate::store::Store;
use crate::types::{ThreatIntelConfig, ThreatIntelEntry};
use anyhow::Result;
use chrono::Utc;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};

/// Manager for downloading, caching, and matching Cyber Threat Intelligence (CTI) feeds.
pub struct ThreatIntelManager {
    store: Arc<Store>,
    config: ThreatIntelConfig,
}

impl ThreatIntelManager {
    pub fn new(store: Arc<Store>, config: ThreatIntelConfig) -> Self {
        Self { store, config }
    }

    /// Check if an IP address is recognized as a known malicious C2 or compromised host.
    pub fn is_malicious(&self, ip: &str) -> Result<Option<ThreatIntelEntry>> {
        self.store.is_ip_malicious(ip)
    }

    /// Retrieve summary statistics and recent CTI hits.
    pub fn get_stats(&self) -> Result<(usize, Vec<ThreatIntelEntry>)> {
        self.store.get_threat_intel_stats()
    }

    /// Download and synchronize all configured threat feeds into the local SQLite store.
    pub async fn sync_feeds(&self) -> Result<usize> {
        if !self.config.enabled {
            info!("Threat Intelligence is disabled in config");
            return Ok(0);
        }

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("Hearth-Network-Security/0.1.0")
            .build()?;

        let mut total_synced = 0;

        for feed_url in &self.config.feeds {
            info!("Fetching threat intelligence feed: {}", feed_url);
            match client.get(feed_url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    let body = resp.text().await.unwrap_or_default();
                    let entries = Self::parse_feed(feed_url, &body);
                    match self.store.upsert_threat_intel_ips(&entries) {
                        Ok(saved) => {
                            info!("Successfully synced {} IPs from feed {}", saved, feed_url);
                            total_synced += saved;
                        }
                        Err(e) => {
                            warn!("Failed to store threat IPs from {}: {}", feed_url, e);
                        }
                    }
                }
                Ok(resp) => {
                    warn!(
                        "Threat feed returned status {}: {}",
                        resp.status(),
                        feed_url
                    );
                }
                Err(e) => {
                    warn!("Failed to fetch threat feed {}: {}", feed_url, e);
                }
            }
        }

        info!("Threat intelligence sync complete: {} active malicious IPs tracked", total_synced);
        Ok(total_synced)
    }

    /// Parse raw feed text format into structured ThreatIntelEntry records.
    pub fn parse_feed(feed_url: &str, body: &str) -> Vec<ThreatIntelEntry> {
        let now = Utc::now();
        let (feed_name, threat_type, confidence) = if feed_url.contains("feodotracker") {
            ("Abuse.ch Feodo Tracker", "Botnet C2", 95)
        } else if feed_url.contains("compromised-ips") {
            ("Emerging Threats", "Compromised Host", 85)
        } else if feed_url.contains("urlhaus") {
            ("Abuse.ch URLhaus", "Malware Drop / C2", 90)
        } else {
            ("Custom Feed", "Malicious Host", 80)
        };

        let mut entries = Vec::new();

        for line in body.lines() {
            let trimmed = line.trim();
            // Skip comments and blank lines
            if trimmed.is_empty()
                || trimmed.starts_with('#')
                || trimmed.starts_with(';')
                || trimmed.starts_with("//")
            {
                continue;
            }

            // Extract the first whitespace-separated or comma-separated token
            let raw_ip = trimmed
                .split_whitespace()
                .next()
                .unwrap_or("")
                .split(',')
                .next()
                .unwrap_or("");

            // Validate that token is a valid IP address
            if let Ok(ip) = IpAddr::from_str(raw_ip) {
                // Ignore private LAN, link-local, loopback, multicast, and broadcast IPs
                let is_routable_wan = match ip {
                    IpAddr::V4(v4) => {
                        !v4.is_private()
                            && !v4.is_loopback()
                            && !v4.is_link_local()
                            && !v4.is_broadcast()
                            && !v4.is_documentation()
                            && v4.octets()[0] != 0
                    }
                    IpAddr::V6(v6) => !v6.is_loopback() && !v6.is_multicast() && !v6.is_unspecified(),
                };

                if is_routable_wan {
                    entries.push(ThreatIntelEntry {
                        ip: ip.to_string(),
                        feed: feed_name.to_string(),
                        threat_type: threat_type.to_string(),
                        confidence,
                        description: format!("Flagged by {} as active {}", feed_name, threat_type),
                        last_updated: now,
                    });
                }
            }
        }

        entries
    }

    /// Spawn a background task to synchronize threat intelligence on boot and periodically.
    pub fn start_sync_worker(self: Arc<Self>) {
        tokio::spawn(async move {
            info!("Threat Intelligence background sync worker started");
            // Run initial sync after a short delay (10s) to allow daemon startup
            tokio::time::sleep(Duration::from_secs(10)).await;
            if let Err(e) = self.sync_feeds().await {
                error!("Initial threat intelligence feed sync error: {}", e);
            }

            let sync_hours = self.config.sync_interval_hours.max(1);
            let mut interval = tokio::time::interval(Duration::from_secs(sync_hours * 3600));
            // First tick finishes immediately, skip it
            interval.tick().await;

            loop {
                interval.tick().await;
                info!("Running scheduled threat intelligence sync...");
                if let Err(e) = self.sync_feeds().await {
                    error!("Scheduled threat intelligence feed sync error: {}", e);
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_feed_filters_private_and_internal_ips() {
        let sample = "\
# Feed with mixed IPs
192.168.1.1 # private LAN
10.0.0.5 # private LAN
127.0.0.1 # loopback
198.51.100.1 # test net / documentation
1.1.1.1 # public IP
8.8.8.8 # public IP
";
        let entries = ThreatIntelManager::parse_feed("https://feodotracker.abuse.ch/blocklist.txt", sample);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].ip, "1.1.1.1");
        assert_eq!(entries[1].ip, "8.8.8.8");
    }
}
