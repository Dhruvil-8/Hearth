use crate::store::Store;
use crate::types::FleetConfig;
use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};

/// Comprehensive probe telemetry report transmitted to a central Hearth Fleet Console or SIEM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeTelemetryReport {
    pub probe_id: String,
    pub timestamp: chrono::DateTime<Utc>,
    pub total_devices_discovered: usize,
    pub active_devices_last_24h: usize,
    pub quarantined_devices_count: usize,
    pub unresolved_anomalies_count: usize,
    pub total_bytes_sent_today: u64,
    pub threat_intel_ips_tracked: usize,
    pub total_dns_queries: u64,
    pub blocked_dns_queries: u64,
    pub status: String,
}

/// Multi-Probe Fleet Manager for distributed enterprise deployments and branch offices.
pub struct FleetManager {
    store: Arc<Store>,
    config: FleetConfig,
    client: reqwest::Client,
}

impl FleetManager {
    /// Create a new fleet manager instance.
    pub fn new(store: Arc<Store>, config: FleetConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self {
            store,
            config,
            client,
        }
    }

    /// Compile a real-time probe telemetry snapshot.
    pub fn compile_report(&self) -> Result<ProbeTelemetryReport> {
        let all_devices = self.store.get_all_devices().unwrap_or_default();
        let quarantined = self.store.get_quarantined_devices().unwrap_or_default();
        let anomalies = self.store.get_unresolved_anomalies().unwrap_or_default();
        let total_sent = self.store.get_total_bytes_sent_today().unwrap_or(0);
        let (cti_total, _) = self.store.get_threat_intel_stats().unwrap_or((0, Vec::new()));
        let dns_stats = self.store.get_dns_stats().unwrap_or_default();

        let cutoff_24h = Utc::now() - chrono::Duration::hours(24);
        let active_24h = all_devices.iter().filter(|d| d.last_seen > cutoff_24h).count();

        Ok(ProbeTelemetryReport {
            probe_id: self.config.probe_id.clone(),
            timestamp: Utc::now(),
            total_devices_discovered: all_devices.len(),
            active_devices_last_24h: active_24h,
            quarantined_devices_count: quarantined.len(),
            unresolved_anomalies_count: anomalies.len(),
            total_bytes_sent_today: total_sent,
            threat_intel_ips_tracked: cti_total,
            total_dns_queries: dns_stats.total_queries,
            blocked_dns_queries: dns_stats.blocked_queries,
            status: "healthy".to_string(),
        })
    }

    /// Dispatch probe telemetry to central fleet management endpoint.
    pub async fn send_telemetry(&self) -> Result<()> {
        let endpoint = match &self.config.endpoint {
            Some(ep) if !ep.trim().is_empty() => ep,
            _ => return Ok(()),
        };

        let report = self.compile_report()?;

        let mut req = self.client.post(endpoint).json(&report);
        if let Some(token) = &self.config.api_token {
            if !token.is_empty() {
                req = req.bearer_auth(token);
            }
        }

        let resp = req
            .send()
            .await
            .with_context(|| format!("Failed to transmit telemetry to fleet endpoint: {}", endpoint))?;

        if resp.status().is_success() {
            info!(
                "[FLEET] Successfully transmitted telemetry heartbeat for probe '{}'",
                self.config.probe_id
            );
        } else {
            warn!(
                "[FLEET] Fleet console returned non-success HTTP status: {}",
                resp.status()
            );
        }

        Ok(())
    }

    /// Start the autonomous background telemetry reporter loop.
    pub fn start_worker(self: Arc<Self>) {
        if !self.config.enabled || self.config.endpoint.is_none() {
            info!("[FLEET] Fleet telemetry reporting is disabled or unconfigured.");
            return;
        }

        let interval_secs = self.config.sync_interval_seconds.max(30);
        info!(
            "[FLEET] Starting fleet manager background sync for probe '{}' every {}s",
            self.config.probe_id, interval_secs
        );

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
            loop {
                interval.tick().await;
                if let Err(e) = self.send_telemetry().await {
                    error!("[FLEET] Telemetry transmission error: {}", e);
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compile_report() {
        let store = Arc::new(Store::new(":memory:").unwrap());
        let config = FleetConfig {
            enabled: true,
            endpoint: Some("http://127.0.0.1:9999/telemetry".to_string()),
            probe_id: "test-probe-01".to_string(),
            api_token: Some("secret-token".to_string()),
            sync_interval_seconds: 60,
        };

        let manager = FleetManager::new(store, config);
        let report = manager.compile_report().unwrap();
        assert_eq!(report.probe_id, "test-probe-01");
        assert_eq!(report.status, "healthy");
    }
}

