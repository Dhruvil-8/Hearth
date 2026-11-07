use crate::AppState;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Json};
use hearth_core::stats::generate_weekly_digest;
use serde::{Deserialize, Serialize};

/// GET / — Serve the embedded HTML dashboard.
pub async fn index() -> impl IntoResponse {
    Html(include_str!("../static/index.html"))
}

/// Dashboard summary response.
#[derive(Serialize)]
pub struct DashboardSummary {
    pub total_devices: u32,
    pub total_bytes_sent_today: u64,
    pub active_anomalies: u32,
    pub most_active_device: Option<String>,
}

/// GET /api/summary
pub async fn summary(State(state): State<AppState>) -> impl IntoResponse {
    let devices = state.store.get_all_devices().unwrap_or_default();
    let anomalies = state.store.get_unresolved_anomalies().unwrap_or_default();
    let total_sent = state.store.get_total_bytes_sent_today().unwrap_or(0);
    let most_active = state.store.get_most_active_device_today().unwrap_or(None);

    Json(DashboardSummary {
        total_devices: devices.len() as u32,
        total_bytes_sent_today: total_sent,
        active_anomalies: anomalies.len() as u32,
        most_active_device: most_active,
    })
}

/// Device with computed stats for the device table.
#[derive(Serialize)]
pub struct DeviceWithStats {
    #[serde(flatten)]
    pub device: hearth_core::types::Device,
    pub bytes_sent_last_hour: u64,
    pub bytes_recv_last_hour: u64,
    pub top_country: Option<String>,
    pub anomaly_count: u32,
    pub profile_mature: bool,
    pub open_ports: Vec<hearth_core::types::DevicePort>,
    pub has_insecure_ports: bool,
}

/// GET /api/devices
pub async fn devices(State(state): State<AppState>) -> impl IntoResponse {
    let devices = state.store.get_all_devices().unwrap_or_default();
    let mut result = Vec::new();

    for dev in devices {
        let (sent, recv) = state
            .store
            .get_device_bytes_last_hours(&dev.mac, 1)
            .unwrap_or((0, 0));
        let anomaly_count = state
            .store
            .count_anomalies_for_device(&dev.mac)
            .unwrap_or(0);
        let profile = state.store.get_profile(&dev.mac).unwrap_or(None);
        let profile_mature = profile
            .as_ref()
            .map(|p| p.observation_hours >= 72)
            .unwrap_or(false);

        let ports = state.store.get_ports_for_device(&dev.mac).unwrap_or_default();
        let has_insecure_ports = ports.iter().any(|p| p.is_insecure);

        // Get top country from recent samples
        let top_country = state
            .store
            .get_samples_for_device(&dev.mac, 1)
            .unwrap_or_default()
            .iter()
            .flat_map(|s| &s.top_destinations)
            .filter_map(|d| d.country.clone())
            .next();

        result.push(DeviceWithStats {
            device: dev,
            bytes_sent_last_hour: sent,
            bytes_recv_last_hour: recv,
            top_country,
            anomaly_count,
            profile_mature,
            open_ports: ports,
            has_insecure_ports,
        });
    }

    Json(result)
}

#[derive(Deserialize)]
pub struct HistoryQuery {
    #[serde(default = "default_hours")]
    pub hours: u32,
}
fn default_hours() -> u32 {
    24
}

/// GET /api/devices/:mac/history?hours=24
pub async fn device_history(
    State(state): State<AppState>,
    Path(mac): Path<String>,
    Query(q): Query<HistoryQuery>,
) -> impl IntoResponse {
    let mac = mac.replace("%3A", ":").replace("%3a", ":");
    match state.store.get_samples_for_device(&mac, q.hours) {
        Ok(samples) => Json(samples).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// GET /api/devices/:mac/profile
pub async fn device_profile(
    State(state): State<AppState>,
    Path(mac): Path<String>,
) -> impl IntoResponse {
    let mac = mac.replace("%3A", ":").replace("%3a", ":");
    match state.store.get_profile(&mac) {
        Ok(Some(profile)) => Json(profile).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// GET /api/devices/:mac/ports
pub async fn device_ports(
    State(state): State<AppState>,
    Path(mac): Path<String>,
) -> impl IntoResponse {
    let mac = mac.replace("%3A", ":").replace("%3a", ":");
    match state.store.get_ports_for_device(&mac) {
        Ok(ports) => Json(ports).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// GET /api/devices/:mac/anomalies
pub async fn device_anomalies(
    State(state): State<AppState>,
    Path(mac): Path<String>,
) -> impl IntoResponse {
    let mac = mac.replace("%3A", ":").replace("%3a", ":");
    match state.store.get_anomalies_for_device(&mac) {
        Ok(anomalies) => Json(anomalies).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// GET /api/anomalies
pub async fn anomalies(State(state): State<AppState>) -> impl IntoResponse {
    match state.store.get_unresolved_anomalies() {
        Ok(a) => Json(a).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// POST /api/anomalies/:id/resolve
pub async fn resolve_anomaly(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    match state.store.resolve_anomaly(id) {
        Ok(()) => Json(serde_json::json!({"status": "resolved"})).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// GET /api/digest
pub async fn digest(State(state): State<AppState>) -> impl IntoResponse {
    match generate_weekly_digest(&state.store) {
        Ok(d) => Json(d).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// GET /api/rules
pub async fn rules(State(state): State<AppState>) -> impl IntoResponse {
    let engine = hearth_rules::RulesEngine::new(state.config.clone(), state.store.clone());
    match engine.evaluate().await {
        Ok(actions) => Json(actions).into_response(),
        Err(e) => {
            tracing::error!("Error evaluating rules: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Security overview response.
#[derive(Serialize)]
pub struct SecurityOverview {
    pub total_devices: usize,
    pub devices_with_insecure_ports: usize,
    pub insecure_ports: Vec<hearth_core::types::DevicePort>,
    pub active_anomalies: usize,
}

/// GET /api/security
pub async fn security_overview(State(state): State<AppState>) -> impl IntoResponse {
    let devices = state.store.get_all_devices().unwrap_or_default();
    let insecure_ports = state.store.get_all_insecure_ports().unwrap_or_default();
    let anomalies = state.store.get_unresolved_anomalies().unwrap_or_default();

    let insecure_macs: std::collections::HashSet<String> =
        insecure_ports.iter().map(|p| p.mac.clone()).collect();

    Json(SecurityOverview {
        total_devices: devices.len(),
        devices_with_insecure_ports: insecure_macs.len(),
        insecure_ports,
        active_anomalies: anomalies.len(),
    })
}

/// POST /api/scan
pub async fn trigger_scan(State(state): State<AppState>) -> impl IntoResponse {
    let oui_db = std::sync::Arc::new(hearth_core::oui::OuiDb::load(&state.config.oui_db_path));
    let scanner =
        hearth_core::discovery::NetworkScanner::new(state.store.clone(), oui_db, None);
    let discovered = scanner
        .discover_network(state.config.subnet.as_deref())
        .await
        .unwrap_or_default();

    let port_scanner = hearth_core::scanner::PortScanner::new(state.store.clone(), None);
    let scanned_ports = port_scanner.scan_all().await.unwrap_or_default();

    Json(serde_json::json!({
        "status": "success",
        "discovered_devices": discovered.len(),
        "scanned_ports": scanned_ports.len()
    }))
}

/// POST /api/devices/:mac/quarantine
pub async fn quarantine_device(
    Path(mac): Path<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let rules_engine =
        hearth_rules::RulesEngine::new(state.config.clone(), state.store.clone());
    match rules_engine.quarantine_device(&mac).await {
        Ok(_) => Json(serde_json::json!({
            "status": "quarantined",
            "mac": mac,
            "message": "Device has been isolated at the network firewall."
        }))
        .into_response(),
        Err(e) => {
            tracing::error!("Failed to quarantine device {}: {}", mac, e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// POST /api/devices/:mac/unquarantine
pub async fn unquarantine_device(
    Path(mac): Path<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let rules_engine =
        hearth_rules::RulesEngine::new(state.config.clone(), state.store.clone());
    match rules_engine.unquarantine_device(&mac).await {
        Ok(_) => Json(serde_json::json!({
            "status": "unquarantined",
            "mac": mac,
            "message": "Device quarantine removed. Normal network access restored."
        }))
        .into_response(),
        Err(e) => {
            tracing::error!("Failed to unquarantine device {}: {}", mac, e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// GET /api/threat-intel
pub async fn threat_intel(State(state): State<AppState>) -> impl IntoResponse {
    match state.store.get_threat_intel_stats() {
        Ok((total, recent)) => Json(serde_json::json!({
            "enabled": state.config.threat_intel.enabled,
            "total_tracked_malicious_ips": total,
            "feeds": state.config.threat_intel.feeds,
            "recent_threats": recent
        }))
        .into_response(),
        Err(e) => {
            tracing::error!("Failed to get threat intel stats: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// POST /api/threat-intel/sync
pub async fn sync_threat_intel(State(state): State<AppState>) -> impl IntoResponse {
    let manager = hearth_core::threat_intel::ThreatIntelManager::new(
        state.store.clone(),
        state.config.threat_intel.clone(),
    );
    match manager.sync_feeds().await {
        Ok(synced) => Json(serde_json::json!({
            "status": "success",
            "synced_ips": synced
        }))
        .into_response(),
        Err(e) => {
            tracing::error!("Failed to sync threat intel feeds: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// GET /api/dns/stats
pub async fn dns_stats(State(state): State<AppState>) -> impl IntoResponse {
    match state.store.get_dns_stats() {
        Ok(stats) => Json(serde_json::json!({
            "enabled": state.config.dns.enabled,
            "port": state.config.dns.port,
            "upstream": state.config.dns.upstream,
            "stats": stats
        }))
        .into_response(),
        Err(e) => {
            tracing::error!("Failed to get DNS stats: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// GET /api/dns/queries
pub async fn dns_queries(State(state): State<AppState>) -> impl IntoResponse {
    let queries = state.store.get_recent_dns_queries(100).unwrap_or_default();
    Json(queries)
}

/// POST /api/dns/sync
pub async fn sync_dns_blocklist(State(state): State<AppState>) -> impl IntoResponse {
    let sinkhole =
        hearth_core::dns::DnsSinkhole::new(state.store.clone(), state.config.dns.clone());
    match sinkhole.sync_blocklists().await {
        Ok(synced) => Json(serde_json::json!({
            "status": "success",
            "blocked_domains_synced": synced
        }))
        .into_response(),
        Err(e) => {
            tracing::error!("Failed to sync DNS blocklists: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
