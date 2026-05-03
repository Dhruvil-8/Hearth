use crate::AppState;
use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
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
