mod handlers;

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use hearth_core::store::Store;
use hearth_core::types::Config;
use std::sync::Arc;
use tower_http::cors::CorsLayer;

/// Shared state for all route handlers.
#[derive(Clone)]
pub struct AppState {
    pub store: Arc<Store>,
    pub config: Config,
}

/// Constant-time string equality comparison to prevent timing side-channel attacks.
fn constant_time_compare(a: &str, b: &str) -> bool {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    if a_bytes.len() != b_bytes.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a_bytes.iter().zip(b_bytes.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Authentication middleware enforcing API key for API endpoints.
async fn require_api_key(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    if let Some(ref expected_key) = state.config.api_key {
        if !expected_key.is_empty() {
            let headers = request.headers();
            let auth_header = headers
                .get("x-api-key")
                .or_else(|| headers.get("authorization"))
                .and_then(|h| h.to_str().ok());

            let is_authorized = match auth_header {
                Some(header_val) => {
                    if constant_time_compare(header_val, expected_key) {
                        true
                    } else if let Some(token) = header_val.strip_prefix("Bearer ") {
                        constant_time_compare(token.trim(), expected_key)
                    } else {
                        false
                    }
                }
                None => false,
            };

            if !is_authorized {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({
                        "error": "Unauthorized: Missing or invalid API key. Supply X-API-Key or Bearer token."
                    })),
                )
                    .into_response();
            }
        }
    }

    next.run(request).await
}

/// Start the dashboard HTTP server.
pub async fn serve(port: u16, store: Arc<Store>, config: Config) -> anyhow::Result<()> {
    let state = AppState { store, config };

    // Restrict CORS to local origins to prevent cross-origin intranet exfiltration
    let local_origin_1 = format!("http://127.0.0.1:{}", port).parse::<axum::http::HeaderValue>()?;
    let local_origin_2 = format!("http://localhost:{}", port).parse::<axum::http::HeaderValue>()?;

    let cors = CorsLayer::new()
        .allow_origin([local_origin_1, local_origin_2])
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::AUTHORIZATION,
            axum::http::HeaderName::from_static("x-api-key"),
        ]);

    let api_routes = Router::new()
        .route("/summary", get(handlers::summary))
        .route("/devices", get(handlers::devices))
        .route("/devices/:mac/history", get(handlers::device_history))
        .route("/devices/:mac/profile", get(handlers::device_profile))
        .route("/devices/:mac/ports", get(handlers::device_ports))
        .route(
            "/devices/:mac/anomalies",
            get(handlers::device_anomalies),
        )
        .route("/anomalies", get(handlers::anomalies))
        .route("/anomalies/:id/resolve", post(handlers::resolve_anomaly))
        .route("/scan", post(handlers::trigger_scan))
        .route(
            "/devices/:mac/quarantine",
            post(handlers::quarantine_device),
        )
        .route(
            "/devices/:mac/unquarantine",
            post(handlers::unquarantine_device),
        )
        .route("/threat-intel/sync", post(handlers::sync_threat_intel))
        .route("/dns/sync", post(handlers::sync_dns_blocklist))
        .route("/digest", get(handlers::digest))
        .route("/rules", get(handlers::rules))
        .route("/security", get(handlers::security_overview))
        .route("/threat-intel", get(handlers::threat_intel))
        .route("/dns/stats", get(handlers::dns_stats))
        .route("/dns/queries", get(handlers::dns_queries))
        .layer(middleware::from_fn_with_state(state.clone(), require_api_key));

    let app = Router::new()
        .route("/", get(handlers::index))
        .nest("/api", api_routes)
        .layer(cors)
        .with_state(state);

    let addr = format!("127.0.0.1:{}", port);
    tracing::info!("Dashboard listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
