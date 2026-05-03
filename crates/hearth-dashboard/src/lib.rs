mod handlers;

use axum::{
    routing::{get, post},
    Router,
};
use hearth_core::store::Store;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};

/// Shared state for all route handlers.
#[derive(Clone)]
pub struct AppState {
    pub store: Arc<Store>,
}

/// Start the dashboard HTTP server.
pub async fn serve(port: u16, store: Arc<Store>) -> anyhow::Result<()> {
    let state = AppState { store };

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/", get(handlers::index))
        .route("/api/summary", get(handlers::summary))
        .route("/api/devices", get(handlers::devices))
        .route("/api/devices/:mac/history", get(handlers::device_history))
        .route("/api/devices/:mac/profile", get(handlers::device_profile))
        .route(
            "/api/devices/:mac/anomalies",
            get(handlers::device_anomalies),
        )
        .route("/api/anomalies", get(handlers::anomalies))
        .route(
            "/api/anomalies/:id/resolve",
            post(handlers::resolve_anomaly),
        )
        .route("/api/digest", get(handlers::digest))
        .layer(cors)
        .with_state(state);

    let addr = format!("127.0.0.1:{}", port);
    tracing::info!("Dashboard listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
