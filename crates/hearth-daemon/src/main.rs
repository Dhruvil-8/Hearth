use hearth_core::capture::{start_capture, start_demo_capture, DeviceSnapshot};
use hearth_core::config;
use hearth_core::geo::GeoIpDb;
use hearth_core::oui::OuiDb;
use hearth_core::stats::StatsEngine;
use hearth_core::store::Store;
use hearth_core::types::{Anomaly, Destination, Device, TrafficSample};

use chrono::Utc;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    tracing::info!("Hearth v0.1.0 starting...");

    // 2. Load config
    let config_path = std::env::args()
        .nth(1)
        .or_else(|| {
            std::env::args()
                .position(|a| a == "--config")
                .and_then(|i| std::env::args().nth(i + 1))
        })
        .unwrap_or_else(|| {
            if cfg!(windows) {
                "./config/hearth.toml".to_string()
            } else {
                "/etc/hearth/hearth.toml".to_string()
            }
        });
    let cfg = config::load_or_default(&config_path);
    tracing::info!(
        "Interface: {}, Dashboard port: {}",
        cfg.interface,
        cfg.dashboard_port
    );

    // 3. Open store
    let store = Arc::new(Store::new(&cfg.db_path)?);
    tracing::info!("Database opened at {}", cfg.db_path);

    // 4. Load OUI + GeoIP databases
    let oui_db = Arc::new(OuiDb::load(&cfg.oui_db_path));
    let geo_db = Arc::new(GeoIpDb::load(&cfg.geoip_db_path));

    // 5. Apply device labels from config
    for dev_cfg in &cfg.devices {
        if let Ok(Some(mut existing)) = store
            .get_all_devices()
            .map(|ds| ds.into_iter().find(|d| d.mac == dev_cfg.mac))
        {
            existing.label = Some(dev_cfg.label.clone());
            let _ = store.upsert_device(&existing);
        }
    }

    // 6. Channels
    let (snapshot_tx, mut snapshot_rx) = mpsc::channel::<Vec<DeviceSnapshot>>(64);
    let (anomaly_tx, mut anomaly_rx) = mpsc::channel::<Anomaly>(256);

    // 7. Spawn dashboard
    let dash_store = Arc::clone(&store);
    let dash_port = cfg.dashboard_port;
    tokio::spawn(async move {
        if let Err(e) = hearth_dashboard::serve(dash_port, dash_store).await {
            tracing::error!("Dashboard server error: {}", e);
        }
    });
    tracing::info!(
        "Dashboard available at http://127.0.0.1:{}",
        cfg.dashboard_port
    );

    // 8. Spawn capture thread
    let iface = cfg.interface.clone();
    let cap_tx = snapshot_tx.clone();
    std::thread::spawn(move || {
        // Try real capture first, fall back to demo mode
        match start_capture(&iface, cap_tx.clone()) {
            Ok(()) => {}
            Err(e) => {
                tracing::warn!("Real capture failed ({}), switching to demo mode", e);
                if let Err(e2) = start_demo_capture(cap_tx) {
                    tracing::error!("Demo capture also failed: {}", e2);
                }
            }
        }
    });

    // 9. Stats engine
    let stats = StatsEngine::new(Arc::clone(&store), anomaly_tx);

    // 10. Daily pruning task
    let prune_store = Arc::clone(&store);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(86400)).await;
            tracing::info!("Running daily sample pruning...");
            if let Err(e) = prune_store.prune_old_samples(7) {
                tracing::error!("Pruning failed: {}", e);
            }
        }
    });

    // 11. Anomaly logging task
    tokio::spawn(async move {
        while let Some(anomaly) = anomaly_rx.recv().await {
            tracing::warn!(
                "Alert: [{}] {} — {}",
                anomaly.kind,
                anomaly.mac,
                anomaly.detail
            );
        }
    });

    // 12. Main event loop — receive snapshots, enrich, store, analyze
    tracing::info!("Hearth is running. Waiting for network data...");
    while let Some(snapshots) = snapshot_rx.recv().await {
        for snap in &snapshots {
            let vendor = oui_db.lookup(&snap.mac);
            let now = Utc::now();

            // Upsert device
            let device = Device {
                mac: snap.mac.clone(),
                ip: snap.ip,
                vendor: vendor.clone(),
                label: None,
                first_seen: now,
                last_seen: now,
            };
            if let Err(e) = store.upsert_device(&device) {
                tracing::error!("Failed to upsert device {}: {}", snap.mac, e);
            }

            // Build enriched destinations
            let destinations: Vec<Destination> = snap
                .destinations
                .iter()
                .map(|(ip, bytes)| {
                    let country = geo_db.lookup_country(ip);
                    let domain = dns_lookup(ip);
                    Destination {
                        ip: *ip,
                        domain,
                        country,
                        bytes: *bytes,
                    }
                })
                .collect();

            // Insert traffic sample
            let sample = TrafficSample {
                id: None,
                mac: snap.mac.clone(),
                timestamp: now,
                bytes_sent: snap.bytes_sent,
                bytes_recv: snap.bytes_recv,
                top_destinations: destinations,
            };
            if let Err(e) = store.insert_sample(&sample) {
                tracing::error!("Failed to insert sample for {}: {}", snap.mac, e);
            }
        }

        // Run stats engine
        if let Err(e) = stats.process_new_samples(&snapshots).await {
            tracing::error!("Stats engine error: {}", e);
        }
    }

    tracing::info!("Hearth shutting down.");
    Ok(())
}

/// Best-effort reverse DNS lookup.
fn dns_lookup(ip: &std::net::IpAddr) -> Option<String> {
    match dns_lookup::lookup_addr(ip) {
        Ok(hostname) if hostname != ip.to_string() => Some(hostname),
        _ => None,
    }
}
