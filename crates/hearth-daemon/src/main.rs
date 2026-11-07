use hearth_core::ai_analyst::AiAnalyst;
use hearth_core::alerts::AlertDispatcher;
use hearth_core::arp_guard::ArpGuard;
use hearth_core::capture::{start_capture, start_demo_capture, DeviceSnapshot};
use hearth_core::config;
use hearth_core::dhcp_guard::DhcpGuard;
use hearth_core::discovery::NetworkScanner;
use hearth_core::dns::DnsSinkhole;
use hearth_core::geo::GeoIpDb;
use hearth_core::oui::OuiDb;
use hearth_core::ra_guard::RaGuard;
use hearth_core::scanner::PortScanner;
use hearth_core::stats::StatsEngine;
use hearth_core::store::Store;
use hearth_core::threat_intel::ThreatIntelManager;
use hearth_core::types::{Anomaly, AnomalyKind, Destination, Device, TrafficSample};
use hearth_rules::RulesEngine;

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
        if let Ok(Some(mut existing)) = store.get_device(&dev_cfg.mac) {
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
    let dash_cfg = cfg.clone();
    tokio::spawn(async move {
        if let Err(e) = hearth_dashboard::serve(dash_port, dash_store, dash_cfg).await {
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
    let cap_anomaly_tx = anomaly_tx.clone();
    std::thread::spawn(move || {
        // Try real capture first, fall back to demo mode
        match start_capture(&iface, cap_tx.clone(), Some(cap_anomaly_tx.clone())) {
            Ok(()) => {}
            Err(e) => {
                tracing::warn!("Real capture failed ({}), switching to demo mode", e);
                if let Err(e2) = start_demo_capture(cap_tx, Some(cap_anomaly_tx)) {
                    tracing::error!("Demo capture also failed: {}", e2);
                }
            }
        }
    });

    // 9. Stats engine
    let stats = StatsEngine::new(Arc::clone(&store), anomaly_tx.clone());

    // 10. Rules engine background enforcement loop
    let rules_engine = Arc::new(RulesEngine::new(cfg.clone(), Arc::clone(&store)));
    let rules_engine_task = Arc::clone(&rules_engine);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            match rules_engine_task.evaluate().await {
                Ok(actions) => {
                    if !actions.is_empty() {
                        tracing::info!("Evaluating rules: {} active actions", actions.len());
                        if let Err(e) = rules_engine_task.apply(&actions) {
                            tracing::error!("Failed to apply firewall rules: {}", e);
                        }
                    }
                }
                Err(e) => tracing::error!("Failed to evaluate firewall rules: {}", e),
            }
        }
    });

    // 11. Active network discovery & IoT vulnerability scanner task
    let net_scanner = Arc::new(NetworkScanner::new(
        Arc::clone(&store),
        Arc::clone(&oui_db),
        Some(anomaly_tx.clone()),
    ));
    let port_scanner = Arc::new(PortScanner::new(
        Arc::clone(&store),
        Some(anomaly_tx.clone()),
    ));
    let subnet_cfg = cfg.subnet.clone();

    let bg_scanner = Arc::clone(&net_scanner);
    let bg_port_scanner = Arc::clone(&port_scanner);
    tokio::spawn(async move {
        // Initial scan on boot
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        tracing::info!("Running initial active network discovery sweep...");
        if let Err(e) = bg_scanner.discover_network(subnet_cfg.as_deref()).await {
            tracing::error!("Initial network discovery error: {}", e);
        }
        tracing::info!("Running initial IoT vulnerability port scan...");
        if let Err(e) = bg_port_scanner.scan_all().await {
            tracing::error!("Initial port scan error: {}", e);
        }

        // Recurring scan every 15 minutes
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(900));
        loop {
            interval.tick().await;
            tracing::info!("Running periodic network discovery sweep...");
            let _ = bg_scanner.discover_network(subnet_cfg.as_deref()).await;
            let _ = bg_port_scanner.scan_all().await;
        }
    });

    // 12. Cyber Threat Intelligence (CTI) Feed Synchronizer
    let threat_intel = Arc::new(ThreatIntelManager::new(
        Arc::clone(&store),
        cfg.threat_intel.clone(),
    ));
    threat_intel.start_sync_worker();

    // 13. Anti-ARP Spoofing & MITM Guard
    let arp_guard = Arc::new(ArpGuard::new(
        Arc::clone(&store),
        anomaly_tx.clone(),
    ));
    arp_guard.clone().start_monitor(30);

    // 14. Anti-Rogue DHCP Guard (Anti-LAN hijacking)
    let dhcp_guard = Arc::new(DhcpGuard::new(
        Arc::clone(&store),
        anomaly_tx.clone(),
    ));
    let dhcp_guard_task = Arc::clone(&dhcp_guard);
    tokio::spawn(async move {
        // Attempt to bind UDP port 68 to intercept DHCP offers; falls back gracefully if port is taken
        if let Ok(socket) = tokio::net::UdpSocket::bind("0.0.0.0:68").await {
            let mut buf = [0u8; 1500];
            while let Ok((len, src)) = socket.recv_from(&mut buf).await {
                let _ = dhcp_guard_task.inspect_dhcp(src.ip(), "UNKNOWN", &buf[..len]).await;
            }
        }
    });

    // 15. Anti-Rogue IPv6 Router Guard (RFC 6105 RA-Guard)
    let _ra_guard = Arc::new(RaGuard::new(
        Arc::clone(&store),
        anomaly_tx.clone(),
    ));

    // 16. Native DNS Threat Sinkhole with Zero-Day Heuristic DGA & Tunneling Anomaly Engine
    let dns_sinkhole = Arc::new(
        DnsSinkhole::new(Arc::clone(&store), cfg.dns.clone())
            .with_anomaly_tx(anomaly_tx.clone()),
    );
    if cfg.dns.enabled {
        let dns = Arc::clone(&dns_sinkhole);
        tokio::spawn(async move {
            if let Err(e) = dns.run_server().await {
                tracing::warn!("DNS sinkhole service stopped: {}", e);
            }
        });
    }

    // 17. Daily pruning task
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

    // 18. Anomaly logging & Webhook/Syslog Alert Dispatcher
    let alert_dispatcher = AlertDispatcher::new(cfg.notifications.clone());
    let alert_store = Arc::clone(&store);
    let auto_quarantine_rules = Arc::clone(&rules_engine);
    let auto_quarantine_arp_guard = Arc::clone(&arp_guard);
    let auto_quarantine_enabled = cfg.threat_intel.auto_quarantine;
    let ai_analyst = Arc::new(AiAnalyst::new(cfg.ai_analyst.clone()));
    let ai_analyst_enabled = cfg.ai_analyst.enabled;

    tokio::spawn(async move {
        while let Some(anomaly) = anomaly_rx.recv().await {
            tracing::warn!(
                "Alert: [{}] {} — {}",
                anomaly.kind,
                anomaly.mac,
                anomaly.detail
            );

            let label = alert_store
                .get_device(&anomaly.mac)
                .ok()
                .flatten()
                .and_then(|d| d.label);

            let is_gateway = auto_quarantine_arp_guard.is_known_gateway_mac(&anomaly.mac).await;

            // 1. Optional Hybrid "Reflex + Brain" AI Investigation:
            // If user enabled AI Analyst, submit sanitized incident dossier to the configured local/API LLM.
            let mut ai_handled_quarantine = false;
            if ai_analyst_enabled {
                tracing::info!("🤖 Invoking AI Analyst for anomaly on device {}...", anomaly.mac);
                match ai_analyst.evaluate_incident(&anomaly, label.as_deref(), None).await {
                    Ok(decision) => {
                        tracing::info!(
                            "🧠 AI Analyst Assessment [{}]: Confidence={:.2}, Severity={:?}, Action={:?}\nReasoning: {}",
                            anomaly.mac,
                            decision.confidence,
                            decision.threat_severity,
                            decision.recommended_action,
                            decision.reasoning
                        );

                        let guardrail_eval = ai_analyst.validate_guardrails(&anomaly.mac, &decision, is_gateway);
                        if guardrail_eval.allowed_to_quarantine {
                            tracing::warn!(
                                "🛡️ AI AUTONOMOUS QUARANTINE EXECUTING: Device {} isolated based on verified high-confidence AI reasoning!",
                                anomaly.mac
                            );
                            if let Err(e) = auto_quarantine_rules.quarantine_device(&anomaly.mac).await {
                                tracing::error!("Failed to execute AI quarantine for {}: {}", anomaly.mac, e);
                            }
                            ai_handled_quarantine = true;
                        } else if let Some(veto) = guardrail_eval.veto_reason {
                            tracing::info!("🛡️ Guardrail Veto for {}: {}", anomaly.mac, veto);
                        }
                    }
                    Err(e) => {
                        tracing::warn!("AI Analyst offline or timed out: {}. Gracefully falling back to deterministic reflex rules.", e);
                    }
                }
            }

            // 2. Deterministic reflex quarantine (fallback or when AI is disabled):
            if !ai_handled_quarantine
                && auto_quarantine_enabled
                && (anomaly.kind == AnomalyKind::MaliciousDest
                    || anomaly.kind == AnomalyKind::MaliciousTlsFingerprint
                    || anomaly.kind == AnomalyKind::CanaryTripDetected
                    || anomaly.kind == AnomalyKind::DgaDomainDetected
                    || anomaly.kind == AnomalyKind::DnsTunnelingExfiltration)
            {
                let is_critical_infra = anomaly.mac == "00:00:00:00:00:00"
                    || anomaly.mac == "FF:FF:FF:FF:FF:FF"
                    || anomaly.mac.eq_ignore_ascii_case("UNKNOWN")
                    || is_gateway;

                if is_critical_infra {
                    tracing::error!(
                        "🛡️ SECURITY GUARD: Auto-quarantine suppressed for critical infrastructure / default gateway MAC {}!",
                        anomaly.mac
                    );
                } else {
                    tracing::warn!(
                        "🚨 AUTONOMOUS DEFENSE TRIGGERED: Auto-quarantining device {} due to confirmed threat ({})!",
                        anomaly.mac, anomaly.kind
                    );
                    if let Err(e) = auto_quarantine_rules.quarantine_device(&anomaly.mac).await {
                        tracing::error!("Failed to auto-quarantine device {}: {}", anomaly.mac, e);
                    }
                }
            }

            if let Err(e) = alert_dispatcher.dispatch(&anomaly, label.as_deref()).await {
                tracing::error!("Failed to dispatch webhook alert: {}", e);
            }
        }
    });

    // 14. Main event loop — receive snapshots, enrich, store, analyze
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
                is_quarantined: false,
            };
            if let Err(e) = store.upsert_device(&device) {
                tracing::error!("Failed to upsert device {}: {}", snap.mac, e);
            }

            // Build enriched destinations asynchronously without blocking Tokio worker thread
            let mut destinations = Vec::with_capacity(snap.destinations.len());
            for (ip, bytes) in &snap.destinations {
                let country = geo_db.lookup_country(ip);
                let domain = async_dns_lookup(*ip).await;
                destinations.push(Destination {
                    ip: *ip,
                    domain,
                    country,
                    bytes: *bytes,
                });
            }

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

/// Non-blocking, timeout-bounded reverse DNS lookup to prevent Tokio worker thread starvation.
async fn async_dns_lookup(ip: std::net::IpAddr) -> Option<String> {
    tokio::time::timeout(std::time::Duration::from_millis(200), async move {
        tokio::task::spawn_blocking(move || match dns_lookup::lookup_addr(&ip) {
            Ok(hostname) if hostname != ip.to_string() => Some(hostname),
            _ => None,
        })
        .await
        .ok()
        .flatten()
    })
    .await
    .ok()
    .flatten()
}
