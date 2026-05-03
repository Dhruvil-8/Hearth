use chrono::Utc;
use hearth_core::capture::DeviceSnapshot;
use hearth_core::stats::StatsEngine;
use hearth_core::store::Store;
use hearth_core::types::*;
use std::net::IpAddr;
use std::sync::Arc;

/// Helper to create a store with a mature profile for testing anomaly detection.
fn setup_with_mature_profile() -> (Arc<Store>, tokio::sync::mpsc::Receiver<Anomaly>) {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let (tx, rx) = tokio::sync::mpsc::channel(64);

    // Create device
    store
        .upsert_device(&Device {
            mac: "AA:BB:CC:DD:EE:01".into(),
            ip: "192.168.1.100".parse().unwrap(),
            vendor: None,
            label: Some("Test Device".into()),
            first_seen: Utc::now(),
            last_seen: Utc::now(),
        })
        .unwrap();

    // Insert enough samples for a mature profile (72+ hours)
    let base_time = Utc::now() - chrono::Duration::days(5);
    for h in 0..120 {
        let ts = base_time + chrono::Duration::hours(h);
        store
            .insert_sample(&TrafficSample {
                id: None,
                mac: "AA:BB:CC:DD:EE:01".into(),
                timestamp: ts,
                bytes_sent: 5000, // baseline ~5000/hr
                bytes_recv: 10000,
                top_destinations: vec![Destination {
                    ip: "8.8.8.8".parse().unwrap(),
                    domain: None,
                    country: Some("US".into()),
                    bytes: 5000,
                }],
            })
            .unwrap();
    }

    // Build initial profile
    store
        .upsert_profile(&DeviceProfile {
            mac: "AA:BB:CC:DD:EE:01".into(),
            baseline_bytes_sent_per_hour_mean: 5000.0,
            baseline_bytes_sent_per_hour_stddev: 500.0,
            known_destinations: vec!["8.8.8.8".into()],
            active_hours: vec![8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20],
            profile_built_at: Utc::now(),
            observation_hours: 120,
        })
        .unwrap();

    (store, rx)
}

#[tokio::test]
async fn test_excessive_upload_anomaly() {
    let (store, mut rx) = setup_with_mature_profile();
    let (atx, _) = tokio::sync::mpsc::channel(64);
    let engine = StatsEngine::new(store.clone(), atx);

    // Create a snapshot with excessive upload (> mean + 3*stddev = 5000 + 1500 = 6500)
    let snapshot = DeviceSnapshot {
        mac: "AA:BB:CC:DD:EE:01".into(),
        ip: "192.168.1.100".parse().unwrap(),
        bytes_sent: 50000, // Way above threshold
        bytes_recv: 10000,
        destinations: vec![("8.8.8.8".parse::<IpAddr>().unwrap(), 50000)],
    };

    engine.process_new_samples(&[snapshot]).await.unwrap();

    // Check that an ExcessiveUpload anomaly was stored
    let anomalies = store.get_unresolved_anomalies().unwrap();
    let upload_anomalies: Vec<_> = anomalies
        .iter()
        .filter(|a| a.kind == AnomalyKind::ExcessiveUpload)
        .collect();
    assert!(
        !upload_anomalies.is_empty(),
        "Should detect ExcessiveUpload anomaly"
    );
}

#[tokio::test]
async fn test_new_destination_anomaly() {
    let (store, _rx) = setup_with_mature_profile();
    let (atx, _) = tokio::sync::mpsc::channel(64);
    let engine = StatsEngine::new(store.clone(), atx);

    // Contact a NEW public IP not in known_destinations
    let snapshot = DeviceSnapshot {
        mac: "AA:BB:CC:DD:EE:01".into(),
        ip: "192.168.1.100".parse().unwrap(),
        bytes_sent: 1000,
        bytes_recv: 2000,
        destinations: vec![
            ("185.199.108.153".parse::<IpAddr>().unwrap(), 1000), // New destination
        ],
    };

    engine.process_new_samples(&[snapshot]).await.unwrap();

    let anomalies = store.get_unresolved_anomalies().unwrap();
    let new_dest: Vec<_> = anomalies
        .iter()
        .filter(|a| a.kind == AnomalyKind::NewDestination)
        .collect();
    assert!(!new_dest.is_empty(), "Should detect NewDestination anomaly");
}

#[tokio::test]
async fn test_no_anomaly_for_known_destination() {
    let (store, _rx) = setup_with_mature_profile();
    let (atx, _) = tokio::sync::mpsc::channel(64);
    let engine = StatsEngine::new(store.clone(), atx);

    // Contact a KNOWN IP — should not trigger anomaly
    let snapshot = DeviceSnapshot {
        mac: "AA:BB:CC:DD:EE:01".into(),
        ip: "192.168.1.100".parse().unwrap(),
        bytes_sent: 3000,
        bytes_recv: 5000,
        destinations: vec![("8.8.8.8".parse::<IpAddr>().unwrap(), 3000)],
    };

    engine.process_new_samples(&[snapshot]).await.unwrap();

    let anomalies = store.get_unresolved_anomalies().unwrap();
    let new_dest: Vec<_> = anomalies
        .iter()
        .filter(|a| a.kind == AnomalyKind::NewDestination)
        .collect();
    assert!(
        new_dest.is_empty(),
        "Should NOT detect anomaly for known destination"
    );
}

#[tokio::test]
async fn test_no_anomaly_for_private_ip() {
    let (store, _rx) = setup_with_mature_profile();
    let (atx, _) = tokio::sync::mpsc::channel(64);
    let engine = StatsEngine::new(store.clone(), atx);

    // Contact a private IP — should never trigger NewDestination
    let snapshot = DeviceSnapshot {
        mac: "AA:BB:CC:DD:EE:01".into(),
        ip: "192.168.1.100".parse().unwrap(),
        bytes_sent: 1000,
        bytes_recv: 2000,
        destinations: vec![("192.168.1.1".parse::<IpAddr>().unwrap(), 1000)],
    };

    engine.process_new_samples(&[snapshot]).await.unwrap();

    let anomalies = store.get_unresolved_anomalies().unwrap();
    let new_dest: Vec<_> = anomalies
        .iter()
        .filter(|a| a.kind == AnomalyKind::NewDestination)
        .collect();
    assert!(
        new_dest.is_empty(),
        "Should NOT flag private IPs as new destinations"
    );
}

#[tokio::test]
async fn test_no_anomaly_for_immature_profile() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let (atx, _) = tokio::sync::mpsc::channel(64);
    let engine = StatsEngine::new(store.clone(), atx);

    // Create device with immature profile (< 72 hours)
    store
        .upsert_device(&Device {
            mac: "BB:CC:DD:EE:FF:00".into(),
            ip: "192.168.1.200".parse().unwrap(),
            vendor: None,
            label: None,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
        })
        .unwrap();

    store
        .upsert_profile(&DeviceProfile {
            mac: "BB:CC:DD:EE:FF:00".into(),
            baseline_bytes_sent_per_hour_mean: 1000.0,
            baseline_bytes_sent_per_hour_stddev: 100.0,
            known_destinations: vec![],
            active_hours: vec![10, 11, 12],
            profile_built_at: Utc::now(),
            observation_hours: 48, // Below 72h threshold
        })
        .unwrap();

    let snapshot = DeviceSnapshot {
        mac: "BB:CC:DD:EE:FF:00".into(),
        ip: "192.168.1.200".parse().unwrap(),
        bytes_sent: 999999, // Massive upload — but profile is immature
        bytes_recv: 0,
        destinations: vec![],
    };

    engine.process_new_samples(&[snapshot]).await.unwrap();

    let anomalies = store.get_unresolved_anomalies().unwrap();
    assert!(
        anomalies.is_empty(),
        "Immature profiles should not trigger anomalies"
    );
}
