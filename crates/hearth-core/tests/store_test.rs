use chrono::Utc;
use hearth_core::store::Store;
use hearth_core::types::*;
use std::net::IpAddr;

#[test]
fn test_device_crud() {
    let store = Store::new(":memory:").unwrap();

    let device = Device {
        mac: "AA:BB:CC:DD:EE:FF".to_string(),
        ip: "192.168.1.100".parse::<IpAddr>().unwrap(),
        vendor: Some("TestVendor".to_string()),
        label: Some("Test Device".to_string()),
        first_seen: Utc::now(),
        last_seen: Utc::now(),
        is_quarantined: false,
    };

    store.upsert_device(&device).unwrap();
    let devices = store.get_all_devices().unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].mac, "AA:BB:CC:DD:EE:FF");
    assert_eq!(devices[0].vendor, Some("TestVendor".to_string()));
    assert_eq!(devices[0].label, Some("Test Device".to_string()));
}

#[test]
fn test_device_upsert_updates() {
    let store = Store::new(":memory:").unwrap();

    let device1 = Device {
        mac: "AA:BB:CC:DD:EE:FF".to_string(),
        ip: "192.168.1.100".parse().unwrap(),
        vendor: Some("OldVendor".to_string()),
        label: None,
        first_seen: Utc::now(),
        last_seen: Utc::now(),
        is_quarantined: false,
    };
    store.upsert_device(&device1).unwrap();

    let device2 = Device {
        mac: "AA:BB:CC:DD:EE:FF".to_string(),
        ip: "192.168.1.101".parse().unwrap(),
        vendor: Some("NewVendor".to_string()),
        label: Some("Updated".to_string()),
        first_seen: Utc::now(),
        last_seen: Utc::now(),
        is_quarantined: false,
    };
    store.upsert_device(&device2).unwrap();

    let devices = store.get_all_devices().unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].vendor, Some("NewVendor".to_string()));
}

#[test]
fn test_device_upsert_preserves_first_seen_and_existing_label() {
    let store = Store::new(":memory:").unwrap();
    let first_seen = Utc::now() - chrono::Duration::days(2);
    let first_last_seen = Utc::now() - chrono::Duration::days(1);
    let new_last_seen = Utc::now();

    store
        .upsert_device(&Device {
            mac: "AA:BB:CC:DD:EE:FF".to_string(),
            ip: "192.168.1.100".parse().unwrap(),
            vendor: Some("OldVendor".to_string()),
            label: Some("Kitchen Speaker".to_string()),
            first_seen,
            last_seen: first_last_seen,
            is_quarantined: false,
        })
        .unwrap();

    store
        .upsert_device(&Device {
            mac: "AA:BB:CC:DD:EE:FF".to_string(),
            ip: "192.168.1.101".parse().unwrap(),
            vendor: Some("NewVendor".to_string()),
            label: None,
            first_seen: new_last_seen,
            last_seen: new_last_seen,
            is_quarantined: false,
        })
        .unwrap();

    let devices = store.get_all_devices().unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].ip, "192.168.1.101".parse::<IpAddr>().unwrap());
    assert_eq!(devices[0].vendor, Some("NewVendor".to_string()));
    assert_eq!(devices[0].label, Some("Kitchen Speaker".to_string()));
    assert_eq!(devices[0].first_seen, first_seen);
    assert_eq!(devices[0].last_seen, new_last_seen);
}

#[test]
fn test_traffic_sample_insert_and_query() {
    let store = Store::new(":memory:").unwrap();

    // Must create device first (foreign key)
    let device = Device {
        mac: "AA:BB:CC:DD:EE:01".to_string(),
        ip: "192.168.1.50".parse().unwrap(),
        vendor: None,
        label: None,
        first_seen: Utc::now(),
        last_seen: Utc::now(),
        is_quarantined: false,
    };
    store.upsert_device(&device).unwrap();

    let sample = TrafficSample {
        id: None,
        mac: "AA:BB:CC:DD:EE:01".to_string(),
        timestamp: Utc::now(),
        bytes_sent: 1024,
        bytes_recv: 2048,
        top_destinations: vec![Destination {
            ip: "8.8.8.8".parse().unwrap(),
            domain: Some("dns.google".to_string()),
            country: Some("US".to_string()),
            bytes: 512,
        }],
    };

    store.insert_sample(&sample).unwrap();
    let samples = store
        .get_samples_for_device("AA:BB:CC:DD:EE:01", 1)
        .unwrap();
    assert_eq!(samples.len(), 1);
    assert_eq!(samples[0].bytes_sent, 1024);
    assert_eq!(samples[0].top_destinations.len(), 1);
    assert_eq!(
        samples[0].top_destinations[0].domain,
        Some("dns.google".to_string())
    );
}

#[test]
fn test_anomaly_crud() {
    let store = Store::new(":memory:").unwrap();

    let anomaly = Anomaly {
        id: None,
        mac: "AA:BB:CC:DD:EE:FF".to_string(),
        detected_at: Utc::now(),
        kind: AnomalyKind::ExcessiveUpload,
        detail: "Test anomaly".to_string(),
        resolved: false,
    };

    let id = store.insert_anomaly(&anomaly).unwrap();
    assert!(id > 0);

    let unresolved = store.get_unresolved_anomalies().unwrap();
    assert_eq!(unresolved.len(), 1);
    assert_eq!(unresolved[0].kind, AnomalyKind::ExcessiveUpload);

    store.resolve_anomaly(id).unwrap();
    let unresolved = store.get_unresolved_anomalies().unwrap();
    assert_eq!(unresolved.len(), 0);
}

#[test]
fn test_profile_crud() {
    let store = Store::new(":memory:").unwrap();

    let profile = DeviceProfile {
        mac: "AA:BB:CC:DD:EE:FF".to_string(),
        baseline_bytes_sent_per_hour_mean: 5000.0,
        baseline_bytes_sent_per_hour_stddev: 1200.0,
        known_destinations: vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()],
        active_hours: vec![8, 9, 10, 11, 12, 13, 14, 15, 16, 17],
        profile_built_at: Utc::now(),
        observation_hours: 96,
    };

    store.upsert_profile(&profile).unwrap();

    let retrieved = store.get_profile("AA:BB:CC:DD:EE:FF").unwrap().unwrap();
    assert_eq!(retrieved.observation_hours, 96);
    assert!((retrieved.baseline_bytes_sent_per_hour_mean - 5000.0).abs() < 0.01);
    assert_eq!(retrieved.known_destinations.len(), 2);
    assert_eq!(retrieved.active_hours.len(), 10);
}

#[test]
fn test_device_bytes_aggregation() {
    let store = Store::new(":memory:").unwrap();

    let device = Device {
        mac: "AA:BB:CC:DD:EE:01".to_string(),
        ip: "192.168.1.50".parse().unwrap(),
        vendor: None,
        label: None,
        first_seen: Utc::now(),
        last_seen: Utc::now(),
        is_quarantined: false,
    };
    store.upsert_device(&device).unwrap();

    for i in 0..5 {
        store
            .insert_sample(&TrafficSample {
                id: None,
                mac: "AA:BB:CC:DD:EE:01".to_string(),
                timestamp: Utc::now(),
                bytes_sent: 1000 + i * 100,
                bytes_recv: 2000 + i * 200,
                top_destinations: vec![],
            })
            .unwrap();
    }

    let (sent, recv) = store
        .get_device_bytes_last_hours("AA:BB:CC:DD:EE:01", 1)
        .unwrap();
    assert_eq!(sent, 6000); // 1000+1100+1200+1300+1400
    assert_eq!(recv, 12000); // 2000+2200+2400+2600+2800
}

#[test]
fn test_prune_old_samples() {
    let store = Store::new(":memory:").unwrap();

    let device = Device {
        mac: "AA:BB:CC:DD:EE:01".to_string(),
        ip: "192.168.1.50".parse().unwrap(),
        vendor: None,
        label: None,
        first_seen: Utc::now(),
        last_seen: Utc::now(),
        is_quarantined: false,
    };
    store.upsert_device(&device).unwrap();

    // Insert a sample with current time
    store
        .insert_sample(&TrafficSample {
            id: None,
            mac: "AA:BB:CC:DD:EE:01".to_string(),
            timestamp: Utc::now(),
            bytes_sent: 1000,
            bytes_recv: 2000,
            top_destinations: vec![],
        })
        .unwrap();

    // Prune (nothing should be pruned since it's recent)
    store.prune_old_samples(7).unwrap();
    let samples = store.get_recent_samples(24).unwrap();
    assert_eq!(samples.len(), 1);
}

#[test]
fn test_get_profile_nonexistent() {
    let store = Store::new(":memory:").unwrap();
    let result = store.get_profile("NONEXISTENT").unwrap();
    assert!(result.is_none());
}

#[test]
fn test_device_exists_and_get_device() {
    let store = Store::new(":memory:").unwrap();
    assert!(!store.device_exists("AA:BB:CC:DD:EE:01").unwrap());

    let device = Device {
        mac: "AA:BB:CC:DD:EE:01".to_string(),
        ip: "192.168.1.50".parse().unwrap(),
        vendor: Some("Espressif".into()),
        label: Some("Smart Plug".into()),
        first_seen: Utc::now(),
        last_seen: Utc::now(),
        is_quarantined: false,
    };
    store.upsert_device(&device).unwrap();

    assert!(store.device_exists("AA:BB:CC:DD:EE:01").unwrap());
    let fetched = store.get_device("AA:BB:CC:DD:EE:01").unwrap();
    assert!(fetched.is_some());
    let fetched = fetched.unwrap();
    assert_eq!(fetched.label, Some("Smart Plug".into()));
    assert_eq!(fetched.vendor, Some("Espressif".into()));
}

#[test]
fn test_device_ports_crud_and_insecure() {
    let store = Store::new(":memory:").unwrap();

    let port1 = DevicePort {
        mac: "AA:BB:CC:DD:EE:01".to_string(),
        port: 23,
        service: "Telnet".into(),
        is_insecure: true,
        discovered_at: Utc::now(),
    };
    let port2 = DevicePort {
        mac: "AA:BB:CC:DD:EE:01".to_string(),
        port: 80,
        service: "HTTP".into(),
        is_insecure: false,
        discovered_at: Utc::now(),
    };

    store.upsert_device_port(&port1).unwrap();
    store.upsert_device_port(&port2).unwrap();

    let ports = store.get_ports_for_device("AA:BB:CC:DD:EE:01").unwrap();
    assert_eq!(ports.len(), 2);
    assert_eq!(ports[0].port, 23);
    assert!(ports[0].is_insecure);
    assert_eq!(ports[1].port, 80);
    assert!(!ports[1].is_insecure);

    let insecure = store.get_all_insecure_ports().unwrap();
    assert_eq!(insecure.len(), 1);
    assert_eq!(insecure[0].port, 23);
    assert_eq!(insecure[0].service, "Telnet");
}

#[test]
fn test_recent_unresolved_anomaly_check() {
    let store = Store::new(":memory:").unwrap();

    assert!(!store
        .has_recent_unresolved_anomaly("AA:BB:CC:DD:EE:01", &AnomalyKind::ExcessiveUpload, 2)
        .unwrap());

    let anomaly = Anomaly {
        id: None,
        mac: "AA:BB:CC:DD:EE:01".to_string(),
        detected_at: Utc::now(),
        kind: AnomalyKind::ExcessiveUpload,
        detail: "Upload spike".into(),
        resolved: false,
    };
    let id = store.insert_anomaly(&anomaly).unwrap();

    assert!(store
        .has_recent_unresolved_anomaly("AA:BB:CC:DD:EE:01", &AnomalyKind::ExcessiveUpload, 2)
        .unwrap());
    assert!(!store
        .has_recent_unresolved_anomaly("AA:BB:CC:DD:EE:01", &AnomalyKind::NewDestination, 2)
        .unwrap());

    // Once resolved, has_recent_unresolved should return false
    store.resolve_anomaly(id).unwrap();
    assert!(!store
        .has_recent_unresolved_anomaly("AA:BB:CC:DD:EE:01", &AnomalyKind::ExcessiveUpload, 2)
        .unwrap());
}

#[test]
fn test_device_quarantine_crud() {
    let store = Store::new(":memory:").unwrap();
    let device = Device {
        mac: "AA:BB:CC:DD:EE:99".to_string(),
        ip: "192.168.1.99".parse().unwrap(),
        vendor: Some("Unknown".into()),
        label: Some("Infected IoT".into()),
        first_seen: Utc::now(),
        last_seen: Utc::now(),
        is_quarantined: false,
    };
    store.upsert_device(&device).unwrap();

    assert!(!store.is_device_quarantined("AA:BB:CC:DD:EE:99").unwrap());
    assert_eq!(store.get_quarantined_devices().unwrap().len(), 0);

    // Apply quarantine
    store.set_device_quarantine("AA:BB:CC:DD:EE:99", true).unwrap();
    assert!(store.is_device_quarantined("AA:BB:CC:DD:EE:99").unwrap());

    let quarantined = store.get_quarantined_devices().unwrap();
    assert_eq!(quarantined.len(), 1);
    assert_eq!(quarantined[0].mac, "AA:BB:CC:DD:EE:99");
    assert!(quarantined[0].is_quarantined);

    // Release quarantine
    store.set_device_quarantine("AA:BB:CC:DD:EE:99", false).unwrap();
    assert!(!store.is_device_quarantined("AA:BB:CC:DD:EE:99").unwrap());
    assert_eq!(store.get_quarantined_devices().unwrap().len(), 0);
}

#[test]
fn test_threat_intel_crud_and_lookup() {
    let store = Store::new(":memory:").unwrap();

    let entry = ThreatIntelEntry {
        ip: "198.51.100.25".to_string(),
        feed: "Abuse.ch Feodo Tracker".into(),
        threat_type: "Botnet C2".into(),
        confidence: 95,
        description: "Active Mirai C2 Server".into(),
        last_updated: Utc::now(),
    };

    let saved = store.upsert_threat_intel_ips(&[entry]).unwrap();
    assert_eq!(saved, 1);

    let match_res = store.is_ip_malicious("198.51.100.25").unwrap();
    assert!(match_res.is_some());
    let match_res = match_res.unwrap();
    assert_eq!(match_res.threat_type, "Botnet C2");
    assert_eq!(match_res.confidence, 95);

    assert!(store.is_ip_malicious("8.8.8.8").unwrap().is_none());

    let (total, recent) = store.get_threat_intel_stats().unwrap();
    assert_eq!(total, 1);
    assert_eq!(recent.len(), 1);
}

#[test]
fn test_dns_sinkhole_blocked_domains_and_queries() {
    let store = Store::new(":memory:").unwrap();

    let domains = vec![
        "malware-c2.evil.com".to_string(),
        "phishing-login.ru".to_string(),
    ];
    let count = store.upsert_blocked_domains(&domains, "Threat List").unwrap();
    assert_eq!(count, 2);

    // Direct domain match
    assert!(store.is_domain_blocked("malware-c2.evil.com").unwrap());
    assert!(store.is_domain_blocked("phishing-login.ru").unwrap());
    // Safe domain
    assert!(!store.is_domain_blocked("google.com").unwrap());

    // Subdomain matching if parent was added
    store.upsert_blocked_domains(&["bad-domain.org".to_string()], "Threat List").unwrap();
    assert!(store.is_domain_blocked("sub.bad-domain.org").unwrap());

    // Query logging
    let query_log = DnsQueryLog {
        id: None,
        timestamp: Utc::now(),
        client_ip: "192.168.1.105".parse().unwrap(),
        client_mac: Some("AA:BB:CC:DD:EE:01".into()),
        domain: "malware-c2.evil.com".into(),
        query_type: "A".into(),
        is_blocked: true,
        block_reason: Some("Threat Sinkhole".into()),
    };
    store.insert_dns_query(&query_log).unwrap();

    let stats = store.get_dns_stats().unwrap();
    assert_eq!(stats.total_queries, 1);
    assert_eq!(stats.blocked_queries, 1);
    assert!(stats.total_blocked_domains >= 2);

    let recent_queries = store.get_recent_dns_queries(10).unwrap();
    assert_eq!(recent_queries.len(), 1);
    assert!(recent_queries[0].is_blocked);
    assert_eq!(recent_queries[0].domain, "malware-c2.evil.com");
}


