use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// A discovered device on the local network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    /// MAC address in "AA:BB:CC:DD:EE:FF" format
    pub mac: String,
    /// IP address observed for this device
    pub ip: IpAddr,
    /// Vendor name from OUI lookup (e.g. "Philips Lighting BV")
    pub vendor: Option<String>,
    /// User-assigned friendly name, from config
    pub label: Option<String>,
    /// Timestamp when this device was first observed
    pub first_seen: DateTime<Utc>,
    /// Timestamp when this device was last observed
    pub last_seen: DateTime<Utc>,
    /// Whether this device has been isolated/quarantined from the network
    #[serde(default)]
    pub is_quarantined: bool,
}

/// One traffic observation — written to DB every 60 seconds per device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficSample {
    /// Database row ID (None for new records)
    pub id: Option<i64>,
    /// MAC address of the device
    pub mac: String,
    /// Timestamp of the sample
    pub timestamp: DateTime<Utc>,
    /// Bytes sent by this device in the sample window
    pub bytes_sent: u64,
    /// Bytes received by this device in the sample window
    pub bytes_recv: u64,
    /// Top 5 destinations by bytes
    pub top_destinations: Vec<Destination>,
}

/// A destination observed in traffic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Destination {
    /// Destination IP address
    pub ip: IpAddr,
    /// Resolved domain name from reverse DNS
    pub domain: Option<String>,
    /// Country code from GeoIP lookup (e.g. "US", "RU")
    pub country: Option<String>,
    /// Total bytes sent to this destination
    pub bytes: u64,
}

/// Anomaly flag produced by the stats engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anomaly {
    /// Database row ID (None for new records)
    pub id: Option<i64>,
    /// MAC address of the device that triggered the anomaly
    pub mac: String,
    /// When the anomaly was detected
    pub detected_at: DateTime<Utc>,
    /// Type of anomaly
    pub kind: AnomalyKind,
    /// Human-readable explanation
    pub detail: String,
    /// Whether the anomaly has been resolved/acknowledged
    pub resolved: bool,
}

/// Types of anomalies the stats engine can detect.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AnomalyKind {
    /// bytes_sent > 3σ above baseline
    ExcessiveUpload,
    /// IP never seen before for this device
    NewDestination,
    /// Traffic outside device's normal active hours
    UnusualHour,
    /// hearth-vad detected upload without wake word
    VoiceLeakSuspected,
    /// Unfamiliar device discovered on the network
    NewDevice,
    /// High-risk or insecure port detected (e.g. Telnet, unauthenticated RTSP)
    InsecurePortOpen,
    /// Outbound connection to known C2 botnet or malicious IP (from Threat Intel)
    MaliciousDest,
    /// ARP spoofing / MITM attack detected on LAN (e.g. gateway impersonation)
    ArpSpoofing,
    /// Rogue DHCP server detected offering unauthorized leases or rogue gateways
    RogueDhcp,
    /// Outbound TLS session initiated with a known malicious JA3/JA4 cryptographic fingerprint (C2 botnet)
    MaliciousTlsFingerprint,
    /// Rogue IPv6 router detected sending unauthorized SLAAC Router Advertisements (LAN hijack)
    RogueIpv6Router,
    /// Algorithmic DGA (Domain Generation Algorithm) zero-day C2 domain detected via heuristic Shannon entropy
    DgaDomainDetected,
    /// Covert DNS tunneling or data exfiltration detected in DNS query labels
    DnsTunnelingExfiltration,
    /// Zero-day LAN lateral movement / internal port sweep detected via honeypot canary trip
    CanaryTripDetected,
}

impl std::fmt::Display for AnomalyKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnomalyKind::ExcessiveUpload => write!(f, "ExcessiveUpload"),
            AnomalyKind::NewDestination => write!(f, "NewDestination"),
            AnomalyKind::UnusualHour => write!(f, "UnusualHour"),
            AnomalyKind::VoiceLeakSuspected => write!(f, "VoiceLeakSuspected"),
            AnomalyKind::NewDevice => write!(f, "NewDevice"),
            AnomalyKind::InsecurePortOpen => write!(f, "InsecurePortOpen"),
            AnomalyKind::MaliciousDest => write!(f, "MaliciousDest"),
            AnomalyKind::ArpSpoofing => write!(f, "ArpSpoofing"),
            AnomalyKind::RogueDhcp => write!(f, "RogueDhcp"),
            AnomalyKind::MaliciousTlsFingerprint => write!(f, "MaliciousTlsFingerprint"),
            AnomalyKind::RogueIpv6Router => write!(f, "RogueIpv6Router"),
            AnomalyKind::DgaDomainDetected => write!(f, "DgaDomainDetected"),
            AnomalyKind::DnsTunnelingExfiltration => write!(f, "DnsTunnelingExfiltration"),
            AnomalyKind::CanaryTripDetected => write!(f, "CanaryTripDetected"),
        }
    }
}

impl std::str::FromStr for AnomalyKind {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ExcessiveUpload" => Ok(AnomalyKind::ExcessiveUpload),
            "NewDestination" => Ok(AnomalyKind::NewDestination),
            "UnusualHour" => Ok(AnomalyKind::UnusualHour),
            "VoiceLeakSuspected" => Ok(AnomalyKind::VoiceLeakSuspected),
            "NewDevice" => Ok(AnomalyKind::NewDevice),
            "InsecurePortOpen" => Ok(AnomalyKind::InsecurePortOpen),
            "MaliciousDest" => Ok(AnomalyKind::MaliciousDest),
            "ArpSpoofing" => Ok(AnomalyKind::ArpSpoofing),
            "RogueDhcp" => Ok(AnomalyKind::RogueDhcp),
            "MaliciousTlsFingerprint" => Ok(AnomalyKind::MaliciousTlsFingerprint),
            "RogueIpv6Router" => Ok(AnomalyKind::RogueIpv6Router),
            "DgaDomainDetected" => Ok(AnomalyKind::DgaDomainDetected),
            "DnsTunnelingExfiltration" => Ok(AnomalyKind::DnsTunnelingExfiltration),
            "CanaryTripDetected" => Ok(AnomalyKind::CanaryTripDetected),
            _ => Err(anyhow::anyhow!("Unknown AnomalyKind: {}", s)),
        }
    }
}

/// An open port detected on a device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevicePort {
    pub mac: String,
    pub port: u16,
    pub service: String,
    pub is_insecure: bool,
    pub discovered_at: DateTime<Utc>,
}

/// Device profile — built from 72h of observation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceProfile {
    /// MAC address
    pub mac: String,
    /// Mean bytes sent per hour over observation window
    pub baseline_bytes_sent_per_hour_mean: f64,
    /// Standard deviation of bytes sent per hour
    pub baseline_bytes_sent_per_hour_stddev: f64,
    /// Known destination IP strings
    pub known_destinations: Vec<String>,
    /// Hours (0-23) when device is normally active
    pub active_hours: Vec<u8>,
    /// When this profile was last built
    pub profile_built_at: DateTime<Utc>,
    /// Total hours of observation — must be >= 72 for mature profile
    pub observation_hours: u32,
}

/// Runtime config, loaded from hearth.toml.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Network interface to capture on (e.g. "eth0", "wlan0")
    pub interface: String,
    /// Port for the web dashboard (default 7777)
    #[serde(default = "default_dashboard_port")]
    pub dashboard_port: u16,
    /// Optional subnet for active discovery (e.g. "192.168.1.0/24")
    pub subnet: Option<String>,
    /// Optional API key for securing dashboard and API endpoints
    pub api_key: Option<String>,
    /// Optional explicitly trusted gateway IP to prevent ARP/DHCP spoofing race conditions
    pub gateway_ip: Option<String>,
    /// Optional explicitly trusted gateway MAC to prevent ARP/DHCP spoofing race conditions
    pub gateway_mac: Option<String>,
    /// Path to SQLite database file
    #[serde(default = "default_db_path")]
    pub db_path: String,
    /// Path to OUI CSV database for vendor lookup
    #[serde(default = "default_oui_db_path")]
    pub oui_db_path: String,
    /// Path to GeoLite2 MMDB database for country lookup
    #[serde(default = "default_geoip_db_path")]
    pub geoip_db_path: String,
    /// Notification settings (webhook)
    #[serde(default)]
    pub notifications: NotificationConfig,
    /// Threat intelligence configuration
    #[serde(default)]
    pub threat_intel: ThreatIntelConfig,
    /// DNS threat sinkhole configuration
    #[serde(default)]
    pub dns: DnsConfig,
    /// Autonomous AI Security Analyst configuration (Local LLM or API-based)
    #[serde(default)]
    pub ai_analyst: AiAnalystConfig,
    /// Per-device configuration
    #[serde(default)]
    pub devices: Vec<DeviceConfig>,
}

/// Threat intelligence feed and matching configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_cti_feeds")]
    pub feeds: Vec<String>,
    #[serde(default = "default_cti_sync_hours")]
    pub sync_interval_hours: u64,
    /// Automatically isolate/quarantine devices upon confirmed C2 botnet contact
    #[serde(default)]
    pub auto_quarantine: bool,
}

impl Default for ThreatIntelConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            feeds: default_cti_feeds(),
            sync_interval_hours: default_cti_sync_hours(),
            auto_quarantine: false,
        }
    }
}

fn default_cti_feeds() -> Vec<String> {
    vec![
        "https://feodotracker.abuse.ch/downloads/ipblocklist.txt".to_string(),
        "https://rules.emergingthreats.net/blockrules/compromised-ips.txt".to_string(),
    ]
}

fn default_cti_sync_hours() -> u64 {
    24
}

/// A Threat Intelligence record for a known malicious IP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelEntry {
    pub ip: String,
    pub feed: String,
    pub threat_type: String,
    pub confidence: u8,
    pub description: String,
    pub last_updated: DateTime<Utc>,
}

/// DNS Threat Sinkhole configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_dns_port")]
    pub port: u16,
    #[serde(default = "default_upstream_dns")]
    pub upstream: String,
    /// Optional DNS-over-HTTPS (DoH) upstream resolver URL (e.g. "https://cloudflare-dns.com/dns-query")
    pub doh_upstream: Option<String>,
    #[serde(default = "default_blocklist_urls")]
    pub blocklists: Vec<String>,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            port: default_dns_port(),
            upstream: default_upstream_dns(),
            doh_upstream: None,
            blocklists: default_blocklist_urls(),
        }
    }
}

fn default_dns_port() -> u16 {
    53
}

fn default_upstream_dns() -> String {
    "1.1.1.1:53".to_string()
}

fn default_blocklist_urls() -> Vec<String> {
    vec![
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts".to_string(),
        "https://urlhaus.abuse.ch/downloads/hostfile/".to_string(),
    ]
}

/// Record of an observed DNS query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQueryLog {
    pub id: Option<i64>,
    pub timestamp: DateTime<Utc>,
    pub client_ip: IpAddr,
    pub client_mac: Option<String>,
    pub domain: String,
    pub query_type: String,
    pub is_blocked: bool,
    pub block_reason: Option<String>,
}

/// Summary statistics for the DNS Sinkhole.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnsStats {
    pub total_queries: u64,
    pub blocked_queries: u64,
    pub total_blocked_domains: usize,
    pub last_query_time: Option<DateTime<Utc>>,
}

/// Webhook notification configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NotificationConfig {
    /// Discord, Slack, or generic webhook URL
    pub webhook_url: Option<String>,
    /// Send alert on detected anomalies
    #[serde(default = "default_true")]
    pub notify_on_anomaly: bool,
    /// Send alert when an unfamiliar device joins the network
    #[serde(default = "default_true")]
    pub notify_on_new_device: bool,
    /// Send alert when insecure open ports are discovered
    #[serde(default = "default_true")]
    pub notify_on_vulnerability: bool,
    /// Send alert when outbound traffic to a malicious C2 IP is detected
    #[serde(default = "default_true")]
    pub notify_on_malicious_traffic: bool,
    /// Send alert when ARP spoofing / MITM attack is detected on LAN
    #[serde(default = "default_true")]
    pub notify_on_arp_spoofing: bool,
    /// Send alert when Rogue DHCP server is detected on LAN
    #[serde(default = "default_true")]
    pub notify_on_rogue_dhcp: bool,
    /// Optional Syslog / SIEM collector server address (e.g. "127.0.0.1:514" or "splunk.lan:514")
    pub syslog_server: Option<String>,
    /// Syslog format: "rfc5424" (default) or "cef" (ArcSight Common Event Format)
    #[serde(default = "default_syslog_format")]
    pub syslog_format: String,
}

fn default_syslog_format() -> String {
    "rfc5424".to_string()
}

fn default_true() -> bool {
    true
}

/// Per-device configuration from hearth.toml.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceConfig {
    /// MAC address of the device
    pub mac: String,
    /// Friendly label for the device
    pub label: String,
    /// Optional hard limit for upload per hour in MB
    pub max_upload_per_hour_mb: Option<f64>,
    /// Optional block hours range, e.g. ["23:00", "06:00"]
    pub block_hours: Option<[String; 2]>,
    /// Optional list of allowed domains — if set, all other destinations are blocked
    #[serde(default)]
    pub allow_domains: Option<Vec<String>>,
}

fn default_dashboard_port() -> u16 {
    7777
}

fn default_db_path() -> String {
    if cfg!(windows) {
        "./hearth.db".to_string()
    } else {
        "/var/lib/hearth/hearth.db".to_string()
    }
}

fn default_oui_db_path() -> String {
    if cfg!(windows) {
        "./oui.csv".to_string()
    } else {
        "/var/lib/hearth/oui.csv".to_string()
    }
}

fn default_geoip_db_path() -> String {
    if cfg!(windows) {
        "./GeoLite2-Country.mmdb".to_string()
    } else {
        "/var/lib/hearth/GeoLite2-Country.mmdb".to_string()
    }
}

/// Configuration for the Autonomous AI Security Analyst.
///
/// Completely provider-agnostic and model-agnostic:
/// - Works with Local Inference: Ollama, vLLM, llama.cpp, LocalAI, SGLang, or private clusters (e.g. 70B, 80B, 100B+, 405B models)
/// - Works with Cloud/Hosted APIs: OpenAI, Groq, OpenRouter, Mistral, Together AI, Azure OpenAI, etc.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiAnalystConfig {
    /// Enable or disable autonomous AI investigation
    #[serde(default)]
    pub enabled: bool,
    /// Universal OpenAI-compatible chat completions endpoint URL
    /// Local examples: "http://localhost:11434/v1/chat/completions" (Ollama), "http://192.168.1.50:8000/v1/chat/completions" (vLLM)
    /// API examples: "https://api.openai.com/v1/chat/completions", "https://api.groq.com/openai/v1/chat/completions"
    #[serde(default = "default_ai_endpoint")]
    pub endpoint: String,
    /// Target model identifier (User-selected, e.g. "llama3.3:70b", "deepseek-r1:70b", "qwen2.5:72b", "gpt-4o", "llama-3.1-405b")
    #[serde(default = "default_ai_model")]
    pub model: String,
    /// Optional Bearer API key (required for cloud APIs or authenticated local proxies; leave None for open local servers)
    pub api_key: Option<String>,
    /// Request timeout in seconds (default 60s, accommodates heavy 70B-100B+ reasoning chains)
    #[serde(default = "default_ai_timeout")]
    pub timeout_seconds: u64,
    /// Whether the AI Analyst is authorized to take proactive quarantine actions within strict deterministic guardrails
    #[serde(default)]
    pub autonomous_action: bool,
    /// Whether to deploy an autonomous multi-agent defense swarm (Threat Hunter, Forensics Auditor, Containment Commander)
    #[serde(default = "default_true")]
    pub enable_agent_swarm: bool,
    /// Minimum confidence threshold (0.0 to 1.0) required to trigger proactive quarantine (default 0.85)
    #[serde(default = "default_ai_confidence_threshold")]
    pub confidence_threshold: f64,
    /// Static list of MAC addresses the AI is strictly forbidden from ever isolating (e.g. admin laptops, servers)
    #[serde(default)]
    pub protected_macs: Vec<String>,
    /// Fine-grained permission rules set by the user defining the AI's operational authority
    #[serde(default)]
    pub permissions: AiPermissionsConfig,
}

/// User-configurable permission rules defining the exact operational authority of the AI Agent / Swarm.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiPermissionsConfig {
    /// Allow the AI to apply hardware firewall isolation on compromised devices
    #[serde(default = "default_true")]
    pub allow_quarantine: bool,
    /// Allow the AI to dynamically sinkhole zero-day C2 domains in the DNS proxy
    #[serde(default = "default_true")]
    pub allow_dns_sinkhole: bool,
    /// Allow the AI to trigger active network discovery and port security scans
    #[serde(default = "default_true")]
    pub allow_network_scans: bool,
    /// Allow the AI to mark false-positive or mitigated anomalies as resolved
    #[serde(default = "default_true")]
    pub allow_resolve_anomalies: bool,
    /// Maximum proactive defensive actions allowed per 1-hour window (anti-runaway circuit breaker)
    #[serde(default = "default_max_actions_per_hour")]
    pub max_actions_per_hour: u32,
}

impl Default for AiPermissionsConfig {
    fn default() -> Self {
        Self {
            allow_quarantine: true,
            allow_dns_sinkhole: true,
            allow_network_scans: true,
            allow_resolve_anomalies: true,
            max_actions_per_hour: 20,
        }
    }
}

fn default_max_actions_per_hour() -> u32 {
    20
}

impl Default for AiAnalystConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: default_ai_endpoint(),
            model: default_ai_model(),
            api_key: None,
            timeout_seconds: default_ai_timeout(),
            autonomous_action: false,
            enable_agent_swarm: true,
            confidence_threshold: default_ai_confidence_threshold(),
            protected_macs: Vec::new(),
            permissions: Default::default(),
        }
    }
}

fn default_ai_endpoint() -> String {
    "http://localhost:11434/v1/chat/completions".to_string()
}

fn default_ai_model() -> String {
    "llama3.3:70b".to_string()
}

fn default_ai_timeout() -> u64 {
    60
}

fn default_ai_confidence_threshold() -> f64 {
    0.85
}

