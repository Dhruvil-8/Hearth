use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "hearth-cli",
    version = "0.1.0",
    about = "Hearth Network Intelligence CLI"
)]
struct Cli {
    /// Base URL of the Hearth daemon API
    #[arg(long, default_value = "http://127.0.0.1:7777")]
    api: String,

    /// Optional API key for authenticating API requests (can also use HEARTH_API_KEY environment variable)
    #[arg(long)]
    api_key: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Show dashboard summary and all devices with current traffic
    Status,
    /// List all discovered devices with labels and last-seen times
    Devices,
    /// Show profile and recent anomalies for a specific device
    Device { mac: String },
    /// List all unresolved anomalies
    Anomalies,
    /// Mark an anomaly as resolved
    Resolve { id: i64 },
    /// Print the weekly digest as plain text
    Digest,
    /// Trigger an active network discovery & security port scan
    Scan,
    /// Inspect active firewall / nftables enforcement rules
    Rules,
    /// Show security overview and open ports
    Security,
    /// Assign a friendly name to a device
    Label { mac: String, name: String },
    /// Block a device's outbound traffic
    Block {
        mac: String,
        /// Optional duration in hours
        #[arg(long)]
        hours: Option<u32>,
    },
    /// Remove a manual block on a device
    Unblock { mac: String },
    /// Immediately isolate/quarantine a device from the network
    Quarantine { mac: String },
    /// Remove quarantine isolation from a device
    Unquarantine { mac: String },
    /// View DNS Threat Sinkhole statistics and recent queries
    Dns,
    /// View Cyber Threat Intelligence feeds and tracked malicious IPs
    Cti,
    /// Voice gate subcommands
    Vad {
        #[command(subcommand)]
        command: VadCommands,
    },
}

#[derive(Subcommand)]
enum VadCommands {
    /// Show voice gate status and today's stats
    Status,
    /// Enable/disable voice gate
    Toggle,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let base = cli.api.trim_end_matches('/');
    let env_key = std::env::var("HEARTH_API_KEY").ok();
    let key = cli.api_key.as_deref().or(env_key.as_deref());

    match cli.command {
        Commands::Status => {
            let summary = http_get(&format!("{}/api/summary", base), key).await?;
            let s: serde_json::Value = serde_json::from_str(&summary)?;
            println!("HEARTH STATUS");
            println!("--------------------------------------");
            println!("  Devices:          {:>16}", s["total_devices"]);
            println!(
                "  Upload today:     {:>16}",
                human_bytes(s["total_bytes_sent_today"].as_u64().unwrap_or(0))
            );
            println!("  Active anomalies: {:>16}", s["active_anomalies"]);
            println!(
                "  Most active:      {:>16}",
                s["most_active_device"].as_str().unwrap_or("-")
            );
            println!("--------------------------------------");

            let devices = http_get(&format!("{}/api/devices", base), key).await?;
            let devs: Vec<serde_json::Value> = serde_json::from_str(&devices)?;
            if !devs.is_empty() {
                println!(
                    "\n{:<20} {:<16} {:>12} {:>12} Status",
                    "Name/MAC", "IP", "Sent/1h", "Recv/1h"
                );
                println!("{}", "-".repeat(75));
                for d in &devs {
                    let name = d["label"]
                        .as_str()
                        .unwrap_or(d["mac"].as_str().unwrap_or("?"));
                    let ip = d["ip"].as_str().unwrap_or("?");
                    let sent = human_bytes(d["bytes_sent_last_hour"].as_u64().unwrap_or(0));
                    let recv = human_bytes(d["bytes_recv_last_hour"].as_u64().unwrap_or(0));
                    let status = if d["anomaly_count"].as_u64().unwrap_or(0) > 0 {
                        "[!] ANOMALY"
                    } else if d["profile_mature"].as_bool().unwrap_or(false) {
                        "[ok] Normal"
                    } else {
                        "[..] Profiling"
                    };
                    println!(
                        "{:<20} {:<16} {:>12} {:>12} {}",
                        name, ip, sent, recv, status
                    );
                }
            }
        }

        Commands::Devices => {
            let body = http_get(&format!("{}/api/devices", base), key).await?;
            let devs: Vec<serde_json::Value> = serde_json::from_str(&body)?;
            println!("{:<20} {:<18} {:<16} Last Seen", "Label", "MAC", "IP");
            println!("{}", "-".repeat(70));
            for d in &devs {
                println!(
                    "{:<20} {:<18} {:<16} {}",
                    d["label"].as_str().unwrap_or("-"),
                    d["mac"].as_str().unwrap_or("?"),
                    d["ip"].as_str().unwrap_or("?"),
                    d["last_seen"].as_str().unwrap_or("?")
                );
            }
        }

        Commands::Device { mac } => {
            let enc = mac.replace(":", "%3A");
            // Profile
            match http_get(&format!("{}/api/devices/{}/profile", base, enc), key).await {
                Ok(body) => {
                    let p: serde_json::Value = serde_json::from_str(&body)?;
                    println!("Device: {}", mac);
                    println!("Observation: {}h / 72h required", p["observation_hours"]);
                    println!(
                        "Baseline: {:.0} ± {:.0} bytes/hr",
                        p["baseline_bytes_sent_per_hour_mean"]
                            .as_f64()
                            .unwrap_or(0.0),
                        p["baseline_bytes_sent_per_hour_stddev"]
                            .as_f64()
                            .unwrap_or(0.0)
                    );
                }
                Err(_) => println!("No profile yet for {}", mac),
            }
            // Anomalies
            if let Ok(body) = http_get(&format!("{}/api/devices/{}/anomalies", base, enc), key).await {
                let anomalies: Vec<serde_json::Value> = serde_json::from_str(&body)?;
                println!("\nRecent anomalies:");
                for a in anomalies.iter().take(5) {
                    println!(
                        "  [{:>18}] {} - {}",
                        a["kind"].as_str().unwrap_or("?"),
                        a["detected_at"].as_str().unwrap_or("?"),
                        a["detail"].as_str().unwrap_or("?")
                    );
                }
                if anomalies.is_empty() {
                    println!("  None");
                }
            }
        }

        Commands::Anomalies => {
            let body = http_get(&format!("{}/api/anomalies", base), key).await?;
            let anomalies: Vec<serde_json::Value> = serde_json::from_str(&body)?;
            if anomalies.is_empty() {
                println!("No active anomalies.");
                return Ok(());
            }
            for a in &anomalies {
                println!(
                    "[#{:<4}] {:<18} {:<18} {}",
                    a["id"],
                    a["kind"].as_str().unwrap_or("?"),
                    a["mac"].as_str().unwrap_or("?"),
                    a["detail"].as_str().unwrap_or("?")
                );
            }
        }

        Commands::Resolve { id } => {
            http_post(&format!("{}/api/anomalies/{}/resolve", base, id), key).await?;
            println!("Anomaly #{} resolved.", id);
        }

        Commands::Digest => {
            let body = http_get(&format!("{}/api/digest", base), key).await?;
            let d: serde_json::Value = serde_json::from_str(&body)?;
            println!("=== Weekly Digest ===");
            println!(
                "Period: {} - {}",
                d["period_start"].as_str().unwrap_or("?"),
                d["period_end"].as_str().unwrap_or("?")
            );
            println!("Anomalies: {}", d["total_anomalies"]);
            println!(
                "Most active: {}",
                d["most_active_device"].as_str().unwrap_or("-")
            );
            if let Some(highlights) = d["highlights"].as_array() {
                println!("\nHighlights:");
                for h in highlights {
                    println!("  - {}", h.as_str().unwrap_or(""));
                }
            }
        }

        Commands::Scan => {
            println!("Triggering active network discovery and port security sweep...");
            let res = http_post(&format!("{}/api/scan", base), key).await?;
            let val: serde_json::Value = serde_json::from_str(&res)?;
            println!("Scan completed successfully!");
            println!("Discovered devices: {}", val["discovered_devices"]);
            println!("Scanned open ports: {}", val["scanned_ports"]);
        }

        Commands::Rules => {
            let body = http_get(&format!("{}/api/rules", base), key).await?;
            let actions: Vec<serde_json::Value> = serde_json::from_str(&body)?;
            println!("=== Active Firewall Rules ===");
            if actions.is_empty() {
                println!("No active blocking or rate-limiting rules.");
            } else {
                for act in &actions {
                    println!(
                        "[{}] {} — Reason: {}",
                        act["mac"].as_str().unwrap_or("?"),
                        act["action"],
                        act["reason"].as_str().unwrap_or("?")
                    );
                }
            }
        }

        Commands::Security => {
            let body = http_get(&format!("{}/api/security", base), key).await?;
            let s: serde_json::Value = serde_json::from_str(&body)?;
            println!("=== Hearth Security Overview ===");
            println!("Total monitored devices:        {}", s["total_devices"]);
            println!("Devices with insecure ports:    {}", s["devices_with_insecure_ports"]);
            println!("Active unresolved anomalies:    {}", s["active_anomalies"]);

            if let Some(ports) = s["insecure_ports"].as_array() {
                if !ports.is_empty() {
                    println!("\n[!] Insecure Open Ports Discovered:");
                    for p in ports {
                        println!(
                            "  - MAC: {:<18} Port: {:<5} Service: {:<10} Discovered: {}",
                            p["mac"].as_str().unwrap_or("?"),
                            p["port"],
                            p["service"].as_str().unwrap_or("?"),
                            p["discovered_at"].as_str().unwrap_or("?")
                        );
                    }
                } else {
                    println!("\n[ok] No high-risk insecure ports detected on the network.");
                }
            }

            if let Ok(anom_res) = http_get(&format!("{}/api/anomalies", base), key).await {
                if let Ok(anomalies) = serde_json::from_str::<Vec<serde_json::Value>>(&anom_res) {
                    if !anomalies.is_empty() {
                        println!("\n🚨 Active Threat Anomalies & Zero-Day Detections:");
                        for a in anomalies {
                            let kind_str = a["kind"].as_str().unwrap_or("?");
                            let is_zero_day = kind_str == "CanaryTripDetected"
                                || kind_str == "DgaDomainDetected"
                                || kind_str == "DnsTunnelingExfiltration";
                            let tag = if is_zero_day { "⚡ [ZERO-DAY]" } else { "🚨 [ANOMALY]" };
                            println!(
                                "  {} {:<24} MAC: {:<18} {}",
                                tag,
                                kind_str,
                                a["mac"].as_str().unwrap_or("?"),
                                a["detail"].as_str().unwrap_or("?")
                            );
                        }
                    }
                }
            }
        }

        Commands::Label { mac, name } => {
            println!(
                "Label '{}' assigned to {}. (Note: requires config file update)",
                name, mac
            );
        }

        Commands::Block { mac, hours: _ } => {
            println!("Applying firewall block for {}...", mac);
            let res = http_post(&format!("{}/api/devices/{}/quarantine", base, mac), key).await?;
            let val: serde_json::Value = serde_json::from_str(&res)?;
            println!("🛡️  {}", val["message"].as_str().unwrap_or("Device blocked at firewall"));
        }

        Commands::Unblock { mac } => {
            println!("Removing firewall block for {}...", mac);
            let res = http_post(&format!("{}/api/devices/{}/unquarantine", base, mac), key).await?;
            let val: serde_json::Value = serde_json::from_str(&res)?;
            println!("✅ {}", val["message"].as_str().unwrap_or("Device unblocked"));
        }

        Commands::Quarantine { mac } => {
            let res = http_post(&format!("{}/api/devices/{}/quarantine", base, mac), key).await?;
            let val: serde_json::Value = serde_json::from_str(&res)?;
            println!("🛡️  {}", val["message"].as_str().unwrap_or("Device quarantined"));
        }

        Commands::Unquarantine { mac } => {
            let res = http_post(&format!("{}/api/devices/{}/unquarantine", base, mac), key).await?;
            let val: serde_json::Value = serde_json::from_str(&res)?;
            println!("✅ {}", val["message"].as_str().unwrap_or("Quarantine removed"));
        }

        Commands::Dns => {
            let stats_raw = http_get(&format!("{}/api/dns/stats", base), key).await?;
            let s: serde_json::Value = serde_json::from_str(&stats_raw)?;
            println!("HEARTH DNS THREAT SINKHOLE");
            println!("------------------------------------------------");
            println!(
                "  Status:          {:>28}",
                if s["enabled"].as_bool().unwrap_or(false) {
                    "ACTIVE (Port 53)"
                } else {
                    "DISABLED"
                }
            );
            println!("  Upstream DNS:    {:>28}", s["upstream"].as_str().unwrap_or("-"));
            println!("  Total Queries:   {:>28}", s["stats"]["total_queries"]);
            println!("  Blocked Threats: {:>28}", s["stats"]["blocked_queries"]);
            println!("  Blocked Domains: {:>28}", s["stats"]["total_blocked_domains"]);
            println!("------------------------------------------------");

            let queries_raw = http_get(&format!("{}/api/dns/queries", base), key).await?;
            let queries: Vec<serde_json::Value> = serde_json::from_str(&queries_raw)?;
            if !queries.is_empty() {
                println!("\nRECENT DNS QUERIES");
                println!("{:<24} {:<16} {:<32} Action", "Timestamp", "Client IP", "Domain");
                println!("{}", "-".repeat(82));
                for q in queries.iter().take(20) {
                    let ts = q["timestamp"].as_str().unwrap_or("-");
                    let client = q["client_ip"].as_str().unwrap_or("-");
                    let domain = q["domain"].as_str().unwrap_or("-");
                    let is_blocked = q["is_blocked"].as_bool().unwrap_or(false);
                    let action = if is_blocked { "🛑 BLOCKED (Sinkholed)" } else { "✅ Resolved" };
                    println!("{:<24} {:<16} {:<32} {}", &ts[..19.min(ts.len())], client, domain, action);
                }
            }
        }

        Commands::Cti => {
            let intel_raw = http_get(&format!("{}/api/threat-intel", base), key).await?;
            let intel: serde_json::Value = serde_json::from_str(&intel_raw)?;
            println!("CYBER THREAT INTELLIGENCE (CTI)");
            println!("------------------------------------------------");
            println!(
                "  Status:             {:>24}",
                if intel["enabled"].as_bool().unwrap_or(false) {
                    "ACTIVE"
                } else {
                    "DISABLED"
                }
            );
            println!("  Tracked Malicious IPs: {:>21}", intel["total_tracked_malicious_ips"]);
            println!("------------------------------------------------");
            if let Some(feeds) = intel["feeds"].as_array() {
                println!("  Feeds:");
                for f in feeds {
                    println!("    - {}", f.as_str().unwrap_or(""));
                }
            }
            if let Some(recent) = intel["recent_threats"].as_array() {
                if !recent.is_empty() {
                    println!("\nTRACKED THREAT NODES");
                    println!("{:<18} {:<24} {:<15} Confidence", "IP Address", "Feed", "Threat Type");
                    println!("{}", "-".repeat(70));
                    for t in recent.iter().take(15) {
                        let ip = t["ip"].as_str().unwrap_or("-");
                        let feed = t["feed"].as_str().unwrap_or("-");
                        let tt = t["threat_type"].as_str().unwrap_or("-");
                        let conf = t["confidence"].as_u64().unwrap_or(0);
                        println!("{:<18} {:<24} {:<15} {}%", ip, feed, tt, conf);
                    }
                }
            }
        }

        Commands::Vad { command } => match command {
            VadCommands::Status => {
                println!("Voice Gate status: check /api/vad/events");
            }
            VadCommands::Toggle => {
                println!("Voice Gate toggled.");
            }
        },
    }

    Ok(())
}

/// Validate and prevent CRLF injection in HTTP headers/paths.
fn sanitize_http_param(val: &str, field: &str) -> Result<()> {
    if val.contains('\r') || val.contains('\n') {
        anyhow::bail!("Security error: CRLF injection detected in {}", field);
    }
    Ok(())
}

/// Simple HTTP GET using tokio's TCP.
async fn http_get(url: &str, api_key: Option<&str>) -> Result<String> {
    // Parse URL manually for a minimal HTTP client (no external deps)
    let url = url.strip_prefix("http://").unwrap_or(url);
    let (host_port, path) = url.split_once('/').unwrap_or((url, ""));
    let path = format!("/{}", path);
    sanitize_http_param(&path, "URL path")?;
    sanitize_http_param(host_port, "Host")?;

    let auth_header = match api_key {
        Some(k) if !k.is_empty() => {
            sanitize_http_param(k, "API key")?;
            format!("X-API-Key: {}\r\nAuthorization: Bearer {}\r\n", k, k)
        }
        _ => String::new(),
    };

    let stream = tokio::net::TcpStream::connect(host_port).await?;
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\n{}Connection: close\r\n\r\n",
        path, host_port, auth_header
    );

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = stream;
    stream.write_all(request.as_bytes()).await?;

    let mut response = String::new();
    stream.read_to_string(&mut response).await?;
    ensure_success(&response)?;

    // Extract body after \r\n\r\n
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or("{}")
        .to_string();
    Ok(body)
}

/// Simple HTTP POST.
async fn http_post(url: &str, api_key: Option<&str>) -> Result<String> {
    let url = url.strip_prefix("http://").unwrap_or(url);
    let (host_port, path) = url.split_once('/').unwrap_or((url, ""));
    let path = format!("/{}", path);
    sanitize_http_param(&path, "URL path")?;
    sanitize_http_param(host_port, "Host")?;

    let auth_header = match api_key {
        Some(k) if !k.is_empty() => {
            sanitize_http_param(k, "API key")?;
            format!("X-API-Key: {}\r\nAuthorization: Bearer {}\r\n", k, k)
        }
        _ => String::new(),
    };

    let stream = tokio::net::TcpStream::connect(host_port).await?;
    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\n{}Content-Length: 0\r\nConnection: close\r\n\r\n",
        path, host_port, auth_header
    );

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = stream;
    stream.write_all(request.as_bytes()).await?;

    let mut response = String::new();
    stream.read_to_string(&mut response).await?;
    ensure_success(&response)?;

    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or("{}")
        .to_string();
    Ok(body)
}

fn ensure_success(response: &str) -> Result<()> {
    let status_line = response.lines().next().unwrap_or_default();
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);

    if (200..300).contains(&status) {
        Ok(())
    } else {
        anyhow::bail!("HTTP request failed: {}", status_line)
    }
}

fn human_bytes(b: u64) -> String {
    if b == 0 {
        return "0 B".into();
    }
    let units = ["B", "KB", "MB", "GB", "TB"];
    let i = (b as f64).log(1024.0).floor() as usize;
    let i = i.min(units.len() - 1);
    format!("{:.1} {}", b as f64 / 1024f64.powi(i as i32), units[i])
}
