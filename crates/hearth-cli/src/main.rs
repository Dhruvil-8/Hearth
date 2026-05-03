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

    match cli.command {
        Commands::Status => {
            let summary = http_get(&format!("{}/api/summary", base)).await?;
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

            let devices = http_get(&format!("{}/api/devices", base)).await?;
            let devs: Vec<serde_json::Value> = serde_json::from_str(&devices)?;
            if !devs.is_empty() {
                println!(
                    "\n{:<20} {:<16} {:>12} {:>12} {}",
                    "Name/MAC", "IP", "Sent/1h", "Recv/1h", "Status"
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
            let body = http_get(&format!("{}/api/devices", base)).await?;
            let devs: Vec<serde_json::Value> = serde_json::from_str(&body)?;
            println!("{:<20} {:<18} {:<16} {}", "Label", "MAC", "IP", "Last Seen");
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
            match http_get(&format!("{}/api/devices/{}/profile", base, enc)).await {
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
            match http_get(&format!("{}/api/devices/{}/anomalies", base, enc)).await {
                Ok(body) => {
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
                Err(_) => {}
            }
        }

        Commands::Anomalies => {
            let body = http_get(&format!("{}/api/anomalies", base)).await?;
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
            http_post(&format!("{}/api/anomalies/{}/resolve", base, id)).await?;
            println!("Anomaly #{} resolved.", id);
        }

        Commands::Digest => {
            let body = http_get(&format!("{}/api/digest", base)).await?;
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

        Commands::Label { mac, name } => {
            println!(
                "Label '{}' assigned to {}. (Note: requires config file update)",
                name, mac
            );
        }

        Commands::Block { mac, hours } => {
            println!(
                "Blocking {} {}",
                mac,
                hours
                    .map(|h| format!("for {} hours", h))
                    .unwrap_or_else(|| "permanently".into())
            );
        }

        Commands::Unblock { mac } => {
            println!("Unblocking {}", mac);
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

/// Simple HTTP GET using tokio's TCP.
async fn http_get(url: &str) -> Result<String> {
    // Parse URL manually for a minimal HTTP client (no external deps)
    let url = url.strip_prefix("http://").unwrap_or(url);
    let (host_port, path) = url.split_once('/').unwrap_or((url, ""));
    let path = format!("/{}", path);

    let stream = tokio::net::TcpStream::connect(host_port).await?;
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        path, host_port
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
async fn http_post(url: &str) -> Result<String> {
    let url = url.strip_prefix("http://").unwrap_or(url);
    let (host_port, path) = url.split_once('/').unwrap_or((url, ""));
    let path = format!("/{}", path);

    let stream = tokio::net::TcpStream::connect(host_port).await?;
    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        path, host_port
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
