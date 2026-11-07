# Hearth

**Local network intelligence.**

> [!WARNING]
> **Experimental / AI-Generated Codebase Notice**  
> This project was developed with AI assistance and vibe-coding.**it has NOT been audited or validated in live production environments.**
---

## What Hearth Does

Hearth is a local-first network monitoring daemon for home networks, homelabs, and small IoT setups. It runs on a local machine (such as a Linux server, Raspberry Pi) to provide visibility into what devices are doing on your local network:

- **Active Subnet Discovery & IoT Fingerprinting** — Pings the local `/24` subnet, reads operating system ARP tables, and performs mDNS (`224.0.0.251:5353`) & SSDP (`239.255.255.250:1900`) discovery to auto-extract friendly device names (Chromecast, Sonos, Apple AirPlay, Hue, smart TVs).
- **Targeted IoT Port Scanning** — Scans local devices for common unencrypted or management ports (Telnet `23`, RTSP `554`, FTP `21`, MQTT `1883`, HTTP `80`/`8080`).
- **Statistical Traffic Baselines** — Collects traffic samples to compute per-device hourly baseline averages ($\mu \pm 3\sigma$) and flags unusual volume spikes or activity outside typical hours.
- **DNS Threat Sinkhole & Encrypted DoH Upstream** — An embedded async DNS proxy that checks requested domain names against downloaded community blocklists (StevenBlack hosts, URLhaus) and answers blocked domains with `0.0.0.0`. Enforces trusted private subnet boundaries and optionally resolves external queries via encrypted DNS-over-HTTPS (RFC 8484 DoH) to prevent ISP eavesdropping.
- **Threat Intelligence & Autonomous Quarantine** — Ingests public malicious IP feeds (Feodo Tracker, Emerging Threats) and automatically isolates infected devices via parameterized `nftables` hardware drop rules upon confirmed C2 contact (`auto_quarantine = true`).
- **JA3 Cryptographic TLS Fingerprinting** — Passively parses TLS Client Hello packets to fingerprint client cryptographic configurations without decrypting traffic. Identifies malware and botnet families (Cobalt Strike, Metasploit, Mirai, Trickbot) even when IPs or domains rotate.
- **Anti-ARP Spoofing, Rogue DHCP & IPv6 RA-Guards** — Full-spectrum LAN defense: detects ARP poisoning, blocks unauthorized DHCP servers from hijacking IPv4 gateways/DNS, and inspects ICMPv6 Router Advertisements (RFC 6105 RA-Guard) to prevent rogue SLAAC gateway takeovers.
- **Hardened Firewall Quarantine (`nftables`)** — Generates and applies parameterized `nftables` hardware drop rules with strict MAC validation (direct binary execution with zero shell invocation to prevent command injection).
- **Enterprise SIEM & Webhook Alerts** — Emits structured security events to enterprise SIEMs (Splunk, Graylog, ELK, Datadog) via RFC 5424 Syslog or ArcSight CEF (Common Event Format) over UDP, plus Discord and Slack webhooks.
- **API Key Authentication** — Protects all administrative mutating API routes with `X-API-Key` or `Bearer` token verification.
- **Embedded Web Dashboard** — Built-in web UI on port `7777` with Overview, Security, DNS, Threat Intel, Rules, and Digest views.
- **CLI Utility (`hearth-cli`)** — Command-line tool for headless inspection and administration with `--api-key` and `HEARTH_API_KEY` support.

---

## Architecture

```
hearth/
├── crates/
│   ├── hearth-core/         # Packet capture, discovery, port scanner, DNS, threat intel, SQLite store
│   ├── hearth-daemon/       # Daemon runner — coordinates scanners, monitors, and webhooks
│   ├── hearth-dashboard/    # Axum HTTP server + embedded web dashboard
│   ├── hearth-rules/        # nftables rule generation & quarantine enforcement
│   ├── hearth-cli/          # Command-line interface for status, scanning, and management
│   └── hearth-vad/          # Voice Activity Detection (experimental audio leak detector)
├── config/
│   └── hearth.toml          # Runtime configuration file
├── Dockerfile               # Multi-stage Linux container build
├── docker-compose.yml       # Docker compose setup
└── README.md
```

### Component Flow

```
+-------------------------------------------------------------------------------+
|                               HEARTH DAEMON                                   |
|                                                                               |
|  [DnsSinkhole]        [ThreatIntelManager]      [ArpGuard]                    |
|  (Port 53 DNS proxy)  (Public IP blocklists)    (ARP cache monitor)           |
|                                                                               |
|  [NetworkScanner]     [PortScanner]             [PacketCapture]               |
|  (Active /24 sweep)   (Common IoT ports)        (Promiscuous mode pnet sniffer|
|         |                   |                          |                      |
|         +-------------------+--------------------------+                      |
|                             |                                                 |
|                             v                                                 |
|               [Store] (Local SQLite Database)                                 |
|               - devices, device_ports, traffic_samples                        |
|               - threat_intel_ips, blocked_domains, dns_queries                |
|               - anomalies                                                     |
|                             |                                                 |
|              +--------------+---------------+                                 |
|              v                              v                                 |
|       [StatsEngine]                  [RulesEngine]                            |
|       - Baseline volume checks       - Schedule enforcement                   |
|       - CTI destination matches      - Quarantine (nftables drop)             |
|              |                              |                                 |
|              v                              v                                 |
|       [AlertDispatcher]              [Web Dashboard & REST API]               |
|       - Webhooks (Discord/Slack)     - Port 7777 web interface                |
+-------------------------------------------------------------------------------+
```

---

## Setup & Running

### Option 1: Docker (Recommended)

Requires Docker with Linux host networking support:

```bash
git clone https://github.com/Dhruvil-8/Hearth.git
cd Hearth
docker compose up -d
```

Open **http://localhost:7777** in your browser.

> **Note on DNS Sinkhole:** To use the DNS sinkhole feature, devices on your network must be configured to use the host's IP address as their primary DNS server.

---

### Option 2: Build from Source

#### Prerequisites
- **Rust 1.75+** (`cargo` and `rustc`)
- **CMake** (required by `rusqlite` bundled build)
- **Linux:** `sudo apt install libpcap-dev cmake nftables iputils-ping net-tools`
- **Windows:** [Npcap SDK](https://npcap.com/) (Npcap OEM/SDK or fallback stub)

#### Build
```bash
cargo build --release --workspace
```

#### Run
```bash
./target/release/hearth --config config/hearth.toml
```

---

## Configuration (`config/hearth.toml`)

```toml
# Network interface to monitor (e.g., eth0, wlan0)
interface = "eth0"

# Web dashboard HTTP port
dashboard_port = 7777

# Local SQLite database path
db_path = "./hearth.db"

# Optional: Subnet for active discovery (auto-detected if commented out)
# subnet = "192.168.1.0/24"

# Optional: API key for securing dashboard and API endpoints
# api_key = "your-secret-token"

# Webhook notification settings (Discord / Slack / Generic HTTP POST)
[notifications]
# webhook_url = "https://discord.com/api/webhooks/YOUR_WEBHOOK_URL"
notify_on_anomaly = true
notify_on_new_device = true
notify_on_vulnerability = true
notify_on_malicious_traffic = true
notify_on_arp_spoofing = true

# Cyber Threat Intelligence (CTI) Feed Settings
[threat_intel]
enabled = true
sync_interval_hours = 24
feeds = [
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
]

# DNS Threat Sinkhole Settings (Port 53 UDP)
[dns]
enabled = true
port = 53
upstream = "1.1.1.1:53"
blocklists = [
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://urlhaus.abuse.ch/downloads/hostfile/",
]
```

---

## Web Dashboard (`http://localhost:7777`)

The dashboard provides a visual interface with several tabs:

1. **Overview** — Live device inventory, 1-hour traffic totals, status indicators (`Normal`, `Profiling`, `Anomaly`, `ISOLATED`), and one-click quarantine buttons.
2. **Security** — Summary of detected open ports and IoT vulnerability flags.
3. **DNS Sinkhole** — Query counts, blocked threats, and recent DNS requests.
4. **Threat Intel** — Tracked malicious IP list and sync status.
5. **Rules** — Current `nftables` enforcement rules and schedules.
6. **Weekly Digest** — Summary of network activity and anomalies over the last 7 days.

---

## CLI Reference (`hearth-cli`)

A command-line tool is included for server or headless administration. When an API key is configured in `hearth.toml`, pass `--api-key <KEY>` or set the `HEARTH_API_KEY` environment variable:

```bash
# General status
hearth-cli status                     # Show dashboard summary and active device table
hearth-cli devices                    # List all discovered devices with MAC, IP, and label
hearth-cli device AA:BB:CC:DD:EE:FF   # Show profile and open ports for a specific device

# Security & Scanning
hearth-cli scan                       # Trigger an active subnet sweep and IoT port scan
hearth-cli security                   # Show discovered open ports and at-risk devices
hearth-cli cti                        # View Cyber Threat Intelligence feeds and tracked IPs
hearth-cli dns                        # View DNS sinkhole query stats and recent lookups

# Active Defense & Quarantine (requires API key if configured)
hearth-cli quarantine <MAC>           # Isolate a device at the firewall (nftables drop)
hearth-cli unquarantine <MAC>         # Remove isolation and restore network access
hearth-cli rules                      # View active firewall rules

# Anomalies & Maintenance
hearth-cli anomalies                  # List all unresolved anomalies
hearth-cli resolve <ID>               # Mark an anomaly as resolved
hearth-cli digest                     # Print plain-text weekly digest

# Authentication flag example
hearth-cli --api-key mysecret scan
```

---

## REST API Reference

All endpoints return JSON. When `api_key` is configured in `hearth.toml`, all mutating `POST` endpoints require authentication via `X-API-Key: <key>` or `Authorization: Bearer <key>`. Missing or invalid credentials return `401 Unauthorized`.

| Method | Endpoint | Auth Required | Description |
|---|---|---|---|
| `GET` | `/api/summary` | No | Monitored device count, upload stats, active anomaly count |
| `GET` | `/api/devices` | No | Discovered devices with traffic stats, port badges, and quarantine state |
| `POST` | `/api/devices/:mac/quarantine` | **Yes** | Quarantine a device (applies firewall isolation) |
| `POST` | `/api/devices/:mac/unquarantine` | **Yes** | Remove quarantine isolation |
| `GET` | `/api/devices/:mac/ports` | No | Open ports detected on a specific device |
| `GET` | `/api/devices/:mac/profile` | No | 72h baseline statistics for a device |
| `GET` | `/api/devices/:mac/history` | No | Historical traffic samples (`?hours=24`) |
| `GET` | `/api/security` | No | Network security overview and open ports |
| `POST` | `/api/scan` | **Yes** | Trigger immediate subnet discovery and port scan |
| `GET` | `/api/dns/stats` | No | DNS Sinkhole query counts, blocked queries, and upstream |
| `GET` | `/api/dns/queries` | No | Recent DNS query logs |
| `POST` | `/api/dns/sync` | **Yes** | Force synchronization of DNS domain blocklists |
| `GET` | `/api/threat-intel` | No | Cyber Threat Intelligence stats and tracked IPs |
| `POST` | `/api/threat-intel/sync` | **Yes** | Force synchronization of threat feeds |
| `GET` | `/api/rules` | No | Active firewall rules evaluated by the rules engine |
| `GET` | `/api/anomalies` | No | Unresolved anomalies |
| `POST` | `/api/anomalies/:id/resolve` | **Yes** | Mark an anomaly as resolved |
| `GET` | `/api/digest` | No | Plain-English weekly activity summary |

---

## Testing

The project includes unit and integration tests across all workspace crates:

```bash
cargo test --workspace
```

The test suite covers:
- SQLite store migrations, device CRUD, port tracking, and quarantine states
- Baseline statistics calculation ($\mu \pm 3\sigma$) and anomaly deduplication
- Threat intelligence feed parsing and IP lookup
- DNS wire-format question extraction, A-record parsing, and 0.0.0.0 sinkhole packet generation
- Anti-ARP spoofing gateway detection logic
- Firewall quarantine rule generation

---

## License

MIT License — see [LICENSE](LICENSE)
