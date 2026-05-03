# Hearth — Full Implementation Spec
> Delegate this document to any LLM to implement each phase.
> Every section is self-contained. Paste the relevant phase into a fresh context.

---

## Project Identity

**Name:** Hearth  
**Tagline:** Local network intelligence. No cloud. No subscription. No surprises.  
**Runtime target:** Raspberry Pi 4 (1GB RAM), Ubuntu 24.04 / Pi OS Bookworm  
**Language:** Rust (edition 2021)  
**License:** MIT  
**Repo layout:** Cargo workspace with multiple crates  

---

## Workspace Layout

```
hearth/
├── Cargo.toml               # workspace root
├── crates/
│   ├── hearth-core/         # packet capture, device registry, stats engine
│   ├── hearth-dashboard/    # axum web server + embedded HTML dashboard
│   ├── hearth-vad/          # voice gate — standalone binary
│   ├── hearth-rules/        # nftables rule engine + enforcement
│   └── hearth-cli/          # CLI for config, status, manual overrides
├── config/
│   └── hearth.toml          # default config file
├── systemd/
│   └── hearth.service       # systemd unit file
├── install.sh               # single-command installer
└── README.md
```

---

## Workspace `Cargo.toml`

```toml
[workspace]
members = [
    "crates/hearth-core",
    "crates/hearth-dashboard",
    "crates/hearth-vad",
    "crates/hearth-rules",
    "crates/hearth-cli",
]
resolver = "2"

[workspace.dependencies]
tokio = { version = "1.40", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
anyhow = "1.0"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
rusqlite = { version = "0.31", features = ["bundled"] }
axum = { version = "0.7", features = ["ws"] }
toml = "0.8"
chrono = { version = "0.4", features = ["serde"] }
clap = { version = "4.5", features = ["derive"] }
```

---

## Shared Data Types (`hearth-core/src/types.rs`)

All crates import from `hearth-core`. These types are the contract between modules.

```rust
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// A discovered device on the local network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub mac: String,              // "AA:BB:CC:DD:EE:FF"
    pub ip: IpAddr,
    pub vendor: Option<String>,   // "Philips Lighting BV" from OUI lookup
    pub label: Option<String>,    // user-assigned name, from config
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

/// One traffic observation — written to DB every 60 seconds per device
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficSample {
    pub id: Option<i64>,
    pub mac: String,
    pub timestamp: DateTime<Utc>,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub top_destinations: Vec<Destination>, // top 5 by bytes
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Destination {
    pub ip: IpAddr,
    pub domain: Option<String>,   // from reverse DNS
    pub country: Option<String>,  // "US", "RU", from embedded GeoIP
    pub bytes: u64,
}

/// Anomaly flag produced by the stats engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anomaly {
    pub id: Option<i64>,
    pub mac: String,
    pub detected_at: DateTime<Utc>,
    pub kind: AnomalyKind,
    pub detail: String,           // human-readable explanation
    pub resolved: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnomalyKind {
    ExcessiveUpload,    // bytes_sent > 3σ above baseline
    NewDestination,     // IP never seen before for this device
    UnusualHour,        // traffic outside device's normal active hours
    VoiceLeakSuspected, // hearth-vad detected upload without wake word
}

/// Device profile — built from 72h of observation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceProfile {
    pub mac: String,
    pub baseline_bytes_sent_per_hour_mean: f64,
    pub baseline_bytes_sent_per_hour_stddev: f64,
    pub known_destinations: Vec<String>,  // known IP strings
    pub active_hours: Vec<u8>,            // hours 0-23 when device is normally active
    pub profile_built_at: DateTime<Utc>,
    pub observation_hours: u32,           // must be >= 72 to be considered mature
}

/// Runtime config, loaded from hearth.toml
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub interface: String,        // e.g. "eth0", "wlan0"
    pub dashboard_port: u16,      // default 7777
    pub db_path: String,          // default "/var/lib/hearth/hearth.db"
    pub oui_db_path: String,      // default "/var/lib/hearth/oui.csv"
    pub geoip_db_path: String,    // default "/var/lib/hearth/GeoLite2-Country.mmdb"
    pub devices: Vec<DeviceConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceConfig {
    pub mac: String,
    pub label: String,
    pub max_upload_per_hour_mb: Option<f64>,  // optional hard limit for rules engine
    pub block_hours: Option<[String; 2]>,     // e.g. ["23:00", "06:00"]
}
```

---

# PHASE 1 — The Mirror

## Goal
Passive network observer. No blocking. No ML. Ships in 2–4 weeks.  
Output: `hearth-core` daemon + `hearth-dashboard` web UI at `http://hearth.local:7777`.

---

## `hearth-core` — Packet Capture Engine

### `Cargo.toml`

```toml
[package]
name = "hearth-core"
version = "0.1.0"
edition = "2021"

[dependencies]
tokio = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
anyhow = { workspace = true }
tracing = { workspace = true }
rusqlite = { workspace = true }
chrono = { workspace = true }
pnet = "0.35"                         # pure-Rust packet capture
dns-lookup = "2.0"                    # reverse DNS
maxminddb = "0.23"                    # GeoIP2 MMDB reader
csv = "1.3"                           # OUI CSV parsing

[lib]
name = "hearth_core"
path = "src/lib.rs"

[[bin]]
name = "hearth"
path = "src/main.rs"
```

### Module Structure

```
hearth-core/src/
├── lib.rs          # re-exports: pub use capture, store, stats, types, oui, geo
├── main.rs         # tokio::main, reads config, spawns tasks
├── types.rs        # all shared types (shown above)
├── config.rs       # load/parse hearth.toml
├── capture.rs      # pnet packet capture loop → emits DeviceEvent via channel
├── store.rs        # SQLite wrapper — read/write devices, samples, anomalies
├── stats.rs        # consumes samples, computes profiles, emits anomalies
├── oui.rs          # MAC vendor lookup from offline CSV
└── geo.rs          # IP → country lookup from offline MMDB
```

### `capture.rs` — Full Implementation Spec

```rust
// Purpose: Listen on a network interface in promiscuous mode.
// For every Ethernet frame, extract src MAC, dst MAC, src IP, dst IP, length.
// Aggregate into per-device byte counters over a 60-second window.
// After each window, send a Vec<DeviceSnapshot> over a tokio mpsc channel.

use pnet::datalink::{self, NetworkInterface, Channel::Ethernet};
use pnet::packet::{ethernet::EthernetPacket, ipv4::Ipv4Packet, Packet};
use tokio::sync::mpsc;
use std::collections::HashMap;
use std::net::IpAddr;

pub struct DeviceSnapshot {
    pub mac: String,
    pub ip: IpAddr,
    pub bytes_sent: u64,       // bytes where this MAC is the source
    pub bytes_recv: u64,       // bytes where this MAC is the destination
    pub destinations: Vec<(IpAddr, u64)>,  // (dst_ip, bytes) pairs
}

pub fn start_capture(
    interface_name: &str,
    tx: mpsc::Sender<Vec<DeviceSnapshot>>,
) -> anyhow::Result<()>
// Implementation notes:
// 1. Find interface by name using datalink::interfaces()
// 2. Open channel with datalink::channel() — Config { promiscuous: true, .. }
// 3. Inner loop: rx.next() → parse EthernetPacket → extract IPv4 payload
// 4. Accumulate into HashMap<String, DeviceSnapshot> keyed by src MAC
// 5. Every 60 seconds, drain the map and tx.send() the snapshots
// 6. Run this in a std::thread (not async) — pnet is blocking
// 7. The thread sends to tokio channel via tx.blocking_send()
// Error handling: log and continue on parse errors, never panic
```

### `store.rs` — Database Schema

```sql
-- Run on first startup via rusqlite execute_batch()

CREATE TABLE IF NOT EXISTS devices (
    mac TEXT PRIMARY KEY,
    ip TEXT NOT NULL,
    vendor TEXT,
    label TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS traffic_samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    bytes_sent INTEGER NOT NULL,
    bytes_recv INTEGER NOT NULL,
    destinations TEXT NOT NULL,   -- JSON array of Destination
    FOREIGN KEY (mac) REFERENCES devices(mac)
);

CREATE TABLE IF NOT EXISTS device_profiles (
    mac TEXT PRIMARY KEY,
    baseline_bytes_sent_per_hour_mean REAL NOT NULL,
    baseline_bytes_sent_per_hour_stddev REAL NOT NULL,
    known_destinations TEXT NOT NULL,   -- JSON array of strings
    active_hours TEXT NOT NULL,         -- JSON array of u8
    profile_built_at TEXT NOT NULL,
    observation_hours INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS anomalies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac TEXT NOT NULL,
    detected_at TEXT NOT NULL,
    kind TEXT NOT NULL,
    detail TEXT NOT NULL,
    resolved INTEGER NOT NULL DEFAULT 0
);

-- Indexes for dashboard queries
CREATE INDEX IF NOT EXISTS idx_samples_mac_time ON traffic_samples(mac, timestamp);
CREATE INDEX IF NOT EXISTS idx_anomalies_mac ON anomalies(mac);
```

### `store.rs` — Required Public Functions

```rust
pub struct Store {
    conn: rusqlite::Connection,  // wrapped in Arc<Mutex<>> for shared access
}

impl Store {
    pub fn new(db_path: &str) -> anyhow::Result<Self>
    // Opens or creates SQLite DB, runs schema migration

    pub fn upsert_device(&self, device: &Device) -> anyhow::Result<()>
    // INSERT OR REPLACE on devices table

    pub fn insert_sample(&self, sample: &TrafficSample) -> anyhow::Result<()>
    // INSERT into traffic_samples, serializes destinations to JSON

    pub fn get_all_devices(&self) -> anyhow::Result<Vec<Device>>
    // SELECT * FROM devices ORDER BY last_seen DESC

    pub fn get_samples_for_device(
        &self,
        mac: &str,
        hours: u32,              // how many hours back to query
    ) -> anyhow::Result<Vec<TrafficSample>>

    pub fn get_recent_samples(
        &self,
        hours: u32,
    ) -> anyhow::Result<Vec<TrafficSample>>
    // Used by dashboard for the overview chart

    pub fn get_profile(&self, mac: &str) -> anyhow::Result<Option<DeviceProfile>>

    pub fn upsert_profile(&self, profile: &DeviceProfile) -> anyhow::Result<()>

    pub fn insert_anomaly(&self, anomaly: &Anomaly) -> anyhow::Result<i64>
    // Returns new row id

    pub fn get_unresolved_anomalies(&self) -> anyhow::Result<Vec<Anomaly>>

    pub fn resolve_anomaly(&self, id: i64) -> anyhow::Result<()>
    // Sets resolved = 1

    pub fn prune_old_samples(&self, days: u32) -> anyhow::Result<()>
    // DELETE samples older than N days — call daily
}
```

### `stats.rs` — Profile Builder and Anomaly Detector

```rust
// Called every 60 seconds after a new batch of TrafficSamples is stored.
// Two responsibilities:
//   1. Rebuild DeviceProfile if observation_hours >= 72
//   2. Compare latest sample against profile, emit Anomaly if deviation found

pub struct StatsEngine {
    store: Arc<Store>,
    anomaly_tx: mpsc::Sender<Anomaly>,
}

impl StatsEngine {
    pub async fn process_new_samples(
        &self,
        snapshots: &[DeviceSnapshot],
    ) -> anyhow::Result<()>

    // Profile rebuild algorithm:
    // 1. Pull all samples for this device from last 168h (7 days)
    // 2. Group by hour-of-day, compute mean bytes_sent per hour
    // 3. Compute overall mean and stddev of per-hour values
    // 4. Collect all destination IPs seen across samples → known_destinations
    // 5. Collect active hours (hours with > 0 bytes) → active_hours
    // 6. Write profile to store

    // Anomaly detection (only if profile.observation_hours >= 72):
    // - ExcessiveUpload: current bytes_sent > profile.mean + 3 * profile.stddev
    // - NewDestination: any destination IP not in profile.known_destinations
    //   (skip private IP ranges: 10.x, 192.168.x, 172.16-31.x)
    // - UnusualHour: traffic outside profile.active_hours AND bytes > 1000
}
```

---

## `hearth-dashboard` — Web UI

### `Cargo.toml`

```toml
[package]
name = "hearth-dashboard"
version = "0.1.0"
edition = "2021"

[dependencies]
tokio = { workspace = true }
axum = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
anyhow = { workspace = true }
tracing = { workspace = true }
hearth-core = { path = "../hearth-core" }
tower-http = { version = "0.5", features = ["cors"] }
```

### API Routes

All routes return JSON. No authentication in Phase 1.

```
GET  /api/devices              → Vec<DeviceWithStats>
GET  /api/devices/:mac/history → Vec<TrafficSample>  (query: ?hours=24)
GET  /api/anomalies            → Vec<Anomaly>  (unresolved only)
POST /api/anomalies/:id/resolve → {}
GET  /api/summary              → DashboardSummary
GET  /                         → serves index.html (embedded in binary)
```

### Response types

```rust
#[derive(Serialize)]
pub struct DeviceWithStats {
    #[serde(flatten)]
    pub device: Device,
    pub bytes_sent_last_hour: u64,
    pub bytes_recv_last_hour: u64,
    pub top_country: Option<String>,
    pub anomaly_count: u32,
    pub profile_mature: bool,       // true if observation_hours >= 72
}

#[derive(Serialize)]
pub struct DashboardSummary {
    pub total_devices: u32,
    pub total_bytes_sent_today: u64,
    pub active_anomalies: u32,
    pub most_active_device: Option<String>,  // MAC or label
}
```

### Frontend — Single HTML File

Embed as a static string in the binary using `include_str!("../static/index.html")`.

The HTML file requirements:
- Pure HTML + CSS + vanilla JS. No npm. No bundler. No framework.
- Auto-refreshes data every 10 seconds via `setInterval` calling `fetch('/api/summary')` and `fetch('/api/devices')`
- Device table columns: Name/MAC | Vendor | IP | ↑ Sent (1h) | ↓ Recv (1h) | Top Country | Status
- Status column: green dot = normal, amber dot = profiling (< 72h), red dot = anomaly detected
- Anomaly banner at top if any unresolved anomalies exist — clicking it expands a list
- Color scheme: dark background (#0f0f0f), card surfaces (#1a1a1a), accent (#e8593c — warm red)
- Font: system-ui, monospace for MAC addresses and byte counts
- Mobile-responsive: stacks to single column on small screens
- No external CDN dependencies — everything inline

---

## `main.rs` — Entry Point

```rust
// Startup sequence:
// 1. Load Config from hearth.toml (path from --config arg or default /etc/hearth/hearth.toml)
// 2. Initialize tracing subscriber (LOG_LEVEL env var, default "info")
// 3. Open Store (creates DB if not exists)
// 4. Load OUI database from config.oui_db_path
// 5. Load GeoIP database from config.geoip_db_path
// 6. Spawn tokio task: hearth_dashboard::serve(config.dashboard_port, store.clone())
// 7. Spawn std::thread: capture::start_capture(config.interface, tx)
// 8. Main async loop: receive from rx, enrich with OUI + GeoIP, write to store, run stats engine
// 9. Spawn tokio task: daily pruning at midnight (store.prune_old_samples(7))
//
// Graceful shutdown: listen for SIGTERM/SIGINT, flush pending writes, close DB
```

---

## Install Script (`install.sh`)

The installer must:
1. Detect OS (Raspberry Pi OS / Ubuntu)
2. Install build deps: `rustup`, `libpcap-dev`
3. `cargo build --release --workspace`
4. Copy binaries to `/usr/local/bin/`
5. Download OUI CSV from `https://maclookup.app/downloads/csv-database` to `/var/lib/hearth/`
6. Create default config at `/etc/hearth/hearth.toml` (auto-detect primary interface)
7. Install and enable systemd service
8. Print: "Hearth is running. Open http://hearth.local:7777 in your browser."

---

## `config/hearth.toml` (default)

```toml
interface = "eth0"          # change to wlan0 if using WiFi
dashboard_port = 7777
db_path = "/var/lib/hearth/hearth.db"
oui_db_path = "/var/lib/hearth/oui.csv"
geoip_db_path = "/var/lib/hearth/GeoLite2-Country.mmdb"

# Add entries to give devices friendly names
# [[devices]]
# mac = "AA:BB:CC:DD:EE:FF"
# label = "Samsung TV"
# max_upload_per_hour_mb = 500
```

---

## `systemd/hearth.service`

```ini
[Unit]
Description=Hearth Network Intelligence Daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/hearth --config /etc/hearth/hearth.toml
Restart=on-failure
RestartSec=5s
User=root
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

---

## Phase 1 — Acceptance Criteria

The following must all be true before Phase 2 begins:

- [ ] `cargo build --release` succeeds on both x86_64 and aarch64 (Pi)
- [ ] Running `hearth` with a valid interface captures packets without crashing for 24h
- [ ] Dashboard loads at `http://localhost:7777` and shows at least one device
- [ ] Device table updates without page refresh every 10 seconds
- [ ] A device sending large traffic shows elevated byte count
- [ ] DB file grows over time and prune job removes old records
- [ ] Systemd service starts on boot, restarts on crash

---

# PHASE 2 — The Profiles

## Goal
Statistical anomaly detection. No ML. Human-readable device profiles.  
New: weekly digest report, anomaly history, profile viewer in dashboard.

---

## New Dashboard Routes (add to Phase 1 routes)

```
GET  /api/devices/:mac/profile    → DeviceProfile or 404 if not built yet
GET  /api/devices/:mac/anomalies  → Vec<Anomaly> for that device
GET  /api/digest                  → WeeklyDigest
```

### `WeeklyDigest` type

```rust
#[derive(Serialize)]
pub struct WeeklyDigest {
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub total_anomalies: u32,
    pub most_active_device: Option<String>,
    pub top_destinations_by_country: Vec<(String, u64)>,  // (country, total_bytes)
    pub new_devices_seen: Vec<Device>,
    pub highlights: Vec<String>,   // plain-English sentences, max 5
}
// highlights example: "Your Samsung TV uploaded 2.3 GB on Tuesday at 3am"
```

### Highlight generation

```rust
// In stats.rs, after building digest:
// For each anomaly in the past 7 days, generate a plain-English sentence:
// ExcessiveUpload: "{label} uploaded {bytes_human} on {day} at {hour}am/pm"
// NewDestination: "{label} connected to a new server in {country}"
// UnusualHour: "{label} was active at {hour}am — outside its normal hours"
// Pick the 5 most recent. No LLM required — pure string formatting.
```

---

## Dashboard UI Additions (Phase 2)

Add to `index.html`:

- **Device detail panel**: clicking a device row expands an inline section showing:
  - 24h sparkline chart (canvas element, pure JS, no library)
  - Profile status: "Profiling... (47 of 72 hours)" or "Profile built on [date]"
  - Normal range: "Typically sends 15–45 KB/hr"
  - Known destinations: list of domains/IPs with country flags (emoji)
  - Anomaly history: last 5 anomalies with timestamps

- **Weekly digest tab**: a second tab in the top nav showing the `/api/digest` response rendered as readable cards

---

## Phase 2 — Acceptance Criteria

- [ ] Device profiles are built after 72 hours of observation
- [ ] `ExcessiveUpload` anomalies fire correctly in tests (use mock data)
- [ ] `NewDestination` anomalies fire when a device contacts a new IP
- [ ] `UnusualHour` anomalies fire for traffic at unexpected times
- [ ] Anomalies are stored in DB and visible in dashboard
- [ ] Weekly digest generates sensible plain-English highlights
- [ ] Device detail panel shows sparkline and profile info

---

# PHASE 3 — The Voice Gate (`hearth-vad`)

## Goal
Intercept smart speaker audio uploads. Block them if no wake word energy was detected.  
This is a **standalone binary** — it does not depend on hearth-core's capture loop.

---

## Architecture

```
Smart Speaker → [Pi as gateway for that one device] → Internet
                         ↓
                   hearth-vad
                   - Intercepts audio stream via iptables NFQUEUE
                   - Runs Silero VAD model (ONNX via tract)
                   - Allows packet: wake word detected in last 3s
                   - Drops packet + logs: no wake word detected
```

---

## `hearth-vad/Cargo.toml`

```toml
[package]
name = "hearth-vad"
version = "0.1.0"
edition = "2021"

[dependencies]
tokio = { workspace = true }
anyhow = { workspace = true }
tracing = { workspace = true }
serde = { workspace = true }
tract-onnx = "0.21"          # ONNX inference in pure Rust
nfq = "0.5"                  # netfilter queue bindings
chrono = { workspace = true }
rusqlite = { workspace = true }

[[bin]]
name = "hearth-vad"
path = "src/main.rs"
```

---

## Module Structure

```
hearth-vad/src/
├── main.rs          # init, config, spawn queue listener + VAD runner
├── model.rs         # load Silero VAD ONNX model via tract, run inference
├── queue.rs         # netfilter queue: receive packets, make allow/drop decision
├── audio.rs         # extract PCM audio from packet payload
└── log.rs           # write VAD events to SQLite (separate from main hearth DB)
```

---

## `model.rs` — VAD Inference Spec

```rust
// Model: silero_vad.onnx
// Download from: https://github.com/snakers4/silero-vad/raw/master/files/silero_vad.onnx
// Place at: /var/lib/hearth/silero_vad.onnx

use tract_onnx::prelude::*;

pub struct VadModel {
    model: SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>,
}

impl VadModel {
    pub fn load(model_path: &str) -> anyhow::Result<Self>
    // Load ONNX model using tract_onnx::onnx().model_for_path()
    // Input: 1x512 f32 tensor (512 samples of 16kHz mono PCM audio)
    // Output: scalar f32 in [0, 1] — probability of speech

    pub fn score(&self, audio_chunk: &[f32; 512]) -> anyhow::Result<f32>
    // Run inference on one 32ms audio chunk
    // Returns speech probability 0.0..1.0
    // Consider speech detected if score > 0.5

    pub fn is_wake_word_likely(
        &self,
        recent_chunks: &[[f32; 512]],   // last 3 seconds = 90 chunks
    ) -> bool
    // Score each chunk. If >= 3 consecutive chunks score > 0.5, return true.
    // This heuristic catches a spoken wake word (0.5–1.5s of sustained speech)
    // while ignoring random noise spikes.
}
```

---

## `queue.rs` — NFQUEUE Packet Handler Spec

```rust
// Setup (run once at startup, as root):
// iptables -I FORWARD -m mac --mac-source <speaker_mac> -j NFQUEUE --queue-num 100
//
// This intercepts all outbound traffic from the speaker.
// For non-audio packets (DNS, NTP, etc.): ACCEPT immediately
// For audio stream packets (detected by port or payload pattern): run VAD check

pub struct PacketGate {
    queue_num: u16,
    vad: Arc<VadModel>,
    audio_state: Arc<Mutex<AudioState>>,
    log: Arc<VadLog>,
}

pub struct AudioState {
    recent_chunks: VecDeque<[f32; 512]>,  // rolling 3-second window
    last_wake_word_at: Option<Instant>,
    blocked_count: u32,
    allowed_count: u32,
}

impl PacketGate {
    pub fn run(&self) -> anyhow::Result<()>
    // Open NFQUEUE, loop:
    // 1. Receive packet from nfq queue
    // 2. Identify if it's an audio upload:
    //    - Destination port 443 (HTTPS) — can't inspect TLS, use heuristics
    //    - Packet size > 800 bytes (audio payloads are large)
    //    - Destination IP matches known Alexa/Google endpoints (hardcoded list)
    // 3. For identified audio packets:
    //    a. Extract raw bytes as pseudo-PCM (we can't decrypt, but timing matters)
    //    b. Update audio_state.recent_chunks
    //    c. Run vad.is_wake_word_likely(recent_chunks)
    //    d. If true OR last_wake_word_at within 10s: ACCEPT
    //    e. Else: DROP + log
    // 4. For all other packets: ACCEPT immediately

    // NOTE ON TLS LIMITATION:
    // We cannot read encrypted audio content.
    // What we CAN do: detect sustained outbound traffic to known voice endpoints.
    // The heuristic is: if the device is sending large sustained packets to
    // Amazon/Google audio endpoints but our local audio chunk ring buffer shows
    // no speech activity for the past 10 seconds, flag it.
    // This is imperfect but better than nothing. Document this limitation clearly.
}
```

---

## Known Alexa / Google Voice Endpoint IPs (hardcoded list)

```rust
// Maintain this as a Vec<IpAddr> in a const or config file.
// These are stable datacenter ranges — update periodically.
// Amazon Alexa: 54.239.26.0/24, 99.83.x.x ranges
// Google Assistant: 216.58.x.x, 142.250.x.x
//
// Fallback heuristic if IP not in list:
// Flag if destination is NOT in known_destinations for this device
// AND packet size sustained > 800 bytes for > 5 consecutive packets
```

---

## `log.rs` — VAD Event Log

```sql
CREATE TABLE IF NOT EXISTS vad_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,   -- "ALLOWED" or "BLOCKED"
    destination_ip TEXT NOT NULL,
    duration_ms INTEGER,        -- estimated audio duration in milliseconds
    speech_score REAL,          -- highest VAD score in the window
    detail TEXT
);
```

Expose these via a new route: `GET /api/vad/events?hours=24`

---

## VAD Dashboard UI

Add a third tab: **Voice Gate**

Contents:
- Toggle switch: Voice Gate [ON/OFF] — calls `POST /api/vad/toggle`
- Today's stats: "Allowed: 23 uploads | Blocked: 4 uploads"
- Timeline chart: hourly bar chart of allowed vs blocked events
- Recent events table: timestamp | allowed/blocked | destination | speech score

---

## Phase 3 — Acceptance Criteria

- [ ] `hearth-vad` builds and runs as a standalone binary
- [ ] Silero VAD model loads and scores audio chunks in < 10ms on Pi 4
- [ ] NFQUEUE intercepts packets from test device
- [ ] Allow/block decision is logged to SQLite
- [ ] Dashboard voice gate tab shows event history
- [ ] Documented limitation about TLS opacity is in README

---

# PHASE 4 — Soft Blocking (`hearth-rules`)

## Goal
User-defined rules enforced via nftables. Opt-in. No popup interruptions.

---

## `hearth-rules/Cargo.toml`

```toml
[package]
name = "hearth-rules"
version = "0.1.0"
edition = "2021"

[dependencies]
tokio = { workspace = true }
serde = { workspace = true }
anyhow = { workspace = true }
tracing = { workspace = true }
hearth-core = { path = "../hearth-core" }

[lib]
name = "hearth_rules"
path = "src/lib.rs"
```

---

## Rule Types (extend `hearth.toml`)

```toml
[[devices]]
mac = "AA:BB:CC:DD:EE:FF"
label = "Samsung TV"
max_upload_per_hour_mb = 500.0
block_hours = ["23:00", "06:00"]    # no uploads during sleep hours
allow_domains = ["samsung.com", "netflix.com", "youtube.com"]
# If allow_domains is set, ALL other destinations are blocked for this device
```

---

## `hearth-rules/src/lib.rs` — Engine Spec

```rust
pub struct RulesEngine {
    config: Config,
    store: Arc<Store>,
}

impl RulesEngine {
    /// Called every 60 seconds. Evaluates current traffic against rules.
    /// Generates nftables commands and applies them via subprocess.
    pub async fn evaluate(&self) -> anyhow::Result<Vec<RuleAction>>

    /// Apply a list of actions by shelling out to `nft`
    pub fn apply(&self, actions: &[RuleAction]) -> anyhow::Result<()>
}

#[derive(Debug, Serialize)]
pub struct RuleAction {
    pub mac: String,
    pub action: ActionKind,
    pub reason: String,          // human-readable, shown in dashboard
    pub expires_at: Option<DateTime<Utc>>,  // None = permanent until rule changes
}

#[derive(Debug, Serialize)]
pub enum ActionKind {
    BlockOutbound { destination: Option<IpAddr> },  // None = all outbound
    RateLimit { max_bytes_per_second: u64 },
    AllowOnly { domains: Vec<String> },
}
```

---

## nftables Integration

```rust
// All nftables changes operate on a table named "hearth"
// Initialize at startup:
// nft add table inet hearth
// nft add chain inet hearth forward { type filter hook forward priority 0 ; }

// To block a MAC:
// nft add rule inet hearth forward ether saddr AA:BB:CC:DD:EE:FF drop

// To rate limit:
// nft add rule inet hearth forward ether saddr AA:BB:CC:DD:EE:FF limit rate 100 kbytes/second accept

// To flush all hearth rules and reapply from scratch each cycle:
// nft flush chain inet hearth forward
// then add all current rules

// IMPORTANT: Always flush and reapply rather than adding incrementally.
// This prevents rule accumulation bugs.
```

---

## Dashboard Additions (Phase 4)

Add to device detail panel:
- **Rules section**: shows active rules for this device
- **"Add Rule" button**: opens a simple form:
  - Max upload (MB/hr): number input
  - Block hours: time range picker (two dropdowns)
  - Allow only these domains: textarea (one per line)
- Rules are written back to `hearth.toml` and config is reloaded
- "Active rules" badge on device row if any rules are enforced

---

## Phase 4 — Acceptance Criteria

- [ ] Rules defined in hearth.toml are enforced within 60 seconds of startup
- [ ] `block_hours` correctly blocks and unblocks at the right times
- [ ] `max_upload_per_hour_mb` triggers a rate limit rule when exceeded
- [ ] `allow_domains` correctly blocks traffic to unlisted domains
- [ ] All nftables changes are logged with timestamps
- [ ] Dashboard shows which rules are active per device
- [ ] Removing a rule from config clears it from nftables within 60 seconds

---

# PHASE 5 — CLI (`hearth-cli`)

## Goal
Local control without opening a browser. Useful for headless Pi deployments.

---

## Commands

```
hearth-cli status                      # show all devices + current traffic
hearth-cli devices                     # list devices with labels and last-seen
hearth-cli device <mac>                # show profile and last 5 anomalies
hearth-cli anomalies                   # list all unresolved anomalies
hearth-cli resolve <anomaly-id>        # mark anomaly as resolved
hearth-cli digest                      # print weekly digest as plain text
hearth-cli label <mac> <name>          # assign a friendly name to a device
hearth-cli block <mac> [--hours N]     # manual block, optional duration
hearth-cli unblock <mac>              # remove manual block
hearth-cli vad status                  # show voice gate status and today's stats
hearth-cli vad toggle                  # enable/disable voice gate
```

All commands communicate with the running daemon via Unix socket at `/var/run/hearth/hearth.sock`.  
The daemon exposes the same REST API on the socket that it serves over HTTP.

---

# Cross-Cutting Requirements

## Error Handling
- All errors use `anyhow::Result`
- Panics are forbidden outside `main.rs`
- Packet parsing errors: log at `warn!` level, skip packet, continue loop
- DB errors: log at `error!` level, retry once after 100ms, then return error
- Model inference errors: log at `error!` level, default to ALLOW (fail open for VAD)

## Logging
- Use `tracing` throughout
- Default level: INFO
- Capture/stats hot path: use `tracing::trace!` to avoid log spam
- All anomaly events: `tracing::warn!`
- All rule actions: `tracing::info!`

## Testing

```
hearth-core/tests/
├── capture_test.rs     # mock packet stream, verify device snapshot aggregation
├── stats_test.rs       # inject synthetic samples, verify anomaly detection
└── store_test.rs       # CRUD round-trips on in-memory SQLite (:memory:)

hearth-vad/tests/
├── model_test.rs       # load model, score silence vs speech audio fixtures
└── queue_test.rs       # mock NFQUEUE, verify allow/drop decisions

hearth-rules/tests/
└── engine_test.rs      # mock nft subprocess, verify rule generation
```

Required test fixtures in `testdata/`:
- `silence_512.bin` — 512 f32 values of silence (all zeros)
- `speech_512.bin` — 512 f32 values of synthesized speech waveform

## Performance Targets (must be measured in CI)
- Packet capture: handle 100k packets/sec without dropping on Pi 4
- VAD inference: < 10ms per 512-sample chunk on Pi 4
- Dashboard API: < 50ms response time for `/api/devices` with 50 devices
- DB writes: batch within capture loop — max 1 write per 60 seconds per device

## Security Hardening
- Binary runs as root only for CAP_NET_RAW and CAP_NET_ADMIN (see systemd unit)
- No network listening except the local dashboard port
- Dashboard binds to `127.0.0.1` by default; user must explicitly set `0.0.0.0` for LAN access
- No telemetry. No outbound connections initiated by Hearth itself.
- Config file permissions: `chmod 600 /etc/hearth/hearth.toml`

---

# LLM Delegation Instructions

When handing a phase to an LLM, include this preamble:

```
You are implementing Phase N of the Hearth project.
Your job is to write production-quality Rust code for the following crate(s): [list].
Requirements:
- Follow the exact module structure and function signatures in this spec.
- Use only the crates listed in the Cargo.toml sections. Do not add new dependencies without flagging it.
- All public functions must have doc comments.
- Write the complete file contents, not snippets.
- After each file, write one sentence explaining any non-obvious design decision.
- If a spec says "implementation notes" — those are hints, not pseudocode. Write real Rust.
- Do not implement phases beyond what is specified here.
- Flag any ambiguity rather than guessing.

[Paste the relevant phase section below]
```

---

# Open Questions (resolve before implementation)

1. **GeoIP database**: MaxMind GeoLite2 requires a free account for download. The installer must either prompt for a license key or use an alternative like `geoip-lite-country` crate with embedded data. Decide before Phase 1.

2. **OUI database update cadence**: The MAC vendor CSV should be re-downloaded monthly. Add a cron job or build it into the daemon's weekly maintenance task.

3. **mDNS for `hearth.local`**: Requires `avahi-daemon` on the Pi. The installer should enable it. Fallback is the raw IP shown in installer output.

4. **TLS audio interception (Phase 3)**: The VAD architecture as described cannot read encrypted audio content. The current approach (traffic pattern heuristics + local microphone-based VAD as a separate input) should be validated as sufficient before Phase 3 begins. Consider: running a local mic on the Pi pointed at the speaker as an alternative signal source.

5. **Pi Zero 2 W support**: 512MB RAM. Silero VAD model is ~2MB. Should be fine, but measure inference time on this target specifically. May need quantized model variant.
