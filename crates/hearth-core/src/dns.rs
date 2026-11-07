use crate::store::Store;
use crate::types::{Anomaly, AnomalyKind, DnsConfig, DnsQueryLog, DnsStats};
use anyhow::Result;
use chrono::Utc;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Heuristic evaluation result for zero-day DNS threats.
#[derive(Debug, Clone, PartialEq)]
pub enum DnsHeuristicResult {
    Clean,
    DgaDomain { entropy: f64, detail: String },
    DnsTunneling { label_len: usize, detail: String },
}

/// Calculate Shannon entropy for a string slice:
/// H = - sum(p * log2(p))
pub fn calculate_shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts: std::collections::HashMap<char, f64> = std::collections::HashMap::with_capacity(36);
    let mut total: f64 = 0.0;
    for ch in s.chars() {
        if ch.is_alphanumeric() {
            *counts.entry(ch.to_ascii_lowercase()).or_insert(0.0) += 1.0;
            total += 1.0;
        }
    }
    if total <= 1.0 {
        return 0.0;
    }
    let mut entropy: f64 = 0.0;
    for &count in counts.values() {
        let p: f64 = count / total;
        entropy -= p * p.log2();
    }
    entropy
}

/// Evaluate whether a queried domain exhibits characteristics of a Zero-Day DGA
/// (Domain Generation Algorithm) or DNS Tunneling data exfiltration.
pub fn check_zero_day_heuristics(domain: &str) -> DnsHeuristicResult {
    let clean = domain.trim().trim_end_matches('.').to_lowercase();
    if clean.is_empty() {
        return DnsHeuristicResult::Clean;
    }

    // Skip reverse DNS and local queries
    if clean.ends_with(".in-addr.arpa")
        || clean.ends_with(".ip6.arpa")
        || clean.ends_with(".local")
        || clean.ends_with(".internal")
        || clean.ends_with(".lan")
    {
        return DnsHeuristicResult::Clean;
    }

    // Skip well-known high-entropy CDNs / cloud provider subdomains
    if clean.ends_with(".cloudfront.net")
        || clean.ends_with(".akamaized.net")
        || clean.ends_with(".azureedge.net")
        || clean.ends_with(".trafficmanager.net")
        || clean.ends_with(".googleusercontent.com")
        || clean.ends_with(".github.io")
    {
        return DnsHeuristicResult::Clean;
    }

    let labels: Vec<&str> = clean.split('.').collect();
    if labels.is_empty() {
        return DnsHeuristicResult::Clean;
    }

    // 1. Check for DNS Tunneling: excessive label length (>= 45 chars) or excessive overall query length (>= 150 chars)
    if clean.len() >= 150 {
        return DnsHeuristicResult::DnsTunneling {
            label_len: clean.len(),
            detail: format!(
                "Total query length ({} bytes) exceeds normal DNS limit (suspected tunnel payload)",
                clean.len()
            ),
        };
    }

    for label in &labels {
        if label.len() >= 45 {
            return DnsHeuristicResult::DnsTunneling {
                label_len: label.len(),
                detail: format!(
                    "Subdomain label length ({} chars) indicates base32/base64 encoded exfiltration",
                    label.len()
                ),
            };
        }
    }

    // 2. Check for Algorithmic DGA (Domain Generation Algorithm):
    // Examine the second-level domain (SLD) or deepest non-subdomain label.
    let candidate_sld = if labels.len() >= 2 {
        labels[labels.len() - 2]
    } else {
        labels[0]
    };

    if candidate_sld.len() >= 12 {
        let entropy = calculate_shannon_entropy(candidate_sld);
        let vowels = candidate_sld
            .chars()
            .filter(|c| matches!(c, 'a' | 'e' | 'i' | 'o' | 'u'))
            .count();
        let vowel_ratio = vowels as f64 / candidate_sld.len() as f64;

        // DGA patterns:
        // High entropy (>= 3.65) with low vowel ratio (< 0.20) or very high entropy (>= 3.85)
        if (entropy >= 3.65 && vowel_ratio < 0.20) || (entropy >= 3.85 && candidate_sld.len() >= 14) {
            return DnsHeuristicResult::DgaDomain {
                entropy,
                detail: format!(
                    "SLD label '{}' exhibits high Shannon entropy ({:.2}) and low vowel ratio ({:.2}), matching DGA botnet beaconing",
                    candidate_sld, entropy, vowel_ratio
                ),
            };
        }
    }

    DnsHeuristicResult::Clean
}

/// High-performance asynchronous DNS Threat Sinkhole and Domain Logger.
pub struct DnsSinkhole {
    store: Arc<Store>,
    config: DnsConfig,
    /// Fast in-memory cache of blocked domains for sub-millisecond filtering
    memory_blocklist: Arc<RwLock<HashSet<String>>>,
    /// In-memory cache for IP -> Domain correlation (used by dashboard and packet capture)
    ip_to_domain: Arc<RwLock<std::collections::HashMap<IpAddr, String>>>,
    /// HTTP client for encrypted DNS-over-HTTPS (DoH) queries
    http_client: reqwest::Client,
    /// Optional channel to broadcast detected zero-day security anomalies
    anomaly_tx: Option<tokio::sync::mpsc::Sender<Anomaly>>,
}

impl DnsSinkhole {
    pub fn new(store: Arc<Store>, config: DnsConfig) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self {
            store,
            config,
            memory_blocklist: Arc::new(RwLock::new(HashSet::new())),
            ip_to_domain: Arc::new(RwLock::new(std::collections::HashMap::new())),
            http_client,
            anomaly_tx: None,
        }
    }

    /// Attach an anomaly event channel to receive real-time zero-day DGA and DNS tunneling alerts.
    pub fn with_anomaly_tx(mut self, tx: tokio::sync::mpsc::Sender<Anomaly>) -> Self {
        self.anomaly_tx = Some(tx);
        self
    }

    /// Retrieve the cached domain name for a given destination IP if observed recently.
    pub async fn lookup_domain_for_ip(&self, ip: &IpAddr) -> Option<String> {
        self.ip_to_domain.read().await.get(ip).cloned()
    }

    /// Retrieve DNS sinkhole statistics.
    pub fn get_stats(&self) -> Result<DnsStats> {
        self.store.get_dns_stats()
    }

    /// Check if a domain is blocked (checks in-memory set first, then store).
    pub async fn is_blocked(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase().trim_end_matches('.').to_string();
        {
            let set = self.memory_blocklist.read().await;
            if set.contains(&domain_lower) {
                return true;
            }
            // Check parent zones (e.g. ads.google.com -> google.com)
            let parts: Vec<&str> = domain_lower.split('.').collect();
            if parts.len() > 2 {
                for i in 1..parts.len() - 1 {
                    let parent = parts[i..].join(".");
                    if set.contains(&parent) {
                        return true;
                    }
                }
            }
        }

        // Fallback to SQLite check
        self.store.is_domain_blocked(&domain_lower).unwrap_or(false)
    }

    /// Download and sync configured domain threat blocklists.
    pub async fn sync_blocklists(&self) -> Result<usize> {
        if !self.config.enabled {
            info!("DNS Sinkhole is disabled in config");
            return Ok(0);
        }

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("Hearth-DNS-Sinkhole/0.1.0")
            .build()?;

        let mut all_domains = Vec::new();

        for url in &self.config.blocklists {
            info!("Fetching DNS threat blocklist: {}", url);
            match client.get(url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    let body = resp.text().await.unwrap_or_default();
                    let domains = Self::parse_hosts_file(&body);
                    info!("Parsed {} domains from blocklist {}", domains.len(), url);
                    all_domains.extend(domains);
                }
                Ok(resp) => {
                    warn!("Blocklist URL returned status {}: {}", resp.status(), url);
                }
                Err(e) => {
                    warn!("Failed to fetch blocklist {}: {}", url, e);
                }
            }
        }

        if !all_domains.is_empty() {
            // Update in-memory hash set
            {
                let mut mem = self.memory_blocklist.write().await;
                for d in &all_domains {
                    mem.insert(d.clone());
                }
            }

            // Persist into SQLite
            match self.store.upsert_blocked_domains(&all_domains, "Community Threat List") {
                Ok(saved) => {
                    info!("DNS Sinkhole synchronized {} blocked malicious domains", saved);
                    return Ok(saved);
                }
                Err(e) => {
                    warn!("Failed to persist blocked domains to SQLite: {}", e);
                }
            }
        }

        Ok(all_domains.len())
    }

    /// Parse standard hosts-file or domain-list formats.
    pub fn parse_hosts_file(content: &str) -> Vec<String> {
        let mut domains = Vec::new();
        for raw_line in content.lines() {
            // Strip comments
            let line = raw_line
                .split('#')
                .next()
                .unwrap_or("")
                .split(';')
                .next()
                .unwrap_or("")
                .trim();
            if line.is_empty() {
                continue;
            }

            let tokens: Vec<&str> = line.split_whitespace().collect();
            if tokens.len() >= 2 {
                // Hosts format: "<ip> <domain> [aliases...]"
                let domain = tokens[1].trim().to_lowercase().trim_end_matches('.').to_string();
                if domain != "localhost" && domain != "broadcasthost" && !domain.is_empty() && domain.contains('.') {
                    domains.push(domain);
                }
            } else if tokens.len() == 1 {
                // Raw domain list: "<domain>"
                let domain = tokens[0].trim().to_lowercase().trim_end_matches('.').to_string();
                if !domain.is_empty() && domain.contains('.') {
                    domains.push(domain);
                }
            }
        }
        domains
    }

    /// Run the async UDP DNS server.
    pub async fn run_server(self: Arc<Self>) -> Result<()> {
        if !self.config.enabled {
            info!("DNS Sinkhole is disabled");
            return Ok(());
        }

        let bind_addr = format!("0.0.0.0:{}", self.config.port);
        let socket = match UdpSocket::bind(&bind_addr).await {
            Ok(s) => {
                info!("🛡️ DNS Threat Sinkhole listening on UDP {}", bind_addr);
                s
            }
            Err(e) => {
                warn!(
                    "DNS Sinkhole could not bind to {}: {} (port 53 may require root/admin or is used by systemd-resolved)",
                    bind_addr, e
                );
                return Err(e.into());
            }
        };

        let server_socket = Arc::new(socket);

        let upstream_addr: SocketAddr = self
            .config
            .upstream
            .parse()
            .unwrap_or_else(|_| "1.1.1.1:53".parse().unwrap());

        // Spawn periodic blocklist sync worker (every 24h)
        let sync_self = Arc::clone(&self);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let _ = sync_self.sync_blocklists().await;
            let mut interval = tokio::time::interval(Duration::from_secs(86400));
            interval.tick().await;
            loop {
                interval.tick().await;
                let _ = sync_self.sync_blocklists().await;
            }
        });

        let mut buf = [0u8; 1024];

        loop {
            let (len, client_addr) = match server_socket.recv_from(&mut buf).await {
                Ok(r) => r,
                Err(e) => {
                    warn!("DNS recv error: {}", e);
                    continue;
                }
            };

            let req_data = buf[..len].to_vec();
            let sinkhole = Arc::clone(&self);
            let s_socket = Arc::clone(&server_socket);
            let upstream = upstream_addr;

            // Spawn a task per query for maximum throughput
            tokio::spawn(async move {
                if let Err(e) = sinkhole
                    .handle_dns_query(&req_data, client_addr, upstream, &s_socket)
                    .await
                {
                    tracing::debug!("Error handling DNS query from {}: {}", client_addr, e);
                }
            });
        }
    }

    /// Handle an individual DNS query.
    pub async fn handle_dns_query(
        &self,
        query: &[u8],
        client_addr: SocketAddr,
        upstream_addr: SocketAddr,
        server_socket: &UdpSocket,
    ) -> Result<()> {
        if query.len() < 12 {
            return Ok(());
        }

        // Anti-amplification & WAN boundary enforcement:
        // Reject non-private/WAN DNS queries without responding to prevent DDoS amplification abuse.
        if !Self::is_trusted_dns_client(&client_addr.ip()) {
            warn!(
                "🛑 Dropped DNS query from non-private client {} (anti-amplification protection)",
                client_addr.ip()
            );
            return Ok(());
        }

        let (domain, qtype) = match Self::extract_domain_and_type(query) {
            Some(res) => res,
            None => return Ok(()),
        };

        let mut is_blocked = self.is_blocked(&domain).await;
        let mut block_reason = if is_blocked {
            Some("Threat Blocklist Sinkhole".to_string())
        } else {
            None
        };

        // Zero-Day Heuristic Threat Detection: DGA and DNS Tunneling Heuristics
        if !is_blocked {
            match check_zero_day_heuristics(&domain) {
                DnsHeuristicResult::DgaDomain { entropy, detail } => {
                    is_blocked = true;
                    block_reason = Some(format!("Zero-Day DGA Heuristic (Entropy {:.2}): {}", entropy, detail));
                    warn!("🚨 [ZERO-DAY DGA DETECTED] Sinkholed algorithmic domain '{}' from client {}: {}", domain, client_addr.ip(), detail);

                    if let Some(ref tx) = self.anomaly_tx {
                        let anomaly = Anomaly {
                            id: None,
                            mac: client_addr.ip().to_string(),
                            detected_at: Utc::now(),
                            kind: AnomalyKind::DgaDomainDetected,
                            detail: format!("Algorithmic DGA C2 domain '{}' detected via Shannon entropy ({:.2}) from client {}. Autonomous sinkhole active.", domain, entropy, client_addr.ip()),
                            resolved: false,
                        };
                        let _ = tx.try_send(anomaly);
                    }
                }
                DnsHeuristicResult::DnsTunneling { label_len, detail } => {
                    is_blocked = true;
                    block_reason = Some(format!("Zero-Day DNS Tunneling Heuristic (Label {} bytes): {}", label_len, detail));
                    warn!("🚨 [ZERO-DAY DNS TUNNEL DETECTED] Sinkholed exfiltration query '{}' from client {}: {}", domain, client_addr.ip(), detail);

                    if let Some(ref tx) = self.anomaly_tx {
                        let anomaly = Anomaly {
                            id: None,
                            mac: client_addr.ip().to_string(),
                            detected_at: Utc::now(),
                            kind: AnomalyKind::DnsTunnelingExfiltration,
                            detail: format!("DNS Tunneling / Data Exfiltration query '{}' detected from client {}. Autonomous sinkhole active.", domain, client_addr.ip()),
                            resolved: false,
                        };
                        let _ = tx.try_send(anomaly);
                    }
                }
                DnsHeuristicResult::Clean => {}
            }
        }

        // Log DNS query
        let query_log = DnsQueryLog {
            id: None,
            timestamp: Utc::now(),
            client_ip: client_addr.ip(),
            client_mac: None,
            domain: domain.clone(),
            query_type: format!("{:?}", qtype),
            is_blocked,
            block_reason,
        };
        let _ = self.store.insert_dns_query(&query_log);

        if is_blocked {
            info!("🛑 [DNS SINKHOLE] Blocked malicious domain '{}' from {}", domain, client_addr.ip());
            let sinkhole_resp = Self::build_sinkhole_response(query);
            // Reply directly from port 53 using the server listener socket
            server_socket.send_to(&sinkhole_resp, client_addr).await?;
        } else {
            // Forward to upstream: Try Encrypted DoH first if configured, fallback to UDP
            let mut resolved_data: Option<Vec<u8>> = None;

            if let Some(ref doh_url) = self.config.doh_upstream {
                match self.resolve_doh(doh_url, query).await {
                    Ok(resp_bytes) => {
                        resolved_data = Some(resp_bytes);
                    }
                    Err(e) => {
                        tracing::debug!("DoH query failed ({}), falling back to UDP upstream", e);
                    }
                }
            }

            if resolved_data.is_none() {
                // Forward to standard UDP upstream DNS resolver
                let upstream_client = UdpSocket::bind("0.0.0.0:0").await?;
                upstream_client.send_to(query, upstream_addr).await?;
                let mut upstream_buf = [0u8; 1024];

                if let Ok(Ok((resp_len, _))) = tokio::time::timeout(
                    Duration::from_secs(2),
                    upstream_client.recv_from(&mut upstream_buf),
                )
                .await
                {
                    resolved_data = Some(upstream_buf[..resp_len].to_vec());
                }
            }

            if let Some(resp_data) = resolved_data {
                // Learn domain -> IP mapping from upstream A records (bounded to prevent unbounded growth)
                if let Some(resolved_ip) = Self::extract_resolved_ip(&resp_data) {
                    let mut cache = self.ip_to_domain.write().await;
                    if cache.len() >= 5000 {
                        let to_remove: Vec<_> = cache.keys().take(2500).cloned().collect();
                        for k in to_remove {
                            cache.remove(&k);
                        }
                    }
                    cache.insert(resolved_ip, domain);
                }
                // Send response back from listening port 53
                server_socket.send_to(&resp_data, client_addr).await?;
            }
        }

        Ok(())
    }

    /// Resolve a DNS wire query via encrypted DNS-over-HTTPS (RFC 8484).
    pub async fn resolve_doh(&self, doh_url: &str, query: &[u8]) -> Result<Vec<u8>> {
        let resp = self
            .http_client
            .post(doh_url)
            .header("content-type", "application/dns-message")
            .header("accept", "application/dns-message")
            .body(query.to_vec())
            .send()
            .await?;

        if resp.status().is_success() {
            let bytes = resp.bytes().await?;
            Ok(bytes.to_vec())
        } else {
            anyhow::bail!("DoH upstream status: {}", resp.status())
        }
    }

    /// Extract domain name and query type from raw DNS wire format.
    pub fn extract_domain_and_type(query: &[u8]) -> Option<(String, u16)> {
        if query.len() < 12 {
            return None;
        }

        let mut pos = 12;
        let mut domain_parts = Vec::new();

        while pos < query.len() {
            let len = query[pos] as usize;
            if len == 0 {
                pos += 1;
                break;
            }
            if pos + 1 + len > query.len() {
                return None;
            }
            let part = std::str::from_utf8(&query[pos + 1..pos + 1 + len]).ok()?;
            domain_parts.push(part.to_string());
            pos += 1 + len;
        }

        if domain_parts.is_empty() || pos + 4 > query.len() {
            return None;
        }

        let qtype = ((query[pos] as u16) << 8) | (query[pos + 1] as u16);
        let domain = domain_parts.join(".");

        Some((domain, qtype))
    }

    /// Extract resolved IPv4 from DNS response answer section.
    pub fn extract_resolved_ip(response: &[u8]) -> Option<IpAddr> {
        if response.len() < 16 {
            return None;
        }
        let ancount = ((response[6] as u16) << 8) | (response[7] as u16);
        if ancount == 0 {
            return None;
        }

        // Search for Type 1 (A record) in the response tail
        let mut pos = 12;
        // Skip question section
        while pos < response.len() && response[pos] != 0 {
            pos += response[pos] as usize + 1;
        }
        pos += 5; // skip 0x00, QTYPE (2), QCLASS (2)

        // Read answer records
        while pos + 12 <= response.len() {
            // Skip name (pointer 2 bytes or labels)
            if response[pos] & 0xC0 == 0xC0 {
                pos += 2;
            } else {
                while pos < response.len() && response[pos] != 0 {
                    pos += response[pos] as usize + 1;
                }
                pos += 1;
            }

            if pos + 10 > response.len() {
                break;
            }

            let rtype = ((response[pos] as u16) << 8) | (response[pos + 1] as u16);
            let rdlength = (((response[pos + 8] as u16) << 8) | (response[pos + 9] as u16)) as usize;
            pos += 10;

            if rtype == 1 && rdlength == 4 && pos + 4 <= response.len() {
                return Some(IpAddr::V4(Ipv4Addr::new(
                    response[pos],
                    response[pos + 1],
                    response[pos + 2],
                    response[pos + 3],
                )));
            }
            pos += rdlength;
        }

        None
    }

    /// Construct a 0.0.0.0 Sinkhole DNS response packet.
    pub fn build_sinkhole_response(query: &[u8]) -> Vec<u8> {
        let mut resp = Vec::with_capacity(query.len() + 16);
        if query.len() < 12 {
            return resp;
        }

        // Validate Question section bounds
        let mut pos = 12;
        while pos < query.len() && query[pos] != 0 {
            pos += query[pos] as usize + 1;
        }

        // If the question section is malformed or truncated (missing 0x00 delimiter or QTYPE/QCLASS)
        if pos >= query.len() || pos + 5 > query.len() {
            // Return Format Error (RCODE 1: FormErr) with ANCOUNT 0 to prevent pointer loop
            resp.extend_from_slice(&query[..2]); // ID
            resp.push(0x81); // QR=1, Opcode=0, AA=0, TC=0, RD=1
            resp.push(0x81); // RA=1, Z=0, RCODE=1 (Format Error)
            resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            return resp;
        }

        pos += 5; // skip 0x00, QTYPE, QCLASS

        // Copy header
        resp.extend_from_slice(&query[..2]); // ID
        resp.push(0x81); // Flags: Standard query response, Recursion desired
        resp.push(0x80); // Flags: Recursion available, No error
        resp.extend_from_slice(&query[4..6]); // QDCOUNT (1)
        resp.push(0x00); // ANCOUNT (1)
        resp.push(0x01);
        resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // NSCOUNT, ARCOUNT (0)

        // Copy verified question section (starting at offset 12)
        resp.extend_from_slice(&query[12..pos]);

        // Add Answer: Point to question name at offset 12 (0xc00c)
        resp.push(0xC0);
        resp.push(0x0C);
        resp.push(0x00); // Type: A (1)
        resp.push(0x01);
        resp.push(0x00); // Class: IN (1)
        resp.push(0x01);
        resp.push(0x00); // TTL: 60s
        resp.push(0x00);
        resp.push(0x00);
        resp.push(0x3C);
        resp.push(0x00); // RDLENGTH: 4 bytes
        resp.push(0x04);
        resp.extend_from_slice(&[0, 0, 0, 0]); // RDATA: 0.0.0.0 (Sinkholed)

        resp
    }

    /// Check whether a DNS client IP is in a trusted local/private network range.
    /// Used to enforce private subnet boundaries and prevent DNS amplification abuse.
    pub fn is_trusted_dns_client(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => {
                ipv4.is_loopback() || ipv4.is_private() || ipv4.is_link_local()
            }
            IpAddr::V6(ipv6) => {
                ipv6.is_loopback()
                    || ipv6.is_unicast_link_local()
                    || ((ipv6.segments()[0] & 0xfe00) == 0xfc00)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_trusted_dns_client() {
        // Trusted private and local IPs
        assert!(DnsSinkhole::is_trusted_dns_client(&"127.0.0.1".parse().unwrap()));
        assert!(DnsSinkhole::is_trusted_dns_client(&"192.168.1.100".parse().unwrap()));
        assert!(DnsSinkhole::is_trusted_dns_client(&"10.0.0.5".parse().unwrap()));
        assert!(DnsSinkhole::is_trusted_dns_client(&"172.16.0.1".parse().unwrap()));
        assert!(DnsSinkhole::is_trusted_dns_client(&"169.254.1.1".parse().unwrap()));
        assert!(DnsSinkhole::is_trusted_dns_client(&"::1".parse().unwrap()));
        assert!(DnsSinkhole::is_trusted_dns_client(&"fe80::1".parse().unwrap()));
        assert!(DnsSinkhole::is_trusted_dns_client(&"fd00::1".parse().unwrap()));

        // Untrusted public / WAN IPs
        assert!(!DnsSinkhole::is_trusted_dns_client(&"8.8.8.8".parse().unwrap()));
        assert!(!DnsSinkhole::is_trusted_dns_client(&"1.1.1.1".parse().unwrap()));
        assert!(!DnsSinkhole::is_trusted_dns_client(&"142.250.190.46".parse().unwrap()));
        assert!(!DnsSinkhole::is_trusted_dns_client(&"2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn test_parse_hosts_file() {
        let hosts = "
# Comment
127.0.0.1 localhost
0.0.0.0 malware.com
0.0.0.0 phishing.test.co # inline comment
::1 localhost
10.0.0.1 tracking.net
";
        let domains = DnsSinkhole::parse_hosts_file(hosts);
        assert!(domains.contains(&"malware.com".to_string()));
        assert!(domains.contains(&"phishing.test.co".to_string()));
        assert!(domains.contains(&"tracking.net".to_string()));
        assert!(!domains.contains(&"localhost".to_string()));
    }

    #[test]
    fn test_build_sinkhole_response() {
        let query = vec![
            0x12, 0x34, // ID
            0x01, 0x00, // Flags
            0x00, 0x01, // QDCOUNT (1)
            0x00, 0x00, // ANCOUNT (0)
            0x00, 0x00, // NSCOUNT (0)
            0x00, 0x00, // ARCOUNT (0)
            0x04, b't', b'e', b's', b't', 0x03, b'c', b'o', b'm', 0x00, // Name: test.com
            0x00, 0x01, // Type: A
            0x00, 0x01, // Class: IN
        ];

        let resp = DnsSinkhole::build_sinkhole_response(&query);
        assert_eq!(&resp[..2], &[0x12, 0x34]);
        assert_eq!(resp[2], 0x81);
        assert_eq!(resp[3], 0x80);
        assert_eq!(&resp[6..8], &[0x00, 0x01]);
        assert_eq!(&resp[resp.len() - 4..], &[0, 0, 0, 0]);
    }

    #[test]
    fn test_build_sinkhole_response_malformed_truncated() {
        // Truncated query of 12 bytes with missing question
        let truncated = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let resp = DnsSinkhole::build_sinkhole_response(&truncated);
        assert_eq!(&resp[..2], &[0x12, 0x34]);
        // Should return Format Error (RCODE 1, 0x8181) and ANCOUNT = 0 (no self-referential pointer)
        assert_eq!(resp[3] & 0x0F, 1);
        assert_eq!(&resp[6..8], &[0x00, 0x00]);
    }

    #[test]
    fn test_calculate_shannon_entropy() {
        // Repeated identical characters have low entropy
        let low_entropy = calculate_shannon_entropy("aaaaaaaaaaaa");
        assert_eq!(low_entropy, 0.0);

        // Standard English word
        let google_entropy = calculate_shannon_entropy("google");
        assert!(google_entropy < 2.5);

        // Random algorithmic string (high entropy)
        let high_entropy = calculate_shannon_entropy("z9x4q1m8v3k2l5j0");
        assert!(high_entropy > 3.8);
    }

    #[test]
    fn test_check_zero_day_heuristics_dga_and_tunnel() {
        // Legitimate standard domains
        assert_eq!(check_zero_day_heuristics("google.com"), DnsHeuristicResult::Clean);
        assert_eq!(check_zero_day_heuristics("netflix.com"), DnsHeuristicResult::Clean);
        assert_eq!(check_zero_day_heuristics("api.weather.com"), DnsHeuristicResult::Clean);
        assert_eq!(check_zero_day_heuristics("sub.internal"), DnsHeuristicResult::Clean);
        assert_eq!(check_zero_day_heuristics("1.0.0.127.in-addr.arpa"), DnsHeuristicResult::Clean);

        // Algorithmic DGA domain (high entropy + low vowel ratio)
        match check_zero_day_heuristics("x89qzm3ak91lqwv7.biz") {
            DnsHeuristicResult::DgaDomain { entropy, .. } => {
                assert!(entropy >= 3.65);
            }
            other => panic!("Expected DgaDomain, got {:?}", other),
        }

        // Subdomain DNS tunneling exfiltration (label length >= 45 chars)
        let tunneling_domain = "aW5mbzEyMzQ1Njc4OTA1MTYyNzM4NDk1MDE5Mjg0NzI5Mzg0NzI5Mzg0NzI5.tunnel.evil.com";
        match check_zero_day_heuristics(tunneling_domain) {
            DnsHeuristicResult::DnsTunneling { label_len, .. } => {
                assert!(label_len >= 45);
            }
            other => panic!("Expected DnsTunneling, got {:?}", other),
        }
    }
}
