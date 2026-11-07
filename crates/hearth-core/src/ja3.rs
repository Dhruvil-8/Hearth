use crate::types::{Anomaly, AnomalyKind};
use chrono::Utc;
use std::collections::HashMap;
use std::net::IpAddr;

/// JA3 TLS Client Fingerprint representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ja3Fingerprint {
    pub raw: String,
    pub hash: String,
}

/// Known malicious JA3 fingerprints (threat intelligence database).
fn get_malicious_ja3_signatures() -> HashMap<&'static str, &'static str> {
    let mut sigs = HashMap::new();
    sigs.insert("a0e9f5d64349fb13191bc781f81f42e1", "Cobalt Strike HTTPS Beacon");
    sigs.insert("72a589da586844d7f0818ce684948eea", "Trickbot Banking Trojan");
    sigs.insert("b384547432ea38ce56ec4f7764d774cb", "Emotet Malware Loader");
    sigs.insert("51c64c77e60f3980eea90869b68c58a8", "Metasploit Meterpreter Reverse HTTPS");
    sigs.insert("6734f37431670b3ab4292b8f60f29984", "Mirai IoT Botnet C2 Variant");
    sigs.insert("1904a43477d9c18f15ef232fa8593414", "AsyncRAT / NjRAT C2");
    sigs.insert("e7d705a3286e19ea42f587b344ee6865", "Qakbot Banking Trojan");
    sigs.insert("de9e646271a7d6e676b70ad9b26b4859", "PoshC2 Implant");
    sigs.insert("c1020755d491c14cb5b9c2b9f6f6ef42", "Mythic / Sliver C2 Beacon");
    sigs.insert("5fc67d436cf4a429032e2646d5fa6653", "Havoc C2 Demon Implant");
    sigs.insert("0cce74b019b18d88793740263309a47d", "Brute Ratel C4 Badgers");
    sigs.insert("773906b0ef9dbb6121f42ae1c473406e", "Uncompiled Go/Python C2 Exploit Stager");
    sigs
}

/// Check for anomalous, barebones TLS Client Hello profiles characteristic of custom C2 implants.
pub fn evaluate_tls_stack_heuristics(raw_ja3: &str) -> Option<&'static str> {
    let parts: Vec<&str> = raw_ja3.split(',').collect();
    if parts.len() < 5 {
        return None;
    }

    let ciphers = parts[1];
    let extensions = parts[2];

    // Minimalist raw cipher count: modern OS/browsers send >= 4 ciphers and >= 4 extensions
    let cipher_count = if ciphers.is_empty() { 0 } else { ciphers.split('-').count() };
    let ext_count = if extensions.is_empty() { 0 } else { extensions.split('-').count() };

    // Barebones TLS handshake: single cipher with zero extensions is virtually non-existent
    // in legitimate consumer/enterprise software, but standard in raw socket exploit payloads.
    if cipher_count == 1 && ext_count == 0 {
        return Some("Barebones single-cipher TLS handshake without extensions (characteristic of custom C2 shellcode/stagers)");
    }

    None
}

/// Parse a raw TCP payload and compute the JA3 fingerprint if it is a TLS Client Hello.
pub fn parse_client_hello(payload: &[u8]) -> Option<Ja3Fingerprint> {
    // Minimum TLS record + handshake header: 5 + 4 = 9 bytes
    if payload.len() < 9 {
        return None;
    }

    // Byte 0: Content Type must be 22 (Handshake)
    if payload[0] != 0x16 {
        return None;
    }

    // Byte 5: Handshake Type must be 1 (Client Hello)
    if payload[5] != 0x01 {
        return None;
    }

    // TLS version from Client Hello (bytes 9-10)
    if payload.len() < 11 {
        return None;
    }
    let tls_version = ((payload[9] as u16) << 8) | (payload[10] as u16);

    // Skip Random (32 bytes): pos starts at 11 + 32 = 43
    let mut pos = 43;
    if pos >= payload.len() {
        return None;
    }

    // Session ID length
    let session_id_len = payload[pos] as usize;
    pos += 1 + session_id_len;
    if pos + 2 > payload.len() {
        return None;
    }

    // Cipher Suites length (2 bytes)
    let ciphers_len = (((payload[pos] as u16) << 8) | (payload[pos + 1] as u16)) as usize;
    pos += 2;
    if pos + ciphers_len > payload.len() {
        return None;
    }

    // Extract Cipher Suites (filter GREASE)
    let mut ciphers = Vec::new();
    let mut i = 0;
    while i + 2 <= ciphers_len {
        let cs = ((payload[pos + i] as u16) << 8) | (payload[pos + i + 1] as u16);
        if !is_grease(cs) {
            ciphers.push(cs.to_string());
        }
        i += 2;
    }
    pos += ciphers_len;
    if pos >= payload.len() {
        return None;
    }

    // Compression Methods length
    let comp_len = payload[pos] as usize;
    pos += 1 + comp_len;

    let mut extensions = Vec::new();
    let mut elliptic_curves = Vec::new();
    let mut point_formats = Vec::new();

    // Extensions length (optional in older SSL, standard in TLS)
    if pos + 2 <= payload.len() {
        let ext_len = (((payload[pos] as u16) << 8) | (payload[pos + 1] as u16)) as usize;
        pos += 2;
        let ext_end = (pos + ext_len).min(payload.len());

        while pos + 4 <= ext_end {
            let ext_type = ((payload[pos] as u16) << 8) | (payload[pos + 1] as u16);
            let ext_data_len = (((payload[pos + 2] as u16) << 8) | (payload[pos + 3] as u16)) as usize;
            pos += 4;
            if pos + ext_data_len > ext_end {
                break;
            }

            if !is_grease(ext_type) {
                extensions.push(ext_type.to_string());
            }

            // Extension 0x000a: Supported Groups (Elliptic Curves)
            if ext_type == 0x000A && ext_data_len >= 2 {
                let curves_len = (((payload[pos] as u16) << 8) | (payload[pos + 1] as u16)) as usize;
                let mut c_pos = pos + 2;
                let c_end = (c_pos + curves_len).min(pos + ext_data_len);
                while c_pos + 2 <= c_end {
                    let curve = ((payload[c_pos] as u16) << 8) | (payload[c_pos + 1] as u16);
                    if !is_grease(curve) {
                        elliptic_curves.push(curve.to_string());
                    }
                    c_pos += 2;
                }
            }

            // Extension 0x000b: EC Point Formats
            if ext_type == 0x000B && ext_data_len >= 1 {
                let formats_len = payload[pos] as usize;
                let f_pos = pos + 1;
                let f_end = (f_pos + formats_len).min(pos + ext_data_len);
                for &fmt in &payload[f_pos..f_end] {
                    point_formats.push(fmt.to_string());
                }
            }

            pos += ext_data_len;
        }
    }

    // Build standard JA3 string: SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
    let ja3_raw = format!(
        "{},{},{},{},{}",
        tls_version,
        ciphers.join("-"),
        extensions.join("-"),
        elliptic_curves.join("-"),
        point_formats.join("-")
    );

    let ja3_hash = md5_hex(ja3_raw.as_bytes());

    Some(Ja3Fingerprint {
        raw: ja3_raw,
        hash: ja3_hash,
    })
}

/// Inspect a packet payload for malicious JA3 TLS fingerprints.
pub fn inspect_tls_traffic(
    payload: &[u8],
    src_mac: &str,
    src_ip: IpAddr,
) -> Option<Anomaly> {
    let fp = parse_client_hello(payload)?;
    let signatures = get_malicious_ja3_signatures();

    if let Some(&threat_desc) = signatures.get(fp.hash.as_str()) {
        let detail = format!(
            "Malicious JA3 TLS Fingerprint detected from {} (IP: {}). Fingerprint MD5: {} (Identified: {}). Probable C2 Botnet Infection!",
            src_mac, src_ip, fp.hash, threat_desc
        );

        return Some(Anomaly {
            id: None,
            mac: src_mac.to_string(),
            detected_at: Utc::now(),
            kind: AnomalyKind::MaliciousTlsFingerprint,
            detail,
            resolved: false,
        });
    }

    // Zero-Day Heuristic TLS Inspection
    if let Some(anomaly_reason) = evaluate_tls_stack_heuristics(&fp.raw) {
        let detail = format!(
            "ZERO-DAY HEURISTIC: Anomalous TLS Client Hello from {} (IP: {}). Fingerprint MD5: {}. Reason: {}. Potential stealth C2 beaconing!",
            src_mac, src_ip, fp.hash, anomaly_reason
        );

        return Some(Anomaly {
            id: None,
            mac: src_mac.to_string(),
            detected_at: Utc::now(),
            kind: AnomalyKind::MaliciousTlsFingerprint,
            detail,
            resolved: false,
        });
    }

    None
}

/// Check if a 16-bit TLS value is a GREASE reserved value (RFC 8701).
fn is_grease(val: u16) -> bool {
    (val & 0x0F0F) == 0x0A0A && ((val >> 8) == (val & 0x00FF))
}

/// MD5 hash calculation strictly adhering to RFC 1321.
pub fn md5_hex(data: &[u8]) -> String {
    #[inline(always)]
    fn f(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | (!x & z)
    }
    #[inline(always)]
    fn g(x: u32, y: u32, z: u32) -> u32 {
        (x & z) | (y & !z)
    }
    #[inline(always)]
    fn h(x: u32, y: u32, z: u32) -> u32 {
        x ^ y ^ z
    }
    #[inline(always)]
    fn i_func(x: u32, y: u32, z: u32) -> u32 {
        y ^ (x | !z)
    }

    #[inline(always)]
    #[allow(clippy::too_many_arguments)]
    fn step<F>(a: &mut u32, b: u32, c: u32, d: u32, x: u32, s: u32, ac: u32, f: F)
    where
        F: Fn(u32, u32, u32) -> u32,
    {
        *a = a.wrapping_add(f(b, c, d)).wrapping_add(x).wrapping_add(ac);
        *a = a.rotate_left(s);
        *a = a.wrapping_add(b);
    }

    let mut state: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut padded = data.to_vec();
    padded.push(0x80);

    while (padded.len() % 64) != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_le_bytes());

    for chunk in padded.chunks_exact(64) {
        let mut x = [0u32; 16];
        for (idx, c) in chunk.chunks_exact(4).enumerate() {
            x[idx] = u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
        }

        let (mut a, mut b, mut c, mut d) = (state[0], state[1], state[2], state[3]);

        // Round 1
        step(&mut a, b, c, d, x[0], 7, 0xd76aa478, f);
        step(&mut d, a, b, c, x[1], 12, 0xe8c7b756, f);
        step(&mut c, d, a, b, x[2], 17, 0x242070db, f);
        step(&mut b, c, d, a, x[3], 22, 0xc1bdceee, f);
        step(&mut a, b, c, d, x[4], 7, 0xf57c0faf, f);
        step(&mut d, a, b, c, x[5], 12, 0x4787c62a, f);
        step(&mut c, d, a, b, x[6], 17, 0xa8304613, f);
        step(&mut b, c, d, a, x[7], 22, 0xfd469501, f);
        step(&mut a, b, c, d, x[8], 7, 0x698098d8, f);
        step(&mut d, a, b, c, x[9], 12, 0x8b44f7af, f);
        step(&mut c, d, a, b, x[10], 17, 0xffff5bb1, f);
        step(&mut b, c, d, a, x[11], 22, 0x895cd7be, f);
        step(&mut a, b, c, d, x[12], 7, 0x6b901122, f);
        step(&mut d, a, b, c, x[13], 12, 0xfd987193, f);
        step(&mut c, d, a, b, x[14], 17, 0xa679438e, f);
        step(&mut b, c, d, a, x[15], 22, 0x49b40821, f);

        // Round 2
        step(&mut a, b, c, d, x[1], 5, 0xf61e2562, g);
        step(&mut d, a, b, c, x[6], 9, 0xc040b340, g);
        step(&mut c, d, a, b, x[11], 14, 0x265e5a51, g);
        step(&mut b, c, d, a, x[0], 20, 0xe9b6c7aa, g);
        step(&mut a, b, c, d, x[5], 5, 0xd62f105d, g);
        step(&mut d, a, b, c, x[10], 9, 0x02441453, g);
        step(&mut c, d, a, b, x[15], 14, 0xd8a1e681, g);
        step(&mut b, c, d, a, x[4], 20, 0xe7d3fbc8, g);
        step(&mut a, b, c, d, x[9], 5, 0x21e1cde6, g);
        step(&mut d, a, b, c, x[14], 9, 0xc33707d6, g);
        step(&mut c, d, a, b, x[3], 14, 0xf4d50d87, g);
        step(&mut b, c, d, a, x[8], 20, 0x455a14ed, g);
        step(&mut a, b, c, d, x[13], 5, 0xa9e3e905, g);
        step(&mut d, a, b, c, x[2], 9, 0xfcefa3f8, g);
        step(&mut c, d, a, b, x[7], 14, 0x676f02d9, g);
        step(&mut b, c, d, a, x[12], 20, 0x8d2a4c8a, g);

        // Round 3
        step(&mut a, b, c, d, x[5], 4, 0xfffa3942, h);
        step(&mut d, a, b, c, x[8], 11, 0x8771f681, h);
        step(&mut c, d, a, b, x[11], 16, 0x6d9d6122, h);
        step(&mut b, c, d, a, x[14], 23, 0xfde5380c, h);
        step(&mut a, b, c, d, x[1], 4, 0xa4beea44, h);
        step(&mut d, a, b, c, x[4], 11, 0x4bdecfa9, h);
        step(&mut c, d, a, b, x[7], 16, 0xf6bb4b60, h);
        step(&mut b, c, d, a, x[10], 23, 0xbebfbc70, h);
        step(&mut a, b, c, d, x[13], 4, 0x289b7ec6, h);
        step(&mut d, a, b, c, x[0], 11, 0xeaa127fa, h);
        step(&mut c, d, a, b, x[3], 16, 0xd4ef3085, h);
        step(&mut b, c, d, a, x[6], 23, 0x04881d05, h);
        step(&mut a, b, c, d, x[9], 4, 0xd9d4d039, h);
        step(&mut d, a, b, c, x[12], 11, 0xe6db99e5, h);
        step(&mut c, d, a, b, x[15], 16, 0x1fa27cf8, h);
        step(&mut b, c, d, a, x[2], 23, 0xc4ac5665, h);

        // Round 4
        step(&mut a, b, c, d, x[0], 6, 0xf4292244, i_func);
        step(&mut d, a, b, c, x[7], 10, 0x432aff97, i_func);
        step(&mut c, d, a, b, x[14], 15, 0xab9423a7, i_func);
        step(&mut b, c, d, a, x[5], 21, 0xfc93a039, i_func);
        step(&mut a, b, c, d, x[12], 6, 0x655b59c3, i_func);
        step(&mut d, a, b, c, x[3], 10, 0x8f0ccc92, i_func);
        step(&mut c, d, a, b, x[10], 15, 0xffeff47d, i_func);
        step(&mut b, c, d, a, x[1], 21, 0x85845dd1, i_func);
        step(&mut a, b, c, d, x[8], 6, 0x6fa87e4f, i_func);
        step(&mut d, a, b, c, x[15], 10, 0xfe2ce6e0, i_func);
        step(&mut c, d, a, b, x[6], 15, 0xa3014314, i_func);
        step(&mut b, c, d, a, x[13], 21, 0x4e0811a1, i_func);
        step(&mut a, b, c, d, x[4], 6, 0xf7537e82, i_func);
        step(&mut d, a, b, c, x[11], 10, 0xbd3af235, i_func);
        step(&mut c, d, a, b, x[2], 15, 0x2ad7d2bb, i_func);
        step(&mut b, c, d, a, x[9], 21, 0xeb86d391, i_func);

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
    }

    let mut out = String::with_capacity(32);
    for word in state {
        for byte in word.to_le_bytes() {
            out.push_str(&format!("{:02x}", byte));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_md5_rfc_vectors() {
        assert_eq!(md5_hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(md5_hex(b"a"), "0cc175b9c0f1b6a831c399e269772661");
        assert_eq!(
            md5_hex(b"The quick brown fox jumps over the lazy dog"),
            "9e107d9d372bb6826bd81d3542a419d6"
        );
    }

    #[test]
    fn test_is_grease() {
        assert!(is_grease(0x0a0a));
        assert!(is_grease(0x1a1a));
        assert!(is_grease(0xfafa));
        assert!(!is_grease(0x002f));
        assert!(!is_grease(0x1301));
    }

    #[test]
    fn test_parse_client_hello_synthetic() {
        // Construct a synthetic minimal TLS 1.2 Client Hello
        let mut packet = Vec::new();
        // Record Header
        packet.push(0x16); // Handshake
        packet.extend_from_slice(&[0x03, 0x01]); // Version 3.1
        packet.extend_from_slice(&[0x00, 0x40]); // Length 64

        // Handshake Header
        packet.push(0x01); // Client Hello
        packet.extend_from_slice(&[0x00, 0x00, 0x3C]); // Handshake length

        // Client Version
        packet.extend_from_slice(&[0x03, 0x03]); // TLS 1.2 (771)

        // Random 32 bytes
        packet.extend_from_slice(&[0u8; 32]);

        // Session ID length 0
        packet.push(0x00);

        // Cipher suites: 2 suites (0x002F, 0x0035)
        packet.extend_from_slice(&[0x00, 0x04]); // 4 bytes
        packet.extend_from_slice(&[0x00, 0x2F, 0x00, 0x35]);

        // Compression methods: 1 method (0x00)
        packet.extend_from_slice(&[0x01, 0x00]);

        // Extensions: 0 bytes
        packet.extend_from_slice(&[0x00, 0x00]);

        let fp = parse_client_hello(&packet).expect("Failed to parse Client Hello");
        assert_eq!(fp.raw, "771,47-53,,,");
        assert_eq!(fp.hash, md5_hex(b"771,47-53,,,"));
    }
}
