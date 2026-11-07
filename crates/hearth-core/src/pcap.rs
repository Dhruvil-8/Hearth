use crate::types::ForensicCapture;
use anyhow::{Context, Result};
use chrono::Utc;
use std::collections::VecDeque;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;
use std::time::SystemTime;

/// A raw Ethernet frame captured from the network wire with timestamp.
#[derive(Clone, Debug)]
pub struct RawCapturedPacket {
    pub timestamp: SystemTime,
    pub src_mac: String,
    pub dst_mac: String,
    pub raw_bytes: Vec<u8>,
}

/// Circular in-memory packet ring buffer for zero-day incident digital forensics.
///
/// Keeps the most recent N packets in memory without writing to disk.
/// When an anomaly trips (Canary trip, CTI match, Rogue DHCP, etc.),
/// the buffer automatically flushes the relevant device's packets into a standard Wireshark-compatible `.pcap` file.
pub struct PcapRingBuffer {
    buffer: Mutex<VecDeque<RawCapturedPacket>>,
    capacity: usize,
}

impl Default for PcapRingBuffer {
    fn default() -> Self {
        Self::new(2048)
    }
}

impl PcapRingBuffer {
    /// Create a new circular packet buffer with bounded capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            buffer: Mutex::new(VecDeque::with_capacity(capacity)),
            capacity,
        }
    }

    /// Record a packet into the circular ring buffer.
    pub fn push(&self, packet: RawCapturedPacket) {
        if let Ok(mut buf) = self.buffer.lock() {
            if buf.len() >= self.capacity {
                buf.pop_front();
            }
            buf.push_back(packet);
        }
    }

    /// Dump packets associated with `target_mac` to a standard libpcap file.
    pub fn dump_incident_pcap(
        &self,
        target_mac: &str,
        output_dir: &str,
        trigger_anomaly: &str,
        incident_id: Option<i64>,
    ) -> Result<Option<ForensicCapture>> {
        let normalized_mac = target_mac.to_uppercase();
        let packets: Vec<RawCapturedPacket> = {
            let buf = self.buffer.lock().unwrap();
            let matched: Vec<_> = buf
                .iter()
                .filter(|p| p.src_mac == normalized_mac || p.dst_mac == normalized_mac)
                .cloned()
                .collect();

            if !matched.is_empty() {
                matched
            } else {
                // If no direct MAC match (e.g. synthetic or gateway anomaly), dump the most recent 100 packets as surrounding network context
                buf.iter().rev().take(100).cloned().collect()
            }
        };

        if packets.is_empty() {
            return Ok(None);
        }

        let dir_path = Path::new(output_dir);
        std::fs::create_dir_all(dir_path)
            .with_context(|| format!("Failed to create PCAP forensics directory: {}", output_dir))?;

        let now = Utc::now();
        let safe_mac = normalized_mac.replace(':', "-");
        let filename = format!(
            "incident_{}_{}_{}.pcap",
            now.format("%Y%m%d_%H%M%S"),
            safe_mac,
            trigger_anomaly.replace(' ', "_")
        );
        let file_path = dir_path.join(&filename);

        let file = File::create(&file_path)
            .with_context(|| format!("Failed to create PCAP file at {:?}", file_path))?;
        let mut writer = std::io::BufWriter::new(file);

        write_pcap(&packets, &mut writer)?;

        let metadata = std::fs::metadata(&file_path)?;
        let file_size_bytes = metadata.len();

        Ok(Some(ForensicCapture {
            id: None,
            incident_id,
            mac: normalized_mac,
            created_at: now,
            pcap_path: file_path.to_string_lossy().to_string(),
            filename,
            packet_count: packets.len(),
            file_size_bytes,
            trigger_anomaly: trigger_anomaly.to_string(),
        }))
    }
}

/// Write raw packets to a writer in standard libpcap binary format (Wireshark compliant).
pub fn write_pcap<W: Write>(packets: &[RawCapturedPacket], mut writer: W) -> Result<()> {
    // 1. Write Global PCAP Header (24 bytes)
    // magic_number = 0xa1b2c3d4 (little-endian microsecond pcap)
    writer.write_all(&0xa1b2c3d4u32.to_le_bytes())?;
    // version_major = 2, version_minor = 4
    writer.write_all(&2u16.to_le_bytes())?;
    writer.write_all(&4u16.to_le_bytes())?;
    // thiszone = 0 (GMT)
    writer.write_all(&0i32.to_le_bytes())?;
    // sigfigs = 0
    writer.write_all(&0u32.to_le_bytes())?;
    // snaplen = 65535 (max length)
    writer.write_all(&65535u32.to_le_bytes())?;
    // network = 1 (LINKTYPE_ETHERNET)
    writer.write_all(&1u32.to_le_bytes())?;

    // 2. Write each Packet Record Header (16 bytes) + raw payload
    for pkt in packets {
        let duration = pkt
            .timestamp
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default();
        let ts_sec = duration.as_secs() as u32;
        let ts_usec = duration.subsec_micros();
        let cap_len = (pkt.raw_bytes.len().min(65535)) as u32;
        let orig_len = pkt.raw_bytes.len() as u32;

        writer.write_all(&ts_sec.to_le_bytes())?;
        writer.write_all(&ts_usec.to_le_bytes())?;
        writer.write_all(&cap_len.to_le_bytes())?;
        writer.write_all(&orig_len.to_le_bytes())?;
        writer.write_all(&pkt.raw_bytes[..cap_len as usize])?;
    }

    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_pcap_header_and_records() {
        let mut buffer = Vec::new();
        let pkt = RawCapturedPacket {
            timestamp: SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(100),
            src_mac: "AA:BB:CC:DD:EE:01".to_string(),
            dst_mac: "AA:BB:CC:DD:EE:02".to_string(),
            raw_bytes: vec![0x12, 0x34, 0x56, 0x78],
        };

        write_pcap(&[pkt], &mut buffer).expect("write pcap failed");

        // Global header is 24 bytes, record header is 16 bytes, packet is 4 bytes -> total 44 bytes
        assert_eq!(buffer.len(), 44);

        // Verify magic number 0xa1b2c3d4 in little-endian format: [0xd4, 0xc3, 0xb2, 0xa1]
        assert_eq!(&buffer[0..4], &[0xd4, 0xc3, 0xb2, 0xa1]);
        // Verify linktype = 1 (Ethernet) at offset 20: [0x01, 0x00, 0x00, 0x00]
        assert_eq!(&buffer[20..24], &[0x01, 0x00, 0x00, 0x00]);
        // Verify captured payload matches
        assert_eq!(&buffer[40..44], &[0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn test_ring_buffer_capacity_bounded() {
        let ring = PcapRingBuffer::new(3);
        for i in 0..5 {
            ring.push(RawCapturedPacket {
                timestamp: SystemTime::now(),
                src_mac: format!("00:00:00:00:00:0{}", i),
                dst_mac: "FF:FF:FF:FF:FF:FF".to_string(),
                raw_bytes: vec![i as u8],
            });
        }

        let buf = ring.buffer.lock().unwrap();
        assert_eq!(buf.len(), 3);
        // Oldest (0 and 1) dropped, remaining are 2, 3, 4
        assert_eq!(buf[0].raw_bytes, vec![2]);
        assert_eq!(buf[2].raw_bytes, vec![4]);
    }
}

