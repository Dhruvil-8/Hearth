/// Passive OS Fingerprinting based on TCP SYN parameters (p0f technique).
///
/// Inspects IP TTL, TCP Window Size, and TCP Flags during the initial three-way handshake
/// to classify the host operating system without active probing or intrusive network packets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OsFamily {
    Windows,
    Linux,
    Apple,
    EmbeddedIot,
    NetworkDevice,
    Unknown,
}

impl std::fmt::Display for OsFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OsFamily::Windows => write!(f, "Windows OS"),
            OsFamily::Linux => write!(f, "Linux / Android"),
            OsFamily::Apple => write!(f, "Apple iOS / macOS"),
            OsFamily::EmbeddedIot => write!(f, "Embedded RTOS / IoT"),
            OsFamily::NetworkDevice => write!(f, "Network Appliance / Router"),
            OsFamily::Unknown => write!(f, "Generic IP Device"),
        }
    }
}

pub struct OsFingerprinter;

impl OsFingerprinter {
    /// Classify the operating system family from initial TCP SYN packet parameters.
    pub fn classify_syn(ip_ttl: u8, window_size: u16, is_syn_only: bool) -> Option<OsFamily> {
        if !is_syn_only {
            return None;
        }

        // 1. Windows devices: Default TTL is 128 (observed on LAN between 120 and 128)
        if (120..=128).contains(&ip_ttl) {
            return Some(OsFamily::Windows);
        }

        // 2. Network appliances / switches / Cisco: Default TTL is 255 (observed between 240 and 255)
        if (240..=255).contains(&ip_ttl) {
            return Some(OsFamily::NetworkDevice);
        }

        // 3. Linux / Unix / Apple / Embedded: Default TTL is 64 (observed on LAN between 50 and 64)
        if (50..=64).contains(&ip_ttl) {
            // Apple macOS / iOS strongly prefers a 65535 window size during SYN
            if window_size == 65535 {
                return Some(OsFamily::Apple);
            }

            // Embedded microcontrollers (ESP32, FreeRTOS, Arduino, lwIP) have small TCP windows <= 4096
            if window_size <= 4096 && window_size > 0 {
                return Some(OsFamily::EmbeddedIot);
            }

            // Standard Linux kernel defaults (29200, 14600, 64240, 5840)
            return Some(OsFamily::Linux);
        }

        Some(OsFamily::Unknown)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_windows_syn() {
        let os = OsFingerprinter::classify_syn(128, 64240, true);
        assert_eq!(os, Some(OsFamily::Windows));

        let os2 = OsFingerprinter::classify_syn(126, 8192, true);
        assert_eq!(os2, Some(OsFamily::Windows));
    }

    #[test]
    fn test_classify_apple_syn() {
        let os = OsFingerprinter::classify_syn(64, 65535, true);
        assert_eq!(os, Some(OsFamily::Apple));
    }

    #[test]
    fn test_classify_linux_syn() {
        let os = OsFingerprinter::classify_syn(64, 29200, true);
        assert_eq!(os, Some(OsFamily::Linux));
    }

    #[test]
    fn test_classify_embedded_iot_syn() {
        let os = OsFingerprinter::classify_syn(64, 2048, true);
        assert_eq!(os, Some(OsFamily::EmbeddedIot));
    }

    #[test]
    fn test_ignore_non_syn_packets() {
        let os = OsFingerprinter::classify_syn(64, 29200, false);
        assert_eq!(os, None);
    }
}

