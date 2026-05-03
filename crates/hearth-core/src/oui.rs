use std::collections::HashMap;

/// MAC vendor lookup from an offline IEEE OUI CSV database.
pub struct OuiDb {
    entries: HashMap<String, String>,
}

impl OuiDb {
    /// Load OUI database from a CSV file.
    /// Expected format: MAC prefix (e.g. "AABBCC"), vendor name
    /// Returns an empty DB if the file doesn't exist or can't be parsed.
    pub fn load(path: &str) -> Self {
        let entries = match Self::parse_csv(path) {
            Ok(e) => {
                tracing::info!("Loaded {} OUI entries from {}", e.len(), path);
                e
            }
            Err(e) => {
                tracing::warn!(
                    "Could not load OUI database from {}: {}. Vendor lookup disabled.",
                    path,
                    e
                );
                HashMap::new()
            }
        };
        Self { entries }
    }

    /// Create an empty OUI database (no vendor lookups).
    pub fn empty() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Look up the vendor for a MAC address.
    /// MAC should be in "AA:BB:CC:DD:EE:FF" format.
    pub fn lookup(&self, mac: &str) -> Option<String> {
        if self.entries.is_empty() {
            return None;
        }
        // Extract first 3 octets as the OUI prefix
        let prefix: String = mac
            .chars()
            .filter(|c| *c != ':' && *c != '-')
            .take(6)
            .collect::<String>()
            .to_uppercase();
        self.entries.get(&prefix).cloned()
    }

    fn parse_csv(path: &str) -> anyhow::Result<HashMap<String, String>> {
        let mut entries = HashMap::new();
        let mut rdr = csv::ReaderBuilder::new()
            .has_headers(true)
            .flexible(true)
            .from_path(path)?;

        for result in rdr.records() {
            let record = match result {
                Ok(r) => r,
                Err(_) => continue,
            };
            // Try to get MAC prefix and vendor name from various CSV formats
            if record.len() >= 2 {
                let prefix = record[0].trim().replace([':', '-'], "").to_uppercase();
                let vendor = record[1].trim().to_string();
                if prefix.len() >= 6 && !vendor.is_empty() {
                    entries.insert(prefix[..6].to_string(), vendor);
                }
            }
        }
        Ok(entries)
    }
}
