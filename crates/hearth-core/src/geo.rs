use std::net::IpAddr;

/// GeoIP country lookup from a MaxMind MMDB database.
pub struct GeoIpDb {
    reader: Option<maxminddb::Reader<Vec<u8>>>,
}

impl GeoIpDb {
    /// Load GeoIP database from an MMDB file.
    /// Returns a no-op lookup if the file doesn't exist.
    pub fn load(path: &str) -> Self {
        match maxminddb::Reader::open_readfile(path) {
            Ok(reader) => {
                tracing::info!("Loaded GeoIP database from {}", path);
                Self {
                    reader: Some(reader),
                }
            }
            Err(e) => {
                tracing::warn!(
                    "Could not load GeoIP database from {}: {}. Country lookup disabled.",
                    path,
                    e
                );
                Self { reader: None }
            }
        }
    }

    /// Create an empty GeoIP database (no country lookups).
    pub fn empty() -> Self {
        Self { reader: None }
    }

    /// Look up the country code for an IP address.
    /// Returns ISO 3166-1 alpha-2 code (e.g. "US", "DE").
    pub fn lookup_country(&self, ip: &IpAddr) -> Option<String> {
        let reader = self.reader.as_ref()?;
        let result: Result<maxminddb::geoip2::Country, _> = reader.lookup(*ip);
        match result {
            Ok(data) => data.country.and_then(|c| c.iso_code).map(|s| s.to_string()),
            Err(_) => None,
        }
    }
}
