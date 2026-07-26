//! Geo-IP and ASN enrichment.
//!
//! The operator supplies a MaxMind GeoLite2 database; none is bundled, because
//! the licence does not permit redistribution and a stale copy is worse than
//! none. When no database is configured, enrichment yields `None` and the
//! dashboard buckets those sessions as unlocated rather than inventing
//! coordinates.

use std::net::IpAddr;
use std::path::Path;

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GeoInfo {
    pub country: Option<String>,
    pub country_code: Option<String>,
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub asn: Option<u32>,
    pub as_org: Option<String>,

    /// True when the coordinates were fabricated for local development.
    ///
    /// Carried through to the API and surfaced in the dashboard so nobody
    /// mistakes a demo run for real attribution.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub synthetic: bool,
}

/// The opened MaxMind databases. Either may be absent: an operator can supply
/// city data without ASN data or the reverse.
pub struct MaxMindReaders {
    pub city: Option<maxminddb::Reader<Vec<u8>>>,
    pub asn: Option<maxminddb::Reader<Vec<u8>>>,
}

/// Where location data comes from.
///
/// The MaxMind variant is boxed because it carries two memory-mapped database
/// readers. Inline, it made every GeoProvider value -- including Disabled, the
/// default -- as large as the readers, which is paid on every move of the enum.
pub enum GeoProvider {
    /// No enrichment. Sessions carry no location.
    Disabled,
    /// MaxMind GeoLite2 City and/or ASN databases.
    MaxMind(Box<MaxMindReaders>),
    /// Deterministic fake coordinates, for local development only.
    ///
    /// The end-to-end harness drives every session from 127.0.0.1, which would
    /// leave the attack map permanently empty and untestable. This provider
    /// derives stable coordinates from the address so the map can be exercised;
    /// every result is flagged `synthetic` so it can never be mistaken for
    /// real attribution.
    Synthetic,
}

impl GeoProvider {
    /// Opens the configured MaxMind databases.
    pub fn maxmind(city_path: Option<&Path>, asn_path: Option<&Path>) -> Self {
        let city = city_path.and_then(|p| match maxminddb::Reader::open_readfile(p) {
            Ok(r) => {
                info!(path = %p.display(), "loaded GeoLite2 City database");
                Some(r)
            }
            Err(e) => {
                warn!(path = %p.display(), error = %e, "could not open city database; locations will be empty");
                None
            }
        });

        let asn = asn_path.and_then(|p| match maxminddb::Reader::open_readfile(p) {
            Ok(r) => {
                info!(path = %p.display(), "loaded GeoLite2 ASN database");
                Some(r)
            }
            Err(e) => {
                warn!(path = %p.display(), error = %e, "could not open ASN database");
                None
            }
        });

        if city.is_none() && asn.is_none() {
            return GeoProvider::Disabled;
        }
        GeoProvider::MaxMind(Box::new(MaxMindReaders { city, asn }))
    }

    /// Resolves an address.
    pub fn lookup(&self, ip: &str) -> Option<GeoInfo> {
        let addr: IpAddr = ip.parse().ok()?;

        match self {
            GeoProvider::Disabled => None,

            GeoProvider::Synthetic => Some(synthetic_location(ip)),

            GeoProvider::MaxMind(readers) => {
                let (city, asn) = (&readers.city, &readers.asn);
                // Private and loopback addresses have no public location, and
                // returning one would be a lie the map would render.
                if is_private(&addr) {
                    return None;
                }

                let mut info = GeoInfo::default();

                if let Some(reader) = city {
                    if let Ok(rec) = reader.lookup::<maxminddb::geoip2::City>(addr) {
                        info.country_code = rec
                            .country
                            .as_ref()
                            .and_then(|c| c.iso_code)
                            .map(str::to_string);
                        info.country = rec
                            .country
                            .as_ref()
                            .and_then(|c| c.names.as_ref())
                            .and_then(|n| n.get("en"))
                            .map(|s| s.to_string());
                        info.city = rec
                            .city
                            .as_ref()
                            .and_then(|c| c.names.as_ref())
                            .and_then(|n| n.get("en"))
                            .map(|s| s.to_string());
                        if let Some(loc) = rec.location.as_ref() {
                            info.latitude = loc.latitude;
                            info.longitude = loc.longitude;
                        }
                    }
                }

                if let Some(reader) = asn {
                    if let Ok(rec) = reader.lookup::<maxminddb::geoip2::Asn>(addr) {
                        info.asn = rec.autonomous_system_number;
                        info.as_org = rec.autonomous_system_organization.map(str::to_string);
                    }
                }

                if info.country.is_none() && info.asn.is_none() {
                    None
                } else {
                    Some(info)
                }
            }
        }
    }

    pub fn describe(&self) -> &'static str {
        match self {
            GeoProvider::Disabled => "disabled",
            GeoProvider::MaxMind(_) => "maxmind",
            GeoProvider::Synthetic => "synthetic (development only)",
        }
    }
}

/// is_private reports addresses that have no meaningful public location.
fn is_private(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified()
        }
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
    }
}

/// synthetic_location derives stable pseudo-coordinates from an address.
///
/// Development affordance only. Cities are real so the map looks plausible,
/// but the mapping is a hash and means nothing.
fn synthetic_location(ip: &str) -> GeoInfo {
    const PLACES: &[(&str, &str, &str, f64, f64, u32, &str)] = &[
        (
            "China", "CN", "Shanghai", 31.2222, 121.4581, 4134, "CHINANET",
        ),
        (
            "Russia",
            "RU",
            "Moscow",
            55.7522,
            37.6156,
            12389,
            "Rostelecom",
        ),
        (
            "United States",
            "US",
            "Ashburn",
            39.0437,
            -77.4875,
            14618,
            "Amazon AWS",
        ),
        (
            "Netherlands",
            "NL",
            "Amsterdam",
            52.3740,
            4.8897,
            60781,
            "LeaseWeb",
        ),
        ("Vietnam", "VN", "Hanoi", 21.0245, 105.8412, 45899, "VNPT"),
        (
            "Brazil",
            "BR",
            "Sao Paulo",
            -23.5475,
            -46.6361,
            28573,
            "Claro",
        ),
        ("India", "IN", "Mumbai", 19.0728, 72.8826, 9829, "BSNL"),
        (
            "Germany",
            "DE",
            "Frankfurt",
            50.1155,
            8.6842,
            24940,
            "Hetzner",
        ),
        (
            "Indonesia",
            "ID",
            "Jakarta",
            -6.1750,
            106.8275,
            7713,
            "Telkom",
        ),
        ("Romania", "RO", "Bucharest", 44.4323, 26.1063, 9050, "RTD"),
        (
            "Singapore",
            "SG",
            "Singapore",
            1.2897,
            103.8501,
            16509,
            "Amazon AWS",
        ),
        ("France", "FR", "Roubaix", 50.6942, 3.1746, 16276, "OVH"),
    ];

    // FNV-1a over the address, so the same source always lands in the same
    // place across runs and the map is stable while developing.
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in ip.as_bytes() {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    let (country, code, city, lat, lon, asn, org) = PLACES[(hash % PLACES.len() as u64) as usize];

    // Jitter within roughly a degree so overlapping sources are distinguishable
    // on the map rather than stacking into one dot.
    let jitter_lat = ((hash >> 8) % 200) as f64 / 100.0 - 1.0;
    let jitter_lon = ((hash >> 16) % 200) as f64 / 100.0 - 1.0;

    GeoInfo {
        country: Some(country.to_string()),
        country_code: Some(code.to_string()),
        city: Some(city.to_string()),
        latitude: Some(lat + jitter_lat),
        longitude: Some(lon + jitter_lon),
        asn: Some(asn),
        as_org: Some(org.to_string()),
        synthetic: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_provider_returns_nothing() {
        assert!(GeoProvider::Disabled.lookup("8.8.8.8").is_none());
    }

    #[test]
    fn synthetic_is_stable_and_flagged() {
        let a = GeoProvider::Synthetic.lookup("203.0.113.5").unwrap();
        let b = GeoProvider::Synthetic.lookup("203.0.113.5").unwrap();
        assert_eq!(a.city, b.city);
        assert_eq!(a.latitude, b.latitude);
        assert!(a.synthetic, "synthetic results must be flagged as such");
    }

    #[test]
    fn synthetic_separates_distinct_sources() {
        let a = GeoProvider::Synthetic.lookup("203.0.113.5").unwrap();
        let b = GeoProvider::Synthetic.lookup("198.51.100.9").unwrap();
        assert!(a.latitude != b.latitude || a.longitude != b.longitude);
    }

    #[test]
    fn malformed_addresses_are_rejected() {
        assert!(GeoProvider::Synthetic.lookup("not-an-ip").is_none());
        assert!(GeoProvider::Synthetic.lookup("").is_none());
    }

    #[test]
    fn private_addresses_have_no_public_location() {
        for ip in ["127.0.0.1", "10.1.2.3", "192.168.0.5", "169.254.1.1"] {
            let addr: IpAddr = ip.parse().unwrap();
            assert!(is_private(&addr), "{ip} should be treated as private");
        }
        for ip in ["8.8.8.8", "203.0.113.5"] {
            let addr: IpAddr = ip.parse().unwrap();
            assert!(!is_private(&addr), "{ip} should be treated as public");
        }
    }
}
