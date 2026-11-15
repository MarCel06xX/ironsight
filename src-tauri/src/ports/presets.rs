//! Built-in port lists.
//!
//! Curated by hand for Ironsight, aimed at home, office and lab networks; no data was taken
//! from nmap-services or other port databases. Sources: the IANA port registry (which service
//! a port is assigned to) and the default ports documented by the products themselves
//! (Windows remote management and RPC, NAS/media/IoT devices, databases, web admin UIs).
//!
//! - **Common** (22 ports): what a quick look at a LAN should show - remote access, web,
//!   Windows file sharing, mail, printers, cameras, a database or two. Contains every port of
//!   the former fixed service probe (21, 22, 23, 80, 443, 445, 3389, 8080, 8443).
//! - **Top 100**: Common plus the services found most often on such networks, grouped below.
//! - **Top 1000**: Top 100, every port of the service-name table (`names.rs`, the curated
//!   extension list), then the remaining well-known ports (1-1023) from the lowest up until
//!   there are exactly 1000.
//! - **All**: 1-65535.

use serde::{Deserialize, Serialize};

use super::names;
use super::spec::PortSet;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PortPreset {
    #[default]
    Common,
    Top100,
    Top1000,
    All,
}

impl PortPreset {
    pub fn ports(self) -> PortSet {
        match self {
            Self::Common => PortSet::from_ports(COMMON),
            Self::Top100 => PortSet::from_ports(TOP_100),
            Self::Top1000 => top_1000(),
            Self::All => PortSet::all(),
        }
    }
}

const COMMON: [u16; 22] = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 554, 631, 993, 995, 3306, 3389, 5900,
    8080, 8443, 9100,
];

#[rustfmt::skip]
const TOP_100: [u16; 100] = [
    // Remote access and administration
    22, 23, 513, 514, 2222, 3283, 3389, 5800, 5900, 5901, 5938, 5985, 5986, 6000, 8291, 10000,
    // Web and web admin interfaces
    80, 81, 443, 3000, 5000, 5001, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9090, 9443,
    // Windows, file sharing and storage
    20, 21, 111, 135, 139, 445, 548, 593, 873, 990, 2049, 2869, 3260, 5357,
    // Directory and authentication
    88, 389, 464, 636, 3268,
    // Mail and messaging
    25, 110, 119, 143, 465, 587, 993, 995, 1883, 5222, 5672, 6667, 8883,
    // Name and network services, VPN, proxies
    53, 113, 179, 427, 1080, 1194, 1723, 2000, 3128, 5060, 5061, 7547,
    // Printers, media and home devices
    515, 554, 631, 1900, 5555, 8009, 9100, 32400, 62078,
    // Databases, virtualization, containers, development
    902, 1433, 1521, 2375, 2376, 3306, 3690, 5432, 6379, 6443, 8086, 9200, 9418, 11211, 27017,
];

/// Last port of the IANA "well-known" (system) range.
const LAST_WELL_KNOWN: u16 = 1023;
const TOP_1000_LEN: usize = 1000;

fn top_1000() -> PortSet {
    let curated = PortSet::from_ports(TOP_100.into_iter().chain(names::named_ports()));
    let missing = TOP_1000_LEN.saturating_sub(curated.len());
    let fill = (1..=LAST_WELL_KNOWN)
        .filter(|&port| !curated.contains(port))
        .take(missing);
    PortSet::from_ports(curated.iter().chain(fill))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_subset(small: &PortSet, big: &PortSet) -> bool {
        small.iter().all(|port| big.contains(port))
    }

    #[test]
    fn sizes() {
        assert_eq!(PortPreset::Common.ports().len(), 22);
        assert_eq!(PortPreset::Top100.ports().len(), 100);
        assert_eq!(PortPreset::Top1000.ports().len(), 1000);
        assert_eq!(PortPreset::All.ports().len(), 65_535);
    }

    #[test]
    fn presets_are_nested() {
        let [common, top100, top1000, all] = [
            PortPreset::Common,
            PortPreset::Top100,
            PortPreset::Top1000,
            PortPreset::All,
        ]
        .map(PortPreset::ports);
        assert!(is_subset(&common, &top100));
        assert!(is_subset(&top100, &top1000));
        assert!(is_subset(&top1000, &all));
    }

    #[test]
    fn top_1000_contains_every_named_port_and_fills_with_low_ports() {
        let top1000 = PortPreset::Top1000.ports();
        assert!(names::named_ports().all(|port| top1000.contains(port)));
        // The fill starts at the lowest well-known ports ...
        assert!((1..=100).all(|port| top1000.contains(port)));
        // ... and never goes beyond the well-known range.
        let curated = PortSet::from_ports(TOP_100.into_iter().chain(names::named_ports()));
        assert!(
            top1000
                .iter()
                .filter(|port| !curated.contains(*port))
                .all(|port| port <= LAST_WELL_KNOWN)
        );
        assert!(
            curated.len() < TOP_1000_LEN,
            "curated list outgrew Top 1000"
        );
    }

    #[test]
    fn every_listed_port_has_a_name() {
        for port in PortPreset::Top100.ports().iter() {
            assert!(names::service_name(port).is_some(), "{port}");
        }
    }

    #[test]
    fn old_service_probe_ports_are_common() {
        let common = PortPreset::Common.ports();
        for port in [21, 22, 23, 80, 443, 445, 3389, 8080, 8443] {
            assert!(common.contains(port), "{port}");
        }
    }

    #[test]
    fn serde_names() {
        let names: Vec<String> = [
            PortPreset::Common,
            PortPreset::Top100,
            PortPreset::Top1000,
            PortPreset::All,
        ]
        .iter()
        .map(|p| {
            serde_json::to_value(p)
                .unwrap()
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
        assert_eq!(names, ["common", "top100", "top1000", "all"]);
        assert_eq!(PortPreset::default(), PortPreset::Common);
    }
}
