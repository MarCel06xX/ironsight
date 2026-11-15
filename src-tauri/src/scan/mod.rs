//! Scan data model shared by the engine, enrichment, the Tauri commands and (later) export.

use std::net::IpAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::enrich::{oui, services};
use crate::mac::MacAddr;

pub mod engine;
pub mod range;

pub const DEFAULT_CONCURRENCY: u32 = 64;
pub const MAX_CONCURRENCY: u32 = 256;
pub const DEFAULT_TIMEOUT_MS: u32 = 1000;
pub const MIN_TIMEOUT_MS: u32 = 100;
pub const MAX_TIMEOUT_MS: u32 = 10_000;

#[derive(Debug, Clone, Copy)]
pub struct ScanConfig {
    /// Hosts probed at the same time.
    pub concurrency: usize,
    /// Per-host answer timeout.
    pub timeout: Duration,
    /// Reverse DNS also for addresses that did not answer.
    pub resolve_offline_names: bool,
}

/// When reverse DNS runs for addresses that did not answer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OfflineNames {
    /// Only for scans of up to [`OfflineNames::AUTO_LIMIT`] addresses.
    #[default]
    Auto,
    Always,
    Never,
}

impl OfflineNames {
    pub const AUTO_LIMIT: usize = 1024;

    pub fn enabled_for(self, targets: usize) -> bool {
        match self {
            Self::Auto => targets <= Self::AUTO_LIMIT,
            Self::Always => true,
            Self::Never => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("concurrency must be between 1 and 256")]
    Concurrency,
    #[error("timeout must be between 100 and 10000 ms")]
    Timeout,
}

impl ConfigError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Concurrency => "scan.invalid_concurrency",
            Self::Timeout => "scan.invalid_timeout",
        }
    }
}

impl ScanConfig {
    /// Validates user-supplied limits (see the `MIN_`/`MAX_` constants).
    pub fn new(concurrency: u32, timeout_ms: u32) -> Result<Self, ConfigError> {
        if !(1..=MAX_CONCURRENCY).contains(&concurrency) {
            return Err(ConfigError::Concurrency);
        }
        if !(MIN_TIMEOUT_MS..=MAX_TIMEOUT_MS).contains(&timeout_ms) {
            return Err(ConfigError::Timeout);
        }
        Ok(Self {
            concurrency: concurrency as usize,
            timeout: Duration::from_millis(u64::from(timeout_ms)),
            resolve_offline_names: false,
        })
    }
}

/// Which discovery methods got an answer from a host.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SeenBy {
    pub arp: bool,
    pub icmp: bool,
    pub tcp: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NameSource {
    Dns,
    Mdns,
    Netbios,
}

/// Every name found for a host, by source.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostNames {
    pub dns: Option<String>,
    pub mdns: Option<String>,
    pub netbios: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpInfo {
    pub status: Option<u16>,
    pub server: Option<String>,
    pub title: Option<String>,
}

/// An open TCP port from the probe list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceInfo {
    pub port: u16,
    pub name: &'static str,
    /// Filled for plain-HTTP ports that answered a `GET /`.
    pub http: Option<HttpInfo>,
}

impl ServiceInfo {
    pub fn open(port: u16) -> Self {
        Self {
            port,
            name: services::service_name(port),
            http: None,
        }
    }
}

/// What is known about an address right now.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HostStatus {
    /// Answered during this scan.
    Online,
    /// No answer, but data exists (DNS name, ARP cache entry or a known device).
    Offline,
    /// No answer and nothing known.
    #[default]
    Unused,
}

/// Where a displayed value came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DataSource {
    /// Answer of the device during this scan.
    Live,
    /// Reverse DNS of an address that did not answer.
    Dns,
    /// OS neighbor cache.
    ArpCache,
    /// A device seen earlier (this session or a saved list).
    Remembered,
    /// A loaded previous scan.
    Imported,
}

/// Source per field; `None` where the field is empty.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldSources {
    pub hostname: Option<DataSource>,
    pub mac: Option<DataSource>,
    pub vendor: Option<DataSource>,
    pub services: Option<DataSource>,
    pub workgroup: Option<DataSource>,
}

/// Everything known about one scanned address. Sent once when the host has been probed
/// and, for online hosts, a second time with `complete = true` after enrichment; the
/// frontend treats it as an upsert keyed by `ip`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostResult {
    pub ip: IpAddr,
    pub online: bool,
    /// `false` while name and service lookups are still running.
    pub complete: bool,
    pub seen_by: SeenBy,
    /// ICMP round-trip time; 0 means below one millisecond.
    pub rtt_ms: Option<u32>,
    pub mac: Option<MacAddr>,
    /// Locally administered MAC (randomized/private or virtual): has no vendor.
    pub mac_local: bool,
    pub vendor: Option<String>,
    /// Best available name, see [`HostResult::pick_hostname`].
    pub hostname: Option<String>,
    pub hostname_source: Option<NameSource>,
    pub names: HostNames,
    /// NetBIOS workgroup or domain.
    pub workgroup: Option<String>,
    pub services: Vec<ServiceInfo>,
    /// Unix time in milliseconds when the probe finished.
    pub timestamp_ms: u64,
    pub status: HostStatus,
    /// When the device was last seen online: now for online hosts, from the known-devices
    /// list for remembered ones, unknown otherwise.
    pub last_seen_ms: Option<u64>,
    pub sources: FieldSources,
}

impl HostResult {
    pub fn new(ip: IpAddr) -> Self {
        Self {
            ip,
            online: false,
            complete: false,
            seen_by: SeenBy::default(),
            rtt_ms: None,
            mac: None,
            mac_local: false,
            vendor: None,
            hostname: None,
            hostname_source: None,
            names: HostNames::default(),
            workgroup: None,
            services: Vec::new(),
            timestamp_ms: 0,
            status: HostStatus::Unused,
            last_seen_ms: None,
            sources: FieldSources::default(),
        }
    }

    /// Online if it answered; offline if any data exists; unused otherwise.
    pub fn decide_status(&self) -> HostStatus {
        if self.online {
            HostStatus::Online
        } else if self.hostname.is_some()
            || self.mac.is_some()
            || self.workgroup.is_some()
            || !self.services.is_empty()
        {
            HostStatus::Offline
        } else {
            HostStatus::Unused
        }
    }

    pub fn update_status(&mut self) {
        self.status = self.decide_status();
    }

    /// For an online host: every present field is live data, seen right now.
    pub fn mark_live(&mut self) {
        let live = |present: bool| present.then_some(DataSource::Live);
        self.sources = FieldSources {
            hostname: live(self.hostname.is_some()),
            mac: live(self.mac.is_some()),
            vendor: live(self.vendor.is_some()),
            services: live(!self.services.is_empty()),
            workgroup: live(self.workgroup.is_some()),
        };
        self.last_seen_ms = Some(self.timestamp_ms);
        self.update_status();
    }

    /// Sets the MAC address together with the vendor derived from it.
    pub fn set_mac(&mut self, mac: MacAddr) {
        self.mac = Some(mac);
        self.mac_local = oui::is_locally_administered(mac);
        self.vendor = match self.mac_local {
            true => None,
            false => oui::vendor(mac).map(str::to_owned),
        };
    }

    /// Chooses the display name: DNS first (usually fully qualified), then mDNS, then the
    /// upper-cased, length-limited NetBIOS name.
    pub fn pick_hostname(&mut self) {
        let candidates = [
            (&self.names.dns, NameSource::Dns),
            (&self.names.mdns, NameSource::Mdns),
            (&self.names.netbios, NameSource::Netbios),
        ];
        let best = candidates
            .into_iter()
            .find_map(|(name, source)| Some((name.clone()?, source)));
        (self.hostname, self.hostname_source) = best.unzip();
    }
}

/// Live update: new or updated host results plus the running totals.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanBatch {
    pub scan_id: u64,
    pub hosts: Vec<HostResult>,
    pub scanned: u32,
    pub total: u32,
    pub online: u32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanSummary {
    pub scan_id: u64,
    pub cancelled: bool,
    pub scanned: u32,
    pub total: u32,
    pub online: u32,
    /// Hosts where a probe failed with an OS error (not: host did not answer).
    pub errors: u32,
    pub started_at_ms: u64,
    pub finished_at_ms: u64,
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn host() -> HostResult {
        HostResult::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)))
    }

    #[test]
    fn status_decision() {
        let mut h = host();
        assert_eq!(h.decide_status(), HostStatus::Unused);

        // Any piece of data makes a silent address "offline".
        let mut named = host();
        named.hostname = Some("printer.lan".into());
        assert_eq!(named.decide_status(), HostStatus::Offline);
        let mut cached = host();
        cached.set_mac(MacAddr([0x00, 0x00, 0x0c, 1, 2, 3]));
        assert_eq!(cached.decide_status(), HostStatus::Offline);
        let mut remembered = host();
        remembered.services.push(ServiceInfo::open(80));
        assert_eq!(remembered.decide_status(), HostStatus::Offline);
        let mut grouped = host();
        grouped.workgroup = Some("WORKGROUP".into());
        assert_eq!(grouped.decide_status(), HostStatus::Offline);

        // An answer always wins.
        h.online = true;
        assert_eq!(h.decide_status(), HostStatus::Online);
    }

    #[test]
    fn live_hosts_mark_present_fields_as_live() {
        let mut h = host();
        h.online = true;
        h.timestamp_ms = 42;
        h.names.dns = Some("pc.lan".into());
        h.pick_hostname();
        h.mark_live();
        assert_eq!(h.status, HostStatus::Online);
        assert_eq!(h.last_seen_ms, Some(42));
        assert_eq!(h.sources.hostname, Some(DataSource::Live));
        assert_eq!(h.sources.mac, None);
        assert_eq!(h.sources.services, None);
    }

    #[test]
    fn offline_name_lookup_limit() {
        assert!(OfflineNames::Auto.enabled_for(1024));
        assert!(!OfflineNames::Auto.enabled_for(1025));
        assert!(OfflineNames::Always.enabled_for(65_536));
        assert!(!OfflineNames::Never.enabled_for(1));
    }

    #[test]
    fn hostname_priority() {
        let mut h = host();
        h.pick_hostname();
        assert_eq!((h.hostname.clone(), h.hostname_source), (None, None));

        h.names.netbios = Some("PC".into());
        h.pick_hostname();
        assert_eq!(h.hostname.as_deref(), Some("PC"));
        assert_eq!(h.hostname_source, Some(NameSource::Netbios));

        h.names.mdns = Some("pc.local".into());
        h.pick_hostname();
        assert_eq!(h.hostname_source, Some(NameSource::Mdns));

        h.names.dns = Some("pc.fritz.box".into());
        h.pick_hostname();
        assert_eq!(h.hostname.as_deref(), Some("pc.fritz.box"));
        assert_eq!(h.hostname_source, Some(NameSource::Dns));
    }

    #[test]
    fn mac_sets_vendor_or_local_flag() {
        let mut h = host();
        h.set_mac(MacAddr([0x00, 0x00, 0x0c, 1, 2, 3]));
        assert!(!h.mac_local);
        assert!(h.vendor.is_some());

        h.set_mac(MacAddr([0xda, 0xa1, 0x19, 1, 2, 3]));
        assert!(h.mac_local);
        assert_eq!(h.vendor, None);
    }

    #[test]
    fn serializes_camel_case_for_the_frontend() {
        let mut h = host();
        h.services.push(ServiceInfo::open(80));
        h.names.dns = Some("pc.lan".into());
        h.pick_hostname();
        let json = serde_json::to_value(&h).unwrap();
        assert_eq!(json["ip"], "192.168.1.10");
        assert_eq!(json["hostnameSource"], "dns");
        assert_eq!(json["seenBy"]["tcp"], false);
        assert_eq!(json["macLocal"], false);
        assert_eq!(json["services"][0]["name"], "http");
        assert!(json["services"][0]["http"].is_null());
        assert!(json["rttMs"].is_null());
    }
}
