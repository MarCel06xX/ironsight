//! Scan data model shared by the engine, enrichment, the Tauri commands and (later) export.

use std::net::IpAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::enrich::{oui, services};
use crate::mac::MacAddr;
use crate::ports::scanner::{HostPorts, PortTarget, Probe};
use crate::ports::spec::PortSet;
use crate::ports::{PortSelection, PortState};

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

/// An open TCP port (from the discovery check or a port scan).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceInfo {
    pub port: u16,
    pub name: &'static str,
    /// Filled for plain-HTTP ports that answered a `GET /`.
    pub http: Option<HttpInfo>,
    /// Cleaned greeting of the service (banner grabbing), see `ports::banner`.
    pub banner: Option<String>,
}

impl ServiceInfo {
    pub fn open(port: u16) -> Self {
        Self {
            port,
            name: services::service_name(port),
            http: None,
            banner: None,
        }
    }
}

/// A closed or filtered port, listed when a host has only a few of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListedPort {
    pub port: u16,
    pub state: PortState,
    /// Service usually found on this port (display only).
    pub name: &'static str,
}

/// Port scan of one host. Open ports are in [`HostResult::services`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PortScanInfo {
    pub selection: PortSelection,
    /// Every port of the selection has a result (`false` while running or after a stop).
    pub complete: bool,
    pub probed: u32,
    pub total: u32,
    pub open: u32,
    pub closed: u32,
    pub filtered: u32,
    /// Probes that failed locally (no statement about the port).
    pub errors: u32,
    /// Closed and filtered ports one by one, while there are only a few of a state.
    pub listed: Vec<ListedPort>,
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
    /// Port scan of this host, if one ran.
    pub port_scan: Option<PortScanInfo>,
    /// Answers of the discovery TCP check (`services::DISCOVERY_PORTS`), taken over by a port
    /// scan of this host. Internal, not sent to the frontend.
    #[serde(skip)]
    pub probed_ports: Vec<(u16, PortState)>,
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
            port_scan: None,
            probed_ports: Vec::new(),
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

    /// Port scan target: the discovery check's definite answers (open, closed) are taken
    /// over; ports that stayed silent are probed again.
    pub fn port_target(&self) -> PortTarget {
        let known = self
            .probed_ports
            .iter()
            .filter_map(|&(port, state)| match state {
                PortState::Open => Some((port, Probe::OPEN)),
                PortState::Closed => Some((port, Probe::Closed)),
                PortState::Filtered => None,
            })
            .collect();
        PortTarget { ip: self.ip, known }
    }

    /// Shows a port scan result: open ports join `services` with their banner/HTTP details,
    /// `port_scan` gets the counts. A port the scan has fully covered replaces what was known
    /// before (an open port from host discovery that is closed now disappears); while the scan
    /// runs, or if it was stopped, earlier knowledge stays.
    pub fn apply_ports(&mut self, selection: &PortSelection, set: &PortSet, report: &HostPorts) {
        let open: Vec<_> = report
            .ports
            .iter()
            .filter(|entry| entry.state == PortState::Open)
            .collect();
        // All open ports are listed unless there were too many.
        let authoritative = report.complete && open.len() == report.open as usize;
        let mut services: Vec<ServiceInfo> = std::mem::take(&mut self.services)
            .into_iter()
            .filter(|service| {
                !authoritative
                    || !set.contains(service.port)
                    || open.iter().any(|entry| entry.port == service.port)
            })
            .collect();
        for entry in open {
            match services.iter_mut().find(|s| s.port == entry.port) {
                Some(service) => {
                    // New details win; the discovery's banner/title stay if the scan has none.
                    if entry.banner.is_some() {
                        service.banner.clone_from(&entry.banner);
                    }
                    if entry.http.is_some() {
                        service.http.clone_from(&entry.http);
                    }
                }
                None => services.push(ServiceInfo {
                    port: entry.port,
                    name: services::service_name(entry.port),
                    http: entry.http.clone(),
                    banner: entry.banner.clone(),
                }),
            }
        }
        services.sort_unstable_by_key(|service| service.port);
        self.services = services;
        if self.online {
            self.sources.services = (!self.services.is_empty()).then_some(DataSource::Live);
        }
        self.port_scan = Some(PortScanInfo {
            selection: selection.clone(),
            complete: report.complete,
            probed: report.probed,
            total: report.total,
            open: report.open,
            closed: report.closed,
            filtered: report.filtered,
            errors: report.errors,
            listed: report
                .ports
                .iter()
                .filter(|entry| entry.state != PortState::Open)
                .map(|entry| ListedPort {
                    port: entry.port,
                    state: entry.state,
                    name: services::service_name(entry.port),
                })
                .collect(),
        });
        self.update_status();
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
    use crate::ports::scanner::PortEntry;

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
        assert!(json["services"][0]["banner"].is_null());
        assert!(json["rttMs"].is_null());
        assert!(json["portScan"].is_null());
        // Internal discovery answers are not sent.
        assert!(json.get("probedPorts").is_none());
    }

    fn entry(port: u16, state: PortState, banner: Option<&str>) -> PortEntry {
        PortEntry {
            port,
            state,
            service: crate::ports::names::service_name(port),
            banner: banner.map(str::to_owned),
            http: None,
        }
    }

    fn report(complete: bool, ports: Vec<PortEntry>) -> HostPorts {
        let count = |state| ports.iter().filter(|e| e.state == state).count() as u32;
        HostPorts {
            ip: host().ip,
            complete,
            probed: ports.len() as u32,
            total: 100,
            open: count(PortState::Open),
            closed: count(PortState::Closed),
            filtered: count(PortState::Filtered),
            errors: 0,
            ports,
        }
    }

    fn online_host_with_discovery_services() -> HostResult {
        let mut h = host();
        h.online = true;
        let mut ssh = ServiceInfo::open(22);
        ssh.banner = Some("SSH-2.0-OpenSSH_9.6".into());
        let mut web = ServiceInfo::open(80);
        web.http = Some(HttpInfo {
            status: Some(200),
            server: None,
            title: Some("Router".into()),
        });
        // 445 is outside the scanned set below.
        h.services = vec![ssh, web, ServiceInfo::open(445)];
        h.mark_live();
        h
    }

    #[test]
    fn port_scan_adds_open_ports_and_keeps_discovery_details() {
        let mut h = online_host_with_discovery_services();
        let set = PortSet::parse("1-100,8000").unwrap();
        let selection = PortSelection::Custom("1-100,8000".into());
        h.apply_ports(
            &selection,
            &set,
            &report(
                true,
                vec![
                    entry(21, PortState::Open, Some("220 FTP ready")),
                    entry(22, PortState::Open, None),
                    entry(23, PortState::Closed, None),
                    entry(80, PortState::Open, None),
                    entry(8000, PortState::Filtered, None),
                ],
            ),
        );
        let ports: Vec<u16> = h.services.iter().map(|s| s.port).collect();
        assert_eq!(ports, [21, 22, 80, 445]);
        assert_eq!(h.services[0].banner.as_deref(), Some("220 FTP ready"));
        assert_eq!(h.services[0].name, "ftp");
        // Details found during discovery stay when the scan has none.
        assert_eq!(h.services[1].banner.as_deref(), Some("SSH-2.0-OpenSSH_9.6"));
        assert!(h.services[2].http.is_some());
        let scan = h.port_scan.as_ref().unwrap();
        assert_eq!(scan.selection, selection);
        assert!(scan.complete);
        assert_eq!((scan.open, scan.closed, scan.filtered), (3, 1, 1));
        assert_eq!(
            scan.listed,
            [
                ListedPort {
                    port: 23,
                    state: PortState::Closed,
                    name: "telnet",
                },
                ListedPort {
                    port: 8000,
                    state: PortState::Filtered,
                    name: "http-alt",
                },
            ]
        );
        assert_eq!(h.sources.services, Some(DataSource::Live));
        assert_eq!(h.status, HostStatus::Online);
    }

    #[test]
    fn a_complete_scan_removes_ports_that_are_no_longer_open() {
        let set = PortSet::parse("1-100").unwrap();
        let selection = PortSelection::Custom("1-100".into());
        let scanned = report(true, vec![entry(22, PortState::Open, None)]);

        let mut h = online_host_with_discovery_services();
        h.apply_ports(&selection, &set, &scanned);
        // 80 was open during discovery but not now; 445 was not scanned.
        let ports: Vec<u16> = h.services.iter().map(|s| s.port).collect();
        assert_eq!(ports, [22, 445]);

        // While running (or stopped), nothing is removed yet.
        let mut h = online_host_with_discovery_services();
        h.apply_ports(
            &selection,
            &set,
            &report(false, vec![entry(22, PortState::Open, None)]),
        );
        assert_eq!(h.services.len(), 3);
        assert!(!h.port_scan.as_ref().unwrap().complete);

        // Neither if the list of open ports was cut (too many to list).
        let mut truncated = scanned.clone();
        truncated.open = 2000;
        let mut h = online_host_with_discovery_services();
        h.apply_ports(&selection, &set, &truncated);
        assert_eq!(h.services.len(), 3);
    }

    #[test]
    fn port_target_takes_over_definite_discovery_answers() {
        let mut h = host();
        h.probed_ports = vec![
            (21, PortState::Closed),
            (22, PortState::Open),
            (443, PortState::Filtered),
        ];
        let target = h.port_target();
        assert_eq!(target.ip, h.ip);
        assert_eq!(target.known, [(21, Probe::Closed), (22, Probe::OPEN)]);
    }
}
