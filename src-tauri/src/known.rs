//! Known devices: what earlier scans saw, used to show data for addresses that do not answer.
//!
//! - *Remembered:* every device seen online in this app session (memory only). With the
//!   opt-in setting "Remember devices between sessions" it is also saved as JSON.
//! - *Imported:* devices from a loaded JSON export ("Load previous scan...").
//!
//! Devices are keyed by MAC address, falling back to the IP address when no MAC is known.
//! All loaded data (own file or import) is treated as untrusted and sanitized.

use std::collections::HashSet;
use std::fs;
use std::io::{self, Read};
use std::net::IpAddr;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::enrich::{clean_text, services};
use crate::export::time;
use crate::mac::MacAddr;
use crate::scan::{DataSource, HostNames, HostResult, HttpInfo, ServiceInfo};

/// Version of the known-devices file.
const FILE_VERSION: u32 = 1;
/// Export schema versions the importer understands.
/// JSON export schemas that can be loaded (see `export::json::SCHEMA_VERSION`).
const IMPORT_VERSIONS: [u32; 3] = [1, 2, 3];
const MAX_DEVICES: usize = 10_000;
const MAX_IPS_PER_DEVICE: usize = 8;
const MAX_SERVICES: usize = 64;
const MAX_FILE_BYTES: u64 = 32 * 1024 * 1024;
pub const MAX_IMPORT_BYTES: u64 = 128 * 1024 * 1024;
const MAX_IMPORT_HOSTS: usize = 70_000;
const MAX_NAME_CHARS: usize = 253;
const MAX_TEXT_CHARS: usize = 200;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnownService {
    pub port: u16,
    pub http: Option<HttpInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnownDevice {
    pub mac: Option<MacAddr>,
    /// Addresses the device used, most recent first.
    pub ips: Vec<IpAddr>,
    pub vendor: Option<String>,
    pub names: HostNames,
    pub workgroup: Option<String>,
    pub services: Vec<KnownService>,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
}

/// Addresses and MACs that answered in the current scan.
#[derive(Debug, Clone, Default)]
pub struct LiveSet {
    pub ips: HashSet<IpAddr>,
    pub macs: HashSet<MacAddr>,
}

impl LiveSet {
    pub fn add(&mut self, host: &HostResult) {
        if host.online {
            self.ips.insert(host.ip);
            self.macs.extend(host.mac);
        }
    }
}

#[derive(Debug, Default)]
pub struct KnownDevices {
    remembered: Vec<KnownDevice>,
    imported: Vec<KnownDevice>,
}

impl KnownDevices {
    pub fn remembered(&self) -> &[KnownDevice] {
        &self.remembered
    }

    pub fn set_remembered(&mut self, devices: Vec<KnownDevice>) {
        self.remembered = devices;
    }

    pub fn set_imported(&mut self, devices: Vec<KnownDevice>) {
        self.imported = devices;
    }

    pub fn clear(&mut self) {
        self.remembered.clear();
        self.imported.clear();
    }

    /// Remembers a host that answered. A newer owner of an address takes it over: the
    /// address is removed from every other device.
    pub fn remember(&mut self, host: &HostResult) {
        if !host.online {
            return;
        }
        let seen = host.last_seen_ms.unwrap_or(host.timestamp_ms);
        let ip = host.ip;
        let index = match host.mac {
            Some(mac) => self
                .remembered
                .iter()
                .position(|d| d.mac == Some(mac))
                // An entry known only by this IP gets the MAC now.
                .or_else(|| {
                    self.remembered
                        .iter()
                        .position(|d| d.mac.is_none() && d.ips.contains(&ip))
                }),
            None => self.remembered.iter().position(|d| d.ips.contains(&ip)),
        };
        let index = index.unwrap_or_else(|| {
            self.remembered.push(KnownDevice {
                mac: None,
                ips: Vec::new(),
                vendor: None,
                names: HostNames::default(),
                workgroup: None,
                services: Vec::new(),
                first_seen_ms: seen,
                last_seen_ms: seen,
            });
            self.remembered.len() - 1
        });

        // The address now belongs to this device only.
        for (i, other) in self.remembered.iter_mut().enumerate() {
            if i != index {
                other.ips.retain(|other_ip| *other_ip != ip);
            }
        }

        let device = &mut self.remembered[index];
        device.mac = host.mac.or(device.mac);
        device.ips.retain(|known| *known != ip);
        device.ips.insert(0, ip);
        device.ips.truncate(MAX_IPS_PER_DEVICE);
        if host.vendor.is_some() {
            device.vendor = host.vendor.clone();
        }
        for (target, value) in [
            (&mut device.names.dns, &host.names.dns),
            (&mut device.names.mdns, &host.names.mdns),
            (&mut device.names.netbios, &host.names.netbios),
        ] {
            if value.is_some() {
                *target = value.clone();
            }
        }
        if host.workgroup.is_some() {
            device.workgroup = host.workgroup.clone();
        }
        if host.complete || !host.services.is_empty() {
            device.services = host
                .services
                .iter()
                .map(|s| KnownService {
                    port: s.port,
                    http: s.http.clone(),
                })
                .collect();
        }
        device.first_seen_ms = device.first_seen_ms.min(seen);
        device.last_seen_ms = device.last_seen_ms.max(seen);

        // IP-only entries without an address left are useless; keep MAC entries (the
        // neighbor cache can still find them).
        self.remembered
            .retain(|d| d.mac.is_some() || !d.ips.is_empty());
        trim_oldest(&mut self.remembered);
    }

    /// The known device for a silent address. `cache_mac` is the MAC the OS neighbor cache
    /// has for it, if any. Devices that answered elsewhere in this scan have moved and are
    /// not shown here; when the cache names a MAC, only that device can match.
    pub fn find(
        &self,
        ip: IpAddr,
        cache_mac: Option<MacAddr>,
        live: &LiveSet,
    ) -> Option<(DataSource, &KnownDevice)> {
        if live.ips.contains(&ip) {
            return None;
        }
        let matches = |device: &KnownDevice| match cache_mac {
            Some(mac) => device.mac == Some(mac),
            None => device.ips.contains(&ip),
        };
        if cache_mac.is_some_and(|mac| live.macs.contains(&mac)) {
            return None;
        }
        let candidates = self
            .remembered
            .iter()
            .map(|d| (DataSource::Remembered, d))
            .chain(self.imported.iter().map(|d| (DataSource::Imported, d)));
        let mut best: Option<(DataSource, &KnownDevice)> = None;
        for (source, device) in candidates {
            let moved = device.mac.is_some_and(|mac| live.macs.contains(&mac));
            if !matches(device) || moved {
                continue;
            }
            // Strictly newer wins, so remembered beats imported on a tie.
            if best.is_none_or(|(_, b)| device.last_seen_ms > b.last_seen_ms) {
                best = Some((source, device));
            }
        }
        best
    }
}

/// Keeps the newest [`MAX_DEVICES`] devices.
fn trim_oldest(devices: &mut Vec<KnownDevice>) {
    if devices.len() > MAX_DEVICES {
        devices.sort_by_key(|d| std::cmp::Reverse(d.last_seen_ms));
        devices.truncate(MAX_DEVICES);
    }
}

/// The host as shown for a silent address: its own data (DNS name, ARP cache) plus what is
/// known about the device, each field marked with its source.
pub fn apply_known(base: &HostResult, known: Option<(DataSource, &KnownDevice)>) -> HostResult {
    let mut host = base.clone();
    if base.online {
        return host;
    }
    if let Some((source, device)) = known {
        if host.mac.is_none()
            && let Some(mac) = device.mac
        {
            host.set_mac(mac);
            host.sources.mac = Some(source);
            host.sources.vendor = host.vendor.as_ref().map(|_| source);
        }
        if host.vendor.is_none() && !host.mac_local && device.vendor.is_some() {
            host.vendor = device.vendor.clone();
            host.sources.vendor = Some(source);
        }
        let hostname_before = host.hostname.clone();
        for (target, value) in [
            (&mut host.names.dns, &device.names.dns),
            (&mut host.names.mdns, &device.names.mdns),
            (&mut host.names.netbios, &device.names.netbios),
        ] {
            if target.is_none() {
                *target = value.clone();
            }
        }
        host.pick_hostname();
        if host.hostname != hostname_before {
            host.sources.hostname = Some(source);
        }
        if host.workgroup.is_none() && device.workgroup.is_some() {
            host.workgroup = device.workgroup.clone();
            host.sources.workgroup = Some(source);
        }
        if host.services.is_empty() && !device.services.is_empty() {
            host.services = device
                .services
                .iter()
                .map(|s| ServiceInfo {
                    port: s.port,
                    name: services::service_name(s.port),
                    http: s.http.clone(),
                    banner: None,
                })
                .collect();
            host.sources.services = Some(source);
        }
        host.last_seen_ms = Some(device.last_seen_ms);
    }
    host.update_status();
    host
}

// --- persistence -----------------------------------------------------------------------

#[derive(Serialize)]
struct FileOut<'a> {
    schema_version: u32,
    devices: &'a [KnownDevice],
}

#[derive(Deserialize)]
struct FileIn {
    schema_version: u32,
    devices: Vec<Value>,
}

/// Reads the known-devices file; anything missing or malformed yields an empty list.
pub fn load(path: &Path) -> Vec<KnownDevice> {
    let Ok(text) = read_limited(path, MAX_FILE_BYTES) else {
        return Vec::new();
    };
    let Ok(file) = serde_json::from_str::<FileIn>(&text) else {
        return Vec::new();
    };
    if file.schema_version != FILE_VERSION {
        return Vec::new();
    }
    let mut devices: Vec<KnownDevice> = file
        .devices
        .into_iter()
        .filter_map(|value| serde_json::from_value::<KnownDevice>(value).ok())
        .filter_map(sanitize)
        .collect();
    trim_oldest(&mut devices);
    devices
}

pub fn save(path: &Path, devices: &[KnownDevice]) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let file = FileOut {
        schema_version: FILE_VERSION,
        devices,
    };
    let json = serde_json::to_vec(&file).map_err(io::Error::other)?;
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, json)?;
    fs::rename(&tmp, path)
}

/// Deletes the file; a missing file is fine.
pub fn delete(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

pub fn read_limited(path: &Path, max_bytes: u64) -> io::Result<String> {
    let mut text = String::new();
    fs::File::open(path)?
        .take(max_bytes + 1)
        .read_to_string(&mut text)?;
    if text.len() as u64 > max_bytes {
        return Err(io::Error::other("file is too large"));
    }
    Ok(text)
}

fn clean(value: Option<&str>, max_chars: usize) -> Option<String> {
    value.and_then(|v| clean_text(v, max_chars))
}

fn clean_http(http: Option<&HttpInfo>) -> Option<HttpInfo> {
    let http = http?;
    let cleaned = HttpInfo {
        status: http.status.filter(|s| (100..=599).contains(s)),
        server: clean(http.server.as_deref(), MAX_TEXT_CHARS),
        title: clean(http.title.as_deref(), MAX_TEXT_CHARS),
    };
    (cleaned != HttpInfo::default()).then_some(cleaned)
}

/// Bounds and cleans a device read from disk; `None` if nothing identifies it.
fn sanitize(device: KnownDevice) -> Option<KnownDevice> {
    let mut ips = Vec::new();
    for ip in device.ips {
        if !ips.contains(&ip) && ips.len() < MAX_IPS_PER_DEVICE {
            ips.push(ip);
        }
    }
    if device.mac.is_none() && ips.is_empty() {
        return None;
    }
    let mut ports = HashSet::new();
    let services = device
        .services
        .iter()
        .filter(|s| s.port != 0 && ports.insert(s.port))
        .take(MAX_SERVICES)
        .map(|s| KnownService {
            port: s.port,
            http: clean_http(s.http.as_ref()),
        })
        .collect();
    Some(KnownDevice {
        mac: device.mac,
        ips,
        vendor: clean(device.vendor.as_deref(), MAX_TEXT_CHARS),
        names: HostNames {
            dns: clean(device.names.dns.as_deref(), MAX_NAME_CHARS),
            mdns: clean(device.names.mdns.as_deref(), MAX_NAME_CHARS),
            netbios: clean(device.names.netbios.as_deref(), MAX_NAME_CHARS),
        },
        workgroup: clean(device.workgroup.as_deref(), MAX_TEXT_CHARS),
        services,
        first_seen_ms: device.first_seen_ms.min(device.last_seen_ms),
        last_seen_ms: device.last_seen_ms,
    })
}

// --- import of JSON exports --------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ImportError {
    #[error("not a JSON export of Ironsight")]
    NotAnExport,
    #[error("unsupported schema version {0}")]
    UnsupportedVersion(u64),
    #[error("the file contains no devices that were online")]
    NoDevices,
}

impl ImportError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotAnExport => "import.not_an_export",
            Self::UnsupportedVersion(_) => "import.unsupported_version",
            Self::NoDevices => "import.no_devices",
        }
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ImportNames {
    dns: Option<String>,
    mdns: Option<String>,
    netbios: Option<String>,
}

#[derive(Deserialize)]
struct ImportService {
    port: u16,
    #[serde(default)]
    http: Option<HttpInfo>,
}

/// One host of an export, schema 1, 2 or 3; unknown fields (e.g. the port scan of
/// schema 3) are ignored. Open ports of every schema are in `services`.
#[derive(Deserialize)]
struct ImportHost {
    ip: String,
    #[serde(default)]
    online: bool,
    /// Schema 2.
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    names: ImportNames,
    #[serde(default)]
    mac: Option<String>,
    #[serde(default)]
    vendor: Option<String>,
    #[serde(default)]
    workgroup: Option<String>,
    #[serde(default)]
    services: Vec<Value>,
    #[serde(default)]
    last_update: Option<String>,
    /// Schema 2.
    #[serde(default)]
    last_seen: Option<String>,
}

/// Reads the devices that were online in one of our JSON exports (schema 1 to 3).
pub fn import_export(json: &str, now_ms: u64) -> Result<Vec<KnownDevice>, ImportError> {
    let doc: Value = serde_json::from_str(json).map_err(|_| ImportError::NotAnExport)?;
    let version = doc
        .get("schema_version")
        .and_then(Value::as_u64)
        .ok_or(ImportError::NotAnExport)?;
    if !IMPORT_VERSIONS.iter().any(|v| u64::from(*v) == version) {
        return Err(ImportError::UnsupportedVersion(version));
    }
    let hosts = doc
        .get("hosts")
        .and_then(Value::as_array)
        .ok_or(ImportError::NotAnExport)?;
    let exported_at = doc
        .get("exported_at")
        .and_then(Value::as_str)
        .and_then(time::parse_rfc3339);

    let mut devices: Vec<KnownDevice> = Vec::new();
    for value in hosts.iter().take(MAX_IMPORT_HOSTS) {
        let Ok(host) = serde_json::from_value::<ImportHost>(value.clone()) else {
            continue;
        };
        let was_online = match host.status.as_deref() {
            Some(status) => status == "online",
            None => host.online,
        };
        let Ok(ip) = host.ip.trim().parse::<IpAddr>() else {
            continue;
        };
        if !was_online {
            continue;
        }
        let seen = host
            .last_seen
            .as_deref()
            .or(host.last_update.as_deref())
            .and_then(time::parse_rfc3339)
            .or(exported_at)
            .unwrap_or(now_ms)
            .min(now_ms);
        let mut ports = HashSet::new();
        let services = host
            .services
            .into_iter()
            .filter_map(|s| serde_json::from_value::<ImportService>(s).ok())
            .filter(|s| s.port != 0 && ports.insert(s.port))
            .take(MAX_SERVICES)
            .map(|s| KnownService {
                port: s.port,
                http: s.http,
            })
            .collect();
        let raw = KnownDevice {
            mac: host.mac.as_deref().and_then(|m| m.parse().ok()),
            ips: vec![ip],
            vendor: host.vendor,
            names: HostNames {
                dns: host.names.dns,
                mdns: host.names.mdns,
                netbios: host.names.netbios,
            },
            workgroup: host.workgroup,
            services,
            first_seen_ms: seen,
            last_seen_ms: seen,
        };
        let Some(device) = sanitize(raw) else {
            continue;
        };
        // The same MAC twice (several addresses): one device with all of them.
        match device
            .mac
            .and_then(|mac| devices.iter_mut().find(|d| d.mac == Some(mac)))
        {
            Some(existing) => {
                if !existing.ips.contains(&ip) && existing.ips.len() < MAX_IPS_PER_DEVICE {
                    existing.ips.push(ip);
                }
            }
            None => devices.push(device),
        }
    }
    if devices.is_empty() {
        return Err(ImportError::NoDevices);
    }
    trim_oldest(&mut devices);
    Ok(devices)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::scan::HostStatus;

    const MAC_A: MacAddr = MacAddr([0x00, 0x00, 0x0c, 0, 0, 0xa]);
    const MAC_B: MacAddr = MacAddr([0x00, 0x00, 0x0c, 0, 0, 0xb]);

    fn ip(d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, d))
    }

    fn online(d: u8, mac: Option<MacAddr>, name: &str, at: u64) -> HostResult {
        let mut host = HostResult::new(ip(d));
        host.online = true;
        host.complete = true;
        if let Some(mac) = mac {
            host.set_mac(mac);
        }
        host.names.dns = Some(name.into());
        host.pick_hostname();
        host.services = vec![ServiceInfo::open(80)];
        host.timestamp_ms = at;
        host.mark_live();
        host
    }

    fn silent(d: u8) -> HostResult {
        HostResult::new(ip(d))
    }

    fn name_of(found: Option<(DataSource, &KnownDevice)>) -> Option<String> {
        found.and_then(|(_, d)| d.names.dns.clone())
    }

    #[test]
    fn matching_by_mac_and_by_ip() {
        let mut known = KnownDevices::default();
        known.remember(&online(10, Some(MAC_A), "laptop", 100));
        known.remember(&online(20, None, "remote", 100));
        let live = LiveSet::default();

        // Silent address, no cache entry: matched by IP.
        assert_eq!(
            name_of(known.find(ip(10), None, &live)),
            Some("laptop".into())
        );
        assert_eq!(
            name_of(known.find(ip(20), None, &live)),
            Some("remote".into())
        );
        // The cache names the MAC: matched by MAC, even at another address.
        assert_eq!(
            name_of(known.find(ip(30), Some(MAC_A), &live)),
            Some("laptop".into())
        );
        // The cache names an unknown MAC: the old entry for this IP is not shown.
        assert_eq!(known.find(ip(10), Some(MAC_B), &live), None);
        // Unknown address.
        assert_eq!(known.find(ip(99), None, &live), None);
        let (source, _) = known.find(ip(10), None, &live).unwrap();
        assert_eq!(source, DataSource::Remembered);
    }

    #[test]
    fn reassigned_ip_belongs_to_the_newer_device() {
        let mut known = KnownDevices::default();
        known.remember(&online(10, Some(MAC_A), "old-owner", 100));
        // DHCP gave .10 to another device later.
        known.remember(&online(10, Some(MAC_B), "new-owner", 200));
        let live = LiveSet::default();
        assert_eq!(
            name_of(known.find(ip(10), None, &live)),
            Some("new-owner".into())
        );
        // The old device keeps its MAC entry without the address.
        let old = known
            .remembered()
            .iter()
            .find(|d| d.mac == Some(MAC_A))
            .unwrap();
        assert!(old.ips.is_empty());
        assert_eq!(
            name_of(known.find(ip(50), Some(MAC_A), &live)),
            Some("old-owner".into())
        );
    }

    #[test]
    fn live_device_wins_over_known_data() {
        let mut known = KnownDevices::default();
        known.remember(&online(10, Some(MAC_A), "laptop", 100));
        // This scan: .10 answers with another MAC, and the laptop answers at .11.
        let mut live = LiveSet::default();
        live.add(&online(10, Some(MAC_B), "phone", 300));
        assert_eq!(known.find(ip(10), None, &live), None, "the address is live");

        let mut moved = LiveSet::default();
        moved.add(&online(11, Some(MAC_A), "laptop", 300));
        // The laptop is online elsewhere, so its old address does not show it.
        assert_eq!(known.find(ip(10), None, &moved), None);
        assert_eq!(known.find(ip(10), Some(MAC_A), &moved), None);
    }

    #[test]
    fn newest_entry_wins_and_remembered_beats_imported_on_a_tie() {
        let mut known = KnownDevices::default();
        known.remember(&online(10, Some(MAC_A), "remembered", 100));
        let imported = |name: &str, at: u64| KnownDevice {
            mac: Some(MAC_B),
            ips: vec![ip(10)],
            vendor: None,
            names: HostNames {
                dns: Some(name.into()),
                ..HostNames::default()
            },
            workgroup: None,
            services: Vec::new(),
            first_seen_ms: at,
            last_seen_ms: at,
        };
        let live = LiveSet::default();
        known.set_imported(vec![imported("imported-old", 50)]);
        assert_eq!(
            name_of(known.find(ip(10), None, &live)),
            Some("remembered".into())
        );
        known.set_imported(vec![imported("imported-new", 500)]);
        let (source, device) = known.find(ip(10), None, &live).unwrap();
        assert_eq!(
            (source, device.names.dns.as_deref()),
            (DataSource::Imported, Some("imported-new"))
        );
        known.set_imported(vec![imported("tie", 100)]);
        assert_eq!(
            known.find(ip(10), None, &live).unwrap().0,
            DataSource::Remembered
        );
    }

    #[test]
    fn remembering_merges_and_upgrades_ip_only_entries() {
        let mut known = KnownDevices::default();
        known.remember(&online(10, None, "pc", 100));
        let mut later = online(10, Some(MAC_A), "pc", 200);
        later.names.netbios = Some("PC".into());
        known.remember(&later);
        assert_eq!(known.remembered().len(), 1);
        let device = &known.remembered()[0];
        assert_eq!(device.mac, Some(MAC_A));
        assert_eq!((device.first_seen_ms, device.last_seen_ms), (100, 200));
        assert_eq!(device.names.netbios.as_deref(), Some("PC"));
        // Silent hosts are never remembered.
        known.remember(&silent(11));
        assert_eq!(known.remembered().len(), 1);
    }

    #[test]
    fn apply_marks_every_field_with_its_source() {
        let mut known = KnownDevices::default();
        let mut seen = online(10, Some(MAC_A), "laptop.lan", 1000);
        seen.workgroup = Some("WORKGROUP".into());
        known.remember(&seen);

        let base = silent(10);
        let shown = apply_known(&base, known.find(ip(10), None, &LiveSet::default()));
        assert_eq!(shown.status, HostStatus::Offline);
        assert_eq!(shown.hostname.as_deref(), Some("laptop.lan"));
        assert_eq!(shown.mac, Some(MAC_A));
        assert_eq!(shown.last_seen_ms, Some(1000));
        assert_eq!(shown.services[0].name, "http");
        let s = shown.sources;
        assert_eq!(s.hostname, Some(DataSource::Remembered));
        assert_eq!(s.mac, Some(DataSource::Remembered));
        assert_eq!(s.services, Some(DataSource::Remembered));
        assert_eq!(s.workgroup, Some(DataSource::Remembered));

        // Own data of the silent address (DNS name, cache MAC) keeps its source.
        let mut own = silent(10);
        own.names.dns = Some("from-ptr.lan".into());
        own.pick_hostname();
        own.sources.hostname = Some(DataSource::Dns);
        own.set_mac(MAC_A);
        own.sources.mac = Some(DataSource::ArpCache);
        let shown = apply_known(&own, known.find(ip(10), Some(MAC_A), &LiveSet::default()));
        assert_eq!(shown.hostname.as_deref(), Some("from-ptr.lan"));
        assert_eq!(shown.sources.hostname, Some(DataSource::Dns));
        assert_eq!(shown.sources.mac, Some(DataSource::ArpCache));
        assert_eq!(shown.sources.services, Some(DataSource::Remembered));

        // Nothing known: unused stays unused.
        let nothing = apply_known(&silent(99), None);
        assert_eq!(nothing.status, HostStatus::Unused);
    }

    #[test]
    fn file_round_trip_and_garbage() {
        let dir = std::env::temp_dir().join(format!("ironsight-known-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("known-devices.json");
        let mut known = KnownDevices::default();
        known.remember(&online(10, Some(MAC_A), "laptop", 100));
        known.remember(&online(20, None, "remote", 200));
        save(&path, known.remembered()).unwrap();
        assert_eq!(load(&path), known.remembered());

        for garbage in ["", "{", "[]", r#"{"schema_version":99,"devices":[]}"#] {
            fs::write(&path, garbage).unwrap();
            assert!(load(&path).is_empty(), "{garbage:?}");
        }
        // Bad entries are skipped, hostile strings cleaned.
        fs::write(
            &path,
            r#"{"schema_version":1,"devices":[
                {"mac":"not-a-mac","ips":[]},
                {"mac":null,"ips":[],"vendor":null,"names":{},"workgroup":null,"services":[],"first_seen_ms":1,"last_seen_ms":1},
                {"mac":null,"ips":["192.168.1.7"],"vendor":null,"names":{"dns":"a\u202eb\u0000c","mdns":null,"netbios":null},
                 "workgroup":null,"services":[{"port":0,"http":null},{"port":80,"http":null},{"port":80,"http":null}],
                 "first_seen_ms":9,"last_seen_ms":5}
            ]}"#,
        )
        .unwrap();
        let loaded = load(&path);
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].names.dns.as_deref(), Some("ab c"));
        assert_eq!(loaded[0].services.len(), 1);
        assert_eq!((loaded[0].first_seen_ms, loaded[0].last_seen_ms), (5, 5));

        delete(&path).unwrap();
        delete(&path).unwrap(); // already gone: fine
        fs::remove_dir_all(dir).unwrap();
    }

    const V1: &str = r#"{
        "schema_version": 1,
        "exported_at": "2025-11-14T18:35:00Z",
        "hosts": [
            {"ip": "192.168.1.1", "online": true, "hostname": "fritz.box", "names": {"dns": "fritz.box", "mdns": null, "netbios": "FRITZ"},
             "mac": "00:00:0C:12:34:56", "vendor": "Cisco", "workgroup": null,
             "services": [{"port": 80, "name": "http", "http": {"status": 200, "server": "nginx", "title": "<b>Router</b>"}}],
             "last_update": "2025-11-14T18:30:00Z"},
            {"ip": "192.168.1.2", "online": false, "names": {}, "services": []},
            {"ip": "not-an-ip", "online": true},
            "garbage"
        ]
    }"#;

    #[test]
    fn import_schema_1() {
        let devices = import_export(V1, u64::MAX).unwrap();
        assert_eq!(devices.len(), 1);
        let d = &devices[0];
        assert_eq!(d.ips, [ip(1)]);
        assert_eq!(d.mac, Some(MacAddr([0x00, 0x00, 0x0c, 0x12, 0x34, 0x56])));
        assert_eq!(d.names.netbios.as_deref(), Some("FRITZ"));
        assert_eq!(d.last_seen_ms, 1_763_145_000_000);
        // Untrusted strings stay text; they are only ever shown with textContent.
        assert_eq!(
            d.services[0].http.as_ref().unwrap().title.as_deref(),
            Some("<b>Router</b>")
        );
    }

    #[test]
    fn import_schema_2() {
        let v2 = r#"{
            "schema_version": 2,
            "hosts": [
                {"ip": "192.168.1.5", "online": true, "status": "online", "mac": "00:00:0C:00:00:0A",
                 "names": {"dns": "a.lan"}, "services": [], "last_seen": "2025-11-14T19:30:00+01:00"},
                {"ip": "192.168.1.6", "online": true, "status": "online", "mac": "00:00:0C:00:00:0A",
                 "names": {"dns": "a.lan"}, "services": []},
                {"ip": "192.168.1.7", "online": false, "status": "offline", "names": {"dns": "remembered.lan"}}
            ]
        }"#;
        let devices = import_export(v2, 2_000_000_000_000).unwrap();
        // Only devices that answered; one MAC with two addresses is one device.
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].ips, [ip(5), ip(6)]);
        assert_eq!(devices[0].last_seen_ms, 1_763_145_000_000);
    }

    /// JSON exports written by the released versions with their own code (see the
    /// `write_fixture` tests), one per schema.
    const FIXTURES: [(&str, &str); 3] = [
        (
            "schema 1 (v0.1.3)",
            include_str!("../tests/fixtures/export-schema1-v0.1.3.json"),
        ),
        (
            "schema 2 (v0.2.0)",
            include_str!("../tests/fixtures/export-schema2-v0.2.0.json"),
        ),
        (
            "schema 3 (v0.4.0)",
            include_str!("../tests/fixtures/export-schema3-v0.4.0.json"),
        ),
    ];
    const NAS_MAC: MacAddr = MacAddr([0x00, 0x11, 0x32, 0xaa, 0xbb, 0xcc]);

    #[test]
    fn exports_of_every_schema_version_import() {
        for (name, json) in FIXTURES {
            let devices = import_export(json, u64::MAX).unwrap();
            // Router and NAS answered; the unused address is no device.
            assert_eq!(devices.len(), 2, "{name}");
            let router = devices.iter().find(|d| d.ips == [ip(1)]).unwrap();
            assert_eq!(
                router.mac,
                Some(MacAddr([0x00, 0x00, 0x0c, 0x12, 0x34, 0x56])),
                "{name}"
            );
            assert_eq!(router.names.dns.as_deref(), Some("fritz.box"), "{name}");
            let ports: Vec<u16> = router.services.iter().map(|s| s.port).collect();
            assert!(
                ports.contains(&80) && ports.contains(&443),
                "{name}: {ports:?}"
            );
            let http = router.services.iter().find(|s| s.port == 80).unwrap();
            assert_eq!(
                http.http.as_ref().unwrap().server.as_deref(),
                Some("nginx"),
                "{name}"
            );
            let nas = devices.iter().find(|d| d.ips == [ip(20)]).unwrap();
            assert_eq!(nas.mac, Some(NAS_MAC), "{name}");
            assert_eq!(nas.names.netbios.as_deref(), Some("NAS"), "{name}");
            assert_eq!(nas.workgroup.as_deref(), Some("WORKGROUP"), "{name}");
            let ports: Vec<u16> = nas.services.iter().map(|s| s.port).collect();
            assert_eq!(ports, [22, 445], "{name}");
            assert_eq!(nas.last_seen_ms, 1_763_145_001_000, "{name}");
        }
        // Schema 3 also has the port-scanned SSH port of the router.
        let devices = import_export(FIXTURES[2].1, u64::MAX).unwrap();
        let router = devices.iter().find(|d| d.ips == [ip(1)]).unwrap();
        assert!(router.services.iter().any(|s| s.port == 22));
    }

    #[test]
    fn older_exports_still_work_as_comparison_data() {
        for (name, json) in FIXTURES {
            let mut known = KnownDevices::default();
            known.set_imported(import_export(json, u64::MAX).unwrap());
            let live = LiveSet::default();

            // The NAS is silent now: the imported data fills its row.
            let mut silent = HostResult::new(ip(20));
            silent.complete = true;
            silent.update_status();
            let shown = apply_known(&silent, known.find(ip(20), None, &live));
            assert_eq!(shown.status, HostStatus::Offline, "{name}");
            assert_eq!(shown.hostname.as_deref(), Some("NAS"), "{name}");
            assert_eq!(shown.mac, Some(NAS_MAC), "{name}");
            assert_eq!(shown.sources.hostname, Some(DataSource::Imported), "{name}");
            assert_eq!(shown.sources.services, Some(DataSource::Imported), "{name}");
            assert_eq!(shown.services.len(), 2, "{name}");

            // Found again under a new address via its MAC from the ARP cache.
            assert!(known.find(ip(77), Some(NAS_MAC), &live).is_some(), "{name}");
            // An address that answers right now is never overlaid.
            let mut answering = LiveSet::default();
            answering.ips.insert(ip(20));
            assert!(known.find(ip(20), None, &answering).is_none(), "{name}");
        }
    }

    #[test]
    fn current_exports_import_too() {
        use crate::export::tests::{fixture_hosts, sample_info, sample_options};
        use crate::export::{Delimiter, ExportKind, write_export};
        let mut out = Vec::new();
        let options = sample_options(ExportKind::Json, Delimiter::Semicolon);
        write_export(&mut out, &sample_info(), &fixture_hosts(), &options).unwrap();
        let json = String::from_utf8(out).unwrap();
        let devices = import_export(&json, u64::MAX).unwrap();
        assert_eq!(devices.len(), 2);
        // The checked-in fixture of this schema matches what the writer produces now,
        // apart from the generator version.
        let fixture: Value = serde_json::from_str(FIXTURES[2].1).unwrap();
        let mut current: Value = serde_json::from_str(&json).unwrap();
        current["generator"]["version"] = fixture["generator"]["version"].clone();
        assert_eq!(current, fixture);
    }

    #[test]
    fn import_rejects_other_files() {
        assert_eq!(import_export("", 0), Err(ImportError::NotAnExport));
        assert_eq!(import_export("[1,2]", 0), Err(ImportError::NotAnExport));
        assert_eq!(
            import_export(r#"{"hosts":[]}"#, 0),
            Err(ImportError::NotAnExport)
        );
        assert_eq!(
            import_export(r#"{"schema_version":4,"hosts":[]}"#, 0),
            Err(ImportError::UnsupportedVersion(4))
        );
        assert_eq!(
            import_export(
                r#"{"schema_version":2,"hosts":[{"ip":"10.0.0.1","status":"unused"}]}"#,
                0
            ),
            Err(ImportError::NoDevices)
        );
    }
}
