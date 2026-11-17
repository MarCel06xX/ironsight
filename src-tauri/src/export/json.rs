//! JSON export: everything we know, in a stable snake_case schema that is independent of the
//! IPC format. Bump `SCHEMA_VERSION` on incompatible changes.

use std::io::{self, Write};
use std::net::IpAddr;

use serde::Serialize;

use super::{ExportOptions, PortStepInfo, ScanInfo, Scope, time};
use crate::mac::MacAddr;
use crate::ports::PortSelection;
use crate::scan::{
    FieldSources, HostNames, HostResult, HostStatus, ListedPort, NameSource, PortScanInfo, SeenBy,
    ServiceInfo,
};

/// 2: hosts have `status`, `last_seen` and `sources`.
/// 3: `scan.port_scan`, hosts have `port_scan`, services have `banner`.
pub const SCHEMA_VERSION: u32 = 3;

#[derive(Serialize)]
struct Document<'a> {
    schema_version: u32,
    generator: Generator,
    exported_at: String,
    /// `all` = every scanned address, `view` = the filtered view from the app.
    scope: &'static str,
    scan: Scan<'a>,
    hosts: Vec<Host<'a>>,
}

#[derive(Serialize)]
struct Generator {
    name: &'static str,
    version: &'static str,
}

#[derive(Serialize)]
struct Scan<'a> {
    targets: &'a str,
    started_at: String,
    finished_at: Option<String>,
    cancelled: bool,
    total: u32,
    scanned: u32,
    online: u32,
    errors: u32,
    concurrency: u32,
    timeout_ms: u32,
    /// Port scan after host discovery; `null` if none was requested.
    port_scan: Option<PortStep<'a>>,
}

#[derive(Serialize)]
struct PortStep<'a> {
    /// `{"preset": "top100"}` or `{"custom": "22,80,1000-2000"}`
    selection: &'a PortSelection,
    timeout_ms: u32,
    concurrency: u32,
    max_probes: u64,
    banners: bool,
    /// `null` if the step did not run (scan stopped before, or refused).
    checks_done: Option<u64>,
    checks_total: Option<u64>,
    cancelled: bool,
    /// Error code if the step was refused, e.g. `ports.too_many_probes`.
    error: Option<&'a str>,
}

impl<'a> PortStep<'a> {
    fn new(step: &'a PortStepInfo) -> Self {
        Self {
            selection: &step.selection,
            timeout_ms: step.timeout_ms,
            concurrency: step.concurrency,
            max_probes: step.max_probes,
            banners: step.banners,
            checks_done: step.checks.map(|(done, _)| done),
            checks_total: step.checks.map(|(_, total)| total),
            cancelled: step.cancelled,
            error: step.error,
        }
    }
}

/// Port scan of one host. Its open ports are the host's `services`.
#[derive(Serialize)]
struct HostPortScan<'a> {
    selection: &'a PortSelection,
    /// Every port of the selection was checked.
    complete: bool,
    probed: u32,
    total: u32,
    open: u32,
    closed: u32,
    filtered: u32,
    /// Checks that failed on the scanning computer (no statement about the port).
    errors: u32,
    /// Closed and filtered ports one by one, only while there are few of a state.
    listed: &'a [ListedPort],
}

impl<'a> HostPortScan<'a> {
    fn new(scan: &'a PortScanInfo) -> Self {
        Self {
            selection: &scan.selection,
            complete: scan.complete,
            probed: scan.probed,
            total: scan.total,
            open: scan.open,
            closed: scan.closed,
            filtered: scan.filtered,
            errors: scan.errors,
            listed: &scan.listed,
        }
    }
}

#[derive(Serialize)]
struct Host<'a> {
    ip: IpAddr,
    online: bool,
    status: HostStatus,
    /// When the device was last seen online (UTC); `null` if unknown.
    last_seen: Option<String>,
    /// Where each field came from: live, dns, arpCache, remembered, imported.
    sources: FieldSources,
    hostname: Option<&'a str>,
    hostname_source: Option<NameSource>,
    names: &'a HostNames,
    mac: Option<MacAddr>,
    mac_locally_administered: bool,
    vendor: Option<&'a str>,
    rtt_ms: Option<u32>,
    workgroup: Option<&'a str>,
    seen_by: SeenBy,
    /// Open ports with name, HTTP details and banner.
    services: &'a [ServiceInfo],
    port_scan: Option<HostPortScan<'a>>,
    last_update: String,
}

pub fn write_json(
    out: &mut impl Write,
    info: &ScanInfo,
    hosts: &[HostResult],
    options: &ExportOptions,
) -> io::Result<()> {
    let document = Document {
        schema_version: SCHEMA_VERSION,
        generator: Generator {
            name: "Ironsight",
            version: env!("CARGO_PKG_VERSION"),
        },
        exported_at: time::rfc3339(options.exported_at_ms, 0),
        scope: match options.scope {
            Scope::All => "all",
            Scope::View => "view",
        },
        scan: Scan {
            targets: &info.targets,
            started_at: time::rfc3339(info.started_at_ms, 0),
            finished_at: info.finished_at_ms.map(|ms| time::rfc3339(ms, 0)),
            cancelled: info.cancelled,
            total: info.total,
            scanned: info.scanned,
            online: info.online,
            errors: info.errors,
            concurrency: info.concurrency,
            timeout_ms: info.timeout_ms,
            port_scan: info.port_scan.as_ref().map(PortStep::new),
        },
        hosts: hosts
            .iter()
            .map(|host| Host {
                ip: host.ip,
                online: host.online,
                status: host.status,
                last_seen: host.last_seen_ms.map(|ms| time::rfc3339(ms, 0)),
                sources: host.sources,
                hostname: host.hostname.as_deref(),
                hostname_source: host.hostname_source,
                names: &host.names,
                mac: host.mac,
                mac_locally_administered: host.mac_local,
                vendor: host.vendor.as_deref(),
                rtt_ms: host.rtt_ms,
                workgroup: host.workgroup.as_deref(),
                seen_by: host.seen_by,
                services: &host.services,
                port_scan: host.port_scan.as_ref().map(HostPortScan::new),
                last_update: time::rfc3339(host.timestamp_ms, 0),
            })
            .collect(),
    };
    serde_json::to_writer_pretty(&mut *out, &document).map_err(io::Error::other)?;
    out.write_all(b"\n")
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;
    use crate::export::tests::{sample_hosts, sample_info, sample_options, utf8};
    use crate::export::{Delimiter, ExportKind};

    #[test]
    fn document_contains_metadata_and_all_host_data() {
        let mut out = Vec::new();
        let options = sample_options(ExportKind::Json, Delimiter::Semicolon);
        write_json(&mut out, &sample_info(), &sample_hosts(), &options).unwrap();
        let doc: Value = serde_json::from_str(&utf8(&out)).unwrap();

        assert_eq!(doc["schema_version"], 3);
        assert_eq!(doc["generator"]["name"], "Ironsight");
        assert_eq!(doc["generator"]["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(doc["scope"], "all");
        assert_eq!(doc["exported_at"], "2025-11-14T18:35:00Z");
        assert_eq!(
            doc["scan"],
            json!({
                "targets": "192.168.1.0/24",
                "started_at": "2025-11-14T18:30:00Z",
                "finished_at": "2025-11-14T18:30:12Z",
                "cancelled": false,
                "total": 254,
                "scanned": 254,
                "online": 1,
                "errors": 0,
                "concurrency": 64,
                "timeout_ms": 1000,
                "port_scan": {
                    "selection": {"preset": "top100"},
                    "timeout_ms": 800,
                    "concurrency": 256,
                    "max_probes": 1_000_000,
                    "banners": true,
                    "checks_done": 97,
                    "checks_total": 97,
                    "cancelled": false,
                    "error": null
                }
            })
        );

        let router = &doc["hosts"][0];
        assert_eq!(router["ip"], "192.168.1.1");
        assert_eq!(router["hostname"], "fritz.box");
        assert_eq!(router["hostname_source"], "dns");
        assert_eq!(
            router["names"],
            json!({"dns": "fritz.box", "mdns": null, "netbios": "FRITZ"})
        );
        assert_eq!(router["mac"], "00:00:0C:12:34:56");
        assert_eq!(router["mac_locally_administered"], false);
        assert_eq!(router["rtt_ms"], 2);
        assert_eq!(
            router["seen_by"],
            json!({"arp": true, "icmp": true, "tcp": true})
        );
        assert_eq!(router["services"][0]["port"], 22);
        assert_eq!(router["services"][0]["name"], "ssh");
        assert!(
            router["services"][0]["banner"]
                .as_str()
                .unwrap()
                .starts_with("SSH-2.0-x")
        );
        assert_eq!(router["services"][1]["port"], 80);
        assert_eq!(router["services"][1]["http"]["server"], "nginx");
        assert_eq!(router["services"][1]["banner"], Value::Null);
        assert_eq!(router["services"][2]["http"], Value::Null);
        assert_eq!(
            router["port_scan"],
            json!({
                "selection": {"preset": "top100"},
                "complete": true,
                "probed": 100,
                "total": 100,
                "open": 3,
                "closed": 95,
                "filtered": 2,
                "errors": 0,
                "listed": [
                    {"port": 8000, "state": "filtered", "name": "http-alt"},
                    {"port": 8443, "state": "filtered", "name": "https-alt"}
                ]
            })
        );
        assert_eq!(router["last_update"], "2025-11-14T18:30:00Z");

        assert_eq!(router["status"], "online");
        assert_eq!(router["last_seen"], "2025-11-14T18:30:00Z");
        assert_eq!(router["sources"]["hostname"], "live");
        assert_eq!(router["sources"]["workgroup"], Value::Null);

        let offline = &doc["hosts"][1];
        assert_eq!(offline["online"], false);
        assert_eq!(offline["status"], "unused");
        assert_eq!(offline["last_seen"], Value::Null);
        assert_eq!(offline["hostname"], Value::Null);
        assert_eq!(offline["services"], json!([]));
        assert_eq!(offline["port_scan"], Value::Null);
    }

    #[test]
    fn untrusted_strings_are_valid_json() {
        let mut out = Vec::new();
        let options = sample_options(ExportKind::Json, Delimiter::Semicolon);
        write_json(&mut out, &sample_info(), &sample_hosts(), &options).unwrap();
        let doc: Value = serde_json::from_str(&utf8(&out)).unwrap();
        assert_eq!(
            doc["hosts"][0]["services"][1]["http"]["title"],
            "=cmd|' /C calc'!A0 \"<b>"
        );
    }

    #[test]
    fn custom_selection_and_missing_port_step() {
        let mut info = sample_info();
        info.port_scan = None;
        let mut hosts = sample_hosts();
        if let Some(scan) = hosts[0].port_scan.as_mut() {
            scan.selection = PortSelection::Custom("22,80-90".into());
        }
        let mut out = Vec::new();
        let options = sample_options(ExportKind::Json, Delimiter::Semicolon);
        write_json(&mut out, &info, &hosts, &options).unwrap();
        let doc: Value = serde_json::from_str(&utf8(&out)).unwrap();
        assert_eq!(doc["scan"]["port_scan"], Value::Null);
        assert_eq!(
            doc["hosts"][0]["port_scan"]["selection"],
            json!({"custom": "22,80-90"})
        );
    }
}
