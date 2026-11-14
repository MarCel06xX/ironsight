//! JSON export: everything we know, in a stable snake_case schema that is independent of the
//! IPC format. Bump `SCHEMA_VERSION` on incompatible changes.

use std::io::{self, Write};
use std::net::IpAddr;

use serde::Serialize;

use super::{ExportOptions, ScanInfo, Scope, time};
use crate::mac::MacAddr;
use crate::scan::{HostNames, HostResult, NameSource, SeenBy, ServiceInfo};

pub const SCHEMA_VERSION: u32 = 1;

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
}

#[derive(Serialize)]
struct Host<'a> {
    ip: IpAddr,
    online: bool,
    hostname: Option<&'a str>,
    hostname_source: Option<NameSource>,
    names: &'a HostNames,
    mac: Option<MacAddr>,
    mac_locally_administered: bool,
    vendor: Option<&'a str>,
    rtt_ms: Option<u32>,
    workgroup: Option<&'a str>,
    seen_by: SeenBy,
    services: &'a [ServiceInfo],
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
        },
        hosts: hosts
            .iter()
            .map(|host| Host {
                ip: host.ip,
                online: host.online,
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

        assert_eq!(doc["schema_version"], 1);
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
                "timeout_ms": 1000
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
        assert_eq!(router["services"][0]["port"], 80);
        assert_eq!(router["services"][0]["http"]["server"], "nginx");
        assert_eq!(router["services"][1]["http"], Value::Null);
        assert_eq!(router["last_update"], "2025-11-14T18:30:00Z");

        let offline = &doc["hosts"][1];
        assert_eq!(offline["online"], false);
        assert_eq!(offline["hostname"], Value::Null);
        assert_eq!(offline["services"], json!([]));
    }

    #[test]
    fn untrusted_strings_are_valid_json() {
        let mut out = Vec::new();
        let options = sample_options(ExportKind::Json, Delimiter::Semicolon);
        write_json(&mut out, &sample_info(), &sample_hosts(), &options).unwrap();
        let doc: Value = serde_json::from_str(&utf8(&out)).unwrap();
        assert_eq!(
            doc["hosts"][0]["services"][0]["http"]["title"],
            "=cmd|' /C calc'!A0 \"<b>"
        );
    }
}
