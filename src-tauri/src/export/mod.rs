//! Manual exports of scan results (the only way results ever reach the disk):
//! CSV, JSON and a printable HTML report. All writers are self-written.

use std::io::{self, Write};

use serde::{Deserialize, Serialize};

use crate::scan::{DataSource, HostResult, HostStatus, NameSource};

mod csv;
mod html;
mod json;
mod labels;
pub mod time;

pub use labels::{Labels, ReportLanguage};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Delimiter {
    /// German Excel expects `;`.
    #[default]
    #[serde(rename = ";")]
    Semicolon,
    #[serde(rename = ",")]
    Comma,
}

impl Delimiter {
    pub fn as_char(self) -> char {
        match self {
            Self::Semicolon => ';',
            Self::Comma => ',',
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExportKind {
    Csv,
    Json,
    Html,
}

impl ExportKind {
    pub fn extension(self) -> &'static str {
        match self {
            Self::Csv => "csv",
            Self::Json => "json",
            Self::Html => "html",
        }
    }

    /// Locale key of the file type name shown in the save dialog.
    pub fn label_key(self) -> &'static str {
        match self {
            Self::Csv => "export.formatCsv",
            Self::Json => "export.formatJson",
            Self::Html => "export.formatHtml",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Every scanned address, sorted by IP.
    All,
    /// The rows of the app's filtered view, in its order.
    View,
}

#[derive(Debug, Clone, Copy)]
pub struct ExportOptions {
    pub kind: ExportKind,
    pub delimiter: Delimiter,
    pub language: ReportLanguage,
    /// Used for local times in CSV and HTML; JSON is always UTC.
    pub utc_offset_minutes: i32,
    pub scope: Scope,
    pub exported_at_ms: u64,
}

/// What was scanned, for the export metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanInfo {
    pub targets: String,
    pub started_at_ms: u64,
    pub finished_at_ms: Option<u64>,
    pub cancelled: bool,
    pub total: u32,
    pub scanned: u32,
    pub online: u32,
    pub errors: u32,
    pub concurrency: u32,
    pub timeout_ms: u32,
}

pub fn write_export(
    out: &mut impl Write,
    info: &ScanInfo,
    hosts: &[HostResult],
    options: &ExportOptions,
) -> io::Result<()> {
    let labels = Labels::new(options.language);
    match options.kind {
        ExportKind::Csv => csv::write_csv(
            out,
            hosts,
            options.delimiter,
            &labels,
            options.utc_offset_minutes,
        ),
        ExportKind::Json => json::write_json(out, info, hosts, options),
        ExportKind::Html => html::write_html(out, info, hosts, options, &labels),
    }
}

/// `ironsight-20261114-1930.csv`, from the scan start in local time.
pub fn default_file_name(options: &ExportOptions, started_at_ms: u64) -> String {
    format!(
        "ironsight-{}.{}",
        time::file_stamp(started_at_ms, options.utc_offset_minutes),
        options.kind.extension()
    )
}

// --- helpers shared by the writers -------------------------------------------------------

fn status_key(host: &HostResult) -> &'static str {
    match host.status {
        HostStatus::Online => "status.online",
        HostStatus::Offline => "status.offline",
        HostStatus::Unused => "status.unused",
    }
}

fn origin_key(source: DataSource) -> &'static str {
    match source {
        DataSource::Live => "origin.live",
        DataSource::Dns => "origin.dns",
        DataSource::ArpCache => "origin.arpCache",
        DataSource::Remembered => "origin.remembered",
        DataSource::Imported => "origin.imported",
    }
}

/// Where the shown data came from, e.g. `DNS, ARP cache`; empty if there is none.
fn sources_text(host: &HostResult, labels: &Labels) -> String {
    let s = host.sources;
    let mut seen: Vec<DataSource> = Vec::new();
    for source in [s.hostname, s.mac, s.vendor, s.services, s.workgroup]
        .into_iter()
        .flatten()
    {
        if !seen.contains(&source) {
            seen.push(source);
        }
    }
    seen.into_iter()
        .map(|source| labels.get(origin_key(source)))
        .collect::<Vec<_>>()
        .join(", ")
}

fn source_key(source: NameSource) -> &'static str {
    match source {
        NameSource::Dns => "source.dns",
        NameSource::Mdns => "source.mdns",
        NameSource::Netbios => "source.netbios",
    }
}

/// `22 ssh, 80 http`
fn services_text(host: &HostResult) -> String {
    host.services
        .iter()
        .map(|s| format!("{} {}", s.port, s.name))
        .collect::<Vec<_>>()
        .join(", ")
}

/// `ARP, ICMP, TCP`
fn seen_by_text(host: &HostResult, labels: &Labels) -> String {
    [
        (host.seen_by.arp, "seenBy.arp"),
        (host.seen_by.icmp, "seenBy.icmp"),
        (host.seen_by.tcp, "seenBy.tcp"),
    ]
    .into_iter()
    .filter(|(seen, _)| *seen)
    .map(|(_, key)| labels.get(key))
    .collect::<Vec<_>>()
    .join(", ")
}

/// First HTTP page title and first `Server` header of the host.
fn web_info(host: &HostResult) -> (Option<&str>, Option<&str>) {
    let infos = || host.services.iter().filter_map(|s| s.http.as_ref());
    let title = infos().find_map(|h| h.title.as_deref());
    let server = infos().find_map(|h| h.server.as_deref());
    (title, server)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;
    use crate::mac::MacAddr;
    use crate::scan::{HttpInfo, SeenBy, ServiceInfo};

    pub(crate) const STARTED: u64 = 1_763_145_000_000; // 2025-11-14T18:30:00Z

    pub(crate) fn utf8(bytes: &[u8]) -> String {
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    pub(crate) fn sample_info() -> ScanInfo {
        ScanInfo {
            targets: "192.168.1.0/24".into(),
            started_at_ms: STARTED,
            finished_at_ms: Some(STARTED + 12_000),
            cancelled: false,
            total: 254,
            scanned: 254,
            online: 1,
            errors: 0,
            concurrency: 64,
            timeout_ms: 1000,
        }
    }

    pub(crate) fn sample_options(kind: ExportKind, delimiter: Delimiter) -> ExportOptions {
        ExportOptions {
            kind,
            delimiter,
            language: ReportLanguage::En,
            utc_offset_minutes: 60,
            scope: Scope::All,
            exported_at_ms: STARTED + 300_000,
        }
    }

    /// An enriched router (with a hostile page title) and an offline address.
    pub(crate) fn sample_hosts() -> Vec<HostResult> {
        let mut router = HostResult::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        router.online = true;
        router.complete = true;
        router.seen_by = SeenBy {
            arp: true,
            icmp: true,
            tcp: true,
        };
        router.rtt_ms = Some(2);
        router.set_mac(MacAddr([0x00, 0x00, 0x0c, 0x12, 0x34, 0x56]));
        router.names.dns = Some("fritz.box".into());
        router.names.netbios = Some("FRITZ".into());
        router.pick_hostname();
        let mut http = ServiceInfo::open(80);
        http.http = Some(HttpInfo {
            status: Some(200),
            server: Some("nginx".into()),
            title: Some("=cmd|' /C calc'!A0 \"<b>".into()),
        });
        router.services = vec![http, ServiceInfo::open(443)];
        router.timestamp_ms = STARTED;
        router.mark_live();

        let mut offline = HostResult::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)));
        offline.complete = true;
        offline.timestamp_ms = STARTED;
        offline.update_status();
        vec![router, offline]
    }

    #[test]
    fn file_names() {
        let options = sample_options(ExportKind::Html, Delimiter::Comma);
        assert_eq!(
            default_file_name(&options, STARTED),
            "ironsight-20251114-1930.html"
        );
    }

    /// Every label the writers use must exist in both locale files.
    #[test]
    fn no_untranslated_keys_in_any_format() {
        let prefixes = [
            "export.", "col.", "status.", "source.", "details.", "seenBy.", "rtt.", "vendor.",
            "origin.",
        ];
        for language in [ReportLanguage::En, ReportLanguage::De] {
            for kind in [ExportKind::Csv, ExportKind::Json, ExportKind::Html] {
                let mut options = sample_options(kind, Delimiter::Semicolon);
                options.language = language;
                let mut info = sample_info();
                info.cancelled = true;
                let mut hosts = sample_hosts();
                hosts[1].mac = Some(MacAddr([0x02, 0, 0, 0, 0, 1]));
                hosts[1].mac_local = true;
                hosts[1].sources.mac = Some(DataSource::ArpCache);
                hosts[1].last_seen_ms = Some(STARTED);
                hosts[1].update_status();
                hosts[1].rtt_ms = Some(0);
                let mut out = Vec::new();
                write_export(&mut out, &info, &hosts, &options).unwrap();
                let text = utf8(&out);
                for prefix in prefixes {
                    assert!(
                        !text.contains(prefix),
                        "{language:?} {kind:?}: raw key {prefix}* in output"
                    );
                }
                for placeholder in [
                    "{version}",
                    "{date}",
                    "{online}",
                    "{scanned}",
                    "{total}",
                    "{count}",
                    "{seconds}",
                    "{ms}",
                ] {
                    assert!(
                        !text.contains(placeholder),
                        "{language:?} {kind:?}: unfilled {placeholder}"
                    );
                }
            }
        }
    }
}
