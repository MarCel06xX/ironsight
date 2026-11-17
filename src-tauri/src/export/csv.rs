//! CSV export: UTF-8 with BOM, CRLF line ends, `;` or `,` as delimiter, RFC 4180 quoting.
//! Text that came from the network is also guarded against spreadsheet formula injection.

use std::borrow::Cow;
use std::io::{self, Write};

use super::labels::Labels;
use super::{
    Delimiter, port_rows, port_scan_text, seen_by_text, services_text, source_key, sources_text,
    state_key, status_key, time, web_info,
};
use crate::ports::PortState;
use crate::scan::HostResult;

const BOM: &[u8] = b"\xEF\xBB\xBF";
/// Leading characters that make Excel & co. evaluate a cell as a formula.
const FORMULA_START: [char; 6] = ['=', '+', '-', '@', '\t', '\r'];

/// A field value; `untrusted` marks text that came from the network.
struct Field<'a> {
    value: Cow<'a, str>,
    untrusted: bool,
}

fn trusted<'a>(value: impl Into<Cow<'a, str>>) -> Field<'a> {
    Field {
        value: value.into(),
        untrusted: false,
    }
}

fn untrusted(value: Option<&str>) -> Field<'_> {
    Field {
        value: Cow::Borrowed(value.unwrap_or("")),
        untrusted: true,
    }
}

/// Quotes a field if it contains the delimiter, quotes or line breaks (or has outer
/// whitespace); untrusted values that look like a formula get a leading apostrophe so
/// spreadsheet apps show them as plain text.
pub fn escape_field(value: &str, delimiter: char, untrusted: bool) -> Cow<'_, str> {
    let guard = untrusted && value.starts_with(FORMULA_START);
    let needs_quotes = guard
        || value.contains([delimiter, '"', '\n', '\r'])
        || value.starts_with(' ')
        || value.ends_with(' ');
    if !needs_quotes {
        return Cow::Borrowed(value);
    }
    let mut out = String::with_capacity(value.len() + 4);
    out.push('"');
    if guard {
        out.push('\'');
    }
    out.push_str(&value.replace('"', "\"\""));
    out.push('"');
    Cow::Owned(out)
}

fn write_row(out: &mut impl Write, fields: &[Field<'_>], delimiter: char) -> io::Result<()> {
    let mut line = String::new();
    for (i, field) in fields.iter().enumerate() {
        if i > 0 {
            line.push(delimiter);
        }
        line.push_str(&escape_field(&field.value, delimiter, field.untrusted));
    }
    line.push_str("\r\n");
    out.write_all(line.as_bytes())
}

pub fn write_csv(
    out: &mut impl Write,
    hosts: &[HostResult],
    delimiter: Delimiter,
    labels: &Labels,
    utc_offset_minutes: i32,
) -> io::Result<()> {
    let delimiter = delimiter.as_char();
    out.write_all(BOM)?;
    let header = [
        "col.status",
        "col.ip",
        "col.hostname",
        "export.col.hostnameSource",
        "export.col.dns",
        "export.col.mdns",
        "export.col.netbios",
        "col.mac",
        "export.col.macLocal",
        "col.vendor",
        "export.col.rttMs",
        "col.workgroup",
        "export.col.openPorts",
        "export.col.httpTitle",
        "export.col.httpServer",
        "details.seenBy",
        "details.lastSeen",
        "col.lastSeen",
        "export.col.source",
        "export.col.portScan",
        "export.col.closedPorts",
        "export.col.filteredPorts",
        "export.col.listedPorts",
        "export.col.banners",
    ]
    .map(|key| trusted(labels.get(key)));
    write_row(out, &header, delimiter)?;

    for host in hosts {
        let (title, server) = web_info(host);
        let mac_local = match (host.mac, host.mac_local) {
            (None, _) => "",
            (Some(_), true) => labels.get("export.yes"),
            (Some(_), false) => labels.get("export.no"),
        };
        let scan = host.port_scan.as_ref();
        let count = |get: fn(&crate::scan::PortScanInfo) -> u32| {
            scan.map(|scan| get(scan).to_string()).unwrap_or_default()
        };
        let rows = port_rows(host);
        // `23 telnet: closed, 8000 http-alt: filtered`
        let listed = rows
            .iter()
            .filter(|row| row.state != PortState::Open)
            .map(|row| {
                format!(
                    "{} {}: {}",
                    row.port,
                    row.name,
                    labels.get(state_key(row.state))
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        // One line per open port that said something: `22 ssh: SSH-2.0-OpenSSH_9.6`
        let banners = rows
            .iter()
            .filter(|row| !row.banner.is_empty())
            .map(|row| format!("{} {}: {}", row.port, row.name, row.banner))
            .collect::<Vec<_>>()
            .join("\n");
        let row = [
            trusted(labels.get(status_key(host))),
            trusted(host.ip.to_string()),
            untrusted(host.hostname.as_deref()),
            trusted(
                host.hostname_source
                    .map_or("", |s| labels.get(source_key(s))),
            ),
            untrusted(host.names.dns.as_deref()),
            untrusted(host.names.mdns.as_deref()),
            untrusted(host.names.netbios.as_deref()),
            trusted(host.mac.map(|m| m.to_string()).unwrap_or_default()),
            trusted(mac_local),
            untrusted(host.vendor.as_deref()),
            trusted(host.rtt_ms.map(|ms| ms.to_string()).unwrap_or_default()),
            untrusted(host.workgroup.as_deref()),
            trusted(services_text(host)),
            untrusted(title),
            untrusted(server),
            trusted(seen_by_text(host, labels)),
            trusted(time::rfc3339(host.timestamp_ms, utc_offset_minutes)),
            trusted(
                host.last_seen_ms
                    .map(|ms| time::rfc3339(ms, utc_offset_minutes))
                    .unwrap_or_default(),
            ),
            trusted(sources_text(host, labels)),
            trusted(scan.map(|s| port_scan_text(s, labels)).unwrap_or_default()),
            trusted(count(|s| s.closed)),
            trusted(count(|s| s.filtered)),
            trusted(listed),
            untrusted(Some(banners.as_str())),
        ];
        write_row(out, &row, delimiter)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::export::labels::ReportLanguage;
    use crate::export::tests::{sample_hosts, utf8};

    #[test]
    fn plain_values_stay_unquoted() {
        assert_eq!(escape_field("192.168.1.1", ';', false), "192.168.1.1");
        assert_eq!(escape_field("", ';', true), "");
        assert_eq!(escape_field("a,b", ';', true), "a,b");
        assert_eq!(escape_field("Büro-PC", ',', true), "Büro-PC");
    }

    #[test]
    fn quoting_rules() {
        assert_eq!(escape_field("a;b", ';', false), "\"a;b\"");
        assert_eq!(escape_field("a,b", ',', false), "\"a,b\"");
        assert_eq!(escape_field("say \"hi\"", ';', false), "\"say \"\"hi\"\"\"");
        assert_eq!(escape_field("two\nlines", ';', false), "\"two\nlines\"");
        assert_eq!(escape_field("cr\rlf", ';', false), "\"cr\rlf\"");
        assert_eq!(escape_field(" padded ", ';', false), "\" padded \"");
    }

    #[test]
    fn formula_injection_is_neutralized_for_network_text() {
        for evil in ["=1+1", "+cmd", "-2+3", "@SUM(A1)", "\tx", "\rx"] {
            let escaped = escape_field(evil, ';', true);
            assert!(escaped.starts_with("\"'"), "{evil:?} -> {escaped}");
        }
        assert_eq!(
            escape_field("=HYPERLINK(\"x\")", ';', true),
            "\"'=HYPERLINK(\"\"x\"\")\""
        );
        // Values we produce ourselves are left alone.
        assert_eq!(escape_field("-", ';', false), "-");
    }

    #[test]
    fn full_file_layout() {
        let mut out = Vec::new();
        let labels = Labels::new(ReportLanguage::En);
        write_csv(&mut out, &sample_hosts(), Delimiter::Semicolon, &labels, 60).unwrap();
        assert!(out.starts_with(BOM));
        let text = utf8(&out[BOM.len()..]);
        let lines: Vec<&str> = text.split("\r\n").collect();
        assert_eq!(
            lines.len(),
            4,
            "header, 2 hosts, trailing empty line: {text}"
        );
        assert_eq!(lines[3], "");
        assert!(lines[0].starts_with("Status;IP address;Hostname;Hostname source;"));
        assert_eq!(lines[0].split(';').count(), 24);
        assert!(
            lines[0].ends_with(
                ";Last seen;Data source;Port scan;Closed ports;Filtered ports;\
                 Listed closed/filtered ports;Banners"
            ),
            "{}",
            lines[0]
        );

        let router = lines[1];
        assert!(router.starts_with("Online;192.168.1.1;fritz.box;DNS;fritz.box;;FRITZ;"));
        assert!(router.contains(";no;"), "{router}");
        assert!(router.contains(";22 ssh, 80 http, 443 https;"), "{router}");
        assert!(
            router.contains(";2025-11-14T19:30:00+01:00;2025-11-14T19:30:00+01:00;live"),
            "{router}"
        );
        // The malicious title is quoted, its quotes doubled and the formula guarded.
        assert!(
            router.contains(";\"'=cmd|' /C calc'!A0 \"\"<b>\";"),
            "{router}"
        );
        // Port scan columns; banners one per line in one quoted cell, quotes doubled.
        assert!(
            router.contains(
                ";live;Top 100 – 100 of 100 checked;95;2;\
                 8000 http-alt: filtered, 8443 https-alt: filtered;\
                 \"22 ssh: SSH-2.0-x =HYPERLINK(\"\"http://evil\"\") <img src=x onerror=alert(1)>\n\
                 80 http: HTTP 200 · nginx · =cmd|' /C calc'!A0 \"\"<b>\""
            ),
            "{router}"
        );
        assert!(router.ends_with('"'), "{router}");

        assert!(
            lines[2].starts_with("Unused;192.168.1.2;;;;;;;;;;;;;;;"),
            "{}",
            lines[2]
        );
        // No port scan: the port columns stay empty.
        assert!(lines[2].ends_with(";;;;;;"), "{}", lines[2]);
    }

    #[test]
    fn banners_with_delimiters_and_formulas_stay_one_cell() {
        let mut hosts = sample_hosts();
        hosts[0].services[0].banner = Some("=1+1; a,b \"c\"".into());
        hosts[0].services.truncate(1);
        let mut out = Vec::new();
        let labels = Labels::new(ReportLanguage::En);
        write_csv(&mut out, &hosts, Delimiter::Semicolon, &labels, 0).unwrap();
        let text = utf8(&out[BOM.len()..]);
        let router = text.split("\r\n").nth(1).unwrap();
        // Starts with the port number, so no formula; quoted for the delimiter and quotes.
        assert!(
            router.ends_with(";\"22 ssh: =1+1; a,b \"\"c\"\"\""),
            "{router}"
        );
    }

    #[test]
    fn comma_delimiter_quotes_port_lists() {
        let mut out = Vec::new();
        let labels = Labels::new(ReportLanguage::De);
        write_csv(&mut out, &sample_hosts(), Delimiter::Comma, &labels, 0).unwrap();
        let text = utf8(&out[BOM.len()..]);
        assert!(text.starts_with("Status,IP-Adresse,Hostname,"));
        assert!(text.contains(",\"22 ssh, 80 http, 443 https\","), "{text}");
        assert!(
            text.contains(",Top 100 – 100 von 100 geprüft,95,2,"),
            "{text}"
        );
        assert!(text.contains(",nein,"), "{text}");
    }
}
