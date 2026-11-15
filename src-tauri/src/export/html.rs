//! Self-contained, printable HTML report (inline CSS, no scripts). Every dynamic value is
//! escaped; a restrictive CSP inside the file blocks scripts even if escaping were bypassed.

use std::fmt::Write as _;
use std::io::{self, Write};

use super::labels::Labels;
use super::{ExportOptions, ScanInfo, Scope, source_key, sources_text, status_key, time, web_info};
use crate::scan::{HostResult, HostStatus, NameSource};

const STYLE: &str = r#"
:root { color-scheme: light; }
* { box-sizing: border-box; }
body { margin: 24px; font: 13px/1.45 "Segoe UI", system-ui, sans-serif; color: #1d2330; background: #fff; }
h1 { margin: 0 0 2px; font-size: 20px; }
.sub, .small, footer { color: #5d6675; }
.sub { margin: 0 0 16px; }
.small { font-size: 11px; }
.mono { font-family: Consolas, "Cascadia Mono", monospace; }
table { border-collapse: collapse; }
.meta { margin-bottom: 20px; }
.meta th { padding: 2px 16px 2px 0; color: #5d6675; font-weight: 600; text-align: left; vertical-align: top; }
.meta td { padding: 2px 0; overflow-wrap: anywhere; }
.hosts { width: 100%; }
.hosts th, .hosts td { padding: 4px 8px; border-bottom: 1px solid #d5d9e0; text-align: left; vertical-align: top; overflow-wrap: anywhere; }
.hosts th { background: #eef1f5; font-weight: 600; white-space: nowrap; }
.hosts tbody tr:nth-child(even) td { background: #f8f9fb; }
.hosts tr.offline td { color: #6b7380; }
.hosts tr.unused td { color: #a0a7b3; }
.dot { display: inline-block; width: 8px; height: 8px; margin-right: 6px; border-radius: 50%; background: #a0a7b3; }
.dot.on { background: #1f9d55; }
footer { margin-top: 20px; font-size: 11px; }
@page { size: A4 landscape; margin: 12mm; }
@media print {
  body { margin: 0; }
  thead { display: table-header-group; }
  tr { break-inside: avoid; }
  * { print-color-adjust: exact; -webkit-print-color-adjust: exact; }
}
"#;

/// Escapes text for HTML element content and attribute values.
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

fn meta_row(html: &mut String, label: &str, value: &str, class: &str) {
    let _ = write!(
        html,
        "<tr><th>{}</th><td class=\"{class}\">{}</td></tr>",
        escape(label),
        escape(value)
    );
}

fn small(html: &mut String, text: &str) {
    let _ = write!(html, "<div class=\"small\">{}</div>", escape(text));
}

pub fn write_html(
    out: &mut impl Write,
    info: &ScanInfo,
    hosts: &[HostResult],
    options: &ExportOptions,
    labels: &Labels,
) -> io::Result<()> {
    let offset = options.utc_offset_minutes;
    let title = labels.get("export.reportTitle");
    let mut html = String::with_capacity(4096 + hosts.len() * 400);

    let _ = write!(
        html,
        "<!doctype html>\n<html lang=\"{lang}\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">\n\
         <title>{title} – {targets}</title>\n<style>{STYLE}</style>\n</head>\n<body>\n",
        lang = labels.language().tag(),
        title = escape(title),
        targets = escape(&info.targets),
    );

    let generated = labels.fill(
        "export.generatedBy",
        &[
            ("version", env!("CARGO_PKG_VERSION")),
            ("date", &time::readable(options.exported_at_ms, offset)),
        ],
    );
    let _ = write!(
        html,
        "<header><h1>{}</h1><p class=\"sub\">{}</p></header>\n<table class=\"meta\">",
        escape(title),
        escape(&generated)
    );
    meta_row(
        &mut html,
        labels.get("export.targets"),
        &info.targets,
        "mono",
    );
    meta_row(
        &mut html,
        labels.get("export.started"),
        &time::readable(info.started_at_ms, offset),
        "",
    );
    if let Some(finished) = info.finished_at_ms {
        meta_row(
            &mut html,
            labels.get("export.finished"),
            &time::readable(finished, offset),
            "",
        );
        let duration = labels.seconds(finished.saturating_sub(info.started_at_ms));
        meta_row(&mut html, labels.get("export.duration"), &duration, "");
    }
    let scanned = labels.count(u64::from(info.scanned));
    let total = labels.count(u64::from(info.total));
    let mut result = labels.fill(
        "export.resultSummary",
        &[
            ("online", &labels.count(u64::from(info.online))),
            ("scanned", &scanned),
        ],
    );
    if info.cancelled {
        result.push(' ');
        result.push_str(&labels.fill(
            "export.resultCancelled",
            &[("scanned", &scanned), ("total", &total)],
        ));
    }
    meta_row(&mut html, labels.get("export.result"), &result, "");
    let rows_key = match options.scope {
        Scope::All => "export.rowsAll",
        Scope::View => "export.rowsView",
    };
    let rows = labels.fill(rows_key, &[("count", &labels.count(hosts.len() as u64))]);
    meta_row(&mut html, labels.get("export.rows"), &rows, "");
    html.push_str("</table>\n");

    html.push_str("<table class=\"hosts\"><thead><tr>");
    for key in [
        "col.status",
        "col.ip",
        "col.hostname",
        "col.mac",
        "col.vendor",
        "col.rtt",
        "col.services",
        "col.web",
        "col.workgroup",
        "col.lastSeen",
        "export.col.source",
    ] {
        let _ = write!(html, "<th>{}</th>", escape(labels.get(key)));
    }
    html.push_str("</tr></thead>\n<tbody>\n");
    for host in hosts {
        host_row(&mut html, host, labels, offset);
    }
    html.push_str("</tbody></table>\n");

    let _ = write!(
        html,
        "<footer>{}</footer>\n</body>\n</html>\n",
        escape(labels.get("export.legal"))
    );
    out.write_all(html.as_bytes())
}

fn host_row(html: &mut String, host: &HostResult, labels: &Labels, offset: i32) {
    let class = match host.status {
        HostStatus::Online => "",
        HostStatus::Offline => " class=\"offline\"",
        HostStatus::Unused => " class=\"unused\"",
    };
    let dot = if host.online { "dot on" } else { "dot" };
    let _ = write!(
        html,
        "<tr{class}><td><span class=\"{dot}\"></span>{}</td><td class=\"mono\">{}</td><td>",
        escape(labels.get(status_key(host))),
        host.ip
    );

    // Hostname with its source, then names from the other sources.
    if let (Some(name), Some(source)) = (&host.hostname, host.hostname_source) {
        html.push_str(&escape(name));
        small(html, labels.get(source_key(source)));
    }
    for (source, name) in [
        (NameSource::Dns, &host.names.dns),
        (NameSource::Mdns, &host.names.mdns),
        (NameSource::Netbios, &host.names.netbios),
    ] {
        if let Some(name) = name
            && host.hostname_source != Some(source)
        {
            small(html, &format!("{}: {name}", labels.get(source_key(source))));
        }
    }

    html.push_str("</td><td class=\"mono\">");
    if let Some(mac) = host.mac {
        let _ = write!(html, "{mac}");
    }
    html.push_str("</td><td>");
    if host.mac_local {
        small(html, labels.get("vendor.local"));
    } else if let Some(vendor) = &host.vendor {
        html.push_str(&escape(vendor));
    }
    html.push_str("</td><td>");
    if let Some(rtt) = host.rtt_ms {
        let text = match rtt {
            0 => labels.get("rtt.subMs").to_owned(),
            ms => labels.fill("rtt.ms", &[("ms", &labels.count(u64::from(ms)))]),
        };
        html.push_str(&escape(&text));
    }
    html.push_str("</td><td>");
    for service in &host.services {
        let _ = write!(html, "<div>{} {}</div>", service.port, escape(service.name));
        if let Some(http) = &service.http {
            if let Some(title) = &http.title {
                small(html, title);
            }
            if let Some(server) = &http.server {
                small(html, server);
            }
        }
    }
    html.push_str("</td><td>");
    let (title, server) = web_info(host);
    if let Some(text) = title.or(server) {
        html.push_str(&escape(text));
    }
    html.push_str("</td><td>");
    if let Some(workgroup) = &host.workgroup {
        html.push_str(&escape(workgroup));
    }
    html.push_str("</td><td>");
    if let Some(seen) = host.last_seen_ms {
        html.push_str(&escape(&time::readable(seen, offset)));
    }
    let _ = writeln!(
        html,
        "</td><td>{}</td></tr>",
        escape(&sources_text(host, labels))
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::export::labels::ReportLanguage;
    use crate::export::tests::{sample_hosts, sample_info, sample_options, utf8};
    use crate::export::{Delimiter, ExportKind};

    fn report(language: ReportLanguage, hosts: &[HostResult]) -> String {
        let mut out = Vec::new();
        let mut options = sample_options(ExportKind::Html, Delimiter::Semicolon);
        options.language = language;
        let labels = Labels::new(language);
        write_html(&mut out, &sample_info(), hosts, &options, &labels).unwrap();
        utf8(&out)
    }

    #[test]
    fn escapes_everything_special() {
        assert_eq!(
            escape("<a href='x'>&\"</a>"),
            "&lt;a href=&#39;x&#39;&gt;&amp;&quot;&lt;/a&gt;"
        );
        assert_eq!(escape("Büro – ok"), "Büro – ok");
    }

    #[test]
    fn untrusted_values_cannot_inject_markup() {
        let mut hosts = sample_hosts();
        let evil = "<script>alert(1)</script><img src=x onerror=alert(2)>";
        hosts[0].hostname = Some(evil.into());
        hosts[0].names.netbios = Some("</td></tr><tr><td>".into());
        hosts[0].workgroup = Some("\"><svg onload=alert(3)>".into());
        let html = report(ReportLanguage::En, &hosts);

        assert!(!html.contains("<script"), "script tag leaked");
        assert!(!html.contains("<img"), "img tag leaked");
        assert!(!html.contains("<svg"), "svg tag leaked");
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(html.contains("&lt;/td&gt;&lt;/tr&gt;"));
        assert!(html.contains("&quot;&gt;&lt;svg onload=alert(3)&gt;"));
        // Exactly one host row per host despite the injected row markup.
        assert_eq!(html.matches("<tr class=\"unused\">").count(), 1);
        assert_eq!(html.matches("<td><span class=\"dot").count(), 2);
    }

    #[test]
    fn report_structure() {
        let html = report(ReportLanguage::En, &sample_hosts());
        assert!(html.starts_with("<!doctype html>\n<html lang=\"en\">"));
        assert!(html.contains("default-src 'none'"));
        assert!(html.contains("<title>Ironsight scan report – 192.168.1.0/24</title>"));
        assert!(html.contains("<td class=\"mono\">192.168.1.0/24</td>"));
        assert!(html.contains("2025-11-14 19:30:00 (UTC+01:00)"));
        assert!(html.contains("<td class=\"\">12.0 s</td>"));
        assert!(html.contains("1 of 254 scanned addresses online"));
        assert!(html.contains("All scanned addresses (2)"));
        assert!(html.contains(
            "fritz.box<div class=\"small\">DNS</div><div class=\"small\">NetBIOS: FRITZ</div>"
        ));
        assert!(html.contains("<div>80 http</div>"));
        assert!(!html.contains("<script"));
        assert!(html.trim_end().ends_with("</html>"));
    }

    #[test]
    fn german_report() {
        let html = report(ReportLanguage::De, &sample_hosts());
        assert!(html.contains("<html lang=\"de\">"));
        assert!(html.contains("Hersteller"));
        assert!(html.contains("12,0 s"));
    }
}
