//! Self-contained, printable HTML report (inline CSS, no scripts). Every dynamic value is
//! escaped; a restrictive CSP inside the file blocks scripts even if escaping were bypassed.

use std::fmt::Write as _;
use std::io::{self, Write};

use super::labels::Labels;
use super::{
    ExportOptions, PortStepInfo, ScanInfo, Scope, port_rows, selection_text, source_key,
    sources_text, state_key, status_key, time, web_info,
};
use crate::ports::PortState;
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
h2 { margin: 24px 0 10px; font-size: 16px; }
.host-ports { margin: 0 0 16px; break-inside: avoid; }
.host-ports h3 { margin: 0 0 2px; font-size: 13px; }
.ports-table { width: 100%; max-width: 960px; margin-top: 4px; table-layout: fixed; }
.ports-table th:nth-child(1) { width: 64px; }
.ports-table th:nth-child(2) { width: 130px; }
.ports-table th:nth-child(3) { width: 100px; }
.ports-table th, .ports-table td { padding: 3px 10px 3px 0; border-bottom: 1px solid #d5d9e0; text-align: left; vertical-align: top; overflow-wrap: anywhere; }
.ports-table th { font-weight: 600; color: #5d6675; }
.state-open { color: #15803d; font-weight: 600; }
.state-closed { color: #5d6675; }
.state-filtered { color: #5d6675; font-style: italic; }
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
    if let Some(step) = &info.port_scan {
        meta_row(
            &mut html,
            labels.get("export.portScan"),
            &port_step_text(step, labels),
            "",
        );
    }
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

    // One block per host with known ports: open ports with banners, listed closed/filtered.
    let with_ports: Vec<&HostResult> = hosts
        .iter()
        .filter(|host| host.port_scan.is_some() || !host.services.is_empty())
        .collect();
    if !with_ports.is_empty() {
        let _ = writeln!(
            html,
            "<section class=\"ports\"><h2>{}</h2>",
            escape(labels.get("details.ports"))
        );
        for host in with_ports {
            host_ports(&mut html, host, labels);
        }
        html.push_str("</section>\n");
    }

    let _ = write!(
        html,
        "<footer>{}</footer>\n</body>\n</html>\n",
        escape(labels.get("export.legal"))
    );
    out.write_all(html.as_bytes())
}

/// `Top 100 – 1,347 of 1,347 checks · banners read`
fn port_step_text(step: &PortStepInfo, labels: &Labels) -> String {
    let selection = selection_text(&step.selection, labels);
    let mut text = match (step.error, step.checks) {
        (Some(_), _) => labels.fill("export.portStepRefused", &[("selection", &selection)]),
        (None, None) => labels.fill("export.portStepSkipped", &[("selection", &selection)]),
        (None, Some((done, total))) => labels.fill(
            "export.portStepDone",
            &[
                ("selection", &selection),
                ("done", &labels.count(done)),
                ("total", &labels.count(total)),
            ],
        ),
    };
    if step.cancelled {
        text.push(' ');
        text.push_str(labels.get("export.portScanStopped"));
    }
    text.push_str(" · ");
    text.push_str(labels.get(match step.banners {
        true => "export.portStepBanners",
        false => "export.portStepNoBanners",
    }));
    text
}

fn state_class(state: PortState) -> &'static str {
    match state {
        PortState::Open => "state-open",
        PortState::Closed => "state-closed",
        PortState::Filtered => "state-filtered",
    }
}

/// Ports block of one host (see [`port_rows`]); every value is escaped.
fn host_ports(html: &mut String, host: &HostResult, labels: &Labels) {
    let _ = write!(
        html,
        "<div class=\"host-ports\"><h3><span class=\"mono\">{}</span>",
        host.ip
    );
    if let Some(name) = &host.hostname {
        let _ = write!(html, " – {}", escape(name));
    }
    html.push_str("</h3>");
    let count = |n: u32| labels.count(u64::from(n));
    match &host.port_scan {
        Some(scan) => {
            let selection = selection_text(&scan.selection, labels);
            small(
                html,
                &labels.fill("details.portScan", &[("selection", &selection)]),
            );
            small(
                html,
                &labels.fill(
                    "details.portScanCounts",
                    &[
                        ("probed", &count(scan.probed)),
                        ("total", &count(scan.total)),
                        ("open", &count(scan.open)),
                        ("closed", &count(scan.closed)),
                        ("filtered", &count(scan.filtered)),
                    ],
                ),
            );
            if !scan.complete {
                small(html, labels.get("details.portScanIncomplete"));
            }
            if scan.errors > 0 {
                small(
                    html,
                    &labels.fill("details.portScanErrors", &[("errors", &count(scan.errors))]),
                );
            }
        }
        None => small(html, labels.get("details.discoveryPorts")),
    }

    let rows = port_rows(host);
    if rows.is_empty() {
        small(html, labels.get("details.noOpenPorts"));
    } else {
        html.push_str("<table class=\"ports-table\"><thead><tr>");
        for key in [
            "ports.colPort",
            "ports.colService",
            "ports.colState",
            "ports.colBanner",
        ] {
            let _ = write!(html, "<th>{}</th>", escape(labels.get(key)));
        }
        html.push_str("</tr></thead><tbody>");
        for row in &rows {
            let name = if row.name == "unknown" { "" } else { row.name };
            let _ = write!(
                html,
                "<tr><td class=\"mono\">{}</td><td>{}</td><td class=\"{}\">{}</td><td>{}</td></tr>",
                row.port,
                escape(name),
                state_class(row.state),
                escape(labels.get(state_key(row.state))),
                escape(&row.banner)
            );
        }
        html.push_str("</tbody></table>");
    }
    if let Some(scan) = &host.port_scan {
        let shown = |state: PortState| rows.iter().filter(|row| row.state == state).count() as u32;
        for (total, state, key) in [
            (scan.open, PortState::Open, "details.moreOpen"),
            (scan.closed, PortState::Closed, "details.closedNotListed"),
            (
                scan.filtered,
                PortState::Filtered,
                "details.filteredNotListed",
            ),
        ] {
            let hidden = total.saturating_sub(shown(state));
            if hidden > 0 {
                small(html, &labels.fill(key, &[("count", &count(hidden))]));
            }
        }
    }
    html.push_str("</div>\n");
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

        // Port scan metadata and the ports block of the router.
        assert!(
            html.contains(
                "<th>Port scan</th><td class=\"\">Top 100 – 97 of 97 checks · banners read</td>"
            ),
            "{html}"
        );
        assert_eq!(html.matches("<div class=\"host-ports\">").count(), 1);
        assert!(html.contains("<h3><span class=\"mono\">192.168.1.1</span> – fritz.box</h3>"));
        assert!(html.contains("100 of 100 checked – 3 open, 95 closed, 2 filtered"));
        assert!(html.contains(
            "<tr><td class=\"mono\">8000</td><td>http-alt</td><td class=\"state-filtered\">filtered</td><td></td></tr>"
        ));
        assert!(html.contains("95 closed ports not listed."));
        // The hostile banner is text.
        assert!(html.contains(
            "SSH-2.0-x =HYPERLINK(&quot;http://evil&quot;) &lt;img src=x onerror=alert(1)&gt;"
        ));
        assert!(!html.contains("<img"));
    }

    /// Manual look at the layout:
    /// `REPORT_OUT=<file>.html cargo test write_sample_report -- --ignored`
    #[test]
    #[ignore = "writes a sample report"]
    fn write_sample_report() {
        let hosts = crate::export::tests::fixture_hosts();
        let language = match std::env::var("REPORT_LANG").as_deref() {
            Ok("de") => ReportLanguage::De,
            _ => ReportLanguage::En,
        };
        std::fs::write(
            std::env::var("REPORT_OUT").unwrap(),
            report(language, &hosts),
        )
        .unwrap();
    }

    #[test]
    fn port_step_texts() {
        let labels = Labels::new(ReportLanguage::En);
        let mut step = sample_info().port_scan.unwrap();
        step.cancelled = true;
        step.banners = false;
        assert_eq!(
            port_step_text(&step, &labels),
            "Top 100 – 97 of 97 checks (stopped) · without banners"
        );
        step.checks = None;
        step.cancelled = false;
        assert!(port_step_text(&step, &labels).starts_with("Top 100 – not run"));
        step.error = Some("ports.too_many_probes");
        assert!(port_step_text(&step, &labels).starts_with("Top 100 – refused"));
    }

    #[test]
    fn german_report() {
        let html = report(ReportLanguage::De, &sample_hosts());
        assert!(html.contains("<html lang=\"de\">"));
        assert!(html.contains("Hersteller"));
        assert!(html.contains("12,0 s"));
    }
}
