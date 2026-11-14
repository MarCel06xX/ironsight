//! TCP connect probes on a small fixed port list, plus a minimal HTTP/1.0 client that reads
//! the `Server` header and the page title. Responses are untrusted and size-limited.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio::time::{Instant, timeout_at};

use super::clean_text;
use crate::scan::HttpInfo;

/// Ports checked on every host, with the service usually found there.
pub const PROBE_PORTS: [(u16, &str); 9] = [
    (21, "ftp"),
    (22, "ssh"),
    (23, "telnet"),
    (80, "http"),
    (443, "https"),
    (445, "smb"),
    (3389, "rdp"),
    (8080, "http-alt"),
    (8443, "https-alt"),
];
/// Plain-HTTP ports whose title is fetched (HTTPS would need a TLS implementation).
const HTTP_PORTS: [u16; 2] = [80, 8080];

const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_REDIRECTS: usize = 3;
const MAX_LOCATION_LEN: usize = 512;
const MAX_TITLE_BYTES: usize = 1024;
const MAX_TITLE_CHARS: usize = 200;
const MAX_SERVER_CHARS: usize = 100;

pub fn service_name(port: u16) -> &'static str {
    PROBE_PORTS
        .iter()
        .find(|(p, _)| *p == port)
        .map_or("unknown", |(_, name)| name)
}

/// Ports of [`PROBE_PORTS`] that accept a TCP connection within `timeout`, ascending.
pub async fn open_ports(ip: IpAddr, timeout: Duration) -> Vec<u16> {
    let ports: Vec<u16> = PROBE_PORTS.iter().map(|(port, _)| *port).collect();
    connectable(ip, &ports, timeout).await
}

async fn connectable(ip: IpAddr, ports: &[u16], timeout: Duration) -> Vec<u16> {
    let mut probes = JoinSet::new();
    for &port in ports {
        probes.spawn(async move {
            let connect = TcpStream::connect(SocketAddr::new(ip, port));
            matches!(tokio::time::timeout(timeout, connect).await, Ok(Ok(_))).then_some(port)
        });
    }
    let mut open = Vec::new();
    while let Some(result) = probes.join_next().await {
        if let Ok(Some(port)) = result {
            open.push(port);
        }
    }
    open.sort_unstable();
    open
}

/// Fetches `Server` header and title for every plain-HTTP port in `open`.
pub async fn http_infos(ip: IpAddr, open: &[u16], timeout: Duration) -> Vec<(u16, HttpInfo)> {
    let mut fetches = JoinSet::new();
    for &port in open.iter().filter(|port| HTTP_PORTS.contains(port)) {
        fetches.spawn(async move { Some((port, http_info(ip, port, timeout).await?)) });
    }
    let mut infos = Vec::new();
    while let Some(result) = fetches.join_next().await {
        if let Ok(Some(info)) = result {
            infos.push(info);
        }
    }
    infos
}

/// `GET /` with up to [`MAX_REDIRECTS`] same-origin redirects, all within twice `timeout`.
async fn http_info(ip: IpAddr, port: u16, timeout: Duration) -> Option<HttpInfo> {
    let deadline = Instant::now() + timeout * 2;
    let mut path = String::from("/");
    let mut info: Option<HttpInfo> = None;
    for _ in 0..=MAX_REDIRECTS {
        let Some(response) = fetch(ip, port, &path, deadline)
            .await
            .as_deref()
            .and_then(parse_response)
        else {
            break;
        };
        let next = redirect_path(&response, ip, port, &path);
        let info = info.get_or_insert_with(HttpInfo::default);
        info.status = response.status;
        info.server = info.server.take().or(response.server);
        info.title = response.title.or(info.title.take());
        match next {
            Some(next) => path = next,
            None => break,
        }
    }
    info
}

/// Sends one request and returns what arrived until EOF, size limit or `deadline`.
async fn fetch(ip: IpAddr, port: u16, path: &str, deadline: Instant) -> Option<Vec<u8>> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = timeout_at(deadline, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;
    let host = if port == 80 {
        match ip {
            IpAddr::V4(v4) => v4.to_string(),
            IpAddr::V6(v6) => format!("[{v6}]"),
        }
    } else {
        addr.to_string()
    };
    let request = format!(
        "GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: Ironsight/{}\r\n\
         Accept: text/html,*/*\r\nConnection: close\r\n\r\n",
        env!("CARGO_PKG_VERSION")
    );
    timeout_at(deadline, stream.write_all(request.as_bytes()))
        .await
        .ok()?
        .ok()?;

    let mut data = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match timeout_at(deadline, stream.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => {
                // Re-scan a few bytes so a tag split across two reads is still found.
                let scan_from = data.len().saturating_sub(8);
                data.extend_from_slice(&chunk[..n]);
                if data.len() >= MAX_RESPONSE_BYTES
                    || find_ci(&data[scan_from..], b"</title").is_some()
                    || is_complete_redirect(&data)
                {
                    break;
                }
            }
            // EOF, error or deadline: work with what arrived so far.
            _ => break,
        }
    }
    data.truncate(MAX_RESPONSE_BYTES);
    (!data.is_empty()).then_some(data)
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Response {
    status: Option<u16>,
    server: Option<String>,
    location: Option<String>,
    title: Option<String>,
}

/// Parses status line, the headers we care about and the HTML title. `None` if not HTTP.
fn parse_response(raw: &[u8]) -> Option<Response> {
    if !raw.starts_with(b"HTTP/") {
        return None;
    }
    let (head, body) = split_head(raw);
    let mut lines = head
        .split(|&b| b == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line));
    let mut response = Response {
        status: lines.next().and_then(status_code),
        ..Response::default()
    };
    for line in lines {
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            continue;
        };
        let (name, value) = (line[..colon].trim_ascii(), line[colon + 1..].trim_ascii());
        if name.eq_ignore_ascii_case(b"server") && response.server.is_none() {
            response.server = clean_text(&decode_text(value), MAX_SERVER_CHARS);
        } else if name.eq_ignore_ascii_case(b"location") && response.location.is_none() {
            response.location = std::str::from_utf8(value).ok().map(str::to_owned);
        }
    }
    response.title = extract_title(body);
    Some(response)
}

/// Splits at the blank line after the headers; without one, everything is header.
fn split_head(raw: &[u8]) -> (&[u8], &[u8]) {
    for separator in [b"\r\n\r\n".as_slice(), b"\n\n"] {
        if let Some(at) = find_ci(raw, separator) {
            return (&raw[..at], &raw[at + separator.len()..]);
        }
    }
    (raw, &[])
}

/// `HTTP/1.1 200 OK` -> 200
fn status_code(status_line: &[u8]) -> Option<u16> {
    let code = status_line
        .split(|&b| b == b' ')
        .filter(|part| !part.is_empty())
        .nth(1)?;
    if code.len() != 3 || !code.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(code).ok()?.parse().ok()
}

/// Headers are complete and announce a redirect: no need to wait for a body.
fn is_complete_redirect(data: &[u8]) -> bool {
    let (head, _) = split_head(data);
    head.len() < data.len()
        && head
            .split(|&b| b == b'\n')
            .next()
            .and_then(status_code)
            .is_some_and(|code| (300..400).contains(&code))
}

fn extract_title(body: &[u8]) -> Option<String> {
    let open = find_ci(body, b"<title")?;
    let after_tag_name = &body[open + b"<title".len()..];
    // `<title>` or `<title attr="...">`, but not e.g. `<titlebar>`.
    if !matches!(
        after_tag_name.first(),
        Some(b'>' | b' ' | b'\t' | b'\r' | b'\n')
    ) {
        return None;
    }
    let content_start = after_tag_name.iter().position(|&b| b == b'>')? + 1;
    let content = &after_tag_name[content_start..];
    let end = find_ci(content, b"</title").unwrap_or(content.len());
    let content = &content[..end.min(MAX_TITLE_BYTES)];
    clean_text(&decode_entities(&decode_text(content)), MAX_TITLE_CHARS)
}

/// UTF-8 if valid, otherwise Latin-1 (old embedded web servers).
fn decode_text(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(text) => text.to_owned(),
        Err(_) => bytes.iter().map(|&b| char::from(b)).collect(),
    }
}

/// Decodes the HTML entities that commonly show up in titles; unknown ones stay as text.
fn decode_entities(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let tail = &rest[amp + 1..];
        let entity = tail
            .find(';')
            .filter(|&end| end <= 10)
            .and_then(|end| Some((entity_char(&tail[..end])?, end)));
        match entity {
            Some((ch, end)) => {
                out.push(ch);
                rest = &tail[end + 1..];
            }
            None => {
                out.push('&');
                rest = tail;
            }
        }
    }
    out.push_str(rest);
    out
}

fn entity_char(name: &str) -> Option<char> {
    if let Some(number) = name.strip_prefix('#') {
        let code = match number.strip_prefix(['x', 'X']) {
            Some(hex) => u32::from_str_radix(hex, 16).ok()?,
            None => number.parse().ok()?,
        };
        return char::from_u32(code);
    }
    Some(match name {
        "amp" => '&',
        "lt" => '<',
        "gt" => '>',
        "quot" => '"',
        "apos" => '\'',
        "nbsp" => ' ',
        "auml" => 'ä',
        "ouml" => 'ö',
        "uuml" => 'ü',
        "Auml" => 'Ä',
        "Ouml" => 'Ö',
        "Uuml" => 'Ü',
        "szlig" => 'ß',
        "copy" => '©',
        "reg" => '®',
        "ndash" => '–',
        "mdash" => '—',
        _ => return None,
    })
}

/// Path to request next if `response` redirects within the same host and port.
/// Redirects to other hosts or schemes are never followed: the target is chosen by the
/// scanned device and must not make us send requests elsewhere.
fn redirect_path(response: &Response, ip: IpAddr, port: u16, current: &str) -> Option<String> {
    if !matches!(response.status, Some(301 | 302 | 303 | 307 | 308)) {
        return None;
    }
    let location = response.location.as_deref()?;
    // Printable ASCII only: this goes into our next request line.
    if location.is_empty()
        || location.len() > MAX_LOCATION_LEN
        || !location.bytes().all(|b| b.is_ascii_graphic())
    {
        return None;
    }
    let location = location.split('#').next().unwrap_or_default();

    let path = if location.starts_with("//") {
        return None;
    } else if location.starts_with('/') {
        location.to_owned()
    } else if let Some(rest) = strip_prefix_ci(location, "http://") {
        let (authority, path) = match rest.find('/') {
            Some(slash) => rest.split_at(slash),
            None => (rest, "/"),
        };
        if !is_same_origin(authority, ip, port) {
            return None;
        }
        path.to_owned()
    } else if has_scheme(location) {
        return None;
    } else {
        // Relative to the directory of the current path.
        let current = current.split('?').next().unwrap_or_default();
        let dir_end = current.rfind('/').map_or(0, |slash| slash + 1);
        format!("{}{location}", &current[..dir_end])
    };
    (path != current && path.starts_with('/')).then_some(path)
}

fn is_same_origin(authority: &str, ip: IpAddr, port: u16) -> bool {
    if let Ok(addr) = authority.parse::<SocketAddr>() {
        return addr == SocketAddr::new(ip, port);
    }
    let host = authority
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(authority);
    port == 80 && host.parse::<IpAddr>() == Ok(ip)
}

/// `scheme:` before any path, query or fragment character.
fn has_scheme(location: &str) -> bool {
    location
        .find([':', '/', '?', '#'])
        .is_some_and(|at| location[at..].starts_with(':'))
}

fn strip_prefix_ci<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    let head = text.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &text[prefix.len()..])
}

/// Position of `needle` in `haystack`, ignoring ASCII case.
fn find_ci(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window.eq_ignore_ascii_case(needle))
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use tokio::net::TcpListener;

    use super::*;

    const IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

    fn title_of(body: &str) -> Option<String> {
        extract_title(body.as_bytes())
    }

    #[test]
    fn parses_status_headers_and_title() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nSERVER:  nginx/1.24.0 \r\n\
                    \r\n<html><head><title>Router Login</title></head></html>";
        let response = parse_response(raw).unwrap();
        assert_eq!(response.status, Some(200));
        assert_eq!(response.server.as_deref(), Some("nginx/1.24.0"));
        assert_eq!(response.title.as_deref(), Some("Router Login"));
        assert_eq!(response.location, None);
    }

    #[test]
    fn tolerates_bare_newlines_and_missing_body() {
        let response = parse_response(b"HTTP/1.0 401 Unauthorized\nServer: lighttpd\n\n").unwrap();
        assert_eq!(response.status, Some(401));
        assert_eq!(response.server.as_deref(), Some("lighttpd"));
        assert_eq!(response.title, None);

        let headers_only = parse_response(b"HTTP/1.1 204 No Content\r\nServer: x").unwrap();
        assert_eq!(headers_only.status, Some(204));
        assert_eq!(headers_only.server.as_deref(), Some("x"));
    }

    #[test]
    fn non_http_data_is_ignored() {
        assert_eq!(parse_response(b"SSH-2.0-OpenSSH_9.6\r\n"), None);
        assert_eq!(parse_response(b""), None);
        assert_eq!(parse_response(&[0xFF; 64]), None);
        // HTTP prefix but nonsense after it must not panic.
        let odd = parse_response(b"HTTP/\xff\xfe\n:\n::\nServer\n\n<title").unwrap();
        assert_eq!(odd, Response::default());
    }

    #[test]
    fn status_codes() {
        assert_eq!(status_code(b"HTTP/1.1 301 Moved Permanently"), Some(301));
        assert_eq!(status_code(b"HTTP/1.1  200"), Some(200));
        for bad in [
            "HTTP/1.1",
            "HTTP/1.1 20",
            "HTTP/1.1 2000 OK",
            "HTTP/1.1 +20 OK",
            "HTTP/1.1 abc",
        ] {
            assert_eq!(status_code(bad.as_bytes()), None, "{bad}");
        }
    }

    #[test]
    fn title_variants() {
        assert_eq!(title_of("<TITLE>Upper</TITLE>").as_deref(), Some("Upper"));
        assert_eq!(
            title_of("<title id=\"t\" lang=en>With attributes</title>").as_deref(),
            Some("With attributes")
        );
        assert_eq!(
            title_of("<title>\r\n   FRITZ!Box \t 7590\n</title>").as_deref(),
            Some("FRITZ!Box 7590")
        );
        // Cut off before the closing tag (size limit or timeout).
        assert_eq!(title_of("<title>Partial ti").as_deref(), Some("Partial ti"));
        assert_eq!(title_of("<title></title>"), None);
        assert_eq!(title_of("<title>   </title>"), None);
        assert_eq!(title_of("<titlebar>no</titlebar>"), None);
        assert_eq!(title_of("<title"), None);
        assert_eq!(title_of("no html here"), None);
    }

    #[test]
    fn title_entities_and_encodings() {
        assert_eq!(
            title_of("<title>Tom &amp; Jerry &lt;3 &#8211; B&uuml;ro &#x41;&nbsp;B</title>")
                .as_deref(),
            Some("Tom & Jerry <3 – Büro A B")
        );
        // Unknown or unterminated entities stay literal.
        assert_eq!(
            title_of("<title>AT&T &bogus; &amp</title>").as_deref(),
            Some("AT&T &bogus; &amp")
        );
        // Latin-1 bytes from an old device.
        assert_eq!(
            extract_title(b"<title>B\xfcro-Drucker</title>").as_deref(),
            Some("Büro-Drucker")
        );
        // Control characters and markup inside the title are just text.
        assert_eq!(
            title_of("<title>a\u{0}b&#0;&#27;<script>x</script></title>").as_deref(),
            Some("a b <script>x</script>")
        );
    }

    #[test]
    fn long_values_are_truncated() {
        let title = title_of(&format!("<title>{}</title>", "x".repeat(5000))).unwrap();
        assert_eq!(title.chars().count(), MAX_TITLE_CHARS);
        let raw = format!("HTTP/1.1 200 OK\r\nServer: {}\r\n\r\n", "s".repeat(5000));
        let server = parse_response(raw.as_bytes()).unwrap().server.unwrap();
        assert_eq!(server.chars().count(), MAX_SERVER_CHARS);
    }

    fn redirect(status: u16, location: &str, port: u16, current: &str) -> Option<String> {
        let response = Response {
            status: Some(status),
            location: Some(location.to_owned()),
            ..Response::default()
        };
        redirect_path(&response, IP, port, current)
    }

    #[test]
    fn follows_same_origin_redirects() {
        assert_eq!(
            redirect(302, "/login.html", 80, "/").as_deref(),
            Some("/login.html")
        );
        assert_eq!(
            redirect(301, "http://192.168.1.1/ui/", 80, "/").as_deref(),
            Some("/ui/")
        );
        assert_eq!(
            redirect(307, "HTTP://192.168.1.1:8080/a?b=1#frag", 8080, "/").as_deref(),
            Some("/a?b=1")
        );
        assert_eq!(
            redirect(302, "http://192.168.1.1", 80, "/x").as_deref(),
            Some("/")
        );
        // Relative to the current directory.
        assert_eq!(redirect(302, "login", 80, "/").as_deref(), Some("/login"));
        assert_eq!(
            redirect(302, "index.htm", 80, "/admin/start?x=/y").as_deref(),
            Some("/admin/index.htm")
        );
        // A URL inside the query string is not a scheme.
        assert_eq!(
            redirect(302, "/login?next=http://evil.example/", 80, "/").as_deref(),
            Some("/login?next=http://evil.example/")
        );
    }

    #[test]
    fn refuses_other_redirects() {
        // Other host, port or scheme.
        assert_eq!(redirect(302, "http://192.168.1.2/", 80, "/"), None);
        assert_eq!(redirect(302, "http://192.168.1.1:8080/", 80, "/"), None);
        assert_eq!(redirect(302, "http://192.168.1.1/", 8080, "/"), None);
        assert_eq!(redirect(302, "http://example.com/", 80, "/"), None);
        assert_eq!(
            redirect(302, "http://192.168.1.1@example.com/", 80, "/"),
            None
        );
        assert_eq!(redirect(302, "https://192.168.1.1/", 80, "/"), None);
        assert_eq!(redirect(302, "//example.com/", 80, "/"), None);
        assert_eq!(redirect(302, "ftp://192.168.1.1/", 80, "/"), None);
        assert_eq!(redirect(302, "javascript:alert(1)", 80, "/"), None);
        // Header injection and junk.
        assert_eq!(redirect(302, "/a\r\nX-Evil: 1", 80, "/"), None);
        assert_eq!(redirect(302, "/a b", 80, "/"), None);
        assert_eq!(redirect(302, "/caf\u{e9}", 80, "/"), None);
        assert_eq!(redirect(302, "", 80, "/"), None);
        assert_eq!(
            redirect(302, &format!("/{}", "a".repeat(600)), 80, "/"),
            None
        );
        // Not a redirect status, or a redirect to itself.
        assert_eq!(redirect(200, "/login", 80, "/"), None);
        assert_eq!(redirect(304, "/login", 80, "/"), None);
        assert_eq!(redirect(302, "/", 80, "/"), None);
    }

    #[test]
    fn redirect_detection_needs_complete_headers() {
        assert!(is_complete_redirect(
            b"HTTP/1.1 302 Found\r\nLocation: /x\r\n\r\n"
        ));
        assert!(!is_complete_redirect(
            b"HTTP/1.1 302 Found\r\nLocation: /x\r\n"
        ));
        assert!(!is_complete_redirect(b"HTTP/1.1 200 OK\r\n\r\n<html>"));
    }

    #[test]
    fn known_service_names() {
        assert_eq!(service_name(445), "smb");
        assert_eq!(service_name(8443), "https-alt");
        assert_eq!(service_name(1234), "unknown");
    }

    /// Serves the given raw responses, one per accepted connection.
    async fn serve(responses: Vec<&'static [u8]>) -> u16 {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            for response in responses {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0u8; 1024];
                let _ = stream.read(&mut request).await;
                let _ = stream.write_all(response).await;
            }
        });
        port
    }

    #[tokio::test]
    async fn fetches_title_through_a_redirect() {
        let port = serve(vec![
            b"HTTP/1.1 302 Found\r\nServer: tiny/1.0\r\nLocation: /home\r\n\r\n",
            b"HTTP/1.1 200 OK\r\n\r\n<html><title>Home &amp; Garden</title><body>...",
        ])
        .await;
        let info = http_info(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert_eq!(info.status, Some(200));
        assert_eq!(info.server.as_deref(), Some("tiny/1.0"));
        assert_eq!(info.title.as_deref(), Some("Home & Garden"));
    }

    #[tokio::test]
    async fn foreign_redirect_is_reported_but_not_followed() {
        let port = serve(vec![
            b"HTTP/1.1 301 Moved\r\nLocation: https://example.com/\r\n\r\n",
        ])
        .await;
        let info = http_info(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert_eq!(info.status, Some(301));
        assert_eq!(info.title, None);
    }

    #[tokio::test]
    async fn non_http_service_yields_nothing() {
        let port = serve(vec![b"220 mail.example ESMTP ready\r\n"]).await;
        let info = http_info(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
            Duration::from_secs(2),
        )
        .await;
        assert_eq!(info, None);
    }

    #[tokio::test]
    async fn detects_open_and_closed_ports() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let open = listener.local_addr().unwrap().port();
        // Bind and drop a second listener to get a port that is closed right now.
        let closed = {
            let temp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            temp.local_addr().unwrap().port()
        };
        let found = connectable(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            &[open, closed],
            Duration::from_secs(2),
        )
        .await;
        assert_eq!(found, [open]);
    }
}
