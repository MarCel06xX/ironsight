//! Banner grabbing on open ports. Most services that talk first (FTP, SSH, SMTP, POP3, IMAP,
//! VNC, MySQL, ...) are read passively: we send nothing and keep what arrives within a short
//! wait. HTTP ports get a `GET /` through the existing HTTP probe (`enrich::services`).
//! Everything received is untrusted: see [`sanitize`].

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout_at};

use super::names::service_name;
use crate::enrich::{clean_text, services};
use crate::scan::HttpInfo;

/// Bytes read from a service at most.
pub const MAX_BANNER_BYTES: usize = 1024;
/// Characters kept after cleaning.
pub const MAX_BANNER_CHARS: usize = 256;
/// Once data arrived, more must follow within this pause (multi-line greetings come in one
/// burst); otherwise the banner is complete.
const IDLE_GAP: Duration = Duration::from_millis(200);
/// Hard limit after the first byte, against services that trickle data.
const MAX_EXTRA: Duration = Duration::from_secs(1);
/// In binary data, printable runs shorter than this are dropped as noise.
const MIN_TEXT_RUN: usize = 4;

/// Ports where the client always speaks first (TLS-wrapped services, Windows RPC/SMB/RDP,
/// DNS, LDAP, Kerberos): a passive read would only wait for nothing.
const CLIENT_FIRST: &[u16] = &[
    53, 88, 135, 139, 389, 443, 445, 464, 465, 636, 853, 990, 992, 993, 995, 2376, 3268, 3269,
    3389, 4443, 5001, 5061, 5671, 5986, 6443, 6697, 7443, 8443, 8444, 8883, 9443, 10443, 16993,
];

/// How details are read from an open port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// `GET /` for status, `Server` header and title.
    Http,
    /// Read what the service sends by itself.
    Passive,
    /// Nothing to read without speaking the protocol.
    None,
}

pub fn method(port: u16) -> Method {
    if matches!(service_name(port), Some("http" | "http-alt")) {
        Method::Http
    } else if CLIENT_FIRST.binary_search(&port).is_ok() {
        Method::None
    } else {
        Method::Passive
    }
}

/// What was learned from an open port besides "open".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Details {
    pub banner: Option<String>,
    pub http: Option<HttpInfo>,
}

/// How long to wait for a greeting: the probe timeout, kept within 0.5-2 s.
pub fn greeting_wait(timeout: Duration) -> Duration {
    timeout.clamp(Duration::from_millis(500), Duration::from_secs(2))
}

/// Reads the details of an open port over `stream` (or, for HTTP, new connections).
pub async fn grab(addr: SocketAddr, stream: TcpStream, timeout: Duration) -> Details {
    match method(addr.port()) {
        Method::Http => {
            // The HTTP probe opens its own connections (it follows same-origin redirects).
            drop(stream);
            Details {
                banner: None,
                http: services::http_info(addr.ip(), addr.port(), timeout).await,
            }
        }
        Method::Passive => Details {
            banner: read_passive(stream, greeting_wait(timeout)).await,
            http: None,
        },
        Method::None => Details::default(),
    }
}

/// Connects again and grabs the details of a port already known to be open (ports found
/// open during host discovery). `None` if the port no longer accepts connections.
pub async fn grab_open(ip: IpAddr, port: u16, timeout: Duration) -> Details {
    let addr = SocketAddr::new(ip, port);
    if method(port) == Method::Http {
        return Details {
            banner: None,
            http: services::http_info(ip, port, timeout).await,
        };
    }
    match super::probe::connect(addr, timeout).await {
        super::probe::Connect::Open(stream) => grab(addr, stream, timeout).await,
        _ => Details::default(),
    }
}

/// Waits up to `wait` for the service to send something, then collects what follows in the
/// same burst (up to [`MAX_BANNER_BYTES`]). Nothing is ever sent.
pub async fn read_passive(mut stream: TcpStream, wait: Duration) -> Option<String> {
    let mut data = Vec::new();
    let mut chunk = [0u8; 512];
    let mut deadline = Instant::now() + wait;
    let mut hard_limit = None;
    while data.len() < MAX_BANNER_BYTES {
        match timeout_at(deadline, stream.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => {
                let take = n.min(MAX_BANNER_BYTES - data.len());
                data.extend_from_slice(&chunk[..take]);
                let now = Instant::now();
                let limit = *hard_limit.get_or_insert(now + MAX_EXTRA);
                deadline = (now + IDLE_GAP).min(limit);
            }
            // EOF, error, or quiet for long enough.
            _ => break,
        }
    }
    // Dropping the stream resets the connection (SO_LINGER 0 from the probe).
    sanitize(&data)
}

/// Turns raw bytes from a service into one line of plain text, or `None` if nothing
/// readable is left:
/// - Telnet option negotiation (IAC sequences) and ANSI escape sequences are removed.
/// - Invalid UTF-8 is replaced, never trusted.
/// - If the data contains binary parts (control characters, invalid UTF-8), only printable
///   runs of at least 4 characters are kept, like `strings` does.
/// - Line breaks and control characters become single spaces, invisible and bidi characters
///   are dropped, the result is cut to [`MAX_BANNER_CHARS`] characters.
pub fn sanitize(raw: &[u8]) -> Option<String> {
    let raw = trim_cut_char(&raw[..raw.len().min(MAX_BANNER_BYTES)]);
    let without_escapes = strip_ansi(&strip_telnet(raw));
    let text = String::from_utf8_lossy(&without_escapes);
    let is_binary = |c: char| {
        c == char::REPLACEMENT_CHARACTER || (c.is_control() && !matches!(c, '\t' | '\n' | '\r'))
    };
    let text = if text.chars().any(is_binary) {
        text.split(is_binary)
            .filter(|run| run.trim().chars().count() >= MIN_TEXT_RUN)
            .collect::<Vec<_>>()
            .join(" ")
    } else {
        text.into_owned()
    };
    clean_text(&text, MAX_BANNER_CHARS)
}

/// Drops a multi-byte UTF-8 character cut off at the end (the byte limit can split one).
fn trim_cut_char(raw: &[u8]) -> &[u8] {
    for back in 1..=raw.len().min(3) {
        let at = raw.len() - back;
        let byte = raw[at];
        if byte & 0xc0 == 0x80 {
            continue; // continuation byte, the lead byte is further back
        }
        let needed = match byte {
            0xc0..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf7 => 4,
            _ => 1,
        };
        return if needed > back { &raw[..at] } else { raw };
    }
    raw
}

const IAC: u8 = 255;
const SB: u8 = 250;
const SE: u8 = 240;
const WILL: u8 = 251;
const DONT: u8 = 254;

/// Removes Telnet commands: `IAC IAC` is a literal 255, `IAC WILL/WONT/DO/DONT <opt>`,
/// `IAC SB ... IAC SE` and two-byte `IAC <cmd>`.
fn strip_telnet(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if raw[i] != IAC {
            out.push(raw[i]);
            i += 1;
            continue;
        }
        match raw.get(i + 1).copied() {
            Some(IAC) => {
                out.push(IAC);
                i += 2;
            }
            Some(WILL..=DONT) => i += 3,
            Some(SB) => {
                // Skip to after `IAC SE` (or to the end if it never comes).
                let end = raw[i + 2..]
                    .windows(2)
                    .position(|w| w == [IAC, SE])
                    .map_or(raw.len(), |at| i + 2 + at + 2);
                i = end;
            }
            Some(_) => i += 2,
            None => i += 1,
        }
    }
    out
}

/// Removes ANSI escape sequences (`ESC [ ... final`), as used for colored login banners.
fn strip_ansi(raw: &[u8]) -> Vec<u8> {
    const ESC: u8 = 0x1b;
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == ESC && raw.get(i + 1) == Some(&b'[') {
            // Parameters and intermediates, then one final byte in 0x40..=0x7E.
            let rest = &raw[i + 2..];
            let len = rest
                .iter()
                .position(|b| (0x40..=0x7e).contains(b))
                .map_or(rest.len(), |at| at + 1);
            i += 2 + len;
        } else {
            out.push(raw[i]);
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    use super::*;

    fn clean(raw: &[u8]) -> Option<String> {
        sanitize(raw)
    }

    #[test]
    fn plain_greetings_pass_through_as_one_line() {
        assert_eq!(
            clean(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n").as_deref(),
            Some("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5")
        );
        assert_eq!(
            clean(b"220-mail.example ESMTP\r\n220-Welcome\r\n220 ready\r\n").as_deref(),
            Some("220-mail.example ESMTP 220-Welcome 220 ready")
        );
        // Short text without binary parts is kept.
        assert_eq!(clean(b"OK\n").as_deref(), Some("OK"));
        assert_eq!(clean(b"+OK POP3 ready").as_deref(), Some("+OK POP3 ready"));
    }

    #[test]
    fn nothing_readable_is_none() {
        assert_eq!(clean(b""), None);
        assert_eq!(clean(b"\r\n\t  "), None);
        assert_eq!(clean(&[0, 1, 2, 3, 0x7f]), None);
        assert_eq!(clean(&[0xff, 0xfb, 0x01, 0xff, 0xfd, 0x03]), None);
    }

    #[test]
    fn control_characters_become_spaces_or_separators() {
        // Escape sequences other than CSI leave no control character behind.
        assert_eq!(
            clean(b"login:\x07\x08 ready\x1bX").as_deref(),
            Some("login: ready")
        );
        assert_eq!(clean(b"abc\x00def").as_deref(), None);
        assert_eq!(clean(b"abcd\x00efgh").as_deref(), Some("abcd efgh"));
    }

    #[test]
    fn invisible_and_bidi_characters_are_removed() {
        let raw = "FTP \u{202e}gnp.exe\u{200b} ready\u{feff}".as_bytes();
        assert_eq!(clean(raw).as_deref(), Some("FTP gnp.exe ready"));
    }

    #[test]
    fn non_utf8_is_handled_safely() {
        // Latin-1 text: the invalid byte is dropped, the readable parts stay.
        assert_eq!(
            clean(b"220 Willkommen auf dem Server f\xfcr Drucker").as_deref(),
            Some("220 Willkommen auf dem Server f r Drucker")
        );
        // Truncated multi-byte sequence at the end.
        assert_eq!(clean(b"Gr\xc3\xbc\xc3").as_deref(), Some("Grü"));
        // Valid UTF-8 survives.
        assert_eq!(
            clean("Büro-NAS bereit".as_bytes()).as_deref(),
            Some("Büro-NAS bereit")
        );
    }

    #[test]
    fn binary_protocols_keep_their_readable_runs() {
        // MySQL handshake: length header, protocol 10, version, salt, plugin name.
        let mut raw = vec![0x4a, 0, 0, 0, 0x0a];
        raw.extend_from_slice(b"8.0.36\0");
        raw.extend_from_slice(&[0x08, 0, 0, 0, 0x12, 0x9f, 0x01, 0xc3, 0x28, 0x00]);
        raw.extend_from_slice(b"caching_sha2_password\0");
        assert_eq!(clean(&raw).as_deref(), Some("8.0.36 caching_sha2_password"));
        // VNC
        assert_eq!(clean(b"RFB 003.008\n").as_deref(), Some("RFB 003.008"));
    }

    #[test]
    fn telnet_negotiation_is_stripped() {
        let mut raw = vec![IAC, WILL, 1, IAC, 253, 31, IAC, SB, 24, 1, IAC, SE];
        raw.extend_from_slice(b"\r\nRouter login: ");
        raw.extend_from_slice(&[IAC, 241]); // IAC NOP
        assert_eq!(clean(&raw).as_deref(), Some("Router login:"));
        // A literal 255 (IAC IAC) is data; as a lone byte it is invalid UTF-8.
        assert_eq!(strip_telnet(&[b'a', IAC, IAC, b'b']), [b'a', IAC, b'b']);
        // Unterminated subnegotiation and a trailing IAC do not panic.
        assert_eq!(strip_telnet(&[b'x', IAC, SB, 1, 2]), b"x");
        assert_eq!(strip_telnet(&[b'x', IAC]), b"x");
        assert_eq!(strip_telnet(&[IAC, WILL]), b"");
    }

    #[test]
    fn cut_characters_at_the_end_are_dropped() {
        assert_eq!(trim_cut_char(b"ab\xc3"), b"ab");
        assert_eq!(trim_cut_char(b"ab\xe2\x82"), b"ab");
        assert_eq!(trim_cut_char("ab€".as_bytes()), "ab€".as_bytes());
        assert_eq!(trim_cut_char(b"abc"), b"abc");
        assert_eq!(trim_cut_char(b""), b"");
        // Stray continuation bytes are not a cut character (they are invalid anyway).
        assert_eq!(trim_cut_char(b"\x80\x80\x80"), b"\x80\x80\x80");
    }

    #[test]
    fn ansi_colors_are_stripped() {
        assert_eq!(
            clean(b"\x1b[1;32mWelcome\x1b[0m to \x1b[31mNAS\x1b[0m").as_deref(),
            Some("Welcome to NAS")
        );
        assert_eq!(strip_ansi(b"a\x1b[12"), b"a");
    }

    #[test]
    fn length_is_limited() {
        let long = "x".repeat(5000);
        let banner = clean(long.as_bytes()).unwrap();
        assert_eq!(banner.chars().count(), MAX_BANNER_CHARS);
        // Multi-byte characters are cut on a character boundary.
        let wide = "ü".repeat(400);
        assert_eq!(
            clean(wide.as_bytes()).unwrap().chars().count(),
            MAX_BANNER_CHARS
        );
    }

    #[test]
    fn markup_is_kept_as_text() {
        // Escaping is the job of the frontend/export; the sanitizer keeps it verbatim.
        assert_eq!(
            clean(b"<script>alert(1)</script>").as_deref(),
            Some("<script>alert(1)</script>")
        );
    }

    #[test]
    fn methods() {
        assert_eq!(method(80), Method::Http);
        assert_eq!(method(8080), Method::Http);
        assert_eq!(method(8000), Method::Http);
        assert_eq!(method(443), Method::None);
        assert_eq!(method(3389), Method::None);
        assert_eq!(method(22), Method::Passive);
        assert_eq!(method(21), Method::Passive);
        // Unknown ports are read passively; nothing is ever sent to them.
        assert_eq!(method(12345), Method::Passive);
        assert_eq!(method(9100), Method::Passive);
        assert!(CLIENT_FIRST.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn greeting_wait_is_bounded() {
        assert_eq!(
            greeting_wait(Duration::from_millis(100)),
            Duration::from_millis(500)
        );
        assert_eq!(
            greeting_wait(Duration::from_secs(1)),
            Duration::from_secs(1)
        );
        assert_eq!(
            greeting_wait(Duration::from_secs(10)),
            Duration::from_secs(2)
        );
    }

    /// Accepts one connection and runs `serve` on it.
    async fn server<F, Fut>(serve: F) -> SocketAddr
    where
        F: FnOnce(TcpStream) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send,
    {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            serve(stream).await;
        });
        addr
    }

    async fn passive(addr: SocketAddr, wait: Duration) -> Option<String> {
        let stream = TcpStream::connect(addr).await.unwrap();
        read_passive(stream, wait).await
    }

    #[tokio::test]
    async fn reads_a_multi_part_greeting() {
        let addr = server(|mut s| async move {
            s.write_all(b"220-first line\r\n").await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
            s.write_all(b"220 second line\r\n").await.unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
        })
        .await;
        let started = Instant::now();
        let banner = passive(addr, Duration::from_secs(1)).await;
        assert_eq!(banner.as_deref(), Some("220-first line 220 second line"));
        // Stops after the burst, not after the wait or the server's pause.
        assert!(started.elapsed() < Duration::from_millis(800));
    }

    #[tokio::test]
    async fn silent_service_gives_none_after_the_wait() {
        let addr = server(|stream| async move {
            // Keep the connection open without sending anything.
            let _open = stream;
            tokio::time::sleep(Duration::from_secs(5)).await;
        })
        .await;
        let started = Instant::now();
        assert_eq!(passive(addr, Duration::from_millis(300)).await, None);
        let took = started.elapsed();
        assert!(took >= Duration::from_millis(290) && took < Duration::from_secs(1));
    }

    #[tokio::test]
    async fn trickling_service_is_cut_off() {
        let addr = server(|mut s| async move {
            for _ in 0..100 {
                if s.write_all(b"x").await.is_err() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await;
        let started = Instant::now();
        let banner = passive(addr, Duration::from_secs(1)).await.unwrap();
        assert!(started.elapsed() < Duration::from_millis(1500));
        assert!(banner.len() < 20, "{banner}");
    }

    #[tokio::test]
    async fn reads_at_most_the_byte_limit() {
        let addr = server(|mut s| async move {
            let _ = s.write_all(&[b'a'; 10_000]).await;
            tokio::time::sleep(Duration::from_secs(5)).await;
        })
        .await;
        let banner = passive(addr, Duration::from_secs(1)).await.unwrap();
        assert_eq!(banner.len(), MAX_BANNER_CHARS);
    }

    /// HTTP ports are recognized by number (`method`), so a random test port cannot take
    /// that path; this checks the shared HTTP probe it calls.
    #[tokio::test]
    async fn http_details_come_from_the_shared_http_probe() {
        let addr = server(|mut s| async move {
            let mut request = [0u8; 512];
            let _ = s.read(&mut request).await;
            let _ = s
                .write_all(b"HTTP/1.1 200 OK\r\nServer: tiny\r\n\r\n<title>Hi</title>")
                .await;
        })
        .await;
        let info = services::http_info(addr.ip(), addr.port(), Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(info.server.as_deref(), Some("tiny"));
        assert_eq!(info.title.as_deref(), Some("Hi"));
    }

    #[tokio::test]
    async fn grab_reads_passive_banners() {
        let addr = server(|mut s| async move {
            s.write_all(b"SSH-2.0-dropbear_2022.83\r\n").await.unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
        })
        .await;
        // Random test ports are unknown, so they are read passively.
        assert_eq!(method(addr.port()), Method::Passive);
        let stream = TcpStream::connect(addr).await.unwrap();
        let details = grab(addr, stream, Duration::from_secs(1)).await;
        assert_eq!(details.banner.as_deref(), Some("SSH-2.0-dropbear_2022.83"));
        assert_eq!(details.http, None);
    }
}
