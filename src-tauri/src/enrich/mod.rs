//! Enrichment of discovered hosts: names (DNS, mDNS, NetBIOS), vendor, open services and
//! HTTP details. All protocol code is hand-written; replies are treated as untrusted input.

use std::hash::{BuildHasher, Hasher, RandomState};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::task::JoinSet;

use crate::platform::{Adapter, Ipv4Net};
use crate::ports::PortState;
use crate::ports::banner::{self, Method};
use crate::scan::engine::HostProbes;
use crate::scan::{HostNames, HostResult};

pub mod dns;
pub mod mdns;
pub mod netbios;
pub mod oui;
pub mod services;
mod wire;

/// Lookups use the scan's per-host timeout, kept within these bounds.
const MIN_LOOKUP_TIMEOUT: Duration = Duration::from_millis(500);
const MAX_LOOKUP_TIMEOUT: Duration = Duration::from_millis(3000);
/// Large enough for any reply we parse (DNS without EDNS: 512, NBSTAT: a few hundred bytes).
const MAX_DATAGRAM: usize = 4096;

/// A local subnet and the DNS servers configured on its adapter.
struct Link {
    net: Ipv4Net,
    dns_servers: Vec<Ipv4Addr>,
}

/// The real [`HostProbes`] implementation used by the app.
pub struct NetEnricher {
    links: Vec<Link>,
    /// Read banners and HTTP titles of open ports.
    banners: bool,
}

impl NetEnricher {
    pub fn new(adapters: &[Adapter], banners: bool) -> Self {
        let links = adapters
            .iter()
            .flat_map(|adapter| {
                adapter.ipv4.iter().map(|net| Link {
                    net: net.clone(),
                    dns_servers: adapter.dns_servers.clone(),
                })
            })
            .collect();
        Self { links, banners }
    }

    fn is_on_link(&self, ip: Ipv4Addr) -> bool {
        self.links.iter().any(|link| link.net.contains(ip))
    }

    /// DNS servers to ask about `ip`: those of the adapter the host is attached to come
    /// first (a home router knows its own clients), then all others, without duplicates.
    fn dns_servers_for(&self, ip: Option<Ipv4Addr>) -> Vec<Ipv4Addr> {
        let on_link = |link: &&Link| ip.is_some_and(|ip| link.net.contains(ip));
        let preferred = self.links.iter().filter(on_link);
        let mut servers = Vec::new();
        for server in preferred
            .chain(self.links.iter())
            .flat_map(|link| &link.dns_servers)
        {
            if !servers.contains(server) {
                servers.push(*server);
            }
        }
        servers
    }
}

impl HostProbes for NetEnricher {
    async fn tcp_ports(&self, ip: IpAddr, timeout: Duration) -> Vec<(u16, PortState)> {
        services::probe_ports(ip, timeout).await
    }

    async fn reverse_dns(&self, ip: IpAddr, timeout: Duration) -> Option<String> {
        let timeout = timeout.clamp(MIN_LOOKUP_TIMEOUT, MAX_LOOKUP_TIMEOUT);
        let v4 = match ip {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        };
        dns::reverse_lookup(ip, &self.dns_servers_for(v4), timeout).await
    }

    async fn enrich(&self, mut host: HostResult, timeout: Duration) -> HostResult {
        let timeout = timeout.clamp(MIN_LOOKUP_TIMEOUT, MAX_LOOKUP_TIMEOUT);
        let ip = host.ip;
        let v4 = match ip {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        };
        let dns_servers = self.dns_servers_for(v4);
        // mDNS is link-local by design; responders ignore queries from other subnets.
        let use_mdns = v4.is_some_and(|v4| self.is_on_link(v4));
        let open_ports: Vec<u16> = host.services.iter().map(|s| s.port).collect();

        let details = async {
            match self.banners {
                true => tokio::join!(
                    services::http_infos(ip, &open_ports, timeout),
                    passive_banners(ip, &open_ports, timeout),
                ),
                false => (Vec::new(), Vec::new()),
            }
        };
        let (dns_name, node_status, mdns_name, (http, banners)) = tokio::join!(
            dns::reverse_lookup(ip, &dns_servers, timeout),
            netbios::node_status(ip, timeout),
            async {
                match use_mdns {
                    true => mdns::reverse_lookup(ip, timeout).await,
                    false => None,
                }
            },
            details,
        );

        let node_status = node_status.unwrap_or_default();
        host.names = HostNames {
            dns: dns_name,
            mdns: mdns_name,
            netbios: node_status.name,
        };
        host.workgroup = node_status.workgroup;
        // NBSTAT also reveals the MAC of hosts behind a router, where ARP cannot.
        if let (None, Some(mac)) = (host.mac, node_status.mac) {
            host.set_mac(mac);
        }
        for (port, info) in http {
            if let Some(service) = host.services.iter_mut().find(|s| s.port == port) {
                service.http = Some(info);
            }
        }
        for (port, text) in banners {
            if let Some(service) = host.services.iter_mut().find(|s| s.port == port) {
                service.banner = Some(text);
            }
        }
        host.pick_hostname();
        host
    }
}

/// Greetings of the open ports whose services talk first (see `ports::banner`). The
/// discovery check closed its connections at once, so this connects again.
async fn passive_banners(ip: IpAddr, open: &[u16], timeout: Duration) -> Vec<(u16, String)> {
    let mut grabs = JoinSet::new();
    for &port in open
        .iter()
        .filter(|&&port| banner::method(port) == Method::Passive)
    {
        grabs
            .spawn(async move { Some((port, banner::grab_open(ip, port, timeout).await.banner?)) });
    }
    let mut banners = Vec::new();
    while let Some(result) = grabs.join_next().await {
        if let Ok(Some(found)) = result {
            banners.push(found);
        }
    }
    banners
}

/// Sends one datagram from a fresh ephemeral port and returns the first reply from `peer`.
/// The socket is connected, so datagrams from other senders are dropped by the OS.
async fn udp_exchange(peer: SocketAddr, request: &[u8], timeout: Duration) -> io::Result<Vec<u8>> {
    let local: SocketAddr = match peer {
        SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let socket = UdpSocket::bind(local).await?;
    socket.connect(peer).await?;
    socket.send(request).await?;
    let mut reply = vec![0u8; MAX_DATAGRAM];
    let len = tokio::time::timeout(timeout, socket.recv(&mut reply))
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
    reply.truncate(len);
    Ok(reply)
}

/// Unpredictable transaction ID without a random-number crate: `RandomState` is seeded
/// from OS randomness.
fn random_u16() -> u16 {
    RandomState::new().build_hasher().finish() as u16
}

/// Normalizes a string received from the network for display: control characters and
/// whitespace runs become single spaces, invisible/bidi-override characters are dropped,
/// and the result is trimmed and limited to `max_chars`. Empty results become `None`.
pub(crate) fn clean_text(input: &str, max_chars: usize) -> Option<String> {
    let mut out = String::new();
    let mut chars = 0;
    let mut pending_space = false;
    for ch in input.chars() {
        if is_invisible(ch) {
            continue;
        }
        if ch.is_whitespace() || ch.is_control() {
            pending_space = chars > 0;
            continue;
        }
        let needed = 1 + usize::from(pending_space);
        if chars + needed > max_chars {
            break;
        }
        if pending_space {
            out.push(' ');
            pending_space = false;
        }
        out.push(ch);
        chars += needed;
    }
    (!out.is_empty()).then_some(out)
}

/// Zero-width and bidirectional control characters that could disguise displayed text.
fn is_invisible(ch: char) -> bool {
    matches!(
        ch,
        '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adapter(addr: [u8; 4], prefix: u8, dns: &[[u8; 4]]) -> Adapter {
        Adapter {
            id: String::new(),
            name: String::new(),
            description: String::new(),
            mac: None,
            ipv4: vec![Ipv4Net::new(Ipv4Addr::from(addr), prefix)],
            dns_servers: dns.iter().map(|d| Ipv4Addr::from(*d)).collect(),
            has_gateway: true,
        }
    }

    #[test]
    fn clean_text_normalizes_whitespace_and_controls() {
        assert_eq!(
            clean_text("  a \t\r\n b\u{0}c  ", 50).as_deref(),
            Some("a b c")
        );
        assert_eq!(clean_text("\u{1b}[31mred", 50).as_deref(), Some("[31mred"));
        assert_eq!(clean_text("", 50), None);
        assert_eq!(clean_text(" \n\u{7f} ", 50), None);
    }

    #[test]
    fn clean_text_drops_invisible_characters() {
        assert_eq!(
            clean_text("exe.\u{202e}fdp\u{200b}\u{feff}x", 50).as_deref(),
            Some("exe.fdpx")
        );
    }

    #[test]
    fn clean_text_truncates_by_characters() {
        assert_eq!(clean_text("äöüß€", 3).as_deref(), Some("äöü"));
        // No dangling space at the cut.
        assert_eq!(clean_text("ab cd", 3).as_deref(), Some("ab"));
        assert_eq!(clean_text("ab cd", 4).as_deref(), Some("ab c"));
        assert_eq!(clean_text("abc", 0), None);
    }

    #[test]
    fn transaction_ids_vary() {
        let ids: std::collections::HashSet<u16> = (0..64).map(|_| random_u16()).collect();
        assert!(ids.len() > 32);
    }

    #[test]
    fn dns_servers_of_the_hosts_adapter_come_first() {
        let enricher = NetEnricher::new(
            &[
                adapter([10, 8, 0, 2], 24, &[[10, 8, 0, 1], [1, 1, 1, 1]]),
                adapter([192, 168, 178, 20], 24, &[[192, 168, 178, 1], [1, 1, 1, 1]]),
            ],
            true,
        );
        let lan_host = Ipv4Addr::new(192, 168, 178, 50);
        assert_eq!(
            enricher.dns_servers_for(Some(lan_host)),
            [[192, 168, 178, 1], [1, 1, 1, 1], [10, 8, 0, 1]].map(Ipv4Addr::from)
        );
        // Off-link or non-IPv4 targets: adapter order.
        let expected = [[10, 8, 0, 1], [1, 1, 1, 1], [192, 168, 178, 1]].map(Ipv4Addr::from);
        assert_eq!(
            enricher.dns_servers_for(Some(Ipv4Addr::new(8, 8, 8, 8))),
            expected
        );
        assert_eq!(enricher.dns_servers_for(None), expected);

        assert!(enricher.is_on_link(lan_host));
        assert!(!enricher.is_on_link(Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[tokio::test]
    async fn udp_exchange_returns_the_reply_or_times_out() {
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let peer = server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 16];
            // Answer the first datagram only.
            let (len, from) = server.recv_from(&mut buf).await.unwrap();
            server.send_to(&buf[..len], from).await.unwrap();
            let _ = server.recv_from(&mut buf).await;
            std::future::pending::<()>().await;
        });
        let reply = udp_exchange(peer, b"ping", Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(reply, b"ping");

        let error = udp_exchange(peer, b"ping", Duration::from_millis(100))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }
}
