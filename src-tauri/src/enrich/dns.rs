//! Reverse DNS (PTR) lookup, sent directly to the system's DNS servers over UDP.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use super::wire::{build_ptr_query, parse_ptr_response};
use super::{clean_text, random_u16, udp_exchange};

const DNS_PORT: u16 = 53;
/// A second server is only asked if the first one fails or stays silent.
const MAX_SERVERS: usize = 2;
const MAX_HOSTNAME_CHARS: usize = 253;

/// Asks `servers` in order for the PTR record of `ip`.
pub async fn reverse_lookup(ip: IpAddr, servers: &[Ipv4Addr], timeout: Duration) -> Option<String> {
    for server in servers.iter().take(MAX_SERVERS) {
        let id = random_u16();
        let query = build_ptr_query(id, ip, true, false);
        let peer = SocketAddr::from((*server, DNS_PORT));
        let Ok(reply) = udp_exchange(peer, &query, timeout).await else {
            continue;
        };
        match parse_ptr_response(&reply, id) {
            // A definite answer (name or "no such name") ends the search.
            Ok(name) => return name.and_then(|n| clean_text(&n, MAX_HOSTNAME_CHARS)),
            Err(_) => continue,
        }
    }
    None
}
