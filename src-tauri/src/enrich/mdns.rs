//! mDNS reverse lookup (RFC 6762): a PTR query for the host's reverse name, sent straight to
//! the host on UDP 5353 from an ephemeral port. Responders treat that as a one-shot legacy
//! query and answer by unicast, which also passes the local firewall as a normal reply.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use super::wire::{build_ptr_query, parse_ptr_response};
use super::{clean_text, random_u16, udp_exchange};

const MDNS_PORT: u16 = 5353;
const MAX_HOSTNAME_CHARS: usize = 253;

/// Returns the host's mDNS name, e.g. `macbook.local`.
pub async fn reverse_lookup(ip: IpAddr, timeout: Duration) -> Option<String> {
    let id = random_u16();
    let query = build_ptr_query(id, ip, false, true);
    let reply = udp_exchange(SocketAddr::new(ip, MDNS_PORT), &query, timeout)
        .await
        .ok()?;
    let name = parse_ptr_response(&reply, id).ok()??;
    clean_text(&name, MAX_HOSTNAME_CHARS)
}

#[cfg(test)]
mod tests {
    use super::super::wire::WireError;
    use super::super::wire::tests::{header, labels, record};
    use super::*;

    const TYPE_PTR: u16 = 12;
    const TYPE_A: u16 = 1;
    /// Class IN with the mDNS cache-flush bit.
    const IN_FLUSH: u16 = 0x8001;
    /// Authoritative response, as mDNS responders send it.
    const FLAGS: u16 = 0x8400;
    const REVERSE: &str = "23.1.168.192.in-addr.arpa";

    #[test]
    fn legacy_unicast_response_with_question() {
        // One-shot queries get the question echoed back.
        let mut packet = header(0x1234, FLAGS, 1, 1);
        packet.extend(labels(REVERSE));
        packet.extend_from_slice(&[0, 12, 0, 1]);
        packet.extend(record(
            &[0xC0, 0x0C],
            TYPE_PTR,
            1,
            &labels("Janniks-MacBook-Pro.local"),
        ));
        assert_eq!(
            parse_ptr_response(&packet, 0x1234),
            Ok(Some("Janniks-MacBook-Pro.local".into()))
        );
    }

    #[test]
    fn response_without_question_and_with_cache_flush_bit() {
        let mut packet = header(0x1234, FLAGS, 0, 1);
        packet.extend(record(
            &labels(REVERSE),
            TYPE_PTR,
            IN_FLUSH,
            &labels("raspberrypi.local"),
        ));
        assert_eq!(
            parse_ptr_response(&packet, 0x1234),
            Ok(Some("raspberrypi.local".into()))
        );
    }

    #[test]
    fn target_compressed_against_an_earlier_record() {
        // An address record for "printer.local" first, then the PTR pointing back at it.
        let mut packet = header(1, FLAGS, 0, 2);
        let owner_at = packet.len() as u8;
        packet.extend(record(
            &labels("printer.local"),
            TYPE_A,
            IN_FLUSH,
            &[192, 168, 1, 23],
        ));
        packet.extend(record(
            &labels(REVERSE),
            TYPE_PTR,
            IN_FLUSH,
            &[0xC0, owner_at],
        ));
        assert_eq!(
            parse_ptr_response(&packet, 1),
            Ok(Some("printer.local".into()))
        );
    }

    #[test]
    fn utf8_and_spaces_in_names_survive() {
        let mut packet = header(1, FLAGS, 0, 1);
        packet.extend(record(
            &labels(REVERSE),
            TYPE_PTR,
            IN_FLUSH,
            &labels("Büro Drucker.local"),
        ));
        assert_eq!(
            parse_ptr_response(&packet, 1),
            Ok(Some("Büro Drucker.local".into()))
        );
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(parse_ptr_response(&[], 1), Err(WireError::Truncated));
        assert_eq!(
            parse_ptr_response(&[0xFF; 11], 1),
            Err(WireError::Truncated)
        );
        // A query (e.g. another host's multicast question) is not an answer.
        let mut query = header(1, 0x0000, 1, 0);
        query.extend(labels(REVERSE));
        query.extend_from_slice(&[0, 12, 0x80, 1]);
        assert_eq!(
            parse_ptr_response(&query, 1),
            Err(WireError::NotOurResponse)
        );
        // Random bytes after a plausible header.
        let mut noise = header(1, FLAGS, 3, 5);
        noise.extend_from_slice(&[0xC3; 40]);
        assert!(parse_ptr_response(&noise, 1).is_err());
    }
}
