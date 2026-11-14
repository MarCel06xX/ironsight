//! NetBIOS node status (NBSTAT, RFC 1002 section 4.2.17/18) over UDP 137: computer name,
//! workgroup/domain and the adapter's MAC address. Packet and parser are hand-built.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use super::{random_u16, udp_exchange};
use crate::mac::MacAddr;

const NETBIOS_NS_PORT: u16 = 137;
const TYPE_NBSTAT: u16 = 0x0021;
const CLASS_IN: u16 = 0x0001;
const FLAG_RESPONSE: u16 = 0x8000;
const RCODE_MASK: u16 = 0x000F;
const HEADER_LEN: usize = 12;
/// 15 name bytes, 1 suffix byte, 2 flag bytes.
const NAME_ENTRY_LEN: usize = 18;
const NAME_FLAG_GROUP: u16 = 0x8000;
/// Name suffixes: workstation service and file server service.
const SUFFIX_WORKSTATION: u8 = 0x00;
const SUFFIX_SERVER: u8 = 0x20;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NodeStatus {
    pub name: Option<String>,
    pub workgroup: Option<String>,
    pub mac: Option<MacAddr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NbstatError {
    #[error("packet is truncated")]
    Truncated,
    #[error("not a node status response to our query")]
    NotOurResponse,
    #[error("malformed name")]
    BadName,
}

/// Queries the node status of `ip`. `None` if the host does not answer or sends garbage.
pub async fn node_status(ip: IpAddr, timeout: Duration) -> Option<NodeStatus> {
    let id = random_u16();
    let reply = udp_exchange(
        SocketAddr::new(ip, NETBIOS_NS_PORT),
        &build_query(id),
        timeout,
    )
    .await
    .ok()?;
    parse_response(&reply, id).ok()
}

/// Node status request for the wildcard name `*`.
fn build_query(id: u16) -> [u8; 50] {
    let mut packet = [0u8; 50];
    packet[0..2].copy_from_slice(&id.to_be_bytes());
    // Flags stay 0 (query, no recursion); QDCOUNT = 1.
    packet[5] = 1;
    // Name: '*' followed by 15 NUL bytes, each byte split into two nibbles + 'A'.
    packet[12] = 32;
    packet[13] = b'A' + (b'*' >> 4);
    packet[14] = b'A' + (b'*' & 0x0F);
    packet[15..45].fill(b'A');
    packet[45] = 0;
    packet[46..48].copy_from_slice(&TYPE_NBSTAT.to_be_bytes());
    packet[48..50].copy_from_slice(&CLASS_IN.to_be_bytes());
    packet
}

fn parse_response(packet: &[u8], id: u16) -> Result<NodeStatus, NbstatError> {
    let u16_at = |pos: usize| -> Result<u16, NbstatError> {
        let bytes = packet.get(pos..pos + 2).ok_or(NbstatError::Truncated)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    };
    if packet.len() < HEADER_LEN {
        return Err(NbstatError::Truncated);
    }
    let flags = u16_at(2)?;
    if u16_at(0)? != id || flags & FLAG_RESPONSE == 0 || flags & RCODE_MASK != 0 {
        return Err(NbstatError::NotOurResponse);
    }
    let question_count = u16_at(4)?;
    if u16_at(6)? == 0 {
        return Err(NbstatError::NotOurResponse);
    }

    let mut pos = HEADER_LEN;
    for _ in 0..question_count {
        pos = skip_name(packet, pos)? + 4; // QTYPE, QCLASS
    }
    pos = skip_name(packet, pos)?;
    if u16_at(pos)? != TYPE_NBSTAT {
        return Err(NbstatError::NotOurResponse);
    }
    // TYPE, CLASS, TTL precede RDLENGTH.
    let rdata_len = usize::from(u16_at(pos + 8)?);
    let rdata = packet
        .get(pos + 10..pos + 10 + rdata_len)
        .ok_or(NbstatError::Truncated)?;

    let (&name_count, rest) = rdata.split_first().ok_or(NbstatError::Truncated)?;
    let names_len = usize::from(name_count) * NAME_ENTRY_LEN;
    let names = rest.get(..names_len).ok_or(NbstatError::Truncated)?;
    let statistics = &rest[names_len..];

    let mut status = NodeStatus::default();
    let mut server_name = None;
    for entry in names.as_chunks::<NAME_ENTRY_LEN>().0 {
        let suffix = entry[15];
        let is_group = u16::from_be_bytes([entry[16], entry[17]]) & NAME_FLAG_GROUP != 0;
        let Some(name) = decode_name(&entry[..15]) else {
            continue;
        };
        match (suffix, is_group) {
            (SUFFIX_WORKSTATION, false) if status.name.is_none() => status.name = Some(name),
            (SUFFIX_WORKSTATION, true) if status.workgroup.is_none() => {
                status.workgroup = Some(name);
            }
            (SUFFIX_SERVER, false) if server_name.is_none() => server_name = Some(name),
            _ => {}
        }
    }
    status.name = status.name.or(server_name);

    // The statistics block starts with the adapter address; Samba reports all zeros.
    if let Some(&[a, b, c, d, e, f]) = statistics.first_chunk::<6>() {
        let mac = MacAddr([a, b, c, d, e, f]);
        status.mac = (!mac.is_zero()).then_some(mac);
    }
    Ok(status)
}

/// Returns the position after the name starting at `pos` (label sequence or pointer).
fn skip_name(packet: &[u8], mut pos: usize) -> Result<usize, NbstatError> {
    loop {
        let len = *packet.get(pos).ok_or(NbstatError::Truncated)?;
        match len & 0xC0 {
            0x00 if len == 0 => return Ok(pos + 1),
            0x00 => pos += 1 + usize::from(len),
            0xC0 => return Ok(pos + 2),
            _ => return Err(NbstatError::BadName),
        }
    }
}

/// NetBIOS names are space-padded and in an OEM code page; keep printable ASCII only.
fn decode_name(raw: &[u8]) -> Option<String> {
    let name: String = raw
        .iter()
        .map(|&b| match b {
            0x20..=0x7E => char::from(b),
            0x00 => ' ',
            _ => '?',
        })
        .collect();
    let name = name.trim();
    (!name.is_empty()).then(|| name.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: u16 = 0xBEEF;
    const UNIQUE: u16 = 0x0400;
    const GROUP: u16 = 0x8400;
    const WILDCARD: &[u8] = b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00";

    fn entry(name: &str, suffix: u8, flags: u16) -> Vec<u8> {
        let mut out = format!("{name:<15}").into_bytes();
        assert_eq!(out.len(), 15);
        out.push(suffix);
        out.extend_from_slice(&flags.to_be_bytes());
        out
    }

    /// Node status response as Windows sends it: no question, one answer.
    fn response(entries: &[Vec<u8>], mac: [u8; 6]) -> Vec<u8> {
        let mut rdata = vec![entries.len() as u8];
        for e in entries {
            rdata.extend_from_slice(e);
        }
        rdata.extend_from_slice(&mac);
        rdata.extend_from_slice(&[0; 40]); // rest of the statistics block

        let mut packet = Vec::new();
        packet.extend_from_slice(&ID.to_be_bytes());
        packet.extend_from_slice(&[0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0]);
        packet.extend_from_slice(WILDCARD);
        packet.extend_from_slice(&TYPE_NBSTAT.to_be_bytes());
        packet.extend_from_slice(&CLASS_IN.to_be_bytes());
        packet.extend_from_slice(&[0; 4]); // TTL
        packet.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        packet.extend_from_slice(&rdata);
        packet
    }

    fn windows_pc() -> Vec<u8> {
        response(
            &[
                entry("DESKTOP-AB12CD3", 0x00, UNIQUE),
                entry("WORKGROUP", 0x00, GROUP),
                entry("DESKTOP-AB12CD3", 0x20, UNIQUE),
                entry("WORKGROUP", 0x1E, GROUP),
                entry("WORKGROUP", 0x1D, UNIQUE),
                entry("\x01\x02__MSBROWSE__\x02", 0x01, GROUP),
            ],
            [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E],
        )
    }

    #[test]
    fn query_bytes() {
        let query = build_query(ID);
        assert_eq!(query[..12], [0xBE, 0xEF, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(query[12..46], *WILDCARD);
        assert_eq!(query[46..], [0x00, 0x21, 0x00, 0x01]);
    }

    #[test]
    fn parses_windows_response() {
        let status = parse_response(&windows_pc(), ID).unwrap();
        assert_eq!(status.name.as_deref(), Some("DESKTOP-AB12CD3"));
        assert_eq!(status.workgroup.as_deref(), Some("WORKGROUP"));
        assert_eq!(
            status.mac,
            Some(MacAddr([0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E]))
        );
    }

    #[test]
    fn samba_style_response() {
        // Only a file server name, zero MAC, and the question echoed with a pointer name.
        let mut packet = response(&[entry("NAS", 0x20, UNIQUE)], [0; 6]);
        packet[5] = 1; // QDCOUNT = 1
        let mut question = WILDCARD.to_vec();
        question.extend_from_slice(&[0x00, 0x21, 0x00, 0x01]);
        let answer = packet.split_off(HEADER_LEN);
        packet.extend_from_slice(&question);
        packet.extend_from_slice(&[0xC0, 0x0C]); // answer name: pointer to the question
        packet.extend_from_slice(&answer[WILDCARD.len()..]);

        let status = parse_response(&packet, ID).unwrap();
        assert_eq!(status.name.as_deref(), Some("NAS"));
        assert_eq!(status.workgroup, None);
        assert_eq!(status.mac, None);
    }

    #[test]
    fn workstation_name_wins_over_server_name() {
        let packet = response(
            &[
                entry("FILESRV", 0x20, UNIQUE),
                entry("REALNAME", 0x00, UNIQUE),
            ],
            [2, 0, 0, 0, 0, 1],
        );
        let status = parse_response(&packet, ID).unwrap();
        assert_eq!(status.name.as_deref(), Some("REALNAME"));
    }

    #[test]
    fn unprintable_name_bytes_are_replaced() {
        let mut raw = entry("AB", 0x00, UNIQUE);
        raw[2] = 0x84; // OEM umlaut
        raw[3] = 0x07;
        let status = parse_response(&response(&[raw], [0; 6]), ID).unwrap();
        assert_eq!(status.name.as_deref(), Some("AB??"));
    }

    #[test]
    fn empty_name_table() {
        let status = parse_response(&response(&[], [0; 6]), ID).unwrap();
        assert_eq!(status, NodeStatus::default());
    }

    #[test]
    fn rejects_foreign_responses() {
        let packet = windows_pc();
        assert_eq!(
            parse_response(&packet, ID + 1),
            Err(NbstatError::NotOurResponse)
        );

        let mut query = packet.clone();
        query[2] = 0x00; // not a response
        assert_eq!(parse_response(&query, ID), Err(NbstatError::NotOurResponse));

        let mut error = packet.clone();
        error[3] = 0x02; // rcode: server failure
        assert_eq!(parse_response(&error, ID), Err(NbstatError::NotOurResponse));

        let mut no_answer = packet.clone();
        no_answer[7] = 0;
        assert_eq!(
            parse_response(&no_answer, ID),
            Err(NbstatError::NotOurResponse)
        );

        let mut wrong_type = packet.clone();
        wrong_type[HEADER_LEN + WILDCARD.len() + 1] = 0x20; // NB instead of NBSTAT
        assert_eq!(
            parse_response(&wrong_type, ID),
            Err(NbstatError::NotOurResponse)
        );
    }

    #[test]
    fn truncated_packets_never_panic() {
        let packet = windows_pc();
        // RDLENGTH covers the whole rest, so every shorter packet is incomplete.
        for len in 0..packet.len() {
            assert_eq!(
                parse_response(&packet[..len], ID),
                Err(NbstatError::Truncated),
                "length {len}"
            );
        }
    }

    #[test]
    fn lying_lengths_are_caught() {
        // Name count larger than the RDATA.
        let mut packet = response(&[entry("PC", 0x00, UNIQUE)], [0; 6]);
        let count_at = HEADER_LEN + WILDCARD.len() + 10;
        assert_eq!(packet[count_at], 1);
        packet[count_at] = 200;
        assert_eq!(parse_response(&packet, ID), Err(NbstatError::Truncated));

        // RDLENGTH larger than the packet.
        let mut packet = response(&[entry("PC", 0x00, UNIQUE)], [0; 6]);
        packet[count_at - 2] = 0xFF;
        assert_eq!(parse_response(&packet, ID), Err(NbstatError::Truncated));

        // Reserved label type in the answer name.
        let mut packet = response(&[entry("PC", 0x00, UNIQUE)], [0; 6]);
        packet[HEADER_LEN] = 0x80;
        assert_eq!(parse_response(&packet, ID), Err(NbstatError::BadName));
    }
}
