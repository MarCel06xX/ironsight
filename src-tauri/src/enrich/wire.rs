//! Minimal DNS message encoding/decoding (RFC 1035) for PTR lookups, shared by unicast DNS
//! and mDNS. Everything parsed here comes from the network and is bounds-checked.

use std::fmt::Write as _;
use std::net::IpAddr;

const TYPE_PTR: u16 = 12;
const CLASS_IN: u16 = 1;
/// The top class bit is "cache flush" / "unicast response wanted" in mDNS.
const CLASS_MASK: u16 = 0x7FFF;
const FLAG_RESPONSE: u16 = 0x8000;
const FLAG_RECURSION_DESIRED: u16 = 0x0100;
const RCODE_MASK: u16 = 0x000F;
const RCODE_NAME_ERROR: u16 = 3;
const HEADER_LEN: usize = 12;
/// Longest name in presentation form (RFC 1035).
const MAX_NAME_LEN: usize = 253;
/// Compression pointers may chain, but never this deep in real packets.
const MAX_POINTER_JUMPS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    #[error("packet is truncated")]
    Truncated,
    #[error("malformed domain name")]
    BadName,
    #[error("not a response to our query")]
    NotOurResponse,
    #[error("server answered with rcode {0}")]
    Rcode(u8),
}

/// `192.168.1.10` -> `10.1.168.192.in-addr.arpa` (nibble format under `ip6.arpa` for IPv6).
pub fn reverse_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, d] = v4.octets();
            format!("{d}.{c}.{b}.{a}.in-addr.arpa")
        }
        IpAddr::V6(v6) => {
            let mut name = String::with_capacity(72);
            for byte in v6.octets().iter().rev() {
                let _ = write!(name, "{:x}.{:x}.", byte & 0x0F, byte >> 4);
            }
            name.push_str("ip6.arpa");
            name
        }
    }
}

/// Builds a PTR query for the reverse name of `ip`.
/// `unicast_response` sets the mDNS "QU" bit; plain DNS queries leave it off.
pub fn build_ptr_query(
    id: u16,
    ip: IpAddr,
    recursion_desired: bool,
    unicast_response: bool,
) -> Vec<u8> {
    let mut packet = Vec::with_capacity(64);
    packet.extend_from_slice(&id.to_be_bytes());
    let flags = if recursion_desired {
        FLAG_RECURSION_DESIRED
    } else {
        0
    };
    packet.extend_from_slice(&flags.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    packet.extend_from_slice(&[0; 6]); // ANCOUNT, NSCOUNT, ARCOUNT
    for label in reverse_name(ip).split('.') {
        packet.push(label.len() as u8); // labels of a reverse name are at most 7 bytes
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&TYPE_PTR.to_be_bytes());
    let class = if unicast_response {
        CLASS_IN | !CLASS_MASK
    } else {
        CLASS_IN
    };
    packet.extend_from_slice(&class.to_be_bytes());
    packet
}

/// Extracts the first PTR target from the answer section of a response to query `id`.
/// `Ok(None)` means the server answered but has no name (NOERROR without PTR, or NXDOMAIN).
pub fn parse_ptr_response(packet: &[u8], id: u16) -> Result<Option<String>, WireError> {
    let mut reader = Reader { packet, pos: 0 };
    let response_id = reader.u16()?;
    let flags = reader.u16()?;
    let question_count = reader.u16()?;
    let answer_count = reader.u16()?;
    reader.skip(4)?; // NSCOUNT, ARCOUNT
    debug_assert_eq!(reader.pos, HEADER_LEN);

    if response_id != id || flags & FLAG_RESPONSE == 0 {
        return Err(WireError::NotOurResponse);
    }
    match flags & RCODE_MASK {
        0 => {}
        RCODE_NAME_ERROR => return Ok(None),
        rcode => return Err(WireError::Rcode(rcode as u8)),
    }

    for _ in 0..question_count {
        reader.skip_name()?;
        reader.skip(4)?; // QTYPE, QCLASS
    }
    for _ in 0..answer_count {
        reader.skip_name()?;
        let rtype = reader.u16()?;
        let class = reader.u16()?;
        reader.skip(4)?; // TTL
        let rdata_len = usize::from(reader.u16()?);
        let rdata_start = reader.pos;
        reader.skip(rdata_len)?;
        if rtype == TYPE_PTR && class & CLASS_MASK == CLASS_IN {
            // The name must end inside its RDATA; pointers can only go backwards anyway.
            let name = read_name(&packet[..reader.pos], rdata_start)?;
            if !name.is_empty() {
                return Ok(Some(name));
            }
        }
    }
    Ok(None)
}

struct Reader<'a> {
    packet: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn u8(&mut self) -> Result<u8, WireError> {
        let byte = *self.packet.get(self.pos).ok_or(WireError::Truncated)?;
        self.pos += 1;
        Ok(byte)
    }

    fn u16(&mut self) -> Result<u16, WireError> {
        Ok(u16::from_be_bytes([self.u8()?, self.u8()?]))
    }

    fn skip(&mut self, len: usize) -> Result<(), WireError> {
        let end = self.pos.checked_add(len).ok_or(WireError::Truncated)?;
        if end > self.packet.len() {
            return Err(WireError::Truncated);
        }
        self.pos = end;
        Ok(())
    }

    /// Skips a (possibly compressed) name without following pointers.
    fn skip_name(&mut self) -> Result<(), WireError> {
        loop {
            let len = self.u8()?;
            match len & 0xC0 {
                0x00 if len == 0 => return Ok(()),
                0x00 => self.skip(usize::from(len))?,
                0xC0 => return self.skip(1),
                _ => return Err(WireError::BadName),
            }
        }
    }
}

/// Decodes the name starting at `start`, following compression pointers.
/// Returns it in presentation form without the trailing dot.
fn read_name(packet: &[u8], start: usize) -> Result<String, WireError> {
    let mut name = String::new();
    let mut wire_len = 0usize;
    let mut pos = start;
    let mut jumps = 0;
    loop {
        let len = *packet.get(pos).ok_or(WireError::Truncated)?;
        match len & 0xC0 {
            0x00 if len == 0 => return Ok(name),
            0x00 => {
                let len = usize::from(len);
                let label = packet
                    .get(pos + 1..pos + 1 + len)
                    .ok_or(WireError::Truncated)?;
                wire_len += len + 1;
                if wire_len > MAX_NAME_LEN + 1 {
                    return Err(WireError::BadName);
                }
                if !name.is_empty() {
                    name.push('.');
                }
                push_label(&mut name, label);
                pos += 1 + len;
            }
            0xC0 => {
                let low = *packet.get(pos + 1).ok_or(WireError::Truncated)?;
                let target = usize::from(len & 0x3F) << 8 | usize::from(low);
                jumps += 1;
                // Forward pointers are invalid; the jump limit stops crafted loops.
                if target >= pos || jumps > MAX_POINTER_JUMPS {
                    return Err(WireError::BadName);
                }
                pos = target;
            }
            _ => return Err(WireError::BadName),
        }
    }
}

/// Labels are arbitrary bytes; keep them printable and unambiguous.
fn push_label(name: &mut String, label: &[u8]) {
    for ch in String::from_utf8_lossy(label).chars() {
        name.push(if ch.is_control() || ch == '.' {
            '?'
        } else {
            ch
        });
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    const IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
    const QNAME: &[u8] = b"\x0210\x011\x03168\x03192\x07in-addr\x04arpa\x00";

    /// Encodes `name` as uncompressed labels.
    pub(crate) fn labels(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in name.split('.').filter(|l| !l.is_empty()) {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    /// Response header with the given flags and section counts.
    pub(crate) fn header(id: u16, flags: u16, questions: u16, answers: u16) -> Vec<u8> {
        let mut out = Vec::new();
        for value in [id, flags, questions, answers, 0, 0] {
            out.extend_from_slice(&value.to_be_bytes());
        }
        out
    }

    /// Resource record; `owner` and `rdata` are raw wire bytes.
    pub(crate) fn record(owner: &[u8], rtype: u16, class: u16, rdata: &[u8]) -> Vec<u8> {
        let mut out = owner.to_vec();
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&class.to_be_bytes());
        out.extend_from_slice(&120u32.to_be_bytes());
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(rdata);
        out
    }

    fn question() -> Vec<u8> {
        let mut out = QNAME.to_vec();
        out.extend_from_slice(&[0, 12, 0, 1]);
        out
    }

    /// Typical recursive-resolver answer: question echoed, owner compressed to offset 12.
    fn response(id: u16, target: &str) -> Vec<u8> {
        let mut packet = header(id, 0x8180, 1, 1);
        packet.extend(question());
        packet.extend(record(&[0xC0, 0x0C], TYPE_PTR, CLASS_IN, &labels(target)));
        packet
    }

    #[test]
    fn reverse_names() {
        assert_eq!(reverse_name(IP), "10.1.168.192.in-addr.arpa");
        let v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x1234));
        assert_eq!(
            reverse_name(v6),
            "4.3.2.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        );
    }

    #[test]
    fn query_bytes() {
        let mut expected = vec![0xAB, 0xCD, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        expected.extend_from_slice(QNAME);
        expected.extend_from_slice(&[0, 12, 0, 1]);
        assert_eq!(build_ptr_query(0xABCD, IP, true, false), expected);

        // mDNS flavour: no recursion, unicast-response bit set in the class.
        let mdns = build_ptr_query(1, IP, false, true);
        assert_eq!(mdns[2..4], [0, 0]);
        assert_eq!(mdns[mdns.len() - 2..], [0x80, 0x01]);
    }

    #[test]
    fn parses_ptr_answer() {
        let packet = response(7, "pc.fritz.box");
        assert_eq!(
            parse_ptr_response(&packet, 7),
            Ok(Some("pc.fritz.box".into()))
        );
    }

    #[test]
    fn follows_compression_pointers_in_rdata() {
        // Answer 1 is a CNAME (RFC 2317 style delegation), answer 2 the PTR whose target
        // reuses "fritz.box" from the CNAME's RDATA through a pointer.
        let mut packet = header(7, 0x8180, 1, 2);
        packet.extend(question());
        let cname_rdata = labels("10.sub.fritz.box");
        let cname_rdata_at = packet.len() + 2 + 10;
        packet.extend(record(&[0xC0, 0x0C], 5, CLASS_IN, &cname_rdata));
        let fritz_box_at = cname_rdata_at + 3 + 4; // skip "10" and "sub"
        assert_eq!(packet[fritz_box_at..fritz_box_at + 6], *b"\x05fritz");
        let rdata = [b"\x06laptop".as_slice(), &[0xC0, fritz_box_at as u8]].concat();
        packet.extend(record(
            &[0xC0, cname_rdata_at as u8],
            TYPE_PTR,
            CLASS_IN,
            &rdata,
        ));
        assert_eq!(
            parse_ptr_response(&packet, 7),
            Ok(Some("laptop.fritz.box".into()))
        );
    }

    #[test]
    fn no_name_cases() {
        // NXDOMAIN
        let mut nx = header(7, 0x8183, 1, 0);
        nx.extend(question());
        assert_eq!(parse_ptr_response(&nx, 7), Ok(None));
        // NOERROR without answers
        let mut empty = header(7, 0x8180, 1, 0);
        empty.extend(question());
        assert_eq!(parse_ptr_response(&empty, 7), Ok(None));
        // Only a non-PTR record
        let mut other = header(7, 0x8180, 1, 1);
        other.extend(question());
        other.extend(record(&[0xC0, 0x0C], 1, CLASS_IN, &[1, 2, 3, 4]));
        assert_eq!(parse_ptr_response(&other, 7), Ok(None));
        // PTR to the root name
        assert_eq!(parse_ptr_response(&response(7, ""), 7), Ok(None));
    }

    #[test]
    fn rejects_foreign_or_failed_responses() {
        let packet = response(7, "pc.fritz.box");
        assert_eq!(
            parse_ptr_response(&packet, 8),
            Err(WireError::NotOurResponse)
        );

        let mut query_bit = packet.clone();
        query_bit[2] &= 0x7F; // QR = 0: this is a query, not a response
        assert_eq!(
            parse_ptr_response(&query_bit, 7),
            Err(WireError::NotOurResponse)
        );

        let mut servfail = header(7, 0x8182, 1, 0);
        servfail.extend(question());
        assert_eq!(parse_ptr_response(&servfail, 7), Err(WireError::Rcode(2)));
    }

    #[test]
    fn truncated_packets_never_panic() {
        let packet = response(7, "pc.fritz.box");
        for len in 0..packet.len() {
            assert_eq!(
                parse_ptr_response(&packet[..len], 7),
                Err(WireError::Truncated),
                "length {len}"
            );
        }
        // Answer count larger than what is there.
        let mut lying = packet.clone();
        lying[7] = 9;
        assert_eq!(
            parse_ptr_response(&lying, 7),
            Ok(Some("pc.fritz.box".into()))
        );
        lying[7] = 0;
        lying[6] = 0;
        assert_eq!(parse_ptr_response(&lying, 7), Ok(None));
    }

    #[test]
    fn rdata_length_is_enforced() {
        // RDLENGTH claims more bytes than the packet has.
        let mut packet = response(7, "pc.fritz.box");
        let len = packet.len();
        packet[len - 14 - 1] = 200;
        assert_eq!(parse_ptr_response(&packet, 7), Err(WireError::Truncated));

        // Name runs past its RDATA into the next record.
        let mut packet = header(7, 0x8180, 0, 1);
        packet.extend(record(&labels("x"), TYPE_PTR, CLASS_IN, b"\x05ab"));
        packet.extend_from_slice(b"cde\x00");
        assert_eq!(parse_ptr_response(&packet, 7), Err(WireError::Truncated));
    }

    #[test]
    fn malicious_names_are_rejected() {
        let with_rdata = |rdata: &[u8]| {
            let mut packet = header(7, 0x8180, 1, 1);
            packet.extend(question());
            packet.extend(record(&[0xC0, 0x0C], TYPE_PTR, CLASS_IN, rdata));
            packet
        };
        let rdata_at = (HEADER_LEN + QNAME.len() + 4 + 12) as u8;

        // Pointer to itself, forward pointer, and a pointer back into its own label run.
        let itself = with_rdata(&[0xC0, rdata_at]);
        assert_eq!(parse_ptr_response(&itself, 7), Err(WireError::BadName));
        let forward = with_rdata(&[0xC0, 0xFF]);
        assert_eq!(parse_ptr_response(&forward, 7), Err(WireError::BadName));
        let looping = with_rdata(&[1, b'a', 0xC0, rdata_at]);
        assert_eq!(parse_ptr_response(&looping, 7), Err(WireError::BadName));

        // Reserved label types (0x40 / 0x80).
        let reserved = with_rdata(&[0x41, b'a', 0]);
        assert_eq!(parse_ptr_response(&reserved, 7), Err(WireError::BadName));

        // Longer than a legal name: 5 labels of 63 bytes.
        let mut long = Vec::new();
        for _ in 0..5 {
            long.push(63);
            long.extend_from_slice(&[b'a'; 63]);
        }
        long.push(0);
        assert_eq!(
            parse_ptr_response(&with_rdata(&long), 7),
            Err(WireError::BadName)
        );
    }

    #[test]
    fn label_bytes_are_made_printable() {
        let mut packet = header(7, 0x8180, 0, 1);
        let rdata = b"\x06a\x00b.c\x1b\x05caf\xc3\xa9\x02\xff\xfe\x00";
        packet.extend(record(&labels("x"), TYPE_PTR, CLASS_IN, rdata));
        assert_eq!(
            parse_ptr_response(&packet, 7),
            Ok(Some("a?b?c?.café.\u{fffd}\u{fffd}".into()))
        );
    }
}
