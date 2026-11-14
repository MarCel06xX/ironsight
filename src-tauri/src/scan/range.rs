//! Scan target parsing: single IPs, ranges, CIDR blocks and comma-separated lists of those.

use std::net::Ipv4Addr;

/// Hard limit of hosts per scan.
pub const MAX_HOSTS: u64 = 65_536;
/// Smallest accepted CIDR prefix length (largest network).
pub const MIN_PREFIX: u32 = 16;

const MAX_INPUT_LEN: usize = 4096;
const FIRST_UNICAST: u32 = 0x0100_0000; // 1.0.0.0
const LAST_UNICAST: u32 = 0xDFFF_FFFF; // 223.255.255.255

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RangeError {
    #[error("no scan target given")]
    Empty,
    #[error("target input is too long (maximum is 4096 characters)")]
    InputTooLong,
    #[error("'{0}' is not a valid IPv4 address")]
    InvalidAddress(String),
    #[error("'{0}' is not a valid range (use e.g. 192.168.1.10-50 or 192.168.1.1-192.168.2.20)")]
    InvalidRange(String),
    #[error("range '{0}' ends before it starts")]
    ReversedRange(String),
    #[error("'{0}' has an invalid CIDR prefix")]
    InvalidPrefix(String),
    #[error("prefix /{prefix} is too large to scan (allowed: /16 to /32)")]
    PrefixTooLarge { prefix: u32 },
    #[error("'{0}' is outside the scannable unicast range (1.0.0.0 - 223.255.255.255)")]
    NotUnicast(String),
    #[error("{count} hosts selected, the maximum is 65,536 per scan")]
    TooManyHosts { count: u64 },
}

impl RangeError {
    /// Stable identifier the frontend can map to a localized message.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Empty => "range.empty",
            Self::InputTooLong => "range.input_too_long",
            Self::InvalidAddress(_) => "range.invalid_address",
            Self::InvalidRange(_) => "range.invalid_range",
            Self::ReversedRange(_) => "range.reversed",
            Self::InvalidPrefix(_) => "range.invalid_prefix",
            Self::PrefixTooLarge { .. } => "range.prefix_too_large",
            Self::NotUnicast(_) => "range.not_unicast",
            Self::TooManyHosts { .. } => "range.too_many_hosts",
        }
    }

    /// The value the message refers to, for localized messages.
    pub fn detail(&self) -> Option<String> {
        match self {
            Self::Empty | Self::InputTooLong => None,
            Self::InvalidAddress(s)
            | Self::InvalidRange(s)
            | Self::ReversedRange(s)
            | Self::InvalidPrefix(s)
            | Self::NotUnicast(s) => Some(s.clone()),
            Self::PrefixTooLarge { prefix } => Some(prefix.to_string()),
            Self::TooManyHosts { count } => Some(count.to_string()),
        }
    }
}

/// Deduplicated, ascending set of IPv4 scan targets (at most [`MAX_HOSTS`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetSet {
    /// Inclusive, sorted, non-overlapping, non-adjacent ranges.
    ranges: Vec<(u32, u32)>,
    count: usize,
}

impl TargetSet {
    pub fn parse(input: &str) -> Result<Self, RangeError> {
        if input.len() > MAX_INPUT_LEN {
            return Err(RangeError::InputTooLong);
        }
        let mut ranges = Vec::new();
        for item in input.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let (lo, hi) = parse_item(item)?;
            if lo < FIRST_UNICAST || hi > LAST_UNICAST {
                return Err(RangeError::NotUnicast(echo(item)));
            }
            ranges.push((lo, hi));
        }
        if ranges.is_empty() {
            return Err(RangeError::Empty);
        }

        ranges.sort_unstable();
        let mut merged: Vec<(u32, u32)> = Vec::with_capacity(ranges.len());
        for (lo, hi) in ranges {
            match merged.last_mut() {
                Some(last) if u64::from(lo) <= u64::from(last.1) + 1 => last.1 = last.1.max(hi),
                _ => merged.push((lo, hi)),
            }
        }

        // Count in u64 before anything is expanded, so huge ranges are rejected cheaply.
        let count: u64 = merged.iter().map(|&(lo, hi)| u64::from(hi - lo) + 1).sum();
        if count > MAX_HOSTS {
            return Err(RangeError::TooManyHosts { count });
        }
        Ok(Self {
            ranges: merged,
            count: count as usize,
        })
    }

    /// Number of hosts in the set.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Hosts in ascending numeric order.
    pub fn iter(&self) -> impl Iterator<Item = Ipv4Addr> + '_ {
        self.ranges
            .iter()
            .flat_map(|&(lo, hi)| (lo..=hi).map(Ipv4Addr::from))
    }
}

fn parse_item(item: &str) -> Result<(u32, u32), RangeError> {
    if let Some((addr, prefix)) = item.split_once('/') {
        let addr = parse_addr(addr.trim())?;
        let prefix = parse_number(prefix.trim())
            .filter(|p| *p <= 32)
            .ok_or_else(|| RangeError::InvalidPrefix(echo(item)))?;
        if prefix < MIN_PREFIX {
            return Err(RangeError::PrefixTooLarge { prefix });
        }
        let mask = u32::MAX << (32 - prefix); // prefix >= 16, so the shift is at most 16
        let network = addr & mask;
        let broadcast = network | !mask;
        // Network and broadcast address are not hosts, except in /31 and /32.
        Ok(if prefix <= 30 {
            (network + 1, broadcast - 1)
        } else {
            (network, broadcast)
        })
    } else if let Some((start, end)) = item.split_once('-') {
        let start = parse_addr(start.trim())?;
        let end = parse_range_end(start, end.trim())
            .ok_or_else(|| RangeError::InvalidRange(echo(item)))?;
        if end < start {
            return Err(RangeError::ReversedRange(echo(item)));
        }
        Ok((start, end))
    } else {
        let addr = parse_addr(item)?;
        Ok((addr, addr))
    }
}

fn parse_addr(s: &str) -> Result<u32, RangeError> {
    s.parse::<Ipv4Addr>()
        .map(u32::from)
        .map_err(|_| RangeError::InvalidAddress(echo(s)))
}

/// Range end: either a full address or 1-3 trailing octets that replace the end of `start`
/// (`192.168.1.10-50` -> `192.168.1.50`, `192.168.1.10-2.20` -> `192.168.2.20`).
fn parse_range_end(start: u32, s: &str) -> Option<u32> {
    let mut value: u32 = 0;
    let mut octets = 0u32;
    for part in s.split('.') {
        let octet = parse_number(part).filter(|n| *n <= 255)?;
        octets += 1;
        if octets > 4 {
            return None;
        }
        value = (value << 8) | octet;
    }
    Some(if octets == 4 {
        value
    } else {
        (start & (u32::MAX << (8 * octets))) | value
    })
}

/// Plain decimal number with at most 3 digits; no sign, no leading zeros.
fn parse_number(s: &str) -> Option<u32> {
    let valid = !s.is_empty()
        && s.len() <= 3
        && s.bytes().all(|b| b.is_ascii_digit())
        && (s.len() == 1 || !s.starts_with('0'));
    if valid { s.parse().ok() } else { None }
}

/// Shortened copy of user input for error messages.
fn echo(s: &str) -> String {
    s.chars().take(64).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hosts(input: &str) -> Vec<String> {
        TargetSet::parse(input)
            .unwrap()
            .iter()
            .map(|ip| ip.to_string())
            .collect()
    }

    fn count(input: &str) -> usize {
        TargetSet::parse(input).unwrap().len()
    }

    #[test]
    fn single_address() {
        assert_eq!(hosts("192.168.1.10"), ["192.168.1.10"]);
        assert_eq!(hosts("  192.168.1.10  "), ["192.168.1.10"]);
    }

    #[test]
    fn last_octet_range() {
        assert_eq!(
            hosts("192.168.1.10-12"),
            ["192.168.1.10", "192.168.1.11", "192.168.1.12"]
        );
        assert_eq!(count("192.168.1.10-50"), 41);
        assert_eq!(hosts("192.168.1.10-10"), ["192.168.1.10"]);
    }

    #[test]
    fn multi_octet_suffix_range() {
        let set = hosts("192.168.1.254-2.1");
        assert_eq!(
            set,
            [
                "192.168.1.254",
                "192.168.1.255",
                "192.168.2.0",
                "192.168.2.1"
            ]
        );
    }

    #[test]
    fn full_range() {
        assert_eq!(count("192.168.1.1-192.168.2.20"), 255 + 21);
        assert_eq!(hosts("10.0.0.1 - 10.0.0.2"), ["10.0.0.1", "10.0.0.2"]);
    }

    #[test]
    fn cidr_skips_network_and_broadcast() {
        let set = hosts("192.168.1.0/24");
        assert_eq!(set.len(), 254);
        assert_eq!(set.first().unwrap(), "192.168.1.1");
        assert_eq!(set.last().unwrap(), "192.168.1.254");
        assert_eq!(hosts("192.168.1.4/30"), ["192.168.1.5", "192.168.1.6"]);
    }

    #[test]
    fn cidr_masks_host_bits() {
        assert_eq!(hosts("192.168.1.77/24"), hosts("192.168.1.0/24"));
    }

    #[test]
    fn cidr_31_and_32_keep_all_addresses() {
        assert_eq!(hosts("10.0.0.4/31"), ["10.0.0.4", "10.0.0.5"]);
        assert_eq!(hosts("10.0.0.7/32"), ["10.0.0.7"]);
    }

    #[test]
    fn cidr_prefix_limits() {
        assert_eq!(count("10.1.0.0/16"), 65_534);
        assert_eq!(
            TargetSet::parse("10.0.0.0/15"),
            Err(RangeError::PrefixTooLarge { prefix: 15 })
        );
        assert_eq!(
            TargetSet::parse("10.0.0.0/0"),
            Err(RangeError::PrefixTooLarge { prefix: 0 })
        );
        for bad in [
            "10.0.0.0/33",
            "10.0.0.0/",
            "10.0.0.0/x",
            "10.0.0.0/024",
            "10.0.0.0/+24",
        ] {
            assert!(
                matches!(TargetSet::parse(bad), Err(RangeError::InvalidPrefix(_))),
                "{bad}"
            );
        }
    }

    #[test]
    fn host_limit() {
        assert_eq!(count("10.0.0.0-10.0.255.255"), 65_536);
        assert_eq!(
            TargetSet::parse("10.0.0.0-10.1.0.0"),
            Err(RangeError::TooManyHosts { count: 65_537 })
        );
        assert_eq!(
            TargetSet::parse("10.0.0.0/16, 10.1.0.0/16"),
            Err(RangeError::TooManyHosts { count: 131_068 })
        );
        assert_eq!(
            TargetSet::parse("1.0.0.0-223.255.255.255"),
            Err(RangeError::TooManyHosts {
                count: 0xDFFF_FFFF - 0x0100_0000 + 1
            })
        );
    }

    #[test]
    fn comma_list_is_sorted_and_deduplicated() {
        assert_eq!(
            hosts("192.168.1.5, 192.168.1.1-3 ,192.168.1.2,, 10.0.0.1,"),
            [
                "10.0.0.1",
                "192.168.1.1",
                "192.168.1.2",
                "192.168.1.3",
                "192.168.1.5"
            ]
        );
        // Overlapping and adjacent ranges merge instead of counting twice.
        assert_eq!(count("10.0.0.1-100, 10.0.0.50-150, 10.0.0.151"), 151);
        let merged = TargetSet::parse("10.0.0.1-100, 10.0.0.50-150, 10.0.0.151").unwrap();
        assert_eq!(merged.ranges.len(), 1);
    }

    #[test]
    fn empty_input() {
        for empty in ["", "   ", ",", " , , "] {
            assert_eq!(TargetSet::parse(empty), Err(RangeError::Empty), "{empty:?}");
        }
    }

    #[test]
    fn invalid_addresses() {
        for bad in [
            "192.168.1",
            "192.168.1.256",
            "192.168.1.1.1",
            "192.168.01.1",
            "abc",
            "192.168.1.x-5",
            "::1",
        ] {
            assert!(
                matches!(TargetSet::parse(bad), Err(RangeError::InvalidAddress(_))),
                "{bad}"
            );
        }
    }

    #[test]
    fn invalid_ranges() {
        for bad in [
            "192.168.1.1-",
            "192.168.1.1-256",
            "192.168.1.1-+5",
            "192.168.1.1-05",
            "192.168.1.1-2-3",
            "192.168.1.1-1.2.3.4.5",
            "192.168.1.1-a",
        ] {
            assert!(
                matches!(TargetSet::parse(bad), Err(RangeError::InvalidRange(_))),
                "{bad}"
            );
        }
        assert!(matches!(
            TargetSet::parse("192.168.1.50-10"),
            Err(RangeError::ReversedRange(_))
        ));
        assert!(matches!(
            TargetSet::parse("192.168.2.1-192.168.1.1"),
            Err(RangeError::ReversedRange(_))
        ));
    }

    #[test]
    fn non_unicast_is_rejected() {
        for bad in [
            "0.0.0.1",
            "224.0.0.1",
            "255.255.255.255",
            "223.255.255.0-224.0.0.5",
        ] {
            assert!(
                matches!(TargetSet::parse(bad), Err(RangeError::NotUnicast(_))),
                "{bad}"
            );
        }
        assert_eq!(count("223.255.255.255"), 1);
    }

    #[test]
    fn oversized_input_and_long_echo() {
        let long = "1".repeat(MAX_INPUT_LEN + 1);
        assert_eq!(TargetSet::parse(&long), Err(RangeError::InputTooLong));
        let Err(RangeError::InvalidAddress(shown)) = TargetSet::parse(&"x".repeat(500)) else {
            panic!("expected InvalidAddress");
        };
        assert_eq!(shown.len(), 64);
    }
}
