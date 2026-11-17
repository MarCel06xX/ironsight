//! Port lists as typed by the user: single ports, ranges and comma-separated lists of those,
//! e.g. `22,80,443,1000-2000`. Strict: every entry must be valid, nothing is skipped.

use std::fmt;

/// Longest accepted input in bytes; enough for a few hundred single ports.
pub const MAX_SPEC_LEN: usize = 2048;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PortSpecError {
    #[error("no ports given")]
    Empty,
    #[error("port list is too long (maximum is 2048 characters)")]
    InputTooLong,
    #[error("empty entry in the port list (check for doubled or trailing commas)")]
    EmptyEntry,
    #[error("'{0}' is not a valid port number (use digits only, without leading zeros)")]
    InvalidPort(String),
    #[error("port '{0}' is out of range (allowed: 1-65535)")]
    OutOfRange(String),
    #[error("'{0}' is not a valid port range (use e.g. 1000-2000)")]
    InvalidRange(String),
    #[error("port range '{0}' ends before it starts")]
    ReversedRange(String),
}

impl PortSpecError {
    /// Stable identifier the frontend maps to a localized message.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Empty => "ports.empty",
            Self::InputTooLong => "ports.input_too_long",
            Self::EmptyEntry => "ports.empty_entry",
            Self::InvalidPort(_) => "ports.invalid_port",
            Self::OutOfRange(_) => "ports.out_of_range",
            Self::InvalidRange(_) => "ports.invalid_range",
            Self::ReversedRange(_) => "ports.reversed_range",
        }
    }

    /// The entry the message refers to, for localized messages.
    pub fn detail(&self) -> Option<String> {
        match self {
            Self::Empty | Self::InputTooLong | Self::EmptyEntry => None,
            Self::InvalidPort(s)
            | Self::OutOfRange(s)
            | Self::InvalidRange(s)
            | Self::ReversedRange(s) => Some(s.clone()),
        }
    }
}

/// Deduplicated, ascending set of TCP ports (1-65535).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortSet {
    /// Inclusive, sorted, non-overlapping, non-adjacent ranges.
    ranges: Vec<(u16, u16)>,
    count: usize,
}

impl PortSet {
    /// Parses user input. Overlapping and repeated entries are merged, so the result never
    /// contains a port twice (`80,80,70-90` is the same as `70-90`).
    pub fn parse(input: &str) -> Result<Self, PortSpecError> {
        if input.len() > MAX_SPEC_LEN {
            return Err(PortSpecError::InputTooLong);
        }
        if input.trim().is_empty() {
            return Err(PortSpecError::Empty);
        }
        let mut ranges = Vec::new();
        for item in input.split(',').map(str::trim) {
            if item.is_empty() {
                return Err(PortSpecError::EmptyEntry);
            }
            ranges.push(parse_item(item)?);
        }
        Ok(Self::from_ranges(ranges))
    }

    /// Set of the given ports; 0 is ignored.
    pub fn from_ports(ports: impl IntoIterator<Item = u16>) -> Self {
        Self::from_ranges(
            ports
                .into_iter()
                .filter(|&p| p != 0)
                .map(|p| (p, p))
                .collect(),
        )
    }

    /// Every port, `1-65535`.
    pub fn all() -> Self {
        Self::from_ranges(vec![(1, u16::MAX)])
    }

    fn from_ranges(mut ranges: Vec<(u16, u16)>) -> Self {
        ranges.sort_unstable();
        let mut merged: Vec<(u16, u16)> = Vec::with_capacity(ranges.len());
        for (lo, hi) in ranges {
            match merged.last_mut() {
                Some(last) if u32::from(lo) <= u32::from(last.1) + 1 => last.1 = last.1.max(hi),
                _ => merged.push((lo, hi)),
            }
        }
        let count = merged
            .iter()
            .map(|&(lo, hi)| usize::from(hi - lo) + 1)
            .sum();
        Self {
            ranges: merged,
            count,
        }
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn contains(&self, port: u16) -> bool {
        let at = self.ranges.partition_point(|&(_, hi)| hi < port);
        self.ranges.get(at).is_some_and(|&(lo, _)| lo <= port)
    }

    /// Ports in ascending order.
    pub fn iter(&self) -> impl Iterator<Item = u16> + '_ {
        self.ranges.iter().flat_map(|&(lo, hi)| lo..=hi)
    }
}

/// Normalized form, e.g. `22,80,443,1000-2000`; parses back to the same set.
impl fmt::Display for PortSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, &(lo, hi)) in self.ranges.iter().enumerate() {
            if i > 0 {
                f.write_str(",")?;
            }
            if lo == hi {
                write!(f, "{lo}")?;
            } else {
                write!(f, "{lo}-{hi}")?;
            }
        }
        Ok(())
    }
}

fn parse_item(item: &str) -> Result<(u16, u16), PortSpecError> {
    let Some((lo, hi)) = item.split_once('-') else {
        let port = parse_port(item)?;
        return Ok((port, port));
    };
    let (lo, hi) = (lo.trim(), hi.trim());
    // `-80`, `80-`, `1-2-3`
    if lo.is_empty() || hi.is_empty() || hi.contains('-') {
        return Err(PortSpecError::InvalidRange(echo(item)));
    }
    let (lo, hi) = (parse_port(lo)?, parse_port(hi)?);
    if hi < lo {
        return Err(PortSpecError::ReversedRange(echo(item)));
    }
    Ok((lo, hi))
}

/// Plain decimal port number 1-65535: ASCII digits only, no sign, no leading zeros.
fn parse_port(s: &str) -> Result<u16, PortSpecError> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(PortSpecError::InvalidPort(echo(s)));
    }
    if s.len() > 5 {
        return Err(PortSpecError::OutOfRange(echo(s)));
    }
    if s.len() > 1 && s.starts_with('0') {
        return Err(PortSpecError::InvalidPort(echo(s)));
    }
    match s.parse::<u32>() {
        Ok(n @ 1..=65_535) => Ok(n as u16),
        _ => Err(PortSpecError::OutOfRange(echo(s))),
    }
}

/// Shortened copy of user input for error messages.
fn echo(s: &str) -> String {
    const MAX_ECHO_CHARS: usize = 32;
    match s.char_indices().nth(MAX_ECHO_CHARS) {
        Some((cut, _)) => format!("{}…", &s[..cut]),
        None => s.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Number of ports in `1-65535`.
    const ALL_PORTS: usize = 65_535;

    fn ports(input: &str) -> Vec<u16> {
        PortSet::parse(input).unwrap().iter().collect()
    }

    fn err(input: &str) -> PortSpecError {
        PortSet::parse(input).unwrap_err()
    }

    #[test]
    fn single_ports_ranges_and_lists() {
        assert_eq!(ports("22"), [22]);
        assert_eq!(ports("1"), [1]);
        assert_eq!(ports("65535"), [65535]);
        assert_eq!(ports("22,80,443"), [22, 80, 443]);
        assert_eq!(ports("1000-1003"), [1000, 1001, 1002, 1003]);
        assert_eq!(ports("7-7"), [7]);
        assert_eq!(
            ports("22,80,443,1000-1002"),
            [22, 80, 443, 1000, 1001, 1002]
        );
    }

    #[test]
    fn whitespace_around_entries_and_dashes_is_allowed() {
        assert_eq!(ports(" 22 , 80\t,443 "), [22, 80, 443]);
        assert_eq!(ports("1000 - 1002"), [1000, 1001, 1002]);
    }

    #[test]
    fn duplicates_and_overlaps_are_merged() {
        assert_eq!(ports("80,80,80"), [80]);
        assert_eq!(ports("443,22,80"), [22, 80, 443]);
        assert_eq!(ports("10-20,15-25,5"), {
            let mut v = vec![5];
            v.extend(10..=25);
            v
        });
        // Adjacent ranges become one.
        let set = PortSet::parse("1-10,11-20,21").unwrap();
        assert_eq!(set.len(), 21);
        assert_eq!(set.to_string(), "1-21");
    }

    #[test]
    fn full_range() {
        let set = PortSet::parse("1-65535").unwrap();
        assert_eq!(set.len(), ALL_PORTS);
        assert_eq!(set, PortSet::all());
        assert_eq!(set.iter().next(), Some(1));
        assert_eq!(set.iter().last(), Some(65535));
        assert_eq!(set.iter().count(), ALL_PORTS);
        // Overlapping the end does not overflow.
        assert_eq!(PortSet::parse("65000-65535,65535").unwrap().len(), 536);
    }

    #[test]
    fn display_is_normalized_and_round_trips() {
        for (input, normalized) in [
            ("443, 22,80,1000-2000,1500", "22,80,443,1000-2000"),
            ("5,4,3,2,1", "1-5"),
            ("65535", "65535"),
            ("1-65535", "1-65535"),
        ] {
            let set = PortSet::parse(input).unwrap();
            assert_eq!(set.to_string(), normalized);
            assert_eq!(PortSet::parse(normalized).unwrap(), set);
        }
    }

    #[test]
    fn contains_and_len() {
        let set = PortSet::parse("22,80-90,443").unwrap();
        assert_eq!(set.len(), 13);
        for port in [22, 80, 85, 90, 443] {
            assert!(set.contains(port), "{port}");
        }
        for port in [1, 21, 23, 79, 91, 442, 444, 65535] {
            assert!(!set.contains(port), "{port}");
        }
    }

    #[test]
    fn from_ports_dedups_and_ignores_zero() {
        let set = PortSet::from_ports([443, 0, 22, 443, 23]);
        assert_eq!(set.iter().collect::<Vec<_>>(), [22, 23, 443]);
        assert_eq!(PortSet::from_ports([]).len(), 0);
    }

    #[test]
    fn empty_input() {
        for input in ["", " ", "\t\n"] {
            assert_eq!(err(input), PortSpecError::Empty, "{input:?}");
        }
    }

    #[test]
    fn empty_entries_are_rejected() {
        for input in [",", "22,", ",22", "22,,80", "22, ,80"] {
            assert_eq!(err(input), PortSpecError::EmptyEntry, "{input:?}");
        }
    }

    #[test]
    fn invalid_numbers() {
        for input in [
            "a", "80a", "0x50", "+80", "-", "8 0", "80.0", "１２", "080", "00",
        ] {
            assert!(
                matches!(
                    err(input),
                    PortSpecError::InvalidPort(_) | PortSpecError::InvalidRange(_)
                ),
                "{input:?}"
            );
        }
        assert_eq!(err("080"), PortSpecError::InvalidPort("080".into()));
        assert_eq!(err("22,ssh"), PortSpecError::InvalidPort("ssh".into()));
    }

    #[test]
    fn out_of_range_numbers() {
        for input in ["0", "65536", "99999", "123456", "99999999999999999999"] {
            assert!(
                matches!(err(input), PortSpecError::OutOfRange(_)),
                "{input:?}"
            );
        }
        assert_eq!(err("1-70000"), PortSpecError::OutOfRange("70000".into()));
        assert_eq!(err("0-10"), PortSpecError::OutOfRange("0".into()));
    }

    #[test]
    fn invalid_ranges() {
        for input in ["-80", "80-", "1-2-3", "- 5", "1--5"] {
            assert_eq!(
                err(input),
                PortSpecError::InvalidRange(input.into()),
                "{input:?}"
            );
        }
        assert_eq!(err("90-80"), PortSpecError::ReversedRange("90-80".into()));
        assert_eq!(err("a-b"), PortSpecError::InvalidPort("a".into()));
    }

    #[test]
    fn input_length_limit() {
        // Exactly at the limit: valid (e.g. a long list padded with spaces).
        let at_limit = format!("{:<width$}", "80", width = MAX_SPEC_LEN);
        assert_eq!(PortSet::parse(&at_limit).unwrap().len(), 1);
        let over = format!("{at_limit} ");
        assert_eq!(err(&over), PortSpecError::InputTooLong);
        // A list that is too long fails on the length, not on its content.
        let many = (1..=1000)
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",");
        assert!(many.len() > MAX_SPEC_LEN);
        assert_eq!(err(&many), PortSpecError::InputTooLong);
    }

    #[test]
    fn error_details_are_shortened() {
        let long = "x".repeat(100);
        let PortSpecError::InvalidPort(echoed) = err(&long) else {
            panic!("expected an invalid port");
        };
        assert_eq!(echoed.chars().count(), 33);
        assert!(echoed.ends_with('…'));
        // Multi-byte characters are cut on a character boundary.
        let wide = "ü".repeat(40);
        assert!(matches!(err(&wide), PortSpecError::InvalidPort(s) if s.chars().count() == 33));
    }

    #[test]
    fn error_codes_and_details() {
        assert_eq!(err("").code(), "ports.empty");
        assert_eq!(err("").detail(), None);
        let e = err("22,99999");
        assert_eq!(
            (e.code(), e.detail().as_deref()),
            ("ports.out_of_range", Some("99999"))
        );
        assert_eq!(err("5-1").code(), "ports.reversed_range");
        assert_eq!(err("1,,2").code(), "ports.empty_entry");
    }
}
