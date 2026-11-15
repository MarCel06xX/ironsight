//! MAC address type shared by platform, enrichment and export code.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    pub fn is_zero(&self) -> bool {
        self.0 == [0; 6]
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02X}:{b:02X}:{c:02X}:{d:02X}:{e:02X}:{g:02X}")
    }
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid MAC address")]
pub struct MacParseError;

/// Accepts `AA:BB:CC:DD:EE:FF` and `AA-BB-CC-DD-EE-FF` (case-insensitive).
impl FromStr for MacAddr {
    type Err = MacParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut octets = [0u8; 6];
        let mut parts = s.split([':', '-']);
        for octet in &mut octets {
            let part = parts.next().ok_or(MacParseError)?;
            if part.len() != 2 || !part.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(MacParseError);
            }
            *octet = u8::from_str_radix(part, 16).map_err(|_| MacParseError)?;
        }
        if parts.next().is_some() {
            return Err(MacParseError);
        }
        Ok(Self(octets))
    }
}

impl Serialize for MacAddr {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for MacAddr {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_uppercase_with_colons() {
        let mac = MacAddr([0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0xff]);
        assert_eq!(mac.to_string(), "00:1A:2B:3C:4D:FF");
    }

    #[test]
    fn parses_both_separators() {
        let expected = MacAddr([0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0xff]);
        assert_eq!("00:1a:2B:3c:4D:ff".parse(), Ok(expected));
        assert_eq!("00-1A-2B-3C-4D-FF".parse(), Ok(expected));
    }

    #[test]
    fn rejects_malformed_input() {
        for bad in [
            "",
            "00:1A:2B:3C:4D",
            "00:1A:2B:3C:4D:FF:00",
            "0:1A:2B:3C:4D:FF",
            "+0:1A:2B:3C:4D:FF",
            "GG:1A:2B:3C:4D:FF",
            "001A2B3C4DFF",
        ] {
            assert_eq!(bad.parse::<MacAddr>(), Err(MacParseError), "{bad}");
        }
    }

    #[test]
    fn serializes_as_string() {
        let json = serde_json::to_string(&MacAddr([1, 2, 3, 4, 5, 6])).unwrap();
        assert_eq!(json, "\"01:02:03:04:05:06\"");
    }
}
