//! Vendor lookup from the MAC prefix (IEEE MA-L registry), embedded at compile time.
//! The data file is produced by `npm run update-oui` (tools/oui/update-oui.mjs).

use std::sync::LazyLock;

use crate::mac::MacAddr;

static EMBEDDED: &[u8] = include_bytes!("../../data/oui.bin");
static DB: LazyLock<Option<OuiDb<'static>>> = LazyLock::new(|| OuiDb::parse(EMBEDDED));

const MAGIC: &[u8; 4] = b"IOUI";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 16;
const RECORD_LEN: usize = 6;

/// Vendor of a globally unique MAC address, if its prefix is registered.
pub fn vendor(mac: MacAddr) -> Option<&'static str> {
    DB.as_ref()?.lookup(mac)
}

/// Locally administered addresses (second-lowest bit of the first octet) are not assigned by
/// IEEE: randomized/private Wi-Fi addresses and many virtual adapters use them.
pub fn is_locally_administered(mac: MacAddr) -> bool {
    mac.0[0] & 0x02 != 0
}

/// Read-only view of the compact OUI table (format: see tools/oui/update-oui.mjs).
pub struct OuiDb<'a> {
    /// `count` x (prefix: 3 bytes ascending, name offset: u24 LE).
    records: &'a [u8],
    /// Length-prefixed UTF-8 names.
    names: &'a [u8],
}

impl<'a> OuiDb<'a> {
    /// Returns `None` if the header or the section sizes are inconsistent.
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        let header = data.get(..HEADER_LEN)?;
        if &header[..4] != MAGIC || header[4] != VERSION {
            return None;
        }
        let count = u32::from_le_bytes(header[8..12].try_into().ok()?) as usize;
        let names_len = u32::from_le_bytes(header[12..16].try_into().ok()?) as usize;
        let records_end = HEADER_LEN.checked_add(count.checked_mul(RECORD_LEN)?)?;
        let names_end = records_end.checked_add(names_len)?;
        if names_end != data.len() {
            return None;
        }
        Some(Self {
            records: &data[HEADER_LEN..records_end],
            names: &data[records_end..],
        })
    }

    pub fn len(&self) -> usize {
        self.records.len() / RECORD_LEN
    }

    pub fn lookup(&self, mac: MacAddr) -> Option<&'a str> {
        let wanted = &mac.0[..3];
        let (mut lo, mut hi) = (0, self.len());
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let record = self.records.get(mid * RECORD_LEN..(mid + 1) * RECORD_LEN)?;
            match record[..3].cmp(wanted) {
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
                std::cmp::Ordering::Equal => {
                    let offset = u32::from_le_bytes([record[3], record[4], record[5], 0]) as usize;
                    let len = usize::from(*self.names.get(offset)?);
                    let name = self.names.get(offset + 1..offset + 1 + len)?;
                    return std::str::from_utf8(name).ok();
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a table in the on-disk format from sorted `(prefix, name offset)` records.
    fn table(records: &[([u8; 3], u32)], names: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(MAGIC);
        data.extend_from_slice(&[VERSION, 0, 0, 0]);
        data.extend_from_slice(&(records.len() as u32).to_le_bytes());
        data.extend_from_slice(&(names.len() as u32).to_le_bytes());
        for (prefix, offset) in records {
            data.extend_from_slice(prefix);
            data.extend_from_slice(&offset.to_le_bytes()[..3]);
        }
        data.extend_from_slice(names);
        data
    }

    fn mac(prefix: [u8; 3]) -> MacAddr {
        MacAddr([prefix[0], prefix[1], prefix[2], 0x12, 0x34, 0x56])
    }

    const NAMES: &[u8] = b"\x04Acme\x07M\xc3\xbcller";

    fn sample() -> Vec<u8> {
        table(
            &[
                ([0x00, 0x00, 0x0c], 0),
                ([0x00, 0x1a, 0x2b], 5),
                ([0x3c, 0x5a, 0xb4], 0),
                ([0xfc, 0xff, 0xaa], 5),
            ],
            NAMES,
        )
    }

    #[test]
    fn finds_every_entry_and_shares_names() {
        let data = sample();
        let db = OuiDb::parse(&data).unwrap();
        assert_eq!(db.len(), 4);
        assert_eq!(db.lookup(mac([0x00, 0x00, 0x0c])), Some("Acme"));
        assert_eq!(db.lookup(mac([0x00, 0x1a, 0x2b])), Some("Müller"));
        assert_eq!(db.lookup(mac([0x3c, 0x5a, 0xb4])), Some("Acme"));
        assert_eq!(db.lookup(mac([0xfc, 0xff, 0xaa])), Some("Müller"));
    }

    #[test]
    fn unknown_prefixes_return_none() {
        let data = sample();
        let db = OuiDb::parse(&data).unwrap();
        for prefix in [
            [0, 0, 0],
            [0x00, 0x00, 0x0d],
            [0x3c, 0x5a, 0xb3],
            [0xff, 0xff, 0xff],
        ] {
            assert_eq!(db.lookup(mac(prefix)), None, "{prefix:02x?}");
        }
        let empty = table(&[], b"");
        assert_eq!(
            OuiDb::parse(&empty).unwrap().lookup(mac([0, 0, 0x0c])),
            None
        );
    }

    #[test]
    fn rejects_inconsistent_files() {
        let good = sample();
        assert!(OuiDb::parse(&good[..good.len() - 1]).is_none());
        assert!(OuiDb::parse(&good[..10]).is_none());
        assert!(OuiDb::parse(&[]).is_none());

        let mut bad_magic = good.clone();
        bad_magic[0] = b'X';
        assert!(OuiDb::parse(&bad_magic).is_none());

        let mut bad_version = good.clone();
        bad_version[4] = 2;
        assert!(OuiDb::parse(&bad_version).is_none());

        let mut huge_count = good.clone();
        huge_count[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(OuiDb::parse(&huge_count).is_none());
    }

    #[test]
    fn broken_name_references_do_not_panic() {
        // Offset past the name table, and a length byte that runs past the end.
        let out_of_range = table(&[([1, 2, 3], 500)], NAMES);
        assert_eq!(
            OuiDb::parse(&out_of_range).unwrap().lookup(mac([1, 2, 3])),
            None
        );
        let overlong = table(&[([1, 2, 3], 0)], b"\x09abc");
        assert_eq!(
            OuiDb::parse(&overlong).unwrap().lookup(mac([1, 2, 3])),
            None
        );
        let not_utf8 = table(&[([1, 2, 3], 0)], b"\x02\xff\xfe");
        assert_eq!(
            OuiDb::parse(&not_utf8).unwrap().lookup(mac([1, 2, 3])),
            None
        );
    }

    #[test]
    fn embedded_registry_is_valid() {
        let db = OuiDb::parse(EMBEDDED).expect("embedded oui.bin must parse");
        assert!(db.len() > 30_000);
        // 00-00-0C has belonged to Cisco since the registry exists.
        let cisco = vendor(MacAddr([0x00, 0x00, 0x0c, 1, 2, 3])).unwrap();
        assert!(cisco.to_lowercase().contains("cisco"), "{cisco}");
    }

    #[test]
    fn locally_administered_bit() {
        assert!(is_locally_administered(MacAddr([0x02, 0, 0, 0, 0, 1])));
        assert!(is_locally_administered(MacAddr([
            0xda, 0xa1, 0x19, 0, 0, 1
        ])));
        assert!(is_locally_administered(MacAddr([
            0x52, 0x54, 0x00, 0, 0, 1
        ])));
        assert!(!is_locally_administered(MacAddr([
            0x00, 0x1a, 0x2b, 0, 0, 1
        ])));
        assert!(!is_locally_administered(MacAddr([
            0xfc, 0xff, 0xaa, 0, 0, 1
        ])));
    }
}
