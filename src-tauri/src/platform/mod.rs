//! Platform abstraction. Everything OS-specific lives behind [`NetBackend`], so other
//! operating systems (and later raw-socket features) can be added without touching the engine.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;

use crate::mac::MacAddr;

#[cfg(not(windows))]
mod unsupported;
#[cfg(windows)]
mod windows;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NetError {
    #[error("{api} failed with system error {code}")]
    Os { api: &'static str, code: u32 },
    #[error("not supported on this platform")]
    Unsupported,
}

/// An IPv4 address assigned to an adapter, together with its on-link prefix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Ipv4Net {
    pub addr: Ipv4Addr,
    pub prefix_len: u8,
    /// Suggested scan target for this subnet, e.g. `192.168.1.0/24`.
    pub scan_target: String,
}

impl Ipv4Net {
    pub fn new(addr: Ipv4Addr, prefix_len: u8) -> Self {
        let prefix_len = prefix_len.min(32);
        // Subnets larger than the scan limit fall back to the /24 around the adapter address.
        let target_prefix = if prefix_len < 16 { 24 } else { prefix_len };
        let network = u32::from(addr) & mask(target_prefix);
        Self {
            addr,
            prefix_len,
            scan_target: format!("{}/{target_prefix}", Ipv4Addr::from(network)),
        }
    }

    /// Directed broadcast address of the subnet; `None` for /31 and /32.
    pub fn broadcast(&self) -> Option<Ipv4Addr> {
        let host_bits = !mask(self.prefix_len);
        (self.prefix_len <= 30).then(|| Ipv4Addr::from(u32::from(self.addr) | host_bits))
    }

    /// Whether `ip` is on-link, i.e. reachable via ARP from this address.
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let mask = mask(self.prefix_len);
        u32::from(ip) & mask == u32::from(self.addr) & mask
    }
}

fn mask(prefix_len: u8) -> u32 {
    match prefix_len {
        0 => 0,
        n => u32::MAX << (32 - u32::from(n.min(32))),
    }
}

/// An active network adapter with at least one IPv4 address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Adapter {
    pub id: String,
    pub name: String,
    pub description: String,
    pub mac: Option<MacAddr>,
    pub ipv4: Vec<Ipv4Net>,
    /// IPv4 DNS servers configured on this adapter.
    pub dns_servers: Vec<Ipv4Addr>,
    /// Has a default gateway; such adapters are listed first.
    pub has_gateway: bool,
}

/// OS networking primitives. `arp_resolve` and `icmp_ping` block and must be called from
/// a blocking thread (`spawn_blocking`).
pub trait NetBackend: Send + Sync + 'static {
    /// Active, non-loopback adapters that have an IPv4 address.
    fn list_adapters(&self) -> Result<Vec<Adapter>, NetError>;

    /// Resolves the MAC address of an on-link host. `Ok(None)` means no answer.
    /// `src` selects the local address (and thereby the interface) to ask from.
    fn arp_resolve(
        &self,
        target: Ipv4Addr,
        src: Option<Ipv4Addr>,
    ) -> Result<Option<MacAddr>, NetError>;

    /// Sends one ICMP echo request. `Ok(None)` means no reply within `timeout`.
    fn icmp_ping(&self, target: IpAddr, timeout: Duration) -> Result<Option<Duration>, NetError>;

    /// IPv4 entries of the OS neighbor (ARP) cache with a usable MAC address, see
    /// [`usable_neighbor`]. The default (no cache available) is an empty list.
    fn neighbor_cache(&self) -> Result<Vec<Neighbor>, NetError> {
        Ok(Vec::new())
    }
}

/// An entry of the OS neighbor cache: this address had this MAC address recently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Neighbor {
    pub ip: Ipv4Addr,
    pub mac: MacAddr,
}

/// State of a neighbor cache entry (`NL_NEIGHBOR_STATE` on Windows).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeighborState {
    Unreachable,
    Incomplete,
    Probe,
    Delay,
    Stale,
    Reachable,
    Permanent,
    Unknown,
}

/// Turns a raw cache entry into a [`Neighbor`] if it names a real unicast device: the
/// address resolution must have succeeded at some point (not unreachable/incomplete), the
/// hardware address must be a 6-byte unicast MAC (not zero, broadcast or multicast) and the
/// IP must be a unicast address (multicast/broadcast entries are static OS entries).
pub fn usable_neighbor(ip: Ipv4Addr, hw: &[u8], state: NeighborState) -> Option<Neighbor> {
    if matches!(
        state,
        NeighborState::Unreachable | NeighborState::Incomplete | NeighborState::Unknown
    ) {
        return None;
    }
    let bytes: [u8; 6] = hw.try_into().ok()?;
    let mac = MacAddr(bytes);
    let unicast_mac = !mac.is_zero() && bytes[0] & 0x01 == 0;
    let unicast_ip = !(ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_unspecified()
        || ip.is_loopback()
        || ip.octets()[0] >= 224);
    (unicast_mac && unicast_ip).then_some(Neighbor { ip, mac })
}

#[derive(Debug, thiserror::Error)]
pub enum LaunchError {
    #[error("IPv6 targets are not supported yet")]
    Ipv6,
    #[error("could not start {program}: {source}")]
    Spawn {
        program: &'static str,
        source: std::io::Error,
    },
    #[error("system directory not found")]
    NoSystemDir,
    /// Only constructed by the placeholder backend of other platforms.
    #[cfg_attr(windows, allow(dead_code))]
    #[error("not supported on this platform")]
    Unsupported,
}

/// Starts the Remote Desktop client for `ip`.
pub fn open_remote_desktop(ip: IpAddr) -> Result<(), LaunchError> {
    #[cfg(windows)]
    return windows::open_remote_desktop(ip);
    #[cfg(not(windows))]
    return unsupported::open_remote_desktop(ip);
}

/// Shows the file shares of `ip` in the file manager.
pub fn open_file_share(ip: IpAddr) -> Result<(), LaunchError> {
    #[cfg(windows)]
    return windows::open_file_share(ip);
    #[cfg(not(windows))]
    return unsupported::open_file_share(ip);
}

pub fn default_backend() -> Arc<dyn NetBackend> {
    #[cfg(windows)]
    return Arc::new(windows::WindowsBackend);
    #[cfg(not(windows))]
    return Arc::new(unsupported::UnsupportedBackend);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_target_is_the_subnet() {
        let net = Ipv4Net::new(Ipv4Addr::new(192, 168, 1, 23), 24);
        assert_eq!(net.scan_target, "192.168.1.0/24");
        let net = Ipv4Net::new(Ipv4Addr::new(172, 20, 99, 5), 20);
        assert_eq!(net.scan_target, "172.20.96.0/20");
        let net = Ipv4Net::new(Ipv4Addr::new(10, 8, 0, 2), 32);
        assert_eq!(net.scan_target, "10.8.0.2/32");
    }

    #[test]
    fn scan_target_of_huge_subnets_falls_back_to_slash_24() {
        let net = Ipv4Net::new(Ipv4Addr::new(10, 1, 2, 3), 8);
        assert_eq!(net.scan_target, "10.1.2.0/24");
        assert_eq!(net.prefix_len, 8);
    }

    #[test]
    fn broadcast_addresses() {
        let broadcast =
            |addr: [u8; 4], prefix| Ipv4Net::new(Ipv4Addr::from(addr), prefix).broadcast();
        assert_eq!(
            broadcast([192, 168, 1, 23], 24),
            Some(Ipv4Addr::new(192, 168, 1, 255))
        );
        assert_eq!(
            broadcast([172, 20, 99, 5], 20),
            Some(Ipv4Addr::new(172, 20, 111, 255))
        );
        assert_eq!(
            broadcast([10, 0, 0, 4], 30),
            Some(Ipv4Addr::new(10, 0, 0, 7))
        );
        assert_eq!(broadcast([10, 0, 0, 4], 31), None);
        assert_eq!(broadcast([10, 0, 0, 4], 32), None);
    }

    #[test]
    fn neighbor_cache_filtering() {
        let ip = Ipv4Addr::new(192, 168, 1, 23);
        let mac = [0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e];
        let expected = Some(Neighbor {
            ip,
            mac: MacAddr(mac),
        });
        for state in [
            NeighborState::Stale,
            NeighborState::Reachable,
            NeighborState::Delay,
            NeighborState::Probe,
            NeighborState::Permanent,
        ] {
            assert_eq!(usable_neighbor(ip, &mac, state), expected, "{state:?}");
        }
        // Resolution never succeeded.
        for state in [
            NeighborState::Unreachable,
            NeighborState::Incomplete,
            NeighborState::Unknown,
        ] {
            assert_eq!(usable_neighbor(ip, &mac, state), None, "{state:?}");
        }
        // Unusable hardware addresses.
        let stale = NeighborState::Stale;
        assert_eq!(usable_neighbor(ip, &[0; 6], stale), None);
        assert_eq!(usable_neighbor(ip, &[0xff; 6], stale), None);
        assert_eq!(
            usable_neighbor(ip, &[0x01, 0x00, 0x5e, 0, 0, 1], stale),
            None
        );
        assert_eq!(usable_neighbor(ip, &mac[..4], stale), None);
        assert_eq!(usable_neighbor(ip, &[0; 8], stale), None);
        // Static entries for multicast and broadcast addresses.
        let permanent = NeighborState::Permanent;
        for addr in [
            Ipv4Addr::new(224, 0, 0, 22),
            Ipv4Addr::new(239, 255, 255, 250),
            Ipv4Addr::BROADCAST,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::LOCALHOST,
        ] {
            assert_eq!(usable_neighbor(addr, &mac, permanent), None, "{addr}");
        }
    }

    #[test]
    fn contains_uses_the_real_prefix() {
        let net = Ipv4Net::new(Ipv4Addr::new(10, 1, 2, 3), 8);
        assert!(net.contains(Ipv4Addr::new(10, 200, 0, 1)));
        assert!(!net.contains(Ipv4Addr::new(11, 0, 0, 1)));
        let host = Ipv4Net::new(Ipv4Addr::new(10, 8, 0, 2), 32);
        assert!(host.contains(Ipv4Addr::new(10, 8, 0, 2)));
        assert!(!host.contains(Ipv4Addr::new(10, 8, 0, 3)));
        let any = Ipv4Net::new(Ipv4Addr::new(10, 8, 0, 2), 0);
        assert!(any.contains(Ipv4Addr::new(8, 8, 8, 8)));
    }
}
