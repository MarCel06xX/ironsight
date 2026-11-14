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
