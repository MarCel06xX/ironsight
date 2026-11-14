//! Placeholder backend so the crate builds on platforms without an implementation yet.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use super::{Adapter, NetBackend, NetError};
use crate::mac::MacAddr;

pub struct UnsupportedBackend;

impl NetBackend for UnsupportedBackend {
    fn list_adapters(&self) -> Result<Vec<Adapter>, NetError> {
        Err(NetError::Unsupported)
    }

    fn arp_resolve(
        &self,
        _target: Ipv4Addr,
        _src: Option<Ipv4Addr>,
    ) -> Result<Option<MacAddr>, NetError> {
        Err(NetError::Unsupported)
    }

    fn icmp_ping(&self, _target: IpAddr, _timeout: Duration) -> Result<Option<Duration>, NetError> {
        Err(NetError::Unsupported)
    }
}
