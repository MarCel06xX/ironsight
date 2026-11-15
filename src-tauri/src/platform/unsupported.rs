//! Placeholder backend so the crate builds on platforms without an implementation yet.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use super::{Adapter, LaunchError, NetBackend, NetError};
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

pub fn open_remote_desktop(_ip: IpAddr) -> Result<(), LaunchError> {
    Err(LaunchError::Unsupported)
}

pub fn open_file_share(_ip: IpAddr) -> Result<(), LaunchError> {
    Err(LaunchError::Unsupported)
}

/// Nothing to tune yet; the probe's own timeout applies.
pub fn prepare_probe_socket(
    _socket: &tokio::net::TcpSocket,
    _timeout: Duration,
) -> std::io::Result<()> {
    Ok(())
}
