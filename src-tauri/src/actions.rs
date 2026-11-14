//! User-triggered actions on a host that need no OS-specific code: the browser URL and
//! Wake-on-LAN. Starting programs (RDP, Explorer) lives in `platform`.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4, UdpSocket};

use crate::mac::MacAddr;
use crate::platform::{Adapter, Ipv4Net};

/// "Discard" port, the usual Wake-on-LAN destination.
pub const WOL_PORT: u16 = 9;

/// `http(s)://<ip>[:port]/`, built only from typed values.
pub fn web_url(ip: IpAddr, secure: bool, port: u16) -> String {
    let (scheme, default_port) = if secure { ("https", 443) } else { ("http", 80) };
    let host = match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("[{v6}]"),
    };
    if port == default_port {
        format!("{scheme}://{host}/")
    } else {
        format!("{scheme}://{host}:{port}/")
    }
}

/// Only unicast, non-zero addresses identify a single network card.
pub fn is_wakeable(mac: MacAddr) -> bool {
    !mac.is_zero() && mac.0[0] & 0x01 == 0
}

/// Magic packet: six 0xFF bytes followed by the MAC address 16 times.
pub fn magic_packet(mac: MacAddr) -> [u8; 102] {
    let mut packet = [0xFF; 102];
    for chunk in packet[6..].as_chunks_mut::<6>().0 {
        chunk.copy_from_slice(&mac.0);
    }
    packet
}

/// Where to send the magic packet, as (local source address, destination) pairs.
/// A sleeping host has no ARP entry, so broadcasts are used: on the subnet that contains
/// its last known address, or on every subnet if that is unknown or off-link.
pub fn wol_destinations(
    target: Option<Ipv4Addr>,
    adapters: &[Adapter],
) -> Vec<(Ipv4Addr, SocketAddrV4)> {
    let nets: Vec<&Ipv4Net> = adapters.iter().flat_map(|a| &a.ipv4).collect();
    let on_link: Vec<&Ipv4Net> = nets
        .iter()
        .copied()
        .filter(|net| target.is_some_and(|ip| net.contains(ip)))
        .collect();
    let off_link = on_link.is_empty();
    let chosen = if off_link { nets } else { on_link };

    let mut destinations = Vec::new();
    for net in chosen {
        if let Some(broadcast) = net.broadcast() {
            destinations.push((net.addr, SocketAddrV4::new(broadcast, WOL_PORT)));
        }
        destinations.push((net.addr, SocketAddrV4::new(Ipv4Addr::BROADCAST, WOL_PORT)));
    }
    // Off-link: also unicast towards it, which works while the router still knows the MAC.
    if let Some(ip) = target.filter(|_| off_link) {
        destinations.push((Ipv4Addr::UNSPECIFIED, SocketAddrV4::new(ip, WOL_PORT)));
    }
    destinations
}

/// Sends the magic packet to all destinations; succeeds if at least one send worked.
pub fn send_magic_packet(
    mac: MacAddr,
    target: Option<Ipv4Addr>,
    adapters: &[Adapter],
) -> io::Result<usize> {
    let packet = magic_packet(mac);
    let mut sent = 0;
    let mut last_error = None;
    for (src, dst) in wol_destinations(target, adapters) {
        match send_from(src, dst, &packet) {
            Ok(()) => sent += 1,
            Err(e) => last_error = Some(e),
        }
    }
    match (sent, last_error) {
        (0, Some(e)) => Err(e),
        (0, None) => Err(io::Error::other("no network adapter with an IPv4 address")),
        (sent, _) => Ok(sent),
    }
}

fn send_from(src: Ipv4Addr, dst: SocketAddrV4, packet: &[u8]) -> io::Result<()> {
    let socket = UdpSocket::bind(SocketAddrV4::new(src, 0))?;
    socket.set_broadcast(true)?;
    socket.send_to(packet, dst)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;
    use std::time::Duration;

    use super::*;

    const MAC: MacAddr = MacAddr([0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]);

    fn adapter(nets: &[([u8; 4], u8)]) -> Adapter {
        Adapter {
            id: String::new(),
            name: String::new(),
            description: String::new(),
            mac: None,
            ipv4: nets
                .iter()
                .map(|(addr, prefix)| Ipv4Net::new(Ipv4Addr::from(*addr), *prefix))
                .collect(),
            dns_servers: Vec::new(),
            has_gateway: false,
        }
    }

    fn dst(ip: [u8; 4]) -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::from(ip), WOL_PORT)
    }

    #[test]
    fn urls() {
        let v4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(web_url(v4, false, 80), "http://192.168.1.1/");
        assert_eq!(web_url(v4, true, 443), "https://192.168.1.1/");
        assert_eq!(web_url(v4, false, 8080), "http://192.168.1.1:8080/");
        assert_eq!(web_url(v4, true, 8443), "https://192.168.1.1:8443/");
        assert_eq!(web_url(v4, true, 80), "https://192.168.1.1:80/");
        let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert_eq!(web_url(v6, false, 8080), "http://[::1]:8080/");
    }

    #[test]
    fn magic_packet_layout() {
        let packet = magic_packet(MAC);
        assert_eq!(packet[..6], [0xFF; 6]);
        for repeat in packet[6..].chunks(6) {
            assert_eq!(repeat, MAC.0);
        }
        assert_eq!(packet[6..].chunks(6).count(), 16);
    }

    #[test]
    fn wakeable_macs() {
        assert!(is_wakeable(MAC));
        assert!(is_wakeable(MacAddr([0x02, 0, 0, 0, 0, 1]))); // locally administered is fine
        assert!(!is_wakeable(MacAddr([0; 6])));
        assert!(!is_wakeable(MacAddr([0xFF; 6])));
        assert!(!is_wakeable(MacAddr([0x01, 0x00, 0x5e, 0, 0, 1]))); // multicast
    }

    #[test]
    fn on_link_target_uses_its_subnet_only() {
        let adapters = [
            adapter(&[([192, 168, 1, 20], 24)]),
            adapter(&[([10, 8, 0, 2], 24)]),
        ];
        let local = Ipv4Addr::new(192, 168, 1, 20);
        assert_eq!(
            wol_destinations(Some(Ipv4Addr::new(192, 168, 1, 50)), &adapters),
            [
                (local, dst([192, 168, 1, 255])),
                (local, dst([255, 255, 255, 255]))
            ]
        );
    }

    #[test]
    fn unknown_or_off_link_target_uses_every_subnet() {
        let adapters = [adapter(&[([192, 168, 1, 20], 24), ([10, 8, 0, 2], 32)])];
        let lan = Ipv4Addr::new(192, 168, 1, 20);
        let vpn = Ipv4Addr::new(10, 8, 0, 2);
        let everywhere = vec![
            (lan, dst([192, 168, 1, 255])),
            (lan, dst([255, 255, 255, 255])),
            (vpn, dst([255, 255, 255, 255])), // /32 has no directed broadcast
        ];
        assert_eq!(wol_destinations(None, &adapters), everywhere);

        let remote = Ipv4Addr::new(172, 16, 0, 9);
        let mut expected = everywhere;
        expected.push((Ipv4Addr::UNSPECIFIED, dst([172, 16, 0, 9])));
        assert_eq!(wol_destinations(Some(remote), &adapters), expected);

        assert!(wol_destinations(None, &[]).is_empty());
    }

    #[test]
    fn no_adapters_is_an_error() {
        assert!(send_magic_packet(MAC, None, &[]).is_err());
    }

    #[test]
    fn packet_arrives_on_the_wire() {
        let receiver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let std::net::SocketAddr::V4(addr) = receiver.local_addr().unwrap() else {
            unreachable!()
        };
        send_from(Ipv4Addr::LOCALHOST, addr, &magic_packet(MAC)).unwrap();
        let mut buf = [0u8; 200];
        let len = receiver.recv(&mut buf).unwrap();
        assert_eq!(buf[..len], magic_packet(MAC));
    }
}
