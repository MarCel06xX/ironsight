//! Windows backend on top of the IP Helper API. Needs neither admin rights nor Npcap.

use std::ffi::OsString;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::os::windows::ffi::OsStringExt;
use std::os::windows::io::AsRawSocket;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST,
    GET_ADAPTERS_ADDRESSES_FLAGS, GetAdaptersAddresses, GetIpNetTable2, ICMP_ECHO_REPLY,
    IF_TYPE_SOFTWARE_LOOPBACK, IP_ADAPTER_ADDRESSES_LH, IP_SUCCESS, IcmpCloseHandle,
    IcmpCreateFile, IcmpSendEcho, MIB_IPNET_TABLE2, SendARP,
};
use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows::Win32::Networking::WinSock::{
    ADDRESS_FAMILY, IPPROTO_TCP, NL_NEIGHBOR_STATE, NlnsDelay, NlnsIncomplete, NlnsPermanent,
    NlnsProbe, NlnsReachable, NlnsStale, NlnsUnreachable, SIO_TCP_INITIAL_RTO, SOCKADDR_IN, SOCKET,
    SOCKET_ADDRESS, TCP_FAIL_CONNECT_ON_ICMP_ERROR, TCP_INITIAL_RTO_PARAMETERS, WSAGetLastError,
    WSAIoctl, setsockopt,
};
use windows::Win32::System::SystemInformation::{GetSystemDirectoryW, GetSystemWindowsDirectoryW};

use super::{
    Adapter, Ipv4Net, LaunchError, Neighbor, NeighborState, NetBackend, NetError, usable_neighbor,
};
use crate::mac::MacAddr;

const AF_INET: u16 = 2;

// Win32 error codes used below.
const NO_ERROR: u32 = 0;
const ERROR_NOT_SUPPORTED: u32 = 50;
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_BUFFER_OVERFLOW: u32 = 111;
const ERROR_NO_DATA: u32 = 232;
const ERROR_INVALID_USER_BUFFER: u32 = 1784;

/// Upper bound for strings read from OS structures.
const MAX_NAME_LEN: usize = 256;

const PING_PAYLOAD: [u8; 16] = *b"ironsight-ping\0\0";

pub struct WindowsBackend;

impl NetBackend for WindowsBackend {
    fn list_adapters(&self) -> Result<Vec<Adapter>, NetError> {
        let flags = GET_ADAPTERS_ADDRESSES_FLAGS(
            GAA_FLAG_SKIP_ANYCAST.0 | GAA_FLAG_SKIP_MULTICAST.0 | GAA_FLAG_INCLUDE_GATEWAYS.0,
        );
        let mut size: u32 = 16 * 1024;
        // The adapter list can grow between calls, so retry a few times with the reported size.
        for _ in 0..4 {
            // u64 elements keep the buffer aligned for IP_ADAPTER_ADDRESSES_LH.
            let mut buf = vec![0u64; (size as usize).div_ceil(8)];
            size = (buf.len() * 8) as u32;
            // SAFETY: `buf` is writable for `size` bytes and outlives the call.
            let rc = unsafe {
                GetAdaptersAddresses(
                    u32::from(AF_INET),
                    flags,
                    None,
                    Some(buf.as_mut_ptr().cast()),
                    &mut size,
                )
            };
            match rc {
                // SAFETY: on success the buffer holds a valid linked list that lives as
                // long as `buf`, which is still alive here.
                NO_ERROR => return Ok(unsafe { collect_adapters(buf.as_ptr().cast()) }),
                ERROR_NO_DATA => return Ok(Vec::new()),
                ERROR_BUFFER_OVERFLOW => continue,
                code => {
                    return Err(NetError::Os {
                        api: "GetAdaptersAddresses",
                        code,
                    });
                }
            }
        }
        Err(NetError::Os {
            api: "GetAdaptersAddresses",
            code: ERROR_BUFFER_OVERFLOW,
        })
    }

    fn arp_resolve(
        &self,
        target: Ipv4Addr,
        src: Option<Ipv4Addr>,
    ) -> Result<Option<MacAddr>, NetError> {
        let mut mac = [0u8; 8];
        let mut len: u32 = 6;
        // SAFETY: `mac` is larger than the `len` bytes SendARP may write.
        let rc = unsafe {
            SendARP(
                to_net_u32(target),
                src.map_or(0, to_net_u32),
                mac.as_mut_ptr().cast(),
                &mut len,
            )
        };
        match rc {
            NO_ERROR if len == 6 => {
                let mac = MacAddr([mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]]);
                Ok((!mac.is_zero()).then_some(mac))
            }
            ERROR_NOT_SUPPORTED
            | ERROR_INVALID_PARAMETER
            | ERROR_BUFFER_OVERFLOW
            | ERROR_INVALID_USER_BUFFER => Err(NetError::Os {
                api: "SendARP",
                code: rc,
            }),
            // Everything else (ERROR_BAD_NET_NAME, ERROR_GEN_FAILURE, ...) means "no answer".
            _ => Ok(None),
        }
    }

    fn icmp_ping(&self, target: IpAddr, timeout: Duration) -> Result<Option<Duration>, NetError> {
        let IpAddr::V4(target) = target else {
            return Err(NetError::Unsupported);
        };
        let dest = to_net_u32(target);
        let handle = IcmpHandle::open()?;
        // Room for one ICMP_ECHO_REPLY, the echoed payload and an ICMP error message;
        // u64 elements keep it aligned for ICMP_ECHO_REPLY.
        let mut reply = [0u64; 16];
        const {
            assert!(
                size_of::<ICMP_ECHO_REPLY>() + PING_PAYLOAD.len() + 8 <= size_of::<[u64; 16]>()
            );
        }
        let timeout_ms = timeout.as_millis().clamp(1, 60_000) as u32;
        // SAFETY: request and reply buffers are valid for the sizes passed, and the handle
        // stays open until `handle` is dropped.
        let replies = unsafe {
            IcmpSendEcho(
                handle.0,
                dest,
                PING_PAYLOAD.as_ptr().cast(),
                PING_PAYLOAD.len() as u16,
                None,
                reply.as_mut_ptr().cast(),
                size_of_val(&reply) as u32,
                timeout_ms,
            )
        };
        if replies == 0 {
            return Ok(None); // timed out or unreachable
        }
        // SAFETY: with at least one reply, the buffer starts with an ICMP_ECHO_REPLY.
        let first = unsafe { &*reply.as_ptr().cast::<ICMP_ECHO_REPLY>() };
        // Routers answer for dead hosts with "unreachable" from their own address.
        if first.Status == IP_SUCCESS && first.Address == dest {
            Ok(Some(Duration::from_millis(u64::from(first.RoundTripTime))))
        } else {
            Ok(None)
        }
    }

    fn neighbor_cache(&self) -> Result<Vec<Neighbor>, NetError> {
        Self::read_neighbor_cache()
    }
}

/// `mstsc.exe /v:<ip>` from the system directory.
pub fn open_remote_desktop(ip: IpAddr) -> Result<(), LaunchError> {
    let IpAddr::V4(ip) = ip else {
        return Err(LaunchError::Ipv6);
    };
    let program = os_dir(GetSystemDirectoryW)?.join("mstsc.exe");
    launch(program, "mstsc.exe", format!("/v:{ip}"))
}

/// `explorer.exe \\<ip>` from the Windows directory.
pub fn open_file_share(ip: IpAddr) -> Result<(), LaunchError> {
    let IpAddr::V4(ip) = ip else {
        return Err(LaunchError::Ipv6);
    };
    let program = os_dir(GetSystemWindowsDirectoryW)?.join("explorer.exe");
    launch(program, "explorer.exe", format!(r"\\{ip}"))
}

/// Starts `program` (an absolute path, so no search path is involved) without waiting.
/// The single argument is built from a validated address only.
fn launch(program: PathBuf, name: &'static str, arg: String) -> Result<(), LaunchError> {
    Command::new(program)
        .arg(arg)
        .spawn()
        .map(drop)
        .map_err(|source| LaunchError::Spawn {
            program: name,
            source,
        })
}

/// Reads a directory from a `Get*DirectoryW` style API.
fn os_dir(get: unsafe fn(Option<&mut [u16]>) -> u32) -> Result<PathBuf, LaunchError> {
    let mut buf = [0u16; 512];
    // SAFETY: the API writes at most `buf.len()` units and returns the length written.
    let len = unsafe { get(Some(&mut buf)) } as usize;
    if len == 0 || len >= buf.len() {
        return Err(LaunchError::NoSystemDir);
    }
    Ok(PathBuf::from(OsString::from_wide(&buf[..len])))
}

impl WindowsBackend {
    /// IPv4 neighbor cache via `GetIpNetTable2`.
    fn read_neighbor_cache() -> Result<Vec<Neighbor>, NetError> {
        let mut table: *mut MIB_IPNET_TABLE2 = std::ptr::null_mut();
        // SAFETY: on success the API allocates the table, which is freed below.
        let rc = unsafe { GetIpNetTable2(ADDRESS_FAMILY(AF_INET), &mut table) };
        if rc.0 != NO_ERROR || table.is_null() {
            return Err(NetError::Os {
                api: "GetIpNetTable2",
                code: rc.0,
            });
        }
        let mut neighbors = Vec::new();
        // SAFETY: `table` points to a valid table with `NumEntries` rows until it is freed.
        unsafe {
            let count = (*table).NumEntries as usize;
            let rows = std::ptr::addr_of!((*table).Table)
                .cast::<windows::Win32::NetworkManagement::IpHelper::MIB_IPNET_ROW2>();
            for i in 0..count {
                let row = &*rows.add(i);
                if row.Address.si_family.0 != AF_INET {
                    continue;
                }
                let ip = Ipv4Addr::from(row.Address.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes());
                let len = (row.PhysicalAddressLength as usize).min(row.PhysicalAddress.len());
                if let Some(neighbor) =
                    usable_neighbor(ip, &row.PhysicalAddress[..len], neighbor_state(row.State))
                {
                    neighbors.push(neighbor);
                }
            }
            FreeMibTable(table.cast());
        }
        Ok(neighbors)
    }
}

fn neighbor_state(state: NL_NEIGHBOR_STATE) -> NeighborState {
    let states = [
        (NlnsUnreachable, NeighborState::Unreachable),
        (NlnsIncomplete, NeighborState::Incomplete),
        (NlnsProbe, NeighborState::Probe),
        (NlnsDelay, NeighborState::Delay),
        (NlnsStale, NeighborState::Stale),
        (NlnsReachable, NeighborState::Reachable),
        (NlnsPermanent, NeighborState::Permanent),
    ];
    states
        .into_iter()
        .find(|(raw, _)| *raw == state)
        .map_or(NeighborState::Unknown, |(_, mapped)| mapped)
}

/// `TCP_INITIAL_RTO_NO_SYN_RETRANSMISSIONS` from mstcpip.h, `(UCHAR)-2`. The `windows` crate
/// declares it as `u16` (65534), but the field it goes into is a `u8`.
const NO_SYN_RETRANSMISSIONS: u8 = 0xFE;

/// Tunes a TCP socket for a port probe; call before `connect`.
///
/// - No SYN retransmissions (`SIO_TCP_INITIAL_RTO`). By default Windows answers an RST to its
///   SYN by sending the SYN again, so connecting to a closed port takes about 2 s (measured on
///   Windows 11: 2.03 s on loopback, on the own LAN address and against a LAN router) and looks
///   filtered with any shorter timeout. Without retransmissions the RST is reported at once
///   (< 2 ms in the same measurement).
/// - Initial RTO = `timeout`. Without retransmissions the OS gives up after the initial RTO
///   (1 s by default) with `WSAETIMEDOUT`; this makes it wait exactly as long as the probe
///   should (measured: 300 ms -> 0.31 s, 3000 ms -> 3.0 s). Trade-off: a single lost SYN makes
///   a port look filtered.
/// - `TCP_FAIL_CONNECT_ON_ICMP_ERROR` (Windows 10 1903+, best effort): fail as soon as an ICMP
///   "unreachable" arrives instead of waiting for the timeout.
pub fn prepare_probe_socket(socket: &impl AsRawSocket, timeout: Duration) -> io::Result<()> {
    let socket = SOCKET(socket.as_raw_socket() as usize);
    // 0 would mean "system default".
    let rtt_ms = u16::try_from(timeout.as_millis())
        .unwrap_or(u16::MAX)
        .max(1);
    set_initial_rto(socket, rtt_ms, NO_SYN_RETRANSMISSIONS)?;
    let _ = fail_connect_on_icmp_error(socket);
    Ok(())
}

fn set_initial_rto(socket: SOCKET, rtt_ms: u16, max_syn_retransmissions: u8) -> io::Result<()> {
    let params = TCP_INITIAL_RTO_PARAMETERS {
        Rtt: rtt_ms,
        MaxSynRetransmissions: max_syn_retransmissions,
    };
    let mut returned = 0u32;
    // SAFETY: `params` is a valid input buffer of the given size for this control code;
    // there is no output buffer and no overlapped I/O.
    let rc = unsafe {
        WSAIoctl(
            socket,
            SIO_TCP_INITIAL_RTO,
            Some(std::ptr::from_ref(&params).cast()),
            size_of::<TCP_INITIAL_RTO_PARAMETERS>() as u32,
            None,
            0,
            &mut returned,
            None,
            None,
        )
    };
    match rc {
        0 => Ok(()),
        _ => Err(last_socket_error()),
    }
}

fn fail_connect_on_icmp_error(socket: SOCKET) -> io::Result<()> {
    let on = 1u32.to_ne_bytes();
    // SAFETY: plain setsockopt with a 4-byte DWORD value.
    let rc = unsafe {
        setsockopt(
            socket,
            IPPROTO_TCP.0,
            TCP_FAIL_CONNECT_ON_ICMP_ERROR,
            Some(&on),
        )
    };
    match rc {
        0 => Ok(()),
        _ => Err(last_socket_error()),
    }
}

fn last_socket_error() -> io::Error {
    // SAFETY: no preconditions.
    io::Error::from_raw_os_error(unsafe { WSAGetLastError() }.0)
}

/// Closes the ICMP handle on drop.
struct IcmpHandle(HANDLE);

impl IcmpHandle {
    fn open() -> Result<Self, NetError> {
        // SAFETY: no preconditions.
        unsafe { IcmpCreateFile() }
            .map(Self)
            .map_err(|e| NetError::Os {
                api: "IcmpCreateFile",
                code: e.code().0 as u32,
            })
    }
}

impl Drop for IcmpHandle {
    fn drop(&mut self) {
        // SAFETY: the handle came from IcmpCreateFile and is closed exactly once.
        let _ = unsafe { IcmpCloseHandle(self.0) };
    }
}

/// IPv4 address as the network-byte-order `u32` the IP Helper API expects.
fn to_net_u32(ip: Ipv4Addr) -> u32 {
    u32::from_ne_bytes(ip.octets())
}

/// # Safety
/// `first` must be null or point to the adapter list of a successful
/// `GetAdaptersAddresses` call whose buffer is still alive.
unsafe fn collect_adapters(first: *const IP_ADAPTER_ADDRESSES_LH) -> Vec<Adapter> {
    let mut adapters = Vec::new();
    let mut current = first;
    while !current.is_null() {
        // SAFETY: non-null list node inside the live buffer (caller contract).
        let adapter = unsafe { &*current };
        current = adapter.Next;

        if adapter.IfType == IF_TYPE_SOFTWARE_LOOPBACK || adapter.OperStatus != IfOperStatusUp {
            continue;
        }

        let mut ipv4 = Vec::new();
        let mut unicast = adapter.FirstUnicastAddress;
        while !unicast.is_null() {
            // SAFETY: non-null list node inside the live buffer.
            let entry = unsafe { &*unicast };
            unicast = entry.Next;
            // SAFETY: the socket address belongs to the same live buffer.
            if let Some(addr) = unsafe { sockaddr_v4(&entry.Address) } {
                ipv4.push(Ipv4Net::new(addr, entry.OnLinkPrefixLength));
            }
        }
        if ipv4.is_empty() {
            continue;
        }

        let mut has_gateway = false;
        let mut gateway = adapter.FirstGatewayAddress;
        while !gateway.is_null() {
            // SAFETY: non-null list node inside the live buffer.
            let entry = unsafe { &*gateway };
            gateway = entry.Next;
            // SAFETY: the socket address belongs to the same live buffer.
            has_gateway |= unsafe { sockaddr_v4(&entry.Address) }.is_some();
        }

        let mut dns_servers = Vec::new();
        let mut dns = adapter.FirstDnsServerAddress;
        while !dns.is_null() {
            // SAFETY: non-null list node inside the live buffer.
            let entry = unsafe { &*dns };
            dns = entry.Next;
            // SAFETY: the socket address belongs to the same live buffer.
            if let Some(server) = unsafe { sockaddr_v4(&entry.Address) } {
                dns_servers.push(server);
            }
        }

        let mac = (adapter.PhysicalAddressLength == 6)
            .then(|| {
                let p = adapter.PhysicalAddress;
                MacAddr([p[0], p[1], p[2], p[3], p[4], p[5]])
            })
            .filter(|mac| !mac.is_zero());

        // SAFETY: the name pointers are null or NUL-terminated strings in the live buffer.
        let (id, name, description) = unsafe {
            (
                ansi_to_string(adapter.AdapterName.0),
                wide_to_string(adapter.FriendlyName.0),
                wide_to_string(adapter.Description.0),
            )
        };

        adapters.push(Adapter {
            id,
            name,
            description,
            mac,
            ipv4,
            dns_servers,
            has_gateway,
        });
    }
    // Adapters with a default gateway first (stable, so the OS order is kept otherwise).
    adapters.sort_by_key(|a| !a.has_gateway);
    adapters
}

/// # Safety
/// `sa.lpSockaddr` must be null or valid for `sa.iSockaddrLength` bytes.
unsafe fn sockaddr_v4(sa: &SOCKET_ADDRESS) -> Option<Ipv4Addr> {
    let len = usize::try_from(sa.iSockaddrLength).ok()?;
    if sa.lpSockaddr.is_null() || len < size_of::<SOCKADDR_IN>() {
        return None;
    }
    // SAFETY: non-null and large enough for a SOCKADDR_IN (checked above).
    let sin = unsafe { &*sa.lpSockaddr.cast::<SOCKADDR_IN>() };
    if sin.sin_family.0 != AF_INET {
        return None;
    }
    // SAFETY: every bit pattern is a valid `S_addr`.
    let raw = unsafe { sin.sin_addr.S_un.S_addr };
    Some(Ipv4Addr::from(raw.to_ne_bytes()))
}

/// # Safety
/// `ptr` must be null or point to a NUL-terminated UTF-16 string.
unsafe fn wide_to_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut units = Vec::new();
    for i in 0..MAX_NAME_LEN {
        // SAFETY: reading stops at the terminator, so `i` stays inside the string.
        match unsafe { *ptr.add(i) } {
            0 => break,
            unit => units.push(unit),
        }
    }
    String::from_utf16_lossy(&units)
}

/// # Safety
/// `ptr` must be null or point to a NUL-terminated byte string.
unsafe fn ansi_to_string(ptr: *const u8) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut bytes = Vec::new();
    for i in 0..MAX_NAME_LEN {
        // SAFETY: reading stops at the terminator, so `i` stays inside the string.
        match unsafe { *ptr.add(i) } {
            0 => break,
            byte => bytes.push(byte),
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_byte_order() {
        let raw = to_net_u32(Ipv4Addr::new(192, 168, 1, 2));
        assert_eq!(raw.to_ne_bytes(), [192, 168, 1, 2]);
    }

    #[test]
    fn string_helpers_stop_at_terminator_and_handle_null() {
        let wide: Vec<u16> = "Wi-Fi\0junk".encode_utf16().collect();
        // SAFETY: both buffers are NUL-terminated.
        unsafe {
            assert_eq!(wide_to_string(wide.as_ptr()), "Wi-Fi");
            assert_eq!(ansi_to_string(c"{GUID}".as_ptr().cast()), "{GUID}");
            assert_eq!(wide_to_string(std::ptr::null()), "");
            assert_eq!(ansi_to_string(std::ptr::null()), "");
        }
    }

    #[test]
    fn launch_targets_exist() {
        assert!(
            os_dir(GetSystemDirectoryW)
                .unwrap()
                .join("mstsc.exe")
                .is_file()
        );
        assert!(
            os_dir(GetSystemWindowsDirectoryW)
                .unwrap()
                .join("explorer.exe")
                .is_file()
        );
    }

    #[test]
    fn launchers_reject_ipv6() {
        let v6 = IpAddr::V6(std::net::Ipv6Addr::LOCALHOST);
        assert!(matches!(open_remote_desktop(v6), Err(LaunchError::Ipv6)));
        assert!(matches!(open_file_share(v6), Err(LaunchError::Ipv6)));
    }

    // Smoke tests against the real OS; they only assert that the calls are sound.
    #[test]
    fn lists_adapters_without_error() {
        let adapters = WindowsBackend.list_adapters().unwrap();
        for adapter in adapters {
            assert!(!adapter.ipv4.is_empty());
        }
    }

    #[test]
    fn reads_neighbor_cache_without_error() {
        for neighbor in WindowsBackend.neighbor_cache().unwrap() {
            assert!(!neighbor.mac.is_zero());
        }
    }

    #[test]
    fn no_syn_retransmissions_matches_the_sdk_value() {
        use windows::Win32::Networking::WinSock::TCP_INITIAL_RTO_NO_SYN_RETRANSMISSIONS;
        assert_eq!(
            TCP_INITIAL_RTO_NO_SYN_RETRANSMISSIONS as u8,
            NO_SYN_RETRANSMISSIONS
        );
    }

    #[tokio::test]
    async fn probe_sockets_accept_the_tuning() {
        for socket in [
            tokio::net::TcpSocket::new_v4().unwrap(),
            tokio::net::TcpSocket::new_v6().unwrap(),
        ] {
            prepare_probe_socket(&socket, Duration::from_millis(100)).unwrap();
            prepare_probe_socket(&socket, Duration::from_secs(600)).unwrap();
        }
    }

    #[test]
    fn pings_loopback() {
        let rtt = WindowsBackend
            .icmp_ping(IpAddr::V4(Ipv4Addr::LOCALHOST), Duration::from_millis(1000))
            .unwrap();
        assert!(rtt.is_some());
    }
}

/// Manual check against the real network: `cargo test live_scan -- --ignored --nocapture`.
/// Prints only which kinds of data were found, not the data itself.
#[cfg(test)]
mod live {
    use std::sync::Arc;

    use super::*;
    use crate::enrich::NetEnricher;
    use crate::scan::ScanConfig;
    use crate::scan::engine::run_scan;
    use crate::scan::range::TargetSet;
    use tokio::sync::watch;

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "scans the local subnet of the first adapter with a gateway"]
    async fn live_scan_of_local_subnet() {
        let adapters = WindowsBackend.list_adapters().unwrap();
        let Some(net) = adapters
            .iter()
            .find(|a| a.has_gateway)
            .and_then(|a| a.ipv4.first())
        else {
            println!("no adapter with a gateway, nothing to scan");
            return;
        };
        let dns_servers: usize = adapters.iter().map(|a| a.dns_servers.len()).sum();
        // Never more than the /24 around the adapter address.
        let [a, b, c, _] = net.addr.octets();
        let target = format!("{a}.{b}.{c}.0/24");
        let (_cancel, cancelled) = watch::channel(false);
        let started = std::time::Instant::now();
        let summary = run_scan(
            Arc::new(WindowsBackend),
            Arc::new(NetEnricher::new(&adapters)),
            TargetSet::parse(&target).unwrap(),
            ScanConfig {
                concurrency: 64,
                timeout: Duration::from_millis(1000),
                resolve_offline_names: true,
            },
            cancelled,
            1,
            |batch| {
                for host in batch.hosts.iter().filter(|h| h.online && h.complete) {
                    let ports: Vec<u16> = host.services.iter().map(|s| s.port).collect();
                    let http = host.services.iter().filter_map(|s| s.http.as_ref());
                    println!(
                        "online: arp={} icmp={} tcp={} mac={} local={} vendor={} dns={} mdns={} netbios={} workgroup={} ports={ports:?} http_server={} http_title={}",
                        host.seen_by.arp,
                        host.seen_by.icmp,
                        host.seen_by.tcp,
                        host.mac.is_some(),
                        host.mac_local,
                        host.vendor.is_some(),
                        host.names.dns.is_some(),
                        host.names.mdns.is_some(),
                        host.names.netbios.is_some(),
                        host.workgroup.is_some(),
                        http.clone().any(|h| h.server.is_some()),
                        http.clone().any(|h| h.title.is_some()),
                    );
                }
            },
        )
        .await;
        println!(
            "prefix=/{} dns_servers={dns_servers} scanned={} online={} errors={} in {:?}",
            net.prefix_len,
            summary.scanned,
            summary.online,
            summary.errors,
            started.elapsed()
        );
        assert_eq!(summary.scanned, summary.total);
        assert!(summary.online >= 1, "this machine itself must be online");
    }
}
