//! One TCP connect probe and what its result says about the port.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::{TcpSocket, TcpStream};

use crate::platform;

/// Extra time on top of the probe timeout before the attempt is abandoned. With the Windows
/// socket tuning the OS reports the timeout itself; this only catches cases where it does not.
const BACKSTOP: Duration = Duration::from_millis(250);
/// Pause before the single retry after a local resource shortage.
const RETRY_DELAY: Duration = Duration::from_millis(100);

/// What a connect attempt says about a port.
#[derive(Debug)]
pub enum Connect {
    /// The connection was accepted. Dropping the stream resets it (`SO_LINGER` 0).
    Open(TcpStream),
    /// Actively refused (RST).
    Closed,
    /// No answer within the timeout, or an ICMP "unreachable".
    Filtered,
    /// Local error; says nothing about the port.
    Failed,
}

/// Connects to `addr`, waiting at most `timeout` for an answer.
pub async fn connect(addr: SocketAddr, timeout: Duration) -> Connect {
    let mut result = try_connect(addr, timeout).await;
    if let Err(e) = &result
        && is_resource_shortage(e)
    {
        tokio::time::sleep(RETRY_DELAY).await;
        result = try_connect(addr, timeout).await;
    }
    match result {
        Ok(stream) => Connect::Open(stream),
        Err(e) => classify(e),
    }
}

async fn try_connect(addr: SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
    let socket = match addr {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    // Closing sends an RST instead of a FIN, so open ports leave no TIME_WAIT entry behind
    // and large scans cannot use up the ephemeral ports (16,384 on Windows). Closed and
    // filtered ports never get that far (no connection, nothing to linger).
    socket.set_zero_linger()?;
    platform::prepare_probe_socket(&socket, timeout)?;
    match tokio::time::timeout(timeout + BACKSTOP, socket.connect(addr)).await {
        Ok(result) => result,
        Err(_) => Err(io::ErrorKind::TimedOut.into()),
    }
}

fn classify(e: io::Error) -> Connect {
    use io::ErrorKind::*;
    match e.kind() {
        ConnectionRefused | ConnectionReset => Connect::Closed,
        TimedOut | HostUnreachable | NetworkUnreachable => Connect::Filtered,
        _ => Connect::Failed,
    }
}

/// Out of sockets or ephemeral ports for a moment; worth one retry.
fn is_resource_shortage(e: &io::Error) -> bool {
    #[cfg(windows)]
    const NO_BUFFERS: Option<i32> = Some(10055); // WSAENOBUFS
    #[cfg(not(windows))]
    const NO_BUFFERS: Option<i32> = None;
    e.kind() == io::ErrorKind::AddrInUse || (NO_BUFFERS.is_some() && e.raw_os_error() == NO_BUFFERS)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Instant;

    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    use super::*;

    const TIMEOUT: Duration = Duration::from_millis(1000);

    /// A port on loopback that nothing listens on right now.
    async fn closed_port() -> SocketAddr {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        listener.local_addr().unwrap()
    }

    #[tokio::test]
    async fn open_port() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        assert!(matches!(connect(addr, TIMEOUT).await, Connect::Open(_)));
    }

    /// Without the socket tuning this takes about 2 s on Windows (see
    /// `platform::windows::prepare_probe_socket`) and would be reported as filtered.
    #[tokio::test]
    async fn closed_port_is_reported_at_once() {
        let addr = closed_port().await;
        let started = Instant::now();
        let result = connect(addr, TIMEOUT).await;
        let took = started.elapsed();
        assert!(matches!(result, Connect::Closed), "{result:?}");
        assert!(took < Duration::from_millis(300), "took {took:?}");
    }

    /// TEST-NET-1 is never assigned: the SYN goes nowhere (or the route is missing). Either
    /// way the port is filtered, and the OS gives up after the probe timeout, not later.
    #[tokio::test]
    async fn unanswered_port_is_filtered_after_the_timeout() {
        let addr = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 80));
        let timeout = Duration::from_millis(300);
        let started = Instant::now();
        let result = connect(addr, timeout).await;
        let took = started.elapsed();
        assert!(matches!(result, Connect::Filtered), "{result:?}");
        assert!(took < timeout + BACKSTOP, "took {took:?}");
    }

    #[tokio::test]
    async fn open_connections_are_reset_not_closed_gracefully() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let Connect::Open(stream) = connect(addr, TIMEOUT).await else {
            panic!("port should be open");
        };
        let (mut server_side, _) = listener.accept().await.unwrap();
        drop(stream);
        // A graceful close (FIN) would read as end of stream; SO_LINGER 0 sends an RST,
        // so no TIME_WAIT entry is left behind on our side.
        let mut buf = [0u8; 8];
        let read = tokio::time::timeout(TIMEOUT, server_side.read(&mut buf))
            .await
            .unwrap();
        assert_eq!(
            read.map_err(|e| e.kind()),
            Err(io::ErrorKind::ConnectionReset)
        );
    }

    #[test]
    fn error_classification() {
        use io::ErrorKind::*;
        let state = |kind: io::ErrorKind| match classify(kind.into()) {
            Connect::Closed => "closed",
            Connect::Filtered => "filtered",
            Connect::Failed => "failed",
            Connect::Open(_) => unreachable!(),
        };
        assert_eq!(state(ConnectionRefused), "closed");
        assert_eq!(state(ConnectionReset), "closed");
        assert_eq!(state(TimedOut), "filtered");
        assert_eq!(state(HostUnreachable), "filtered");
        assert_eq!(state(NetworkUnreachable), "filtered");
        assert_eq!(state(AddrInUse), "failed");
        assert_eq!(state(PermissionDenied), "failed");
        assert_eq!(state(AddrNotAvailable), "failed");
    }

    #[test]
    fn resource_shortage_detection() {
        assert!(is_resource_shortage(&io::ErrorKind::AddrInUse.into()));
        assert!(!is_resource_shortage(&io::ErrorKind::TimedOut.into()));
        #[cfg(windows)]
        assert!(is_resource_shortage(&io::Error::from_raw_os_error(10055)));
    }

    /// Manual measurement: `cargo test connect_timing -- --ignored --nocapture`.
    /// Compares a plain connect with the tuned probe on a closed loopback port.
    #[tokio::test]
    #[ignore = "measurement, prints timings"]
    async fn connect_timing() {
        let addr = closed_port().await;
        for _ in 0..3 {
            let started = Instant::now();
            let plain = TcpStream::connect(addr).await.map(drop);
            println!(
                "plain connect: {:?} in {:?}",
                plain.map_err(|e| e.kind()),
                started.elapsed()
            );
            let started = Instant::now();
            let tuned = connect(addr, TIMEOUT).await;
            println!("tuned probe:   {tuned:?} in {:?}", started.elapsed());
        }
    }
}
