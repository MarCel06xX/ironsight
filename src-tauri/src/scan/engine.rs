//! Scan orchestration: bounded concurrency, per-host timeout, cancellation and batched
//! live results. Independent of Tauri so it can be tested with a mock backend.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::{Semaphore, mpsc};
use tokio::task::spawn_blocking;
use tokio::time::MissedTickBehavior;

use super::range::TargetSet;
use super::{HostResult, ScanBatch, ScanConfig, ScanSummary, SeenBy};
use crate::mac::MacAddr;
use crate::platform::{Ipv4Net, NetBackend, NetError};

/// Results are flushed to the frontend at this interval ...
const FLUSH_INTERVAL: Duration = Duration::from_millis(100);
/// ... or earlier, once this many have piled up.
const MAX_BATCH: usize = 512;
/// SendARP cannot be aborted and blocks for about 3 s on silent hosts. Hosts are reported
/// after the configured timeout anyway; this caps the threads still waiting in the OS.
const MAX_ARP_THREADS: usize = 240;

/// A local IPv4 subnet; hosts inside it can be resolved via ARP.
struct LocalLink {
    net: Ipv4Net,
    mac: Option<MacAddr>,
}

struct Probe {
    host: HostResult,
    had_error: bool,
}

/// Scans all targets and reports results through `on_batch` while running.
/// Setting `cancel` stops starting new hosts; hosts already in flight still finish.
pub async fn run_scan<F>(
    backend: Arc<dyn NetBackend>,
    targets: TargetSet,
    config: ScanConfig,
    cancel: Arc<AtomicBool>,
    scan_id: u64,
    on_batch: F,
) -> ScanSummary
where
    F: Fn(ScanBatch) + Send,
{
    let started_at_ms = now_ms();
    let total = targets.len() as u32;
    let links = Arc::new(local_links(&backend).await);

    let (tx, mut rx) = mpsc::channel::<Probe>(1024);
    let producer = tokio::spawn(produce(
        backend,
        targets,
        config,
        Arc::clone(&cancel),
        links,
        tx,
    ));

    let (mut scanned, mut online, mut errors) = (0u32, 0u32, 0u32);
    let mut pending: Vec<HostResult> = Vec::new();
    let flush = |pending: &mut Vec<HostResult>, scanned: u32, online: u32| {
        on_batch(ScanBatch {
            scan_id,
            hosts: std::mem::take(pending),
            scanned,
            total,
            online,
        });
    };

    let mut ticker = tokio::time::interval(FLUSH_INTERVAL);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            probe = rx.recv() => {
                // The channel closes once the producer and all host tasks are done.
                let Some(probe) = probe else { break };
                scanned += 1;
                online += u32::from(probe.host.online);
                errors += u32::from(probe.had_error);
                pending.push(probe.host);
                if pending.len() >= MAX_BATCH {
                    flush(&mut pending, scanned, online);
                }
            }
            _ = ticker.tick() => {
                if !pending.is_empty() {
                    flush(&mut pending, scanned, online);
                }
            }
        }
    }
    if !pending.is_empty() {
        flush(&mut pending, scanned, online);
    }
    let _ = producer.await;

    ScanSummary {
        scan_id,
        cancelled: cancel.load(Ordering::Relaxed) && scanned < total,
        scanned,
        total,
        online,
        errors,
        started_at_ms,
        finished_at_ms: now_ms(),
    }
}

/// Starts one task per host, never more than `config.concurrency` at a time.
async fn produce(
    backend: Arc<dyn NetBackend>,
    targets: TargetSet,
    config: ScanConfig,
    cancel: Arc<AtomicBool>,
    links: Arc<Vec<LocalLink>>,
    tx: mpsc::Sender<Probe>,
) {
    let concurrency = config.concurrency.max(1);
    let host_slots = Arc::new(Semaphore::new(concurrency));
    let arp_slots = Arc::new(Semaphore::new((concurrency * 3).min(MAX_ARP_THREADS)));

    for ip in targets.iter() {
        let Ok(permit) = Arc::clone(&host_slots).acquire_owned().await else {
            break;
        };
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        let backend = Arc::clone(&backend);
        let links = Arc::clone(&links);
        let arp_slots = Arc::clone(&arp_slots);
        let tx = tx.clone();
        tokio::spawn(async move {
            let probe = probe_host(backend, ip, &links, arp_slots, config.timeout).await;
            let _ = tx.send(probe).await;
            drop(permit);
        });
    }
}

/// ARP (on-link targets only) and ICMP run in parallel; the host is online if either answers.
async fn probe_host(
    backend: Arc<dyn NetBackend>,
    ip: Ipv4Addr,
    links: &[LocalLink],
    arp_slots: Arc<Semaphore>,
    timeout: Duration,
) -> Probe {
    // One of this machine's own addresses: online by definition, MAC known from the adapter.
    let own = links.iter().find(|link| link.net.addr == ip);
    let arp_src = match own {
        Some(_) => None,
        None => links
            .iter()
            .find(|link| link.net.contains(ip))
            .map(|link| link.net.addr),
    };

    let icmp_task = {
        let backend = Arc::clone(&backend);
        spawn_blocking(move || backend.icmp_ping(IpAddr::V4(ip), timeout))
    };
    let arp_task = async {
        let Some(src) = arp_src else {
            return Ok(None);
        };
        let Ok(permit) = arp_slots.acquire_owned().await else {
            return Ok(None);
        };
        let handle = spawn_blocking(move || {
            let _permit = permit; // released when the OS call returns, not when we stop waiting
            backend.arp_resolve(ip, Some(src))
        });
        match tokio::time::timeout(timeout, handle).await {
            Ok(Ok(result)) => result,
            // Deadline passed (the thread finishes on its own) or the task panicked.
            _ => Ok::<_, NetError>(None),
        }
    };
    let (icmp, arp) = tokio::join!(icmp_task, arp_task);

    let mut had_error = false;
    let rtt = match icmp {
        Ok(Ok(rtt)) => rtt,
        _ => {
            had_error = true;
            None
        }
    };
    let arp_mac = arp.unwrap_or_else(|_| {
        had_error = true;
        None
    });

    let seen_by = SeenBy {
        arp: arp_mac.is_some(),
        icmp: rtt.is_some(),
    };
    Probe {
        host: HostResult {
            ip: IpAddr::V4(ip),
            online: own.is_some() || seen_by.arp || seen_by.icmp,
            mac: own.and_then(|link| link.mac).or(arp_mac),
            rtt_ms: rtt.map(|d| u32::try_from(d.as_millis()).unwrap_or(u32::MAX)),
            seen_by,
            timestamp_ms: now_ms(),
        },
        had_error,
    }
}

async fn local_links(backend: &Arc<dyn NetBackend>) -> Vec<LocalLink> {
    let backend = Arc::clone(backend);
    let adapters = spawn_blocking(move || backend.list_adapters())
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or_default();
    adapters
        .into_iter()
        .flat_map(|adapter| {
            let mac = adapter.mac;
            adapter
                .ipv4
                .into_iter()
                .map(move |net| LocalLink { net, mac })
        })
        .collect()
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::sync::Mutex;
    use std::sync::atomic::AtomicUsize;

    use super::*;
    use crate::platform::Adapter;

    const OWN_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
    const OWN_MAC: MacAddr = MacAddr([2, 0, 0, 0, 0, 1]);

    /// Fake network 10.0.0.0/24 with this machine at 10.0.0.1.
    #[derive(Default)]
    struct MockBackend {
        arp_hosts: HashSet<Ipv4Addr>,
        icmp_hosts: HashSet<Ipv4Addr>,
        arp_delay: Duration,
        fail_icmp: bool,
        arp_calls: Mutex<Vec<(Ipv4Addr, Option<Ipv4Addr>)>>,
        in_flight: AtomicUsize,
        max_in_flight: AtomicUsize,
    }

    impl NetBackend for MockBackend {
        fn list_adapters(&self) -> Result<Vec<Adapter>, NetError> {
            Ok(vec![Adapter {
                id: "mock".into(),
                name: "Mock".into(),
                description: String::new(),
                mac: Some(OWN_MAC),
                ipv4: vec![Ipv4Net::new(OWN_IP, 24)],
                has_gateway: true,
            }])
        }

        fn arp_resolve(
            &self,
            target: Ipv4Addr,
            src: Option<Ipv4Addr>,
        ) -> Result<Option<MacAddr>, NetError> {
            self.arp_calls.lock().unwrap().push((target, src));
            std::thread::sleep(self.arp_delay);
            let [.., last] = target.octets();
            Ok(self
                .arp_hosts
                .contains(&target)
                .then_some(MacAddr([2, 0, 0, 0, 0, last])))
        }

        fn icmp_ping(
            &self,
            target: IpAddr,
            _timeout: Duration,
        ) -> Result<Option<Duration>, NetError> {
            let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_in_flight.fetch_max(now, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(5));
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            if self.fail_icmp {
                return Err(NetError::Unsupported);
            }
            let IpAddr::V4(target) = target else {
                return Ok(None);
            };
            Ok(self
                .icmp_hosts
                .contains(&target)
                .then_some(Duration::from_millis(3)))
        }
    }

    fn ip(last: u8) -> Ipv4Addr {
        Ipv4Addr::new(10, 0, 0, last)
    }

    async fn scan(
        backend: Arc<MockBackend>,
        targets: &str,
        concurrency: usize,
        cancel: bool,
    ) -> (Vec<ScanBatch>, ScanSummary) {
        let batches = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&batches);
        let summary = run_scan(
            backend,
            TargetSet::parse(targets).unwrap(),
            ScanConfig {
                concurrency,
                timeout: Duration::from_millis(200),
            },
            Arc::new(AtomicBool::new(cancel)),
            7,
            move |batch| sink.lock().unwrap().push(batch),
        )
        .await;
        let batches = std::mem::take(&mut *batches.lock().unwrap());
        (batches, summary)
    }

    fn host(batches: &[ScanBatch], addr: Ipv4Addr) -> HostResult {
        batches
            .iter()
            .flat_map(|b| &b.hosts)
            .find(|h| h.ip == IpAddr::V4(addr))
            .cloned()
            .unwrap()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn reports_every_host_with_the_right_status() {
        let backend = Arc::new(MockBackend {
            arp_hosts: [ip(5), ip(9)].into(),
            icmp_hosts: [ip(5), ip(12)].into(),
            ..Default::default()
        });
        let (batches, summary) = scan(Arc::clone(&backend), "10.0.0.1-20", 4, false).await;

        assert_eq!(
            (summary.scan_id, summary.total, summary.scanned),
            (7, 20, 20)
        );
        assert_eq!((summary.online, summary.errors), (4, 0));
        assert!(!summary.cancelled);
        assert!(summary.finished_at_ms >= summary.started_at_ms);

        let count: usize = batches.iter().map(|b| b.hosts.len()).sum();
        assert_eq!(count, 20);
        let last = batches.last().unwrap();
        assert_eq!((last.scanned, last.total, last.online), (20, 20, 4));

        let both = host(&batches, ip(5));
        assert!(both.online && both.seen_by.arp && both.seen_by.icmp);
        assert_eq!(both.mac, Some(MacAddr([2, 0, 0, 0, 0, 5])));
        assert_eq!(both.rtt_ms, Some(3));

        let arp_only = host(&batches, ip(9));
        assert!(arp_only.online && arp_only.seen_by.arp && !arp_only.seen_by.icmp);
        assert_eq!(arp_only.rtt_ms, None);

        let icmp_only = host(&batches, ip(12));
        assert!(icmp_only.online && icmp_only.mac.is_none());

        let offline = host(&batches, ip(13));
        assert!(!offline.online && offline.mac.is_none() && offline.rtt_ms.is_none());

        assert!(backend.max_in_flight.load(Ordering::SeqCst) <= 4);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn own_address_is_online_without_arp() {
        let backend = Arc::new(MockBackend::default());
        let (batches, summary) = scan(Arc::clone(&backend), "10.0.0.1-2", 4, false).await;

        let own = host(&batches, OWN_IP);
        assert!(own.online && !own.seen_by.arp);
        assert_eq!(own.mac, Some(OWN_MAC));
        assert_eq!(summary.online, 1);
        // Only the other host is asked via ARP, from our own address.
        assert_eq!(*backend.arp_calls.lock().unwrap(), [(ip(2), Some(OWN_IP))]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn off_link_targets_skip_arp() {
        let remote = Ipv4Addr::new(192, 168, 50, 1);
        let backend = Arc::new(MockBackend {
            icmp_hosts: [remote].into(),
            ..Default::default()
        });
        let (batches, summary) = scan(Arc::clone(&backend), "192.168.50.1-2", 4, false).await;

        assert_eq!(summary.online, 1);
        assert!(host(&batches, remote).mac.is_none());
        assert!(backend.arp_calls.lock().unwrap().is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn slow_arp_is_cut_off_at_the_timeout() {
        let backend = Arc::new(MockBackend {
            arp_hosts: [ip(5)].into(),
            arp_delay: Duration::from_millis(1500),
            ..Default::default()
        });
        let started = std::time::Instant::now();
        let (batches, summary) = scan(backend, "10.0.0.5", 4, false).await;

        assert!(started.elapsed() < Duration::from_millis(1200));
        assert_eq!(summary.online, 0);
        assert!(!host(&batches, ip(5)).online);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn backend_errors_are_counted_not_fatal() {
        let backend = Arc::new(MockBackend {
            arp_hosts: [ip(5)].into(),
            fail_icmp: true,
            ..Default::default()
        });
        let (batches, summary) = scan(backend, "10.0.0.5-6", 4, false).await;

        assert_eq!((summary.scanned, summary.online, summary.errors), (2, 1, 2));
        assert!(host(&batches, ip(5)).online);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn cancelled_scan_stops_early() {
        let backend = Arc::new(MockBackend::default());
        let (batches, summary) = scan(backend, "10.0.0.1-200", 4, true).await;

        assert!(summary.cancelled);
        assert_eq!((summary.scanned, summary.total), (0, 200));
        assert!(batches.is_empty());
    }
}
