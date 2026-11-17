//! Scan orchestration: bounded concurrency, per-host timeout, cancellation and batched
//! live results. Independent of Tauri and of real network I/O (see [`NetBackend`] and
//! [`HostProbes`]), so it can be tested with mocks.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch};
use tokio::task::{JoinHandle, spawn_blocking};
use tokio::time::MissedTickBehavior;

use super::range::TargetSet;
use super::{DataSource, HostResult, ScanBatch, ScanConfig, ScanSummary, SeenBy, ServiceInfo};
use crate::mac::MacAddr;
use crate::platform::{Ipv4Net, NetBackend, NetError};
use crate::ports::PortState;

/// Results are flushed to the frontend at this interval ...
const FLUSH_INTERVAL: Duration = Duration::from_millis(100);
/// ... or earlier, once this many have piled up.
const MAX_BATCH: usize = 512;
/// The OS ARP call cannot be aborted and blocks for about 3 s on silent hosts (it retries
/// once per second). This caps the threads waiting in it.
const MAX_ARP_THREADS: usize = 240;
/// Safety net for waiting on an ARP call; the OS gives up well before this.
const ARP_HARD_LIMIT: Duration = Duration::from_secs(5);
/// Reverse DNS lookups for silent addresses running at the same time (spares the DNS server).
const MAX_OFFLINE_DNS: usize = 32;

/// Portable (socket-based) probing and enrichment, implemented by `enrich::NetEnricher`.
pub trait HostProbes: Send + Sync + 'static {
    /// Answers of the discovery TCP check (open, closed or filtered per port), ascending.
    fn tcp_ports(
        &self,
        ip: IpAddr,
        timeout: Duration,
    ) -> impl Future<Output = Vec<(u16, PortState)>> + Send;

    /// Adds names, vendor and service details to a host that was found online.
    fn enrich(
        &self,
        host: HostResult,
        timeout: Duration,
    ) -> impl Future<Output = HostResult> + Send;

    /// Reverse DNS (PTR) name of an address, also if the device itself did not answer.
    fn reverse_dns(
        &self,
        ip: IpAddr,
        timeout: Duration,
    ) -> impl Future<Output = Option<String>> + Send;
}

/// A local IPv4 subnet; hosts inside it can be resolved via ARP.
struct LocalLink {
    net: Ipv4Net,
    mac: Option<MacAddr>,
}

enum Update {
    /// First result for a host; counts towards the progress.
    Probed { host: HostResult, had_error: bool },
    /// Same host again with more data. `became_online`: it was reported offline before.
    Changed {
        host: HostResult,
        became_online: bool,
    },
}

type ArpHandle = JoinHandle<Result<Option<MacAddr>, NetError>>;

/// Everything a host task needs, shared between all of them.
struct Shared<P> {
    backend: Arc<dyn NetBackend>,
    probes: Arc<P>,
    links: Vec<LocalLink>,
    host_slots: Arc<Semaphore>,
    arp_slots: Arc<Semaphore>,
    dns_slots: Arc<Semaphore>,
    timeout: Duration,
    resolve_offline_names: bool,
    cancel: watch::Receiver<bool>,
}

/// Scans all targets and reports results through `on_batch` while running.
/// Setting `cancel` to `true` stops the scan: no new hosts are started and pending
/// lookups are dropped; hosts in the middle of their probe are still reported.
pub async fn run_scan<P, F>(
    backend: Arc<dyn NetBackend>,
    probes: Arc<P>,
    targets: TargetSet,
    config: ScanConfig,
    cancel: watch::Receiver<bool>,
    scan_id: u64,
    on_batch: F,
) -> ScanSummary
where
    P: HostProbes,
    F: Fn(ScanBatch) + Send,
{
    let started_at_ms = now_ms();
    let total = targets.len() as u32;
    let concurrency = config.concurrency.max(1);
    let neighbor_backend = Arc::clone(&backend);
    let shared = Arc::new(Shared {
        links: local_links(&backend).await,
        backend,
        probes,
        host_slots: Arc::new(Semaphore::new(concurrency)),
        arp_slots: Arc::new(Semaphore::new((concurrency * 3).min(MAX_ARP_THREADS))),
        dns_slots: Arc::new(Semaphore::new(MAX_OFFLINE_DNS)),
        timeout: config.timeout,
        resolve_offline_names: config.resolve_offline_names,
        cancel: cancel.clone(),
    });
    // Latest state of every address that did not answer, for the neighbor cache step.
    let mut silent: HashMap<IpAddr, HostResult> = HashMap::new();

    let (tx, mut rx) = mpsc::channel::<Update>(1024);
    let producer = tokio::spawn(produce(shared, targets, tx));

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
            update = rx.recv() => {
                // The channel closes once the producer and all host tasks are done.
                let Some(update) = update else { break };
                let host = match &update {
                    Update::Probed { host, .. } | Update::Changed { host, .. } => host,
                };
                if host.online {
                    silent.remove(&host.ip);
                } else {
                    silent.insert(host.ip, host.clone());
                }
                match update {
                    Update::Probed { host, had_error } => {
                        scanned += 1;
                        online += u32::from(host.online);
                        errors += u32::from(had_error);
                        pending.push(host);
                    }
                    Update::Changed { host, became_online } => {
                        online += u32::from(became_online);
                        pending.push(host);
                    }
                }
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
    // Silent addresses the OS still knows from its neighbor (ARP) cache get MAC and vendor.
    pending.extend(apply_neighbor_cache(&neighbor_backend, &mut silent).await);
    if !pending.is_empty() {
        flush(&mut pending, scanned, online);
    }
    let _ = producer.await;

    ScanSummary {
        scan_id,
        cancelled: *cancel.borrow() && scanned < total,
        scanned,
        total,
        online,
        errors,
        started_at_ms,
        finished_at_ms: now_ms(),
    }
}

/// Resolves once the scan is cancelled (never, if the sender is gone).
pub(crate) async fn cancelled(cancel: &mut watch::Receiver<bool>) {
    if cancel.wait_for(|cancelled| *cancelled).await.is_err() {
        std::future::pending::<()>().await;
    }
}

/// Starts one task per host; at most `concurrency` hosts are probed at the same time.
async fn produce<P: HostProbes>(
    shared: Arc<Shared<P>>,
    targets: TargetSet,
    tx: mpsc::Sender<Update>,
) {
    let mut cancel = shared.cancel.clone();
    for ip in targets.iter() {
        let permit = tokio::select! {
            permit = Arc::clone(&shared.host_slots).acquire_owned() => permit,
            _ = cancelled(&mut cancel) => break,
        };
        let Ok(permit) = permit else { break };
        if shared.is_cancelled() {
            break;
        }
        let shared = Arc::clone(&shared);
        let tx = tx.clone();
        tokio::spawn(async move {
            let mut cancel = shared.cancel.clone();
            if let Some(follow_up) = probe_and_report(&shared, ip, &tx, permit).await {
                // Lookups after the first report are dropped when the scan is stopped.
                tokio::select! {
                    _ = follow_up.run(&shared, &tx) => {}
                    _ = cancelled(&mut cancel) => {}
                }
            }
        });
    }
}

/// Work left for a host after its first report.
struct FollowUp {
    host: HostResult,
    /// ARP call that had not returned when the probe timeout expired.
    arp: Option<ArpHandle>,
    permit: OwnedSemaphorePermit,
}

/// Probes one host and sends its first report. Returns what is left to do, if anything.
async fn probe_and_report<P: HostProbes>(
    shared: &Shared<P>,
    ip: Ipv4Addr,
    tx: &mpsc::Sender<Update>,
    permit: OwnedSemaphorePermit,
) -> Option<FollowUp> {
    let (mut host, had_error, arp) = discover(shared, ip).await;
    // Offline hosts have nothing to look up; a late ARP answer may still revive them.
    host.complete = !host.online || shared.is_cancelled();
    let first = Update::Probed {
        host: host.clone(),
        had_error,
    };
    if tx.send(first).await.is_err() || shared.is_cancelled() {
        return None;
    }
    let wanted = host.online || arp.is_some() || shared.resolve_offline_names;
    wanted.then_some(FollowUp { host, arp, permit })
}

impl FollowUp {
    async fn run<P: HostProbes>(self, shared: &Shared<P>, tx: &mpsc::Sender<Update>) {
        let Self {
            mut host,
            mut arp,
            mut permit,
        } = self;

        if !host.online {
            // Nothing answered within the timeout, but the OS is still asking via ARP
            // (sleeping phones often answer the second request). Waiting needs no slot.
            // Meanwhile the DNS server may still know a name for the address.
            drop(permit);
            let name_lookup = async {
                match shared.resolve_offline_names {
                    true => shared.offline_name(host.ip).await,
                    false => None,
                }
            };
            let (late_mac, name) = tokio::join!(late_arp(arp.take()), name_lookup);
            let Some(mac) = late_mac else {
                if let Some(name) = name {
                    host.names.dns = Some(name);
                    host.pick_hostname();
                    host.sources.hostname = Some(DataSource::Dns);
                    host.update_status();
                    let named = Update::Changed {
                        host,
                        became_online: false,
                    };
                    let _ = tx.send(named).await;
                }
                return;
            };
            host.online = true;
            host.complete = false;
            host.seen_by.arp = true;
            host.set_mac(mac);
            host.mark_live();
            let revived = Update::Changed {
                host: host.clone(),
                became_online: true,
            };
            if tx.send(revived).await.is_err() {
                return;
            }
            let Ok(slot) = Arc::clone(&shared.host_slots).acquire_owned().await else {
                return;
            };
            permit = slot;
        }

        let (mut host, late_mac) = tokio::join!(
            shared.probes.enrich(host, shared.timeout),
            late_arp(arp.take())
        );
        if let Some(mac) = late_mac {
            host.seen_by.arp = true;
            host.set_mac(mac);
        }
        host.complete = true;
        host.mark_live();
        let enriched = Update::Changed {
            host,
            became_online: false,
        };
        let _ = tx.send(enriched).await;
        drop(permit);
    }
}

/// Waits for an ARP call that outlived the probe timeout.
async fn late_arp(handle: Option<ArpHandle>) -> Option<MacAddr> {
    let result = tokio::time::timeout(ARP_HARD_LIMIT, handle?).await;
    result.ok()?.ok()?.ok()?
}

impl<P: HostProbes> Shared<P> {
    fn is_cancelled(&self) -> bool {
        *self.cancel.borrow()
    }

    /// Local address to send ARP requests for `ip` from; `None` if `ip` is off-link or
    /// one of this machine's own addresses.
    fn arp_source(&self, ip: Ipv4Addr) -> Option<Ipv4Addr> {
        if self.links.iter().any(|link| link.net.addr == ip) {
            return None;
        }
        self.links
            .iter()
            .find(|link| link.net.contains(ip))
            .map(|link| link.net.addr)
    }

    /// Reverse DNS for an address that did not answer, limited to a few lookups at a time.
    async fn offline_name(&self, ip: IpAddr) -> Option<String> {
        let _permit = Arc::clone(&self.dns_slots).acquire_owned().await.ok()?;
        self.probes.reverse_dns(ip, self.timeout).await
    }

    /// Starts the blocking ARP call once a thread slot is free.
    async fn spawn_arp(&self, ip: Ipv4Addr, src: Ipv4Addr) -> Option<ArpHandle> {
        let permit = Arc::clone(&self.arp_slots).acquire_owned().await.ok()?;
        let backend = Arc::clone(&self.backend);
        Some(spawn_blocking(move || {
            let _permit = permit; // released when the OS call returns, not when we stop waiting
            backend.arp_resolve(ip, Some(src))
        }))
    }
}

/// ARP (on-link targets only), ICMP and the TCP probes run in parallel; the host is online
/// if any of them gets an answer within the timeout. Returns the host, whether a probe hit
/// an OS error, and the ARP call if it is still running.
async fn discover<P: HostProbes>(
    shared: &Shared<P>,
    ip: Ipv4Addr,
) -> (HostResult, bool, Option<ArpHandle>) {
    let timeout = shared.timeout;
    // One of this machine's own addresses: online by definition, MAC known from the adapter.
    let own = shared.links.iter().find(|link| link.net.addr == ip);

    let mut arp_handle = match shared.arp_source(ip) {
        Some(src) => shared.spawn_arp(ip, src).await,
        None => None,
    };
    let icmp_task = {
        let backend = Arc::clone(&shared.backend);
        spawn_blocking(move || backend.icmp_ping(IpAddr::V4(ip), timeout))
    };
    let arp_task = async {
        match arp_handle.as_mut() {
            // `None`: not finished within the timeout, the handle stays valid.
            Some(handle) => tokio::time::timeout(timeout, handle).await.ok(),
            None => Some(Ok(Ok(None))),
        }
    };
    let tcp_task = shared.probes.tcp_ports(IpAddr::V4(ip), timeout);
    let (icmp, arp, tcp_answers) = tokio::join!(icmp_task, arp_task, tcp_task);
    // Only an accepted connection counts as a sign of life: some firewalls answer with a
    // reset for addresses that do not exist.
    let open_ports: Vec<u16> = tcp_answers
        .iter()
        .filter(|&&(_, state)| state == PortState::Open)
        .map(|&(port, _)| port)
        .collect();

    let mut had_error = false;
    let rtt = match icmp {
        Ok(Ok(rtt)) => rtt,
        _ => {
            had_error = true;
            None
        }
    };
    let (arp_mac, arp_pending) = match arp {
        Some(Ok(Ok(mac))) => (mac, None),
        Some(_) => {
            had_error = true;
            (None, None)
        }
        None => (None, arp_handle),
    };

    let mut host = HostResult::new(IpAddr::V4(ip));
    host.seen_by = SeenBy {
        arp: arp_mac.is_some(),
        icmp: rtt.is_some(),
        tcp: !open_ports.is_empty(),
    };
    host.online = own.is_some() || host.seen_by.arp || host.seen_by.icmp || host.seen_by.tcp;
    host.rtt_ms = rtt.map(|d| u32::try_from(d.as_millis()).unwrap_or(u32::MAX));
    host.services = open_ports.into_iter().map(ServiceInfo::open).collect();
    host.probed_ports = tcp_answers;
    if let Some(mac) = own.and_then(|link| link.mac).or(arp_mac) {
        host.set_mac(mac);
    }
    host.timestamp_ms = now_ms();
    if host.online {
        host.mark_live();
    } else {
        host.update_status();
    }
    (host, had_error, arp_pending)
}

/// Fills MAC and vendor of silent addresses from the OS neighbor cache and returns the
/// hosts that changed.
async fn apply_neighbor_cache(
    backend: &Arc<dyn NetBackend>,
    silent: &mut HashMap<IpAddr, HostResult>,
) -> Vec<HostResult> {
    let backend = Arc::clone(backend);
    let neighbors = match spawn_blocking(move || backend.neighbor_cache()).await {
        Ok(Ok(neighbors)) => neighbors,
        _ => return Vec::new(),
    };
    neighbors
        .into_iter()
        .filter_map(|neighbor| {
            let host = silent.get_mut(&IpAddr::V4(neighbor.ip))?;
            if host.mac.is_some() {
                return None;
            }
            host.set_mac(neighbor.mac);
            host.sources.mac = Some(DataSource::ArpCache);
            host.sources.vendor = host.vendor.as_ref().map(|_| DataSource::ArpCache);
            host.update_status();
            Some(host.clone())
        })
        .collect()
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

/// Current Unix time in milliseconds.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Instant;

    use super::*;
    use crate::platform::{Adapter, Neighbor};
    use crate::scan::HostStatus;
    use crate::scan::NameSource;

    const OWN_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
    const OWN_MAC: MacAddr = MacAddr([0x00, 0x00, 0x0c, 0, 0, 1]);
    const TIMEOUT: Duration = Duration::from_millis(200);

    /// Fake network 10.0.0.0/24 with this machine at 10.0.0.1.
    #[derive(Default)]
    struct MockBackend {
        arp_hosts: HashSet<Ipv4Addr>,
        icmp_hosts: HashSet<Ipv4Addr>,
        /// How long every ARP call blocks before it returns.
        arp_delay: Duration,
        fail_icmp: bool,
        arp_calls: Mutex<Vec<(Ipv4Addr, Option<Ipv4Addr>)>>,
        in_flight: AtomicUsize,
        max_in_flight: AtomicUsize,
        neighbors: Vec<Neighbor>,
    }

    impl NetBackend for MockBackend {
        fn list_adapters(&self) -> Result<Vec<Adapter>, NetError> {
            Ok(vec![Adapter {
                id: "mock".into(),
                name: "Mock".into(),
                description: String::new(),
                mac: Some(OWN_MAC),
                ipv4: vec![Ipv4Net::new(OWN_IP, 24)],
                dns_servers: Vec::new(),
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

        fn neighbor_cache(&self) -> Result<Vec<Neighbor>, NetError> {
            Ok(self.neighbors.clone())
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

    /// TCP ports per host; enrichment just derives a DNS name from the address.
    #[derive(Default)]
    struct MockProbes {
        open: HashMap<Ipv4Addr, Vec<u16>>,
        /// Reverse DNS answers.
        ptr: HashMap<Ipv4Addr, String>,
        enrich_delay: Duration,
        enriched: Mutex<Vec<IpAddr>>,
        ptr_lookups: Mutex<Vec<IpAddr>>,
    }

    impl HostProbes for MockProbes {
        async fn tcp_ports(&self, ip: IpAddr, _timeout: Duration) -> Vec<(u16, PortState)> {
            let open = match ip {
                IpAddr::V4(v4) => self.open.get(&v4).cloned().unwrap_or_default(),
                IpAddr::V6(_) => Vec::new(),
            };
            open.into_iter()
                .map(|port| (port, PortState::Open))
                .collect()
        }

        async fn enrich(&self, mut host: HostResult, _timeout: Duration) -> HostResult {
            self.enriched.lock().unwrap().push(host.ip);
            tokio::time::sleep(self.enrich_delay).await;
            host.names.dns = Some(format!("host-{}.lan", host.ip));
            host.pick_hostname();
            host
        }

        async fn reverse_dns(&self, ip: IpAddr, _timeout: Duration) -> Option<String> {
            self.ptr_lookups.lock().unwrap().push(ip);
            match ip {
                IpAddr::V4(v4) => self.ptr.get(&v4).cloned(),
                IpAddr::V6(_) => None,
            }
        }
    }

    fn ip(last: u8) -> Ipv4Addr {
        Ipv4Addr::new(10, 0, 0, last)
    }

    /// Runs a scan; `cancel_after` stops it after that delay (zero: before it starts).
    async fn scan_with(
        backend: Arc<MockBackend>,
        probes: Arc<MockProbes>,
        targets: &str,
        cancel_after: Option<Duration>,
    ) -> (Vec<HostResult>, ScanSummary) {
        let (cancel_tx, cancel_rx) = watch::channel(cancel_after == Some(Duration::ZERO));
        let stopper = tokio::spawn(async move {
            match cancel_after {
                Some(delay) => {
                    tokio::time::sleep(delay).await;
                    cancel_tx.send_replace(true);
                }
                // Keep the sender alive for the whole scan.
                None => cancel_tx.closed().await,
            }
        });
        let batches = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&batches);
        let summary = run_scan(
            backend,
            probes,
            TargetSet::parse(targets).unwrap(),
            ScanConfig {
                concurrency: 4,
                timeout: TIMEOUT,
                resolve_offline_names: true,
            },
            cancel_rx,
            7,
            move |batch: ScanBatch| sink.lock().unwrap().push(batch),
        )
        .await;
        stopper.abort();
        let batches = std::mem::take(&mut *batches.lock().unwrap());
        // Totals in the last batch always match the summary.
        if let Some(last) = batches.last() {
            assert_eq!(
                (last.scan_id, last.scanned, last.total, last.online),
                (7, summary.scanned, summary.total, summary.online)
            );
        }
        let updates = batches.into_iter().flat_map(|b| b.hosts).collect();
        (updates, summary)
    }

    async fn scan(backend: Arc<MockBackend>, targets: &str) -> (Vec<HostResult>, ScanSummary) {
        scan_with(backend, Arc::default(), targets, None).await
    }

    /// All reports for one address, in the order they were sent.
    fn reports(updates: &[HostResult], addr: Ipv4Addr) -> Vec<&HostResult> {
        updates
            .iter()
            .filter(|h| h.ip == IpAddr::V4(addr))
            .collect()
    }

    /// The final state of one address.
    fn host(updates: &[HostResult], addr: Ipv4Addr) -> &HostResult {
        reports(updates, addr).pop().unwrap()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn reports_every_host_with_the_right_status() {
        let backend = Arc::new(MockBackend {
            arp_hosts: [ip(5), ip(9)].into(),
            icmp_hosts: [ip(5), ip(12)].into(),
            ..Default::default()
        });
        let (updates, summary) = scan(Arc::clone(&backend), "10.0.0.2-20").await;

        assert_eq!((summary.total, summary.scanned), (19, 19));
        assert_eq!((summary.online, summary.errors), (3, 0));
        assert!(!summary.cancelled);
        assert!(summary.finished_at_ms >= summary.started_at_ms);
        // Every host once, online hosts a second time after enrichment.
        assert_eq!(updates.len(), 19 + 3);

        let both = host(&updates, ip(5));
        assert!(both.online && both.seen_by.arp && both.seen_by.icmp && !both.seen_by.tcp);
        assert_eq!(both.mac, Some(MacAddr([2, 0, 0, 0, 0, 5])));
        assert_eq!(both.rtt_ms, Some(3));
        assert!(both.timestamp_ms > 0);

        let arp_only = host(&updates, ip(9));
        assert!(arp_only.online && arp_only.seen_by.arp && !arp_only.seen_by.icmp);
        assert_eq!(arp_only.rtt_ms, None);

        let icmp_only = host(&updates, ip(12));
        assert!(icmp_only.online && icmp_only.mac.is_none());

        let offline = host(&updates, ip(13));
        assert!(!offline.online && offline.mac.is_none() && offline.rtt_ms.is_none());

        assert!(backend.max_in_flight.load(Ordering::SeqCst) <= 4);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn online_hosts_are_reported_twice_offline_hosts_once() {
        let backend = Arc::new(MockBackend {
            icmp_hosts: [ip(5)].into(),
            ..Default::default()
        });
        let probes = Arc::new(MockProbes::default());
        let (updates, summary) = scan_with(backend, Arc::clone(&probes), "10.0.0.5-6", None).await;

        let online = reports(&updates, ip(5));
        assert_eq!(online.len(), 2);
        assert!(online[0].online && !online[0].complete && online[0].hostname.is_none());
        assert!(online[1].complete);
        assert_eq!(online[1].hostname.as_deref(), Some("host-10.0.0.5.lan"));
        assert_eq!(online[1].hostname_source, Some(NameSource::Dns));
        // Enrichment keeps what discovery found.
        assert_eq!(online[1].rtt_ms, online[0].rtt_ms);

        let offline = reports(&updates, ip(6));
        assert_eq!(offline.len(), 1);
        assert!(!offline[0].online && offline[0].complete);

        // The second report does not count twice.
        assert_eq!((summary.scanned, summary.online), (2, 1));
        assert_eq!(*probes.enriched.lock().unwrap(), [IpAddr::V4(ip(5))]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn open_tcp_port_alone_makes_a_host_online() {
        let backend = Arc::new(MockBackend::default());
        let probes = Arc::new(MockProbes {
            open: [(ip(7), vec![80, 443])].into(),
            ..Default::default()
        });
        let (updates, summary) = scan_with(backend, probes, "10.0.0.7-8", None).await;

        assert_eq!(summary.online, 1);
        let found = host(&updates, ip(7));
        assert!(found.online && found.seen_by.tcp && !found.seen_by.arp && !found.seen_by.icmp);
        let services: Vec<_> = found.services.iter().map(|s| (s.port, s.name)).collect();
        assert_eq!(services, [(80, "http"), (443, "https")]);
        // The answers are kept for a port scan of the host.
        assert_eq!(
            found.probed_ports,
            [(80, PortState::Open), (443, PortState::Open)]
        );
        assert!(!host(&updates, ip(8)).online);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn own_address_is_online_without_arp() {
        let backend = Arc::new(MockBackend::default());
        let (updates, summary) = scan(Arc::clone(&backend), "10.0.0.1-2").await;

        let own = host(&updates, OWN_IP);
        assert!(own.online && !own.seen_by.arp);
        assert_eq!(own.mac, Some(OWN_MAC));
        assert!(own.vendor.is_some() && !own.mac_local);
        assert_eq!(summary.online, 1);
        // Only the other host is asked via ARP, from our own address.
        assert_eq!(*backend.arp_calls.lock().unwrap(), [(ip(2), Some(OWN_IP))]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn randomized_mac_is_flagged_and_has_no_vendor() {
        let backend = Arc::new(MockBackend {
            arp_hosts: [ip(5)].into(),
            ..Default::default()
        });
        let (updates, _) = scan(backend, "10.0.0.5").await;
        // The mock answers ARP with locally administered 02:... addresses.
        let found = host(&updates, ip(5));
        assert!(found.mac_local && found.vendor.is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn off_link_targets_skip_arp() {
        let remote = Ipv4Addr::new(192, 168, 50, 1);
        let backend = Arc::new(MockBackend {
            icmp_hosts: [remote].into(),
            ..Default::default()
        });
        let (updates, summary) = scan(Arc::clone(&backend), "192.168.50.1-2").await;

        assert_eq!(summary.online, 1);
        assert!(host(&updates, remote).mac.is_none());
        assert!(backend.arp_calls.lock().unwrap().is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn slow_arp_answer_adds_the_mac_to_an_online_host() {
        // ICMP answers at once, ARP only after the probe timeout.
        let backend = Arc::new(MockBackend {
            arp_hosts: [ip(5)].into(),
            icmp_hosts: [ip(5)].into(),
            arp_delay: TIMEOUT * 2,
            ..Default::default()
        });
        let (updates, summary) = scan(Arc::clone(&backend), "10.0.0.5").await;

        let reports = reports(&updates, ip(5));
        assert_eq!(reports.len(), 2);
        assert!(reports[0].online && reports[0].mac.is_none() && !reports[0].seen_by.arp);
        assert_eq!(reports[1].mac, Some(MacAddr([2, 0, 0, 0, 0, 5])));
        assert!(reports[1].seen_by.arp && reports[1].complete);
        assert_eq!(reports[1].hostname.as_deref(), Some("host-10.0.0.5.lan"));
        assert_eq!((summary.scanned, summary.online), (1, 1));
        // The one ARP call is awaited, not repeated.
        assert_eq!(backend.arp_calls.lock().unwrap().len(), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn slow_arp_answer_revives_a_host_reported_offline() {
        // Only ARP answers, and later than the probe timeout (a sleeping phone).
        let backend = Arc::new(MockBackend {
            arp_hosts: [ip(5)].into(),
            arp_delay: TIMEOUT * 2,
            ..Default::default()
        });
        let probes = Arc::new(MockProbes::default());
        let (updates, summary) = scan_with(backend, Arc::clone(&probes), "10.0.0.5-6", None).await;

        let revived = reports(&updates, ip(5));
        assert_eq!(revived.len(), 3);
        assert!(!revived[0].online && revived[0].complete);
        assert!(revived[1].online && !revived[1].complete && revived[1].seen_by.arp);
        assert_eq!(revived[1].mac, Some(MacAddr([2, 0, 0, 0, 0, 5])));
        assert!(revived[2].online && revived[2].complete);
        assert_eq!(revived[2].hostname.as_deref(), Some("host-10.0.0.5.lan"));

        // The host that never answers is reported once and stays offline.
        let dead = reports(&updates, ip(6));
        assert_eq!(dead.len(), 1);
        assert!(!dead[0].online);

        assert_eq!((summary.scanned, summary.online), (2, 1));
        assert_eq!(*probes.enriched.lock().unwrap(), [IpAddr::V4(ip(5))]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn first_report_does_not_wait_for_slow_arp() {
        let backend = Arc::new(MockBackend {
            arp_delay: TIMEOUT * 4,
            ..Default::default()
        });
        let (first_report_tx, first_report_rx) = std::sync::mpsc::channel();
        let (_cancel_tx, cancel_rx) = watch::channel(false);
        let started = Instant::now();
        run_scan(
            backend,
            Arc::new(MockProbes::default()),
            TargetSet::parse("10.0.0.5").unwrap(),
            ScanConfig {
                concurrency: 4,
                timeout: TIMEOUT,
                resolve_offline_names: true,
            },
            cancel_rx,
            1,
            move |_batch: ScanBatch| {
                let _ = first_report_tx.send(started.elapsed());
            },
        )
        .await;
        // Reported right after the timeout, although the scan itself waits for ARP.
        assert!(first_report_rx.recv().unwrap() < TIMEOUT * 3);
        assert!(started.elapsed() >= TIMEOUT * 4);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn backend_errors_are_counted_not_fatal() {
        let backend = Arc::new(MockBackend {
            arp_hosts: [ip(5)].into(),
            fail_icmp: true,
            ..Default::default()
        });
        let (updates, summary) = scan(backend, "10.0.0.5-6").await;

        assert_eq!((summary.scanned, summary.online, summary.errors), (2, 1, 2));
        assert!(host(&updates, ip(5)).online);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn scan_cancelled_before_start_probes_nothing() {
        let backend = Arc::new(MockBackend::default());
        let (updates, summary) = scan_with(
            backend,
            Arc::default(),
            "10.0.0.1-200",
            Some(Duration::ZERO),
        )
        .await;

        assert!(summary.cancelled);
        assert_eq!((summary.scanned, summary.total), (0, 200));
        assert!(updates.is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn cancelling_drops_pending_lookups_quickly() {
        // Every host is online, enrichment and ARP would take far longer than the test.
        let backend = Arc::new(MockBackend {
            icmp_hosts: (2..=200).map(ip).collect(),
            arp_delay: Duration::from_secs(2),
            ..Default::default()
        });
        let probes = Arc::new(MockProbes {
            enrich_delay: Duration::from_secs(30),
            ..Default::default()
        });
        let started = Instant::now();
        let (updates, summary) =
            scan_with(backend, probes, "10.0.0.2-200", Some(TIMEOUT * 2)).await;

        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(summary.cancelled);
        assert!(summary.scanned >= 4 && summary.scanned < 199);
        assert_eq!(summary.online, summary.scanned);
        // Hosts were reported, but none got as far as a finished enrichment.
        assert!(updates.iter().all(|h| h.online && h.hostname.is_none()));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn silent_addresses_get_reverse_dns_names() {
        let backend = Arc::new(MockBackend {
            icmp_hosts: [ip(5)].into(),
            ..Default::default()
        });
        let probes = Arc::new(MockProbes {
            ptr: [(ip(7), "printer.lan".to_string())].into(),
            ..Default::default()
        });
        let (updates, summary) = scan_with(backend, Arc::clone(&probes), "10.0.0.5-8", None).await;

        let named = host(&updates, ip(7));
        assert!(!named.online);
        assert_eq!(named.status, HostStatus::Offline);
        assert_eq!(named.hostname.as_deref(), Some("printer.lan"));
        assert_eq!(named.sources.hostname, Some(DataSource::Dns));
        assert_eq!(named.last_seen_ms, None);

        let unused = host(&updates, ip(8));
        assert_eq!(unused.status, HostStatus::Unused);
        assert_eq!(unused.hostname, None);

        let live = host(&updates, ip(5));
        assert_eq!(live.status, HostStatus::Online);
        assert_eq!(live.sources.hostname, Some(DataSource::Live));
        assert!(live.last_seen_ms.is_some());

        // Online hosts are resolved by the enrichment, not by the offline lookup.
        let mut looked_up = probes.ptr_lookups.lock().unwrap().clone();
        looked_up.sort();
        assert_eq!(looked_up, [6, 7, 8].map(|d| IpAddr::V4(ip(d))));
        assert_eq!((summary.scanned, summary.online), (4, 1));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn offline_reverse_dns_can_be_switched_off() {
        let probes = Arc::new(MockProbes {
            ptr: [(ip(7), "printer.lan".to_string())].into(),
            ..Default::default()
        });
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let batches = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&batches);
        run_scan(
            Arc::new(MockBackend::default()),
            Arc::clone(&probes),
            TargetSet::parse("10.0.0.7").unwrap(),
            ScanConfig {
                concurrency: 4,
                timeout: TIMEOUT,
                resolve_offline_names: false,
            },
            cancel_rx,
            1,
            move |batch: ScanBatch| sink.lock().unwrap().extend(batch.hosts),
        )
        .await;
        drop(cancel_tx);
        assert!(probes.ptr_lookups.lock().unwrap().is_empty());
        let hosts = batches.lock().unwrap();
        assert_eq!(hosts.last().unwrap().status, HostStatus::Unused);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn neighbor_cache_fills_mac_of_silent_addresses() {
        let cached = MacAddr([0x00, 0x00, 0x0c, 0xaa, 0xbb, 0xcc]);
        let backend = Arc::new(MockBackend {
            icmp_hosts: [ip(5)].into(),
            neighbors: vec![
                // Silent address known to the cache.
                Neighbor {
                    ip: ip(9),
                    mac: cached,
                },
                // Online host: its live data stays.
                Neighbor {
                    ip: ip(5),
                    mac: MacAddr([0x00, 0x00, 0x0c, 1, 1, 1]),
                },
                // Outside the scanned range.
                Neighbor {
                    ip: ip(99),
                    mac: cached,
                },
            ],
            ..Default::default()
        });
        let (updates, _) = scan(backend, "10.0.0.5-10").await;

        let from_cache = host(&updates, ip(9));
        assert!(!from_cache.online);
        assert_eq!(from_cache.mac, Some(cached));
        assert!(from_cache.vendor.is_some());
        assert_eq!(from_cache.sources.mac, Some(DataSource::ArpCache));
        assert_eq!(from_cache.sources.vendor, Some(DataSource::ArpCache));
        assert_eq!(from_cache.status, HostStatus::Offline);

        assert_eq!(host(&updates, ip(5)).mac, None);
        assert_eq!(host(&updates, ip(10)).status, HostStatus::Unused);
        assert!(reports(&updates, ip(99)).is_empty());
    }
}
