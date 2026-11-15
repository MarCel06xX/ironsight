//! Port scan orchestration: probes every port of every host with a global and a per-host
//! concurrency limit, reports batched live results and stops quickly when cancelled.
//! Independent of Tauri and of real sockets (see [`PortProber`]), so it is tested with mocks.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch};
use tokio::task::JoinSet;
use tokio::time::MissedTickBehavior;

use super::PortState;
use super::names::service_name;
use super::probe::{self, Connect};
use super::spec::PortSet;
use crate::scan::engine::{cancelled, now_ms};

pub const DEFAULT_TIMEOUT_MS: u32 = 1000;
pub const MIN_TIMEOUT_MS: u32 = 100;
pub const MAX_TIMEOUT_MS: u32 = 10_000;
/// Probes in flight across all hosts.
pub const DEFAULT_CONCURRENCY: u32 = 256;
pub const MAX_CONCURRENCY: u32 = 1024;
/// Probes in flight against one host, so a single device is not flooded.
pub const DEFAULT_PER_HOST: u32 = 32;
pub const MAX_PER_HOST: u32 = 256;
/// Default cap on hosts x ports: a /24 with "Top 1000" (254,000) fits, a /22 does not.
pub const DEFAULT_MAX_PROBES: u64 = 1_000_000;
/// Highest configurable cap: enough for all 65,535 ports on a /24 (16,645,890).
pub const MAX_MAX_PROBES: u64 = 1 << 24;

/// Open ports listed per host; more are only counted (some firewalls accept every port).
pub const MAX_LISTED_OPEN: usize = 1024;
/// Closed or filtered ports are listed one by one while there are at most this many of
/// that state on a host, otherwise only counted (like "997 closed ports").
pub const MAX_LISTED_OTHER: usize = 32;

/// Results are flushed at this interval ...
const FLUSH_INTERVAL: Duration = Duration::from_millis(250);
/// ... or earlier, once this many hosts have changed.
const MAX_BATCH: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PortScanError {
    #[error("port scan timeout must be between 100 and 10000 ms")]
    Timeout,
    #[error("port scan concurrency must be between 1 and 1024")]
    Concurrency,
    #[error("connections per host must be between 1 and 256")]
    PerHost,
    #[error("the probe limit must be between 1 and 16,777,216")]
    MaxProbes,
    #[error("{probes} port probes requested ({hosts} hosts x {ports} ports), the limit is {max}")]
    TooManyProbes {
        hosts: usize,
        ports: usize,
        probes: u64,
        max: u64,
    },
}

impl PortScanError {
    /// Stable identifier the frontend maps to a localized message.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Timeout => "ports.invalid_timeout",
            Self::Concurrency => "ports.invalid_concurrency",
            Self::PerHost => "ports.invalid_per_host",
            Self::MaxProbes => "ports.invalid_max_probes",
            Self::TooManyProbes { .. } => "ports.too_many_probes",
        }
    }

    /// The value the message refers to, for localized messages.
    pub fn detail(&self) -> Option<String> {
        match self {
            Self::TooManyProbes { probes, .. } => Some(probes.to_string()),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortScanConfig {
    /// How long to wait for an answer per port.
    pub timeout: Duration,
    /// Probes in flight overall.
    pub concurrency: usize,
    /// Probes in flight per host; capped at `concurrency`.
    pub per_host: usize,
    /// Scans with more probes (hosts x ports) are refused.
    pub max_probes: u64,
}

impl PortScanConfig {
    /// Validates user-supplied limits (see the `MIN_`/`MAX_` constants).
    pub fn new(
        timeout_ms: u32,
        concurrency: u32,
        per_host: u32,
        max_probes: u64,
    ) -> Result<Self, PortScanError> {
        if !(MIN_TIMEOUT_MS..=MAX_TIMEOUT_MS).contains(&timeout_ms) {
            return Err(PortScanError::Timeout);
        }
        if !(1..=MAX_CONCURRENCY).contains(&concurrency) {
            return Err(PortScanError::Concurrency);
        }
        if !(1..=MAX_PER_HOST).contains(&per_host) {
            return Err(PortScanError::PerHost);
        }
        if !(1..=MAX_MAX_PROBES).contains(&max_probes) {
            return Err(PortScanError::MaxProbes);
        }
        Ok(Self {
            timeout: Duration::from_millis(u64::from(timeout_ms)),
            concurrency: concurrency as usize,
            per_host: per_host as usize,
            max_probes,
        })
    }
}

impl Default for PortScanConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_millis(u64::from(DEFAULT_TIMEOUT_MS)),
            concurrency: DEFAULT_CONCURRENCY as usize,
            per_host: DEFAULT_PER_HOST as usize,
            max_probes: DEFAULT_MAX_PROBES,
        }
    }
}

/// Number of probes for `hosts` x `ports`; refused above `max` (never silently truncated).
pub fn check_probes(hosts: usize, ports: usize, max: u64) -> Result<u64, PortScanError> {
    let probes = (hosts as u64).saturating_mul(ports as u64);
    if probes > max {
        return Err(PortScanError::TooManyProbes {
            hosts,
            ports,
            probes,
            max,
        });
    }
    Ok(probes)
}

/// Result of one probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Probe {
    Open,
    Closed,
    Filtered,
    /// Local error; says nothing about the port.
    Failed,
}

/// Probes one port; implemented by [`TcpProber`].
pub trait PortProber: Send + Sync + 'static {
    fn probe(&self, addr: SocketAddr, timeout: Duration) -> impl Future<Output = Probe> + Send;
}

/// TCP connect probe (see [`probe::connect`]).
pub struct TcpProber;

impl PortProber for TcpProber {
    async fn probe(&self, addr: SocketAddr, timeout: Duration) -> Probe {
        match probe::connect(addr, timeout).await {
            // Dropping the stream resets the connection right away.
            Connect::Open(_stream) => Probe::Open,
            Connect::Closed => Probe::Closed,
            Connect::Filtered => Probe::Filtered,
            Connect::Failed(_) => Probe::Failed,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PortEntry {
    pub port: u16,
    pub state: PortState,
    /// Service usually found on this port (display only).
    pub service: Option<&'static str>,
}

/// Port scan result of one host. Sent while the host is being scanned and once more when it
/// is done or stopped; the frontend treats it as an upsert keyed by `ip`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostPorts {
    pub ip: IpAddr,
    /// Every port has been probed. `false` while running and for hosts stopped by a cancel.
    pub complete: bool,
    /// Ports probed so far.
    pub probed: u32,
    /// Ports to probe.
    pub total: u32,
    /// Ascending: open ports (up to [`MAX_LISTED_OPEN`]), closed and filtered ports while
    /// there are at most [`MAX_LISTED_OTHER`] of that state.
    pub ports: Vec<PortEntry>,
    pub open: u32,
    pub closed: u32,
    pub filtered: u32,
    /// Probes that failed locally (no statement about the port).
    pub errors: u32,
}

/// Live update: changed hosts plus overall progress.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PortBatch {
    pub scan_id: u64,
    pub hosts: Vec<HostPorts>,
    /// Probes finished so far.
    pub done: u64,
    /// Probes overall (hosts x ports).
    pub total: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PortScanSummary {
    pub scan_id: u64,
    pub cancelled: bool,
    pub hosts: u32,
    /// Hosts whose ports were all probed.
    pub hosts_complete: u32,
    pub done: u64,
    pub total: u64,
    /// Open ports over all hosts.
    pub open: u32,
    pub errors: u32,
    pub started_at_ms: u64,
    pub finished_at_ms: u64,
}

/// Probes `ports` on every host in `hosts` and reports results through `on_batch` while
/// running. Refuses scans above `config.max_probes`. Setting `cancel` to `true` stops the
/// scan: no new probes are started and the ones in flight are dropped (closing their sockets).
pub async fn scan_ports<P, F>(
    prober: Arc<P>,
    hosts: Vec<IpAddr>,
    ports: Arc<PortSet>,
    config: PortScanConfig,
    cancel: watch::Receiver<bool>,
    scan_id: u64,
    on_batch: F,
) -> Result<PortScanSummary, PortScanError>
where
    P: PortProber,
    F: Fn(PortBatch) + Send,
{
    let total = check_probes(hosts.len(), ports.len(), config.max_probes)?;
    let started_at_ms = now_ms();
    let concurrency = config.concurrency.max(1);
    let per_host = config
        .per_host
        .clamp(1, concurrency)
        .min(ports.len().max(1));
    // Enough hosts at a time to use the global limit, so hosts finish one after another
    // instead of all at the end.
    let parallel_hosts = concurrency.div_ceil(per_host);
    let port_count = u32::try_from(ports.len()).unwrap_or(u32::MAX);
    let mut states: Vec<HostState> = hosts
        .iter()
        .map(|&ip| HostState::new(ip, port_count))
        .collect();

    let ctx = Arc::new(Ctx {
        prober,
        ports,
        timeout: config.timeout,
        per_host,
        global: Arc::new(Semaphore::new(concurrency)),
        cancel: cancel.clone(),
    });
    let (tx, mut rx) = mpsc::channel::<Msg>(1024);
    let producer = tokio::spawn(produce(ctx, hosts, parallel_hosts, tx));

    let mut done = 0u64;
    let mut dirty: Vec<usize> = Vec::new();
    let flush = |states: &mut [HostState], dirty: &mut Vec<usize>, done: u64| {
        let hosts = dirty
            .drain(..)
            .map(|index| {
                states[index].dirty = false;
                states[index].report()
            })
            .collect();
        on_batch(PortBatch {
            scan_id,
            hosts,
            done,
            total,
        });
    };

    let mut ticker = tokio::time::interval(FLUSH_INTERVAL);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            msg = rx.recv() => {
                // The channel closes once the producer and all host tasks are done.
                let Some(msg) = msg else { break };
                let index = match msg {
                    Msg::Probed { host, port, probe } => {
                        states[host].record(port, probe);
                        done += 1;
                        host
                    }
                    Msg::Lost { host } => {
                        states[host].record_lost();
                        done += 1;
                        host
                    }
                    Msg::Finished { host, complete } => {
                        states[host].complete = complete;
                        host
                    }
                };
                if !states[index].dirty {
                    states[index].dirty = true;
                    dirty.push(index);
                }
                if dirty.len() >= MAX_BATCH {
                    flush(&mut states, &mut dirty, done);
                }
            }
            _ = ticker.tick() => {
                if !dirty.is_empty() {
                    flush(&mut states, &mut dirty, done);
                }
            }
        }
    }
    if !dirty.is_empty() {
        flush(&mut states, &mut dirty, done);
    }
    let _ = producer.await;

    Ok(PortScanSummary {
        scan_id,
        cancelled: *cancel.borrow() && done < total,
        hosts: count_u32(states.len()),
        hosts_complete: count_u32(states.iter().filter(|s| s.complete).count()),
        done,
        total,
        open: states.iter().map(|s| s.open.count).sum(),
        errors: states.iter().map(|s| s.errors).sum(),
        started_at_ms,
        finished_at_ms: now_ms(),
    })
}

fn count_u32(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

enum Msg {
    Probed {
        host: usize,
        port: u16,
        probe: Probe,
    },
    /// A probe task died (panicked); counted as a failed probe.
    Lost {
        host: usize,
    },
    Finished {
        host: usize,
        complete: bool,
    },
}

/// Everything a host task needs, shared between all of them.
struct Ctx<P> {
    prober: Arc<P>,
    ports: Arc<PortSet>,
    timeout: Duration,
    per_host: usize,
    /// Probes in flight overall.
    global: Arc<Semaphore>,
    cancel: watch::Receiver<bool>,
}

/// Starts one task per host; at most `parallel_hosts` hosts are scanned at the same time.
async fn produce<P: PortProber>(
    ctx: Arc<Ctx<P>>,
    hosts: Vec<IpAddr>,
    parallel_hosts: usize,
    tx: mpsc::Sender<Msg>,
) {
    let slots = Arc::new(Semaphore::new(parallel_hosts));
    let mut cancel = ctx.cancel.clone();
    for (index, ip) in hosts.into_iter().enumerate() {
        let slot = tokio::select! {
            biased;
            _ = cancelled(&mut cancel) => break,
            slot = Arc::clone(&slots).acquire_owned() => slot,
        };
        let Ok(slot) = slot else { break };
        tokio::spawn(scan_host(Arc::clone(&ctx), index, ip, tx.clone(), slot));
    }
}

/// Probes every port of one host, at most `per_host` at a time. On cancel the probes in
/// flight are aborted and the host is reported as incomplete.
async fn scan_host<P: PortProber>(
    ctx: Arc<Ctx<P>>,
    index: usize,
    ip: IpAddr,
    tx: mpsc::Sender<Msg>,
    _slot: OwnedSemaphorePermit,
) {
    let mut cancel = ctx.cancel.clone();
    let mut ports = ctx.ports.iter();
    let mut running: JoinSet<(u16, Probe)> = JoinSet::new();
    let complete = 'scan: loop {
        while running.len() < ctx.per_host {
            let Some(port) = ports.next() else { break };
            let permit = tokio::select! {
                biased;
                _ = cancelled(&mut cancel) => break 'scan false,
                permit = Arc::clone(&ctx.global).acquire_owned() => permit,
            };
            let Ok(permit) = permit else {
                break 'scan false;
            };
            let prober = Arc::clone(&ctx.prober);
            let timeout = ctx.timeout;
            running.spawn(async move {
                let probe = prober.probe(SocketAddr::new(ip, port), timeout).await;
                drop(permit);
                (port, probe)
            });
        }
        let joined = tokio::select! {
            biased;
            _ = cancelled(&mut cancel) => break 'scan false,
            joined = running.join_next() => joined,
        };
        let msg = match joined {
            // Nothing in flight and no ports left.
            None => break 'scan true,
            Some(Ok((port, probe))) => Msg::Probed {
                host: index,
                port,
                probe,
            },
            Some(Err(_)) => Msg::Lost { host: index },
        };
        if tx.send(msg).await.is_err() {
            break 'scan false;
        }
    };
    // Aborts what is still in flight (only after a cancel); dropping a connect closes it.
    running.abort_all();
    let _ = tx
        .send(Msg::Finished {
            host: index,
            complete,
        })
        .await;
}

/// Ports of one state on one host: counted, and listed up to a limit.
#[derive(Debug, Default)]
struct Tally {
    count: u32,
    ports: Vec<u16>,
}

impl Tally {
    /// Keeps the first `limit` ports.
    fn add_truncating(&mut self, port: u16, limit: usize) {
        self.count += 1;
        if self.ports.len() < limit {
            self.ports.push(port);
        }
    }

    /// Lists the ports only while there are at most `limit`.
    fn add_while_few(&mut self, port: u16, limit: usize) {
        self.count += 1;
        if self.count as usize <= limit {
            self.ports.push(port);
        } else if !self.ports.is_empty() {
            self.ports = Vec::new();
        }
    }
}

struct HostState {
    ip: IpAddr,
    total: u32,
    probed: u32,
    complete: bool,
    open: Tally,
    closed: Tally,
    filtered: Tally,
    errors: u32,
    /// Changed since the last flush (and queued in the dirty list).
    dirty: bool,
}

impl HostState {
    fn new(ip: IpAddr, total: u32) -> Self {
        Self {
            ip,
            total,
            probed: 0,
            complete: false,
            open: Tally::default(),
            closed: Tally::default(),
            filtered: Tally::default(),
            errors: 0,
            dirty: false,
        }
    }

    fn record(&mut self, port: u16, probe: Probe) {
        self.probed += 1;
        match probe {
            Probe::Open => self.open.add_truncating(port, MAX_LISTED_OPEN),
            Probe::Closed => self.closed.add_while_few(port, MAX_LISTED_OTHER),
            Probe::Filtered => self.filtered.add_while_few(port, MAX_LISTED_OTHER),
            Probe::Failed => self.errors += 1,
        }
    }

    fn record_lost(&mut self) {
        self.probed += 1;
        self.errors += 1;
    }

    fn report(&self) -> HostPorts {
        let entry = |state: PortState| {
            move |&port: &u16| PortEntry {
                port,
                state,
                service: service_name(port),
            }
        };
        let mut ports: Vec<PortEntry> = self
            .open
            .ports
            .iter()
            .map(entry(PortState::Open))
            .chain(self.closed.ports.iter().map(entry(PortState::Closed)))
            .chain(self.filtered.ports.iter().map(entry(PortState::Filtered)))
            .collect();
        ports.sort_unstable_by_key(|entry| entry.port);
        HostPorts {
            ip: self.ip,
            complete: self.complete,
            probed: self.probed,
            total: self.total,
            ports,
            open: self.open.count,
            closed: self.closed.count,
            filtered: self.filtered.count,
            errors: self.errors,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::Ipv4Addr;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Instant;

    use tokio::net::TcpListener;

    use super::*;

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
    }

    /// Answers from a table (default: closed) after `delay`, and records concurrency.
    #[derive(Default)]
    struct MockProber {
        answers: HashMap<SocketAddr, Probe>,
        delay: Duration,
        in_flight: AtomicUsize,
        max_in_flight: AtomicUsize,
        per_host: Mutex<HashMap<IpAddr, usize>>,
        max_per_host: AtomicUsize,
        probes: AtomicUsize,
    }

    /// Counts a probe as in flight until dropped (also when it is aborted).
    struct InFlight<'a> {
        mock: &'a MockProber,
        ip: IpAddr,
    }

    impl Drop for InFlight<'_> {
        fn drop(&mut self) {
            self.mock.in_flight.fetch_sub(1, Ordering::SeqCst);
            *self
                .mock
                .per_host
                .lock()
                .unwrap()
                .get_mut(&self.ip)
                .unwrap() -= 1;
        }
    }

    impl MockProber {
        fn with(answers: &[(IpAddr, u16, Probe)]) -> Self {
            Self {
                answers: answers
                    .iter()
                    .map(|&(ip, port, probe)| (SocketAddr::new(ip, port), probe))
                    .collect(),
                ..Self::default()
            }
        }

        fn enter(&self, ip: IpAddr) -> InFlight<'_> {
            self.probes.fetch_add(1, Ordering::SeqCst);
            let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_in_flight.fetch_max(now, Ordering::SeqCst);
            let mut per_host = self.per_host.lock().unwrap();
            let count = per_host.entry(ip).or_default();
            *count += 1;
            self.max_per_host.fetch_max(*count, Ordering::SeqCst);
            InFlight { mock: self, ip }
        }
    }

    impl PortProber for MockProber {
        async fn probe(&self, addr: SocketAddr, _timeout: Duration) -> Probe {
            let _guard = self.enter(addr.ip());
            tokio::time::sleep(self.delay).await;
            self.answers.get(&addr).copied().unwrap_or(Probe::Closed)
        }
    }

    fn config(concurrency: usize, per_host: usize) -> PortScanConfig {
        PortScanConfig {
            concurrency,
            per_host,
            ..PortScanConfig::default()
        }
    }

    struct Run {
        batches: Vec<PortBatch>,
        summary: Result<PortScanSummary, PortScanError>,
    }

    impl Run {
        /// Final report per host.
        fn last(&self, ip: IpAddr) -> HostPorts {
            self.reports(ip).pop().expect("host was reported")
        }

        fn reports(&self, ip: IpAddr) -> Vec<HostPorts> {
            self.batches
                .iter()
                .flat_map(|b| &b.hosts)
                .filter(|h| h.ip == ip)
                .cloned()
                .collect()
        }

        fn summary(&self) -> &PortScanSummary {
            self.summary.as_ref().unwrap()
        }
    }

    /// Runs a scan; `cancel_after` stops it after that delay (zero: before it starts).
    async fn scan<P: PortProber>(
        prober: Arc<P>,
        hosts: Vec<IpAddr>,
        ports: &str,
        config: PortScanConfig,
        cancel_after: Option<Duration>,
    ) -> Run {
        let (cancel_tx, cancel_rx) = watch::channel(cancel_after == Some(Duration::ZERO));
        let stopper = tokio::spawn(async move {
            match cancel_after {
                Some(delay) => {
                    tokio::time::sleep(delay).await;
                    cancel_tx.send_replace(true);
                }
                None => cancel_tx.closed().await,
            }
        });
        let batches = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&batches);
        let summary = scan_ports(
            prober,
            hosts,
            Arc::new(PortSet::parse(ports).unwrap()),
            config,
            cancel_rx,
            9,
            move |batch| sink.lock().unwrap().push(batch),
        )
        .await;
        stopper.abort();
        let batches = std::mem::take(&mut *batches.lock().unwrap());
        Run { batches, summary }
    }

    fn states(report: &HostPorts) -> Vec<(u16, PortState)> {
        report.ports.iter().map(|e| (e.port, e.state)).collect()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn reports_every_state() {
        let prober = Arc::new(MockProber::with(&[
            (ip(1), 22, Probe::Open),
            (ip(1), 80, Probe::Open),
            (ip(1), 443, Probe::Filtered),
            (ip(1), 23, Probe::Failed),
            (ip(2), 21, Probe::Filtered),
        ]));
        let run = scan(
            prober,
            vec![ip(1), ip(2)],
            "21-23,80,443",
            config(16, 4),
            None,
        )
        .await;

        let first = run.last(ip(1));
        assert!(first.complete);
        assert_eq!((first.probed, first.total), (5, 5));
        assert_eq!(
            (first.open, first.closed, first.filtered, first.errors),
            (2, 1, 1, 1)
        );
        // Few closed/filtered ports: listed with their state. Failed probes are not.
        assert_eq!(
            states(&first),
            [
                (21, PortState::Closed),
                (22, PortState::Open),
                (80, PortState::Open),
                (443, PortState::Filtered),
            ]
        );
        assert_eq!(first.ports[1].service, Some("ssh"));

        let second = run.last(ip(2));
        assert_eq!((second.open, second.closed, second.filtered), (0, 4, 1));

        let summary = run.summary();
        assert_eq!((summary.done, summary.total), (10, 10));
        assert_eq!((summary.hosts, summary.hosts_complete), (2, 2));
        assert_eq!((summary.open, summary.errors), (2, 1));
        assert!(!summary.cancelled);
        assert!(summary.finished_at_ms >= summary.started_at_ms);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn many_closed_or_filtered_ports_are_only_counted() {
        let host = ip(1);
        // 1-100: 22 open, 1-59 except 22 filtered (58), 60-100 closed (41).
        let mut answers: Vec<_> = (1..60).map(|p| (host, p, Probe::Filtered)).collect();
        answers.push((host, 22, Probe::Open));
        let run = scan(
            Arc::new(MockProber::with(&answers)),
            vec![host],
            "1-100",
            config(64, 32),
            None,
        )
        .await;
        let report = run.last(host);
        assert_eq!((report.open, report.filtered, report.closed), (1, 58, 41));
        assert_eq!(states(&report), [(22, PortState::Open)]);

        // A small minority stays listed.
        let mut answers: Vec<_> = (1..=100).map(|p| (host, p, Probe::Filtered)).collect();
        answers[9].2 = Probe::Closed; // port 10
        answers[20].2 = Probe::Open; // port 21
        let run = scan(
            Arc::new(MockProber::with(&answers)),
            vec![host],
            "1-100",
            config(64, 32),
            None,
        )
        .await;
        let report = run.last(host);
        assert_eq!((report.open, report.closed, report.filtered), (1, 1, 98));
        assert_eq!(
            states(&report),
            [(10, PortState::Closed), (21, PortState::Open)]
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn open_port_list_is_capped_but_counted() {
        let host = ip(1);
        let answers: Vec<_> = (1..=1100).map(|p| (host, p, Probe::Open)).collect();
        let run = scan(
            Arc::new(MockProber::with(&answers)),
            vec![host],
            "1-1100",
            config(256, 64),
            None,
        )
        .await;
        let report = run.last(host);
        assert_eq!(report.open, 1100);
        assert_eq!(report.ports.len(), MAX_LISTED_OPEN);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn respects_global_and_per_host_limits() {
        let prober = Arc::new(MockProber {
            delay: Duration::from_millis(15),
            ..MockProber::default()
        });
        let hosts: Vec<IpAddr> = (1..=10).map(ip).collect();
        let run = scan(Arc::clone(&prober), hosts, "1-40", config(16, 4), None).await;
        assert_eq!(run.summary().done, 400);
        assert_eq!(prober.probes.load(Ordering::SeqCst), 400);
        let max_global = prober.max_in_flight.load(Ordering::SeqCst);
        assert!(max_global <= 16, "{max_global}");
        // Several hosts were scanned in parallel to use the global limit.
        assert!(max_global > 4, "{max_global}");
        assert!(prober.max_per_host.load(Ordering::SeqCst) <= 4);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn per_host_limit_is_capped_by_the_global_limit() {
        let prober = Arc::new(MockProber {
            delay: Duration::from_millis(5),
            ..MockProber::default()
        });
        let run = scan(Arc::clone(&prober), vec![ip(1)], "1-50", config(2, 8), None).await;
        assert_eq!(run.summary().done, 50);
        assert!(prober.max_per_host.load(Ordering::SeqCst) <= 2);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn hosts_finish_one_after_another() {
        // One host at a time (global limit = per-host limit): every host is complete
        // before the next one shows up.
        let prober = Arc::new(MockProber {
            delay: Duration::from_millis(5),
            ..MockProber::default()
        });
        let hosts: Vec<IpAddr> = (1..=5).map(ip).collect();
        let run = scan(prober, hosts.clone(), "1-16", config(4, 4), None).await;
        let order: Vec<(IpAddr, bool)> = run
            .batches
            .iter()
            .flat_map(|b| &b.hosts)
            .map(|h| (h.ip, h.complete))
            .collect();
        for pair in hosts.windows(2) {
            let first_of_next = order.iter().position(|&(ip, _)| ip == pair[1]).unwrap();
            let done_of_prev = order
                .iter()
                .position(|&(ip, complete)| ip == pair[0] && complete)
                .unwrap();
            assert!(done_of_prev < first_of_next, "{order:?}");
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn progress_is_monotonic_and_ends_at_the_summary() {
        let prober = Arc::new(MockProber {
            delay: Duration::from_millis(2),
            ..MockProber::default()
        });
        let hosts: Vec<IpAddr> = (1..=8).map(ip).collect();
        let run = scan(prober, hosts, "1-200", config(64, 16), None).await;
        assert!(run.batches.len() > 1);
        assert!(run.batches.windows(2).all(|w| w[0].done <= w[1].done));
        assert!(
            run.batches
                .iter()
                .all(|b| b.scan_id == 9 && b.total == 1600)
        );
        let last = run.batches.last().unwrap();
        assert_eq!(last.done, run.summary().done);
        assert_eq!(last.done, 1600);
        // Per-host progress never goes backwards either.
        for host in (1..=8).map(ip) {
            let reports = run.reports(host);
            assert!(reports.windows(2).all(|w| w[0].probed <= w[1].probed));
            assert!(reports.last().unwrap().complete);
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn cancel_stops_quickly_and_drops_probes_in_flight() {
        // Every probe would hang for a long time.
        let prober = Arc::new(MockProber {
            delay: Duration::from_secs(30),
            ..MockProber::default()
        });
        let hosts: Vec<IpAddr> = (1..=20).map(ip).collect();
        let started = Instant::now();
        let run = scan(
            Arc::clone(&prober),
            hosts,
            "1-1000",
            config(64, 16),
            Some(Duration::from_millis(100)),
        )
        .await;
        assert!(started.elapsed() < Duration::from_secs(1));
        let summary = run.summary();
        assert!(summary.cancelled);
        assert_eq!((summary.done, summary.total), (0, 20_000));
        assert_eq!(summary.hosts_complete, 0);
        // Hosts that had started are reported as incomplete.
        let reports: Vec<HostPorts> = run.batches.into_iter().flat_map(|b| b.hosts).collect();
        assert!(!reports.is_empty());
        assert!(reports.iter().all(|h| !h.complete && h.probed == 0));
        // The aborted probes are dropped right away.
        let deadline = Instant::now() + Duration::from_secs(1);
        while prober.in_flight.load(Ordering::SeqCst) > 0 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(prober.in_flight.load(Ordering::SeqCst), 0);
        assert!(prober.probes.load(Ordering::SeqCst) <= 64);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn cancelled_before_start_probes_nothing() {
        let prober = Arc::new(MockProber::default());
        let run = scan(
            Arc::clone(&prober),
            vec![ip(1), ip(2)],
            "1-100",
            config(16, 4),
            Some(Duration::ZERO),
        )
        .await;
        assert!(run.summary().cancelled);
        assert_eq!(run.summary().done, 0);
        assert!(run.batches.is_empty());
        assert_eq!(prober.probes.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn scans_above_the_probe_limit_are_refused() {
        let prober = Arc::new(MockProber::default());
        let limited = PortScanConfig {
            max_probes: 29,
            ..config(16, 4)
        };
        let hosts = vec![ip(1), ip(2), ip(3)];
        let run = scan(Arc::clone(&prober), hosts.clone(), "1-10", limited, None).await;
        let error = run.summary.unwrap_err();
        assert_eq!(
            error,
            PortScanError::TooManyProbes {
                hosts: 3,
                ports: 10,
                probes: 30,
                max: 29
            }
        );
        assert_eq!(
            (error.code(), error.detail().as_deref()),
            ("ports.too_many_probes", Some("30"))
        );
        assert!(run.batches.is_empty());
        assert_eq!(prober.probes.load(Ordering::SeqCst), 0);

        // Exactly at the limit is fine.
        let at_limit = PortScanConfig {
            max_probes: 30,
            ..limited
        };
        let run = scan(prober, hosts, "1-10", at_limit, None).await;
        assert_eq!(run.summary().done, 30);
    }

    #[test]
    fn probe_limit_of_the_defaults() {
        let max = DEFAULT_MAX_PROBES;
        // A /24 with Top 1000 fits, a /22 does not, nor all ports of 16 hosts.
        assert!(check_probes(254, 1000, max).is_ok());
        assert!(check_probes(1022, 1000, max).is_err());
        assert!(check_probes(16, 65_535, max).is_err());
        assert!(check_probes(1, 65_535, max).is_ok());
        // The highest configurable limit covers all ports of a /24.
        assert!(check_probes(254, 65_535, MAX_MAX_PROBES).is_ok());
        assert!(check_probes(usize::MAX, usize::MAX, MAX_MAX_PROBES).is_err());
    }

    #[tokio::test]
    async fn no_hosts_is_an_empty_scan() {
        let run = scan(
            Arc::new(MockProber::default()),
            Vec::new(),
            "1-100",
            config(16, 4),
            None,
        )
        .await;
        assert_eq!((run.summary().done, run.summary().total), (0, 0));
        assert!(!run.summary().cancelled);
        assert!(run.batches.is_empty());
    }

    #[test]
    fn config_validation() {
        let ok = |t, c, p, m| PortScanConfig::new(t, c, p, m);
        assert!(ok(100, 1, 1, 1).is_ok());
        assert!(ok(10_000, 1024, 256, MAX_MAX_PROBES).is_ok());
        assert_eq!(ok(99, 1, 1, 1), Err(PortScanError::Timeout));
        assert_eq!(ok(10_001, 1, 1, 1), Err(PortScanError::Timeout));
        assert_eq!(ok(1000, 0, 1, 1), Err(PortScanError::Concurrency));
        assert_eq!(ok(1000, 1025, 1, 1), Err(PortScanError::Concurrency));
        assert_eq!(ok(1000, 1, 0, 1), Err(PortScanError::PerHost));
        assert_eq!(ok(1000, 1, 257, 1), Err(PortScanError::PerHost));
        assert_eq!(ok(1000, 1, 1, 0), Err(PortScanError::MaxProbes));
        assert_eq!(
            ok(1000, 1, 1, MAX_MAX_PROBES + 1),
            Err(PortScanError::MaxProbes)
        );
        let defaults = PortScanConfig::default();
        assert_eq!(
            ok(
                DEFAULT_TIMEOUT_MS,
                DEFAULT_CONCURRENCY,
                DEFAULT_PER_HOST,
                DEFAULT_MAX_PROBES
            ),
            Ok(defaults)
        );
        assert_eq!(PortScanError::Timeout.code(), "ports.invalid_timeout");
        assert_eq!(PortScanError::Timeout.detail(), None);
    }

    #[test]
    fn serializes_camel_case_for_the_frontend() {
        let mut state = HostState::new(ip(1), 3);
        state.record(3389, Probe::Open);
        state.record(81, Probe::Closed);
        state.record(5, Probe::Filtered);
        state.complete = true;
        let json = serde_json::to_value(state.report()).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "ip": "10.0.0.1",
                "complete": true,
                "probed": 3,
                "total": 3,
                "ports": [
                    {"port": 5, "state": "filtered", "service": null},
                    {"port": 81, "state": "closed", "service": "http-alt"},
                    {"port": 3389, "state": "open", "service": "rdp"},
                ],
                "open": 1,
                "closed": 1,
                "filtered": 1,
                "errors": 0,
            })
        );
    }

    /// Real sockets on loopback: an open and a closed port, with the real prober.
    #[tokio::test(flavor = "multi_thread")]
    async fn real_scan_of_loopback_finds_open_and_closed_ports() {
        let open_a = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let open_b = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let closed = {
            let temp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            temp.local_addr().unwrap().port()
        };
        let [a, b] = [&open_a, &open_b].map(|l| l.local_addr().unwrap().port());
        let localhost = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let started = Instant::now();
        let run = scan(
            Arc::new(TcpProber),
            vec![localhost],
            &format!("{a},{b},{closed}"),
            PortScanConfig::default(),
            None,
        )
        .await;
        // The closed port does not wait for the 1 s timeout (or the Windows SYN retries).
        assert!(started.elapsed() < Duration::from_millis(800));
        let report = run.last(localhost);
        assert!(report.complete);
        assert_eq!((report.open, report.closed, report.filtered), (2, 1, 0));
        let mut expected = vec![
            (a, PortState::Open),
            (b, PortState::Open),
            (closed, PortState::Closed),
        ];
        expected.sort_unstable_by_key(|&(port, _)| port);
        assert_eq!(states(&report), expected);
        assert_eq!(run.summary().errors, 0);
    }
}

/// Manual check against a real host: `IRONSIGHT_PORTS_HOST=<ip> cargo test live_port_scan --
/// --ignored --nocapture` (default: this machine's own LAN address). Scans "Top 1000" and
/// prints only counts and timing.
#[cfg(all(test, windows))]
mod live {
    use super::*;
    use crate::platform;
    use crate::ports::presets::PortPreset;

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "scans a real host"]
    async fn live_port_scan() {
        let host: IpAddr = match std::env::var("IRONSIGHT_PORTS_HOST") {
            Ok(ip) => ip
                .parse()
                .expect("IRONSIGHT_PORTS_HOST must be an IP address"),
            Err(_) => {
                let adapters = platform::default_backend().list_adapters().unwrap();
                let Some(net) = adapters
                    .iter()
                    .find(|a| a.has_gateway)
                    .and_then(|a| a.ipv4.first())
                else {
                    println!("no adapter with a gateway, nothing to scan");
                    return;
                };
                IpAddr::V4(net.addr)
            }
        };
        let (_cancel, cancelled) = watch::channel(false);
        let started = std::time::Instant::now();
        let batches = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = Arc::clone(&batches);
        let summary = scan_ports(
            Arc::new(TcpProber),
            vec![host],
            Arc::new(PortPreset::Top1000.ports()),
            PortScanConfig::default(),
            cancelled,
            1,
            move |batch| {
                counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                for h in batch.hosts.iter().filter(|h| h.complete) {
                    println!(
                        "open={} closed={} filtered={} errors={} listed={}",
                        h.open,
                        h.closed,
                        h.filtered,
                        h.errors,
                        h.ports.len()
                    );
                }
            },
        )
        .await
        .unwrap();
        println!(
            "done={}/{} batches={} in {:?}",
            summary.done,
            summary.total,
            batches.load(std::sync::atomic::Ordering::Relaxed),
            started.elapsed()
        );
        assert_eq!(summary.done, summary.total);
    }
}
