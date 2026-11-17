//! Tauri commands. All input from the webview is validated here before it reaches the engine.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State, WebviewWindow};
use tauri_plugin_dialog::DialogExt;
use tokio::sync::{oneshot, watch};

use crate::actions;
use crate::enrich::NetEnricher;
use crate::error::CommandError;
use crate::export::{
    self, Delimiter, ExportKind, ExportOptions, Labels, PortStepInfo, ReportLanguage, ScanInfo,
    Scope,
};
use crate::known::{self, KnownDevices, LiveSet};
use crate::mac::MacAddr;
use crate::platform::{self, Adapter, NetBackend};
use crate::portable::{self, PortableState};
use crate::ports::PortSelection;
use crate::ports::scanner::{
    self, HostPorts, PortBatch, PortScanConfig, PortScanSummary, PortTarget, TcpProber,
    check_probes, scan_ports,
};
use crate::ports::spec::PortSet;
use crate::scan::engine::{now_ms, run_scan};
use crate::scan::range::{MAX_HOSTS, TargetSet};
use crate::scan::{
    DEFAULT_CONCURRENCY, DEFAULT_TIMEOUT_MS, DataSource, HostResult, OfflineNames, ScanBatch,
    ScanConfig,
};
use crate::settings::{self, Settings};

pub const EVENT_SCAN_BATCH: &str = "scan:batch";
pub const EVENT_SCAN_FINISHED: &str = "scan:finished";
pub const EVENT_PORTS_BATCH: &str = "ports:batch";
pub const EVENT_PORTS_FINISHED: &str = "ports:finished";

struct ActiveScan {
    id: u64,
    cancel: watch::Sender<bool>,
}

/// Results of the most recent scan, kept in memory (never on disk) for manual export.
struct ScanRecord {
    scan_id: u64,
    info: ScanInfo,
    /// Hosts as the scan found them (without known-device data).
    hosts: HashMap<IpAddr, HostResult>,
    live: LiveSet,
    /// Silent addresses currently shown with known-device data.
    known_applied: HashSet<IpAddr>,
    /// Latest port scan result per host (pipeline step or "Scan ports…").
    ports: HashMap<IpAddr, PortRecord>,
}

/// A port scan report with what was scanned.
struct PortRecord {
    selection: PortSelection,
    set: Arc<PortSet>,
    report: HostPorts,
}

impl ScanRecord {
    fn new(scan_id: u64, info: ScanInfo) -> Self {
        Self {
            scan_id,
            info,
            hosts: HashMap::new(),
            live: LiveSet::default(),
            known_applied: HashSet::new(),
            ports: HashMap::new(),
        }
    }

    fn add(&mut self, host: HostResult) {
        self.live.add(&host);
        self.hosts.insert(host.ip, host);
    }

    /// The host as shown: silent addresses get known-device data, port-scanned hosts their
    /// port results.
    fn effective(&self, host: &HostResult, known: &KnownDevices) -> HostResult {
        let mut shown = self.with_known(host, known);
        if let Some(ports) = self.ports.get(&host.ip) {
            shown.apply_ports(&ports.selection, &ports.set, &ports.report);
        }
        shown
    }

    /// Silent addresses with known-device data, everything else as found.
    fn with_known(&self, host: &HostResult, known: &KnownDevices) -> HostResult {
        if host.online {
            return host.clone();
        }
        // A MAC on a silent address can only come from the neighbor cache.
        let cache_mac = host
            .mac
            .filter(|_| host.sources.mac == Some(DataSource::ArpCache));
        known::apply_known(host, known.find(host.ip, cache_mac, &self.live))
    }

    /// Recomputes known-device data for all silent addresses and returns the rows to send:
    /// all with known data plus those that just lost it.
    fn refresh_known(&mut self, known: &KnownDevices) -> Vec<HostResult> {
        let mut changed = Vec::new();
        let mut applied = HashSet::new();
        for host in self.hosts.values().filter(|h| !h.online) {
            if self.with_known(host, known) != *host {
                applied.insert(host.ip);
                changed.push(self.effective(host, known));
            } else if self.known_applied.contains(&host.ip) {
                changed.push(self.effective(host, known));
            }
        }
        self.known_applied = applied;
        changed.sort_by_key(|host| host.ip);
        changed
    }

    /// Keeps port scan reports of hosts in this scan and returns those hosts as shown.
    fn add_ports(
        &mut self,
        selection: &PortSelection,
        set: &Arc<PortSet>,
        reports: Vec<HostPorts>,
        known: &KnownDevices,
    ) -> Vec<HostResult> {
        let mut shown = Vec::with_capacity(reports.len());
        for report in reports {
            let ip = report.ip;
            if !self.hosts.contains_key(&ip) {
                continue;
            }
            let record = PortRecord {
                selection: selection.clone(),
                set: Arc::clone(set),
                report,
            };
            self.ports.insert(ip, record);
            shown.push(self.effective(&self.hosts[&ip], known));
        }
        shown
    }

    /// Port scan targets after host discovery: every host that answered, ascending, with
    /// the answers of the discovery TCP check.
    fn port_targets(&self) -> Vec<PortTarget> {
        let mut online: Vec<&HostResult> = self.hosts.values().filter(|h| h.online).collect();
        online.sort_by_key(|host| host.ip);
        online.into_iter().map(HostResult::port_target).collect()
    }

    /// All hosts sorted by address, or the given addresses in their order (unknown and
    /// repeated addresses are skipped), as shown in the app.
    fn select(&self, ips: Option<&[IpAddr]>, known: &KnownDevices) -> Vec<HostResult> {
        let hosts: Vec<&HostResult> = match ips {
            None => {
                let mut hosts: Vec<&HostResult> = self.hosts.values().collect();
                hosts.sort_by_key(|host| host.ip);
                hosts
            }
            Some(ips) => {
                let mut seen = HashSet::new();
                ips.iter()
                    .filter(|ip| seen.insert(**ip))
                    .filter_map(|ip| self.hosts.get(ip))
                    .collect()
            }
        };
        hosts
            .into_iter()
            .map(|host| self.effective(host, known))
            .collect()
    }
}

/// Known devices with their (opt-in) file.
#[derive(Default)]
struct KnownState {
    devices: KnownDevices,
    file: Option<PathBuf>,
    persist: bool,
}

impl KnownState {
    /// What to write to disk, if remembering between sessions is on.
    fn snapshot(&self) -> Option<(PathBuf, Vec<known::KnownDevice>)> {
        let file = self.file.clone().filter(|_| self.persist)?;
        Some((file, self.devices.remembered().to_vec()))
    }
}

pub struct AppState {
    backend: Arc<dyn NetBackend>,
    active: Mutex<Option<ActiveScan>>,
    next_scan_id: AtomicU64,
    last_scan: Mutex<Option<ScanRecord>>,
    /// Lock order: `known` before `last_scan`.
    known: Mutex<KnownState>,
}

impl AppState {
    pub fn new(backend: Arc<dyn NetBackend>) -> Self {
        Self {
            backend,
            active: Mutex::new(None),
            next_scan_id: AtomicU64::new(1),
            last_scan: Mutex::new(None),
            known: Mutex::new(KnownState::default()),
        }
    }

    fn known(&self) -> MutexGuard<'_, KnownState> {
        self.known.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn last_scan(&self) -> MutexGuard<'_, Option<ScanRecord>> {
        self.last_scan.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn is_scanning(&self) -> bool {
        self.active().is_some()
    }

    fn record_hosts(&self, scan_id: u64, hosts: Vec<HostResult>) {
        if let Some(record) = self.last_scan().as_mut().filter(|r| r.scan_id == scan_id) {
            for host in hosts {
                record.add(host);
            }
        }
    }

    /// After a scan: remember every device that answered and return the silent addresses
    /// whose display changed through known-device data.
    fn finish_known(
        &self,
        scan_id: u64,
    ) -> (Vec<HostResult>, Option<(PathBuf, Vec<known::KnownDevice>)>) {
        let mut known = self.known();
        let mut last = self.last_scan();
        let Some(record) = last.as_mut().filter(|r| r.scan_id == scan_id) else {
            return (Vec::new(), None);
        };
        for host in record.hosts.values().filter(|h| h.online) {
            known.devices.remember(host);
        }
        let changed = record.refresh_known(&known.devices);
        (changed, known.snapshot())
    }

    /// Re-applies known-device data to the last scan after the list changed.
    fn refresh_last_scan(&self, known: &KnownDevices) -> Vec<HostResult> {
        self.last_scan()
            .as_mut()
            .map(|record| record.refresh_known(known))
            .unwrap_or_default()
    }

    /// Stores port results of the running port scan; returns the changed rows.
    fn record_ports(
        &self,
        selection: &PortSelection,
        set: &Arc<PortSet>,
        reports: Vec<HostPorts>,
    ) -> Vec<HostResult> {
        let known = self.known();
        self.last_scan()
            .as_mut()
            .map(|record| record.add_ports(selection, set, reports, &known.devices))
            .unwrap_or_default()
    }

    /// Records how the port step of a scan ended, for the export metadata.
    fn finish_port_step(&self, scan_id: u64, finished: &PortsFinished) {
        let mut last = self.last_scan();
        let Some(record) = last.as_mut().filter(|r| r.scan_id == scan_id) else {
            return;
        };
        record.info.finished_at_ms = Some(now_ms());
        if let Some(step) = record.info.port_scan.as_mut() {
            step.checks = finished.summary.as_ref().map(|s| (s.done, s.total));
            step.cancelled = finished.summary.as_ref().is_some_and(|s| s.cancelled);
            step.error = finished.error.as_ref().map(|e| e.code);
        }
    }

    fn port_targets(&self, scan_id: u64) -> Vec<PortTarget> {
        self.last_scan()
            .as_ref()
            .filter(|record| record.scan_id == scan_id)
            .map(ScanRecord::port_targets)
            .unwrap_or_default()
    }

    /// Whether `ip` is a row of the last scan.
    fn has_host(&self, ip: IpAddr) -> bool {
        self.last_scan()
            .as_ref()
            .is_some_and(|record| record.hosts.contains_key(&ip))
    }

    fn active(&self) -> MutexGuard<'_, Option<ActiveScan>> {
        // The guarded data is a plain Option, so a poisoned lock is still usable.
        self.active.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Registers a new scan; only one may run at a time.
    fn begin_scan(&self) -> Result<(u64, watch::Receiver<bool>), CommandError> {
        let mut active = self.active();
        if active.is_some() {
            return Err(already_running());
        }
        let id = self.next_scan_id.fetch_add(1, Ordering::Relaxed);
        let (cancel, cancelled) = watch::channel(false);
        *active = Some(ActiveScan { id, cancel });
        Ok((id, cancelled))
    }

    fn end_scan(&self, id: u64) {
        let mut active = self.active();
        if active.as_ref().is_some_and(|scan| scan.id == id) {
            *active = None;
        }
    }

    fn cancel_scan(&self) {
        if let Some(scan) = self.active().as_ref() {
            scan.cancel.send_replace(true);
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScanRequest {
    targets: String,
    concurrency: Option<u32>,
    timeout_ms: Option<u32>,
    /// Reverse DNS for silent addresses (default: auto).
    offline_names: Option<OfflineNames>,
    /// Read banners and HTTP titles of open ports (default: on).
    banners: Option<bool>,
    /// Port scan of the hosts that answered, after host discovery (default: none).
    ports: Option<PortScanOptions>,
}

/// Port scan settings from the frontend; missing limits use the defaults.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PortScanOptions {
    selection: PortSelection,
    timeout_ms: Option<u32>,
    concurrency: Option<u32>,
    per_host: Option<u32>,
    max_probes: Option<u64>,
}

/// Validated port scan settings.
#[derive(Debug, Clone)]
struct PortPlan {
    /// A custom list is kept in normalized form.
    selection: PortSelection,
    set: Arc<PortSet>,
    config: PortScanConfig,
}

impl PortPlan {
    /// Export metadata of the port step; the results are filled in when it ends.
    fn step_info(&self, banners: bool) -> PortStepInfo {
        PortStepInfo {
            selection: self.selection.clone(),
            timeout_ms: u32::try_from(self.config.timeout.as_millis()).unwrap_or(u32::MAX),
            concurrency: u32::try_from(self.config.concurrency).unwrap_or(u32::MAX),
            max_probes: self.config.max_probes,
            banners,
            checks: None,
            cancelled: false,
            error: None,
        }
    }
}

impl PortScanOptions {
    fn plan(&self) -> Result<PortPlan, CommandError> {
        let (selection, set) = self.selection.resolve()?;
        let config = PortScanConfig::new(
            self.timeout_ms.unwrap_or(scanner::DEFAULT_TIMEOUT_MS),
            self.concurrency.unwrap_or(scanner::DEFAULT_CONCURRENCY),
            self.per_host.unwrap_or(scanner::DEFAULT_PER_HOST),
            self.max_probes.unwrap_or(scanner::DEFAULT_MAX_PROBES),
        )?;
        Ok(PortPlan {
            selection,
            set: Arc::new(set),
            config,
        })
    }
}

/// `ports:batch`: hosts whose port results changed (complete rows, an upsert by IP) and the
/// progress of the port scan in probes.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PortsBatch {
    scan_id: u64,
    hosts: Vec<HostResult>,
    done: u64,
    total: u64,
}

/// `ports:finished`: end of a port scan. `error` if it was refused, e.g. above the probe
/// limit (`ports.too_many_probes`).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PortsFinished {
    scan_id: u64,
    summary: Option<PortScanSummary>,
    error: Option<CommandError>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanStarted {
    scan_id: u64,
    total: u32,
}

fn scan_config(request: &ScanRequest) -> Result<ScanConfig, CommandError> {
    let concurrency = request.concurrency.unwrap_or(DEFAULT_CONCURRENCY);
    let timeout_ms = request.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS);
    Ok(ScanConfig::new(concurrency, timeout_ms)?)
}

fn already_running() -> CommandError {
    CommandError::new("scan.already_running", "a scan is already running")
}

fn internal(error: impl std::fmt::Display) -> CommandError {
    CommandError::new("internal", error.to_string())
}

fn io_error(code: &'static str, error: impl std::fmt::Display) -> CommandError {
    CommandError::new(code, error.to_string()).with_detail(error.to_string())
}

#[tauri::command]
pub async fn list_adapters(state: State<'_, AppState>) -> Result<Vec<Adapter>, CommandError> {
    let backend = Arc::clone(&state.backend);
    tauri::async_runtime::spawn_blocking(move || backend.list_adapters())
        .await
        .map_err(internal)?
        .map_err(CommandError::from)
}

/// Starts a scan in the background. Results arrive as `scan:batch` events, the end of the
/// scan (finished or stopped) as one `scan:finished` event.
#[tauri::command]
pub async fn start_scan(
    app: AppHandle,
    state: State<'_, AppState>,
    request: ScanRequest,
) -> Result<ScanStarted, CommandError> {
    if state.is_scanning() {
        return Err(already_running());
    }
    // The frontend clears its table when a scan is started; keep the export data in step.
    *state.last_scan() = None;
    let targets = TargetSet::parse(&request.targets)?;
    let mut config = scan_config(&request)?;
    let port_plan = request
        .ports
        .as_ref()
        .map(PortScanOptions::plan)
        .transpose()?;
    let banners = request.banners.unwrap_or(true);
    config.resolve_offline_names = request
        .offline_names
        .unwrap_or_default()
        .enabled_for(targets.len());
    let total = targets.len() as u32;
    let (scan_id, cancel) = state.begin_scan()?;
    let port_cancel = cancel.clone();
    let backend = Arc::clone(&state.backend);
    *state.last_scan() = Some(ScanRecord::new(
        scan_id,
        ScanInfo {
            targets: request.targets.trim().to_owned(),
            started_at_ms: now_ms(),
            finished_at_ms: None,
            cancelled: false,
            total,
            scanned: 0,
            online: 0,
            errors: 0,
            concurrency: config.concurrency as u32,
            timeout_ms: config.timeout.as_millis() as u32,
            port_scan: port_plan.as_ref().map(|plan| plan.step_info(banners)),
        },
    ));

    tauri::async_runtime::spawn(async move {
        let emitter = app.clone();
        let on_batch = move |batch: ScanBatch| {
            let _ = emitter.emit(EVENT_SCAN_BATCH, &batch);
            emitter
                .state::<AppState>()
                .record_hosts(scan_id, batch.hosts);
        };
        // The enricher needs the adapters to pick DNS servers; a failure only costs names.
        let adapters = {
            let backend = Arc::clone(&backend);
            tauri::async_runtime::spawn_blocking(move || backend.list_adapters())
                .await
                .ok()
                .and_then(Result::ok)
                .unwrap_or_default()
        };
        let probes = Arc::new(NetEnricher::new(&adapters, banners));
        let summary = run_scan(backend, probes, targets, config, cancel, scan_id, on_batch).await;
        let state = app.state::<AppState>();
        if let Some(record) = state.last_scan().as_mut().filter(|r| r.scan_id == scan_id) {
            let info = &mut record.info;
            info.started_at_ms = summary.started_at_ms;
            info.finished_at_ms = Some(summary.finished_at_ms);
            info.cancelled = summary.cancelled;
            info.scanned = summary.scanned;
            info.online = summary.online;
            info.errors = summary.errors;
        }
        // Known devices: remember who answered, show what is known for silent addresses.
        let (changed, snapshot) = state.finish_known(scan_id);
        if !changed.is_empty() {
            let batch = ScanBatch {
                scan_id,
                hosts: changed,
                scanned: summary.scanned,
                total: summary.total,
                online: summary.online,
            };
            let _ = app.emit(EVENT_SCAN_BATCH, &batch);
        }
        if let Some((file, devices)) = snapshot {
            let saved =
                tauri::async_runtime::spawn_blocking(move || known::save(&file, &devices)).await;
            if !matches!(saved, Ok(Ok(()))) {
                eprintln!("saving known devices failed");
            }
        }
        // Port scan of the hosts that answered, unless the scan was stopped.
        let stopped = *port_cancel.borrow();
        let ports_finished = match port_plan {
            Some(plan) if !stopped => {
                let targets = state.port_targets(scan_id);
                Some(run_ports(&app, scan_id, targets, plan, banners, port_cancel).await)
            }
            _ => None,
        };
        if let Some(finished) = &ports_finished {
            state.finish_port_step(scan_id, finished);
        }
        // Free the slot first, so the frontend can start a new scan right after the event.
        state.end_scan(scan_id);
        if let Some(finished) = ports_finished {
            let _ = app.emit(EVENT_PORTS_FINISHED, &finished);
        }
        let _ = app.emit(EVENT_SCAN_FINISHED, summary);
    });

    Ok(ScanStarted { scan_id, total })
}

/// Runs a port scan, sending `ports:batch` events while it runs, and returns the
/// `ports:finished` payload for the caller to send once the scan slot is free.
async fn run_ports(
    app: &AppHandle,
    scan_id: u64,
    targets: Vec<PortTarget>,
    plan: PortPlan,
    banners: bool,
    cancel: watch::Receiver<bool>,
) -> PortsFinished {
    let emitter = app.clone();
    let selection = plan.selection.clone();
    let set = Arc::clone(&plan.set);
    let on_batch = move |batch: PortBatch| {
        let hosts = emitter
            .state::<AppState>()
            .record_ports(&selection, &set, batch.hosts);
        let event = PortsBatch {
            scan_id: batch.scan_id,
            hosts,
            done: batch.done,
            total: batch.total,
        };
        let _ = emitter.emit(EVENT_PORTS_BATCH, &event);
    };
    let prober = Arc::new(TcpProber { banners });
    let result = scan_ports(
        prober,
        targets,
        plan.set,
        plan.config,
        cancel,
        scan_id,
        on_batch,
    )
    .await;
    match result {
        Ok(summary) => PortsFinished {
            scan_id,
            summary: Some(summary),
            error: None,
        },
        Err(e) => PortsFinished {
            scan_id,
            summary: None,
            error: Some(e.into()),
        },
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PortListInfo {
    normalized: String,
    count: u32,
}

/// Checks a custom port list with the scan's own parser (inline feedback in the UI).
#[tauri::command]
pub fn check_port_list(spec: String) -> Result<PortListInfo, CommandError> {
    let set = PortSet::parse(&spec)?;
    Ok(PortListInfo {
        normalized: set.to_string(),
        count: u32::try_from(set.len()).unwrap_or(u32::MAX),
    })
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostPortsRequest {
    ip: IpAddr,
    ports: PortScanOptions,
    /// Read banners and HTTP titles of open ports (default: on).
    banners: Option<bool>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PortScanStarted {
    scan_id: u64,
    /// Probes to make.
    total: u64,
}

/// "Scan ports…" for one host of the last scan, in the background. Results arrive as
/// `ports:batch` events, the end as one `ports:finished` event. It takes the scan slot:
/// `stop_scan` stops it and no other scan can start meanwhile.
#[tauri::command]
pub async fn scan_host_ports(
    app: AppHandle,
    state: State<'_, AppState>,
    request: HostPortsRequest,
) -> Result<PortScanStarted, CommandError> {
    let plan = request.ports.plan()?;
    if !state.has_host(request.ip) {
        return Err(CommandError::new(
            "ports.unknown_host",
            "this address is not part of the scan results",
        ));
    }
    let total = check_probes(1, plan.set.len(), plan.config.max_probes)?;
    let (scan_id, cancel) = state.begin_scan()?;
    let banners = request.banners.unwrap_or(true);
    // A fresh scan: nothing is taken over from host discovery.
    let target = PortTarget::from(request.ip);
    tauri::async_runtime::spawn(async move {
        let finished = run_ports(&app, scan_id, vec![target], plan, banners, cancel).await;
        app.state::<AppState>().end_scan(scan_id);
        let _ = app.emit(EVENT_PORTS_FINISHED, &finished);
    });
    Ok(PortScanStarted { scan_id, total })
}

#[tauri::command]
pub fn stop_scan(state: State<'_, AppState>) {
    state.cancel_scan();
}

/// Next to the exe in the portable build, otherwise in the app config dir.
fn settings_path(app: &AppHandle) -> Result<PathBuf, CommandError> {
    if let Some(paths) = &app.state::<PortableState>().0 {
        return Ok(paths.settings.clone());
    }
    let dir = app
        .path()
        .app_config_dir()
        .map_err(|e| io_error("settings.io", e))?;
    Ok(dir.join(settings::FILE_NAME))
}

/// Saved settings; defaults if there are none or the file is unreadable.
#[tauri::command]
pub async fn load_settings(app: AppHandle) -> Settings {
    match settings_path(&app) {
        Ok(path) => tauri::async_runtime::spawn_blocking(move || Settings::load(&path))
            .await
            .unwrap_or_default(),
        Err(_) => Settings::default(),
    }
}

#[tauri::command]
pub async fn save_settings(
    app: AppHandle,
    state: State<'_, AppState>,
    settings: Settings,
) -> Result<(), CommandError> {
    settings.validate()?;
    let path = settings_path(&app)?;
    let remember = settings.remember_devices;
    tauri::async_runtime::spawn_blocking(move || settings.save(&path))
        .await
        .map_err(internal)?
        .map_err(|e| io_error("settings.io", e))?;

    // Remembering between sessions is opt-in: on writes the file, off deletes it.
    let (file, devices) = {
        let mut known = state.known();
        known.persist = remember;
        (known.file.clone(), known.devices.remembered().to_vec())
    };
    let Some(file) = file else {
        return Ok(());
    };
    tauri::async_runtime::spawn_blocking(move || match remember {
        true => known::save(&file, &devices),
        false => known::delete(&file),
    })
    .await
    .map_err(internal)?
    .map_err(|e| io_error("known.io", e))
}

/// Where remembered devices are stored: next to the portable exe or in the app data dir.
fn known_devices_path(app: &AppHandle) -> Option<PathBuf> {
    if let Some(paths) = &app.state::<PortableState>().0 {
        return Some(paths.known_devices.clone());
    }
    let dir = app.path().app_data_dir().ok()?;
    Some(dir.join("known-devices.json"))
}

/// Startup: find the known-devices file and load it if remembering is switched on.
pub fn init_known_devices(app: &AppHandle) {
    let file = known_devices_path(app);
    let remember = settings_path(app)
        .map(|path| Settings::load(&path).remember_devices)
        .unwrap_or(false);
    let devices = match (&file, remember) {
        (Some(file), true) => known::load(file),
        _ => Vec::new(),
    };
    let state = app.state::<AppState>();
    let mut known = state.known();
    known.devices.set_remembered(devices);
    known.file = file;
    known.persist = remember;
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KnownUpdate {
    /// Devices in the loaded file (import) or 0 (forget).
    devices: usize,
    /// Rows of the current results whose display changed.
    hosts: Vec<HostResult>,
}

fn scan_running() -> CommandError {
    CommandError::new("export.scan_running", "a scan is still running")
}

/// "Load previous scan...": reads one of our JSON exports as a baseline of known devices.
/// Returns `None` if the file dialog was cancelled.
#[tauri::command]
pub async fn import_scan(
    app: AppHandle,
    window: WebviewWindow,
    state: State<'_, AppState>,
) -> Result<Option<KnownUpdate>, CommandError> {
    if state.is_scanning() {
        return Err(scan_running());
    }
    let (tx, rx) = oneshot::channel();
    app.dialog()
        .file()
        .set_parent(&window)
        .add_filter("JSON", &["json"])
        .pick_file(move |path| {
            let _ = tx.send(path);
        });
    let Some(path) = rx.await.ok().flatten() else {
        return Ok(None);
    };
    let path = path.into_path().map_err(|e| io_error("import.io", e))?;
    let devices = tauri::async_runtime::spawn_blocking(move || {
        let text = known::read_limited(&path, known::MAX_IMPORT_BYTES)
            .map_err(|e| io_error("import.io", e))?;
        known::import_export(&text, now_ms())
            .map_err(|e| CommandError::new(e.code(), e.to_string()))
    })
    .await
    .map_err(internal)??;

    let count = devices.len();
    let mut known = state.known();
    known.devices.set_imported(devices);
    let hosts = state.refresh_last_scan(&known.devices);
    Ok(Some(KnownUpdate {
        devices: count,
        hosts,
    }))
}

/// Forgets all known devices (session, saved file and imported baseline).
#[tauri::command]
pub async fn forget_known_devices(state: State<'_, AppState>) -> Result<KnownUpdate, CommandError> {
    if state.is_scanning() {
        return Err(scan_running());
    }
    let (file, hosts) = {
        let mut known = state.known();
        known.devices.clear();
        let hosts = state.refresh_last_scan(&known.devices);
        (known.file.clone(), hosts)
    };
    if let Some(file) = file {
        tauri::async_runtime::spawn_blocking(move || known::delete(&file))
            .await
            .map_err(internal)?
            .map_err(|e| io_error("known.io", e))?;
    }
    Ok(KnownUpdate { devices: 0, hosts })
}

/// Opens `http(s)://<ip>:<port>/` in the default browser. The URL is built from typed
/// values only, never from a string supplied by the webview.
#[tauri::command]
pub async fn open_in_browser(ip: IpAddr, secure: bool, port: u16) -> Result<(), CommandError> {
    if port == 0 {
        return Err(CommandError::new(
            "action.invalid_port",
            "port must not be 0",
        ));
    }
    tauri_plugin_opener::open_url(actions::web_url(ip, secure, port), None::<&str>)
        .map_err(|e| io_error("action.open_failed", e))
}

#[tauri::command]
pub async fn open_remote_desktop(ip: IpAddr) -> Result<(), CommandError> {
    Ok(platform::open_remote_desktop(ip)?)
}

#[tauri::command]
pub async fn open_file_share(ip: IpAddr) -> Result<(), CommandError> {
    Ok(platform::open_file_share(ip)?)
}

/// Sends a Wake-on-LAN magic packet for `mac`; `ip` (the last known address) selects the
/// subnet to broadcast on.
#[tauri::command]
pub async fn wake_on_lan(
    state: State<'_, AppState>,
    mac: String,
    ip: Option<IpAddr>,
) -> Result<(), CommandError> {
    let mac = mac
        .parse::<MacAddr>()
        .ok()
        .filter(|mac| actions::is_wakeable(*mac))
        .ok_or_else(|| CommandError::new("action.invalid_mac", "invalid MAC address"))?;
    let target = match ip {
        Some(IpAddr::V4(v4)) => Some(v4),
        _ => None,
    };
    let backend = Arc::clone(&state.backend);
    tauri::async_runtime::spawn_blocking(move || {
        let adapters = backend.list_adapters().unwrap_or_default();
        actions::send_magic_packet(mac, target, &adapters)
    })
    .await
    .map_err(internal)?
    .map(drop)
    .map_err(|e| io_error("action.wol_failed", e))
}

/// GitHub page of the newest release (opened by the portable build's update dialog).
const RELEASES_URL: &str = "https://github.com/MarCel06xX/ironsight/releases/latest";

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppInfo {
    version: String,
    /// Portable single-exe build: updates are downloaded manually.
    portable: bool,
}

#[tauri::command]
pub fn app_info(app: AppHandle) -> AppInfo {
    AppInfo {
        version: app.package_info().version.to_string(),
        portable: portable::ENABLED,
    }
}

#[tauri::command]
pub async fn open_release_page() -> Result<(), CommandError> {
    tauri_plugin_opener::open_url(RELEASES_URL, None::<&str>)
        .map_err(|e| io_error("action.open_failed", e))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExportRequest {
    format: ExportKind,
    delimiter: Option<Delimiter>,
    /// Rows of the filtered view in display order; `None` exports every scanned address.
    ips: Option<Vec<IpAddr>>,
    language: ReportLanguage,
    /// Local time offset for CSV and HTML timestamps (JavaScript's `-getTimezoneOffset()`).
    utc_offset_minutes: i32,
}

impl ExportRequest {
    fn options(&self) -> Result<ExportOptions, CommandError> {
        let max = export::time::MAX_OFFSET_MINUTES;
        if !(-max..=max).contains(&self.utc_offset_minutes) {
            return Err(CommandError::new(
                "export.invalid_request",
                "invalid UTC offset",
            ));
        }
        if self
            .ips
            .as_ref()
            .is_some_and(|ips| ips.len() as u64 > MAX_HOSTS)
        {
            return Err(CommandError::new("export.invalid_request", "too many rows"));
        }
        Ok(ExportOptions {
            kind: self.format,
            delimiter: self.delimiter.unwrap_or_default(),
            language: self.language,
            utc_offset_minutes: self.utc_offset_minutes,
            scope: if self.ips.is_some() {
                Scope::View
            } else {
                Scope::All
            },
            exported_at_ms: now_ms(),
        })
    }
}

/// Asks for a file name and writes the export. Returns the written path, or `None` if the
/// save dialog was cancelled.
#[tauri::command]
pub async fn export_results(
    app: AppHandle,
    window: WebviewWindow,
    state: State<'_, AppState>,
    request: ExportRequest,
) -> Result<Option<String>, CommandError> {
    let options = request.options()?;
    if state.is_scanning() {
        return Err(CommandError::new(
            "export.scan_running",
            "a scan is still running",
        ));
    }
    let no_results = || CommandError::new("export.no_results", "nothing to export");
    let (info, hosts) = {
        let known = state.known();
        let last = state.last_scan();
        let record = last.as_ref().ok_or_else(no_results)?;
        (
            record.info.clone(),
            record.select(request.ips.as_deref(), &known.devices),
        )
    };
    if hosts.is_empty() {
        return Err(no_results());
    }

    let labels = Labels::new(options.language);
    let extension = options.kind.extension();
    let (tx, rx) = oneshot::channel();
    app.dialog()
        .file()
        .set_parent(&window)
        .set_file_name(export::default_file_name(&options, info.started_at_ms))
        .add_filter(labels.get(options.kind.label_key()), &[extension])
        .save_file(move |path| {
            let _ = tx.send(path);
        });
    let Some(path) = rx.await.ok().flatten() else {
        return Ok(None);
    };
    let mut path = path.into_path().map_err(|e| io_error("export.io", e))?;
    if path.extension().is_none() {
        path.set_extension(extension);
    }

    let shown = path.display().to_string();
    tauri::async_runtime::spawn_blocking(move || {
        let mut out = BufWriter::new(File::create(&path)?);
        export::write_export(&mut out, &info, &hosts, &options)?;
        out.flush()
    })
    .await
    .map_err(internal)?
    .map_err(|e| io_error("export.io", e))?;
    Ok(Some(shown))
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use super::*;

    fn record(last_octets: &[u8]) -> ScanRecord {
        let hosts = last_octets
            .iter()
            .map(|&d| {
                let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, d));
                (ip, HostResult::new(ip))
            })
            .collect();
        let mut record = ScanRecord::new(
            1,
            ScanInfo {
                targets: "10.0.0.0/24".into(),
                started_at_ms: 0,
                finished_at_ms: Some(1),
                cancelled: false,
                total: 254,
                scanned: 254,
                online: 0,
                errors: 0,
                concurrency: 64,
                timeout_ms: 1000,
                port_scan: None,
            },
        );
        record.hosts = hosts;
        record
    }

    fn ip(d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, d))
    }

    #[test]
    fn export_selection() {
        let record = record(&[20, 3, 100, 9]);
        let all: Vec<IpAddr> = record
            .select(None, &KnownDevices::default())
            .iter()
            .map(|h| h.ip)
            .collect();
        assert_eq!(all, [ip(3), ip(9), ip(20), ip(100)]);

        // View order is kept; unknown and repeated addresses are dropped.
        let view = [ip(100), ip(3), ip(77), ip(100), ip(20)];
        let picked: Vec<IpAddr> = record
            .select(Some(&view), &KnownDevices::default())
            .iter()
            .map(|h| h.ip)
            .collect();
        assert_eq!(picked, [ip(100), ip(3), ip(20)]);
        assert!(
            record
                .select(Some(&[]), &KnownDevices::default())
                .is_empty()
        );
    }

    #[test]
    fn known_data_is_applied_and_removed_again() {
        let mut record = record(&[5, 6]);
        let mut known = KnownDevices::default();
        let mut laptop = HostResult::new(ip(5));
        laptop.online = true;
        laptop.names.dns = Some("laptop.lan".into());
        laptop.pick_hostname();
        laptop.timestamp_ms = 7;
        laptop.mark_live();
        known.remember(&laptop);

        let changed = record.refresh_known(&known);
        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0].hostname.as_deref(), Some("laptop.lan"));
        assert_eq!(changed[0].status, crate::scan::HostStatus::Offline);
        // Rows with known data are sent again (cheap: only at scan end, import, forget).
        assert_eq!(record.refresh_known(&known), changed);
        // Forgotten: the row goes back to its own data.
        known.clear();
        let reverted = record.refresh_known(&known);
        assert_eq!(reverted.len(), 1);
        assert_eq!(reverted[0].hostname, None);
        assert!(record.refresh_known(&known).is_empty());
    }

    #[test]
    fn hosts_are_recorded_for_the_current_scan_only() {
        let state = AppState::new(default_backend());
        *state.last_scan() = Some(record(&[]));
        state.record_hosts(2, vec![HostResult::new(ip(1))]);
        assert!(state.last_scan().as_ref().unwrap().hosts.is_empty());
        state.record_hosts(1, vec![HostResult::new(ip(1)), HostResult::new(ip(2))]);
        let mut updated = HostResult::new(ip(1));
        updated.online = true;
        state.record_hosts(1, vec![updated]);
        let last = state.last_scan();
        let hosts = &last.as_ref().unwrap().hosts;
        assert_eq!(hosts.len(), 2);
        assert!(hosts[&ip(1)].online);
    }

    #[test]
    fn export_request_validation() {
        let parse = |json: &str| serde_json::from_str::<ExportRequest>(json);
        let ok = parse(
            r#"{"format":"csv","delimiter":",","ips":null,"language":"de","utcOffsetMinutes":60}"#,
        )
        .unwrap();
        let options = ok.options().unwrap();
        assert_eq!(options.delimiter, Delimiter::Comma);
        assert_eq!(options.scope, Scope::All);
        assert_eq!(options.language, ReportLanguage::De);

        let view = parse(
            r#"{"format":"html","ips":["10.0.0.1"],"language":"en","utcOffsetMinutes":-300}"#,
        )
        .unwrap();
        assert_eq!(view.options().unwrap().scope, Scope::View);
        assert_eq!(view.options().unwrap().delimiter, Delimiter::Semicolon);

        let far = parse(r#"{"format":"json","language":"en","utcOffsetMinutes":900}"#).unwrap();
        assert_eq!(far.options().unwrap_err().code, "export.invalid_request");

        for bad in [
            r#"{"format":"xlsx","language":"en","utcOffsetMinutes":0}"#,
            r#"{"format":"csv","delimiter":"|","language":"en","utcOffsetMinutes":0}"#,
            r#"{"format":"csv","language":"fr","utcOffsetMinutes":0}"#,
            r#"{"format":"csv","ips":["not-an-ip"],"language":"en","utcOffsetMinutes":0}"#,
            r#"{"format":"csv","language":"en","utcOffsetMinutes":0,"path":"C:\x"}"#,
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }
    use crate::platform::default_backend;

    fn request(concurrency: Option<u32>, timeout_ms: Option<u32>) -> ScanRequest {
        ScanRequest {
            targets: String::new(),
            concurrency,
            timeout_ms,
            offline_names: None,
            banners: None,
            ports: None,
        }
    }

    fn options(json: &str) -> Result<PortPlan, CommandError> {
        serde_json::from_str::<PortScanOptions>(json)
            .map_err(|e| CommandError::new("json", e.to_string()))?
            .plan()
    }

    #[test]
    fn port_scan_options() {
        let plan = options(r#"{"selection":{"preset":"top100"}}"#).unwrap();
        assert_eq!(plan.set.len(), 100);
        assert_eq!(plan.config, PortScanConfig::default());

        let plan = options(
            r#"{"selection":{"custom":"443, 22,80"},"timeoutMs":500,"concurrency":64,"perHost":8,"maxProbes":5000}"#,
        )
        .unwrap();
        assert_eq!(plan.selection, PortSelection::Custom("22,80,443".into()));
        assert_eq!(plan.config.timeout, Duration::from_millis(500));
        assert_eq!((plan.config.concurrency, plan.config.per_host), (64, 8));
        assert_eq!(plan.config.max_probes, 5000);

        let code = |json: &str| options(json).unwrap_err().code;
        assert_eq!(
            code(r#"{"selection":{"custom":"22,"}}"#),
            "ports.empty_entry"
        );
        assert_eq!(
            code(r#"{"selection":{"custom":"0"}}"#),
            "ports.out_of_range"
        );
        assert_eq!(
            code(r#"{"selection":{"preset":"common"},"timeoutMs":50}"#),
            "ports.invalid_timeout"
        );
        assert_eq!(
            code(r#"{"selection":{"preset":"common"},"concurrency":5000}"#),
            "ports.invalid_concurrency"
        );
        assert_eq!(
            code(r#"{"selection":{"preset":"common"},"maxProbes":0}"#),
            "ports.invalid_max_probes"
        );
        // Unknown fields and presets are rejected by the parser.
        assert_eq!(code(r#"{"selection":{"preset":"common"},"x":1}"#), "json");
        assert_eq!(code(r#"{"selection":{"preset":"top5"}}"#), "json");
        assert_eq!(code(r#"{}"#), "json");
    }

    #[test]
    fn port_step_end_is_recorded_for_exports() {
        let state = AppState::new(default_backend());
        let mut scan = record(&[]);
        let plan = options(r#"{"selection":{"preset":"top100"},"timeoutMs":700}"#).unwrap();
        scan.info.port_scan = Some(plan.step_info(false));
        *state.last_scan() = Some(scan);
        let refused = PortsFinished {
            scan_id: 1,
            summary: None,
            error: Some(CommandError::new("ports.too_many_probes", "x")),
        };
        state.finish_port_step(2, &refused); // another scan: ignored
        assert_eq!(
            state.last_scan().as_ref().unwrap().info.finished_at_ms,
            Some(1)
        );
        state.finish_port_step(1, &refused);
        let last = state.last_scan();
        let info = &last.as_ref().unwrap().info;
        let step = info.port_scan.as_ref().unwrap();
        assert_eq!(step.timeout_ms, 700);
        assert!(!step.banners);
        assert_eq!(
            (step.checks, step.error),
            (None, Some("ports.too_many_probes"))
        );
        assert!(info.finished_at_ms.unwrap() > 1);
    }

    #[test]
    fn port_list_check() {
        let info = check_port_list(" 443,22, 80-82 ".into()).unwrap();
        assert_eq!((info.normalized.as_str(), info.count), ("22,80-82,443", 5));
        let error = check_port_list("22,".into()).unwrap_err();
        assert_eq!(error.code, "ports.empty_entry");
        let error = check_port_list("x".repeat(5000)).unwrap_err();
        assert_eq!(error.code, "ports.input_too_long");
    }

    #[test]
    fn scan_request_with_port_scan() {
        let request: ScanRequest = serde_json::from_str(
            r#"{"targets":"10.0.0.0/24","banners":false,"ports":{"selection":{"preset":"common"}}}"#,
        )
        .unwrap();
        assert_eq!(request.banners, Some(false));
        assert!(request.ports.is_some());
        let request: HostPortsRequest =
            serde_json::from_str(r#"{"ip":"10.0.0.5","ports":{"selection":{"custom":"22"}}}"#)
                .unwrap();
        assert_eq!(request.ip, ip(5));
        assert_eq!(request.banners, None);
        let bad: Result<HostPortsRequest, _> = serde_json::from_str(
            r#"{"ip":"10.0.0.5","ports":{"selection":{"custom":"22"}},"cmd":"x"}"#,
        );
        assert!(bad.is_err());
    }

    fn online(d: u8, probed: Vec<(u16, crate::ports::PortState)>) -> HostResult {
        let mut host = HostResult::new(ip(d));
        host.online = true;
        host.probed_ports = probed;
        host.mark_live();
        host
    }

    #[test]
    fn port_targets_are_the_hosts_that_answered() {
        use crate::ports::PortState::{Closed, Filtered, Open};
        use crate::ports::scanner::Probe;
        let mut record = record(&[3]);
        record.add(online(9, vec![(22, Open), (80, Closed), (443, Filtered)]));
        record.add(online(5, Vec::new()));
        let targets = record.port_targets();
        let ips: Vec<IpAddr> = targets.iter().map(|t| t.ip).collect();
        assert_eq!(ips, [ip(5), ip(9)]);
        assert_eq!(targets[1].known, [(22, Probe::OPEN), (80, Probe::Closed)]);
    }

    #[test]
    fn port_results_are_shown_and_exported_on_top_of_the_scan() {
        use crate::ports::PortState;
        use crate::ports::scanner::PortEntry;
        let mut record = record(&[]);
        record.add(online(5, Vec::new()));
        let known = KnownDevices::default();
        let selection = PortSelection::Custom("22".into());
        let set = Arc::new(PortSet::parse("22").unwrap());
        let report = |ip: IpAddr| HostPorts {
            ip,
            complete: true,
            probed: 1,
            total: 1,
            ports: vec![PortEntry {
                port: 22,
                state: PortState::Open,
                service: Some("ssh"),
                banner: Some("SSH-2.0-test".into()),
                http: None,
            }],
            open: 1,
            closed: 0,
            filtered: 0,
            errors: 0,
        };
        // Hosts that are not part of the scan are ignored.
        let shown = record.add_ports(&selection, &set, vec![report(ip(5)), report(ip(6))], &known);
        assert_eq!(shown.len(), 1);
        assert_eq!(shown[0].services[0].banner.as_deref(), Some("SSH-2.0-test"));
        assert!(shown[0].port_scan.as_ref().unwrap().complete);
        // The scan's own data stays untouched; exports see the port results.
        assert!(record.hosts[&ip(5)].services.is_empty());
        let exported = record.select(None, &known);
        assert_eq!(exported[0].services.len(), 1);
    }

    #[test]
    fn config_defaults_and_limits() {
        let config = scan_config(&request(None, None)).unwrap();
        assert_eq!(config.concurrency, 64);
        assert_eq!(config.timeout, Duration::from_millis(1000));

        assert!(scan_config(&request(Some(1), Some(100))).is_ok());
        assert!(scan_config(&request(Some(256), Some(10_000))).is_ok());
        for (concurrency, timeout_ms) in [(Some(0), None), (Some(257), None)] {
            let err = scan_config(&request(concurrency, timeout_ms)).unwrap_err();
            assert_eq!(err.code, "scan.invalid_concurrency");
        }
        for (concurrency, timeout_ms) in [(None, Some(99)), (None, Some(10_001))] {
            let err = scan_config(&request(concurrency, timeout_ms)).unwrap_err();
            assert_eq!(err.code, "scan.invalid_timeout");
        }
    }

    #[test]
    fn request_rejects_unknown_fields() {
        let ok: Result<ScanRequest, _> =
            serde_json::from_str(r#"{"targets":"10.0.0.1","timeoutMs":500}"#);
        assert_eq!(ok.unwrap().timeout_ms, Some(500));
        let bad: Result<ScanRequest, _> =
            serde_json::from_str(r#"{"targets":"10.0.0.1","shell":"x"}"#);
        assert!(bad.is_err());
    }

    #[test]
    fn only_one_scan_at_a_time() {
        let state = AppState::new(default_backend());
        let (first, cancel) = state.begin_scan().unwrap();
        assert_eq!(state.begin_scan().unwrap_err().code, "scan.already_running");

        state.cancel_scan();
        assert!(*cancel.borrow());

        state.end_scan(first + 1); // a stale id must not free the slot
        assert!(state.begin_scan().is_err());
        state.end_scan(first);
        let (second, cancel) = state.begin_scan().unwrap();
        assert!(second > first);
        assert!(!*cancel.borrow());
    }
}
