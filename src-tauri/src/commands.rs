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
    self, Delimiter, ExportKind, ExportOptions, Labels, ReportLanguage, ScanInfo, Scope,
};
use crate::mac::MacAddr;
use crate::platform::{self, Adapter, NetBackend};
use crate::portable::PortableDir;
use crate::scan::engine::{now_ms, run_scan};
use crate::scan::range::{MAX_HOSTS, TargetSet};
use crate::scan::{DEFAULT_CONCURRENCY, DEFAULT_TIMEOUT_MS, HostResult, ScanBatch, ScanConfig};
use crate::settings::{self, Settings};

pub const EVENT_SCAN_BATCH: &str = "scan:batch";
pub const EVENT_SCAN_FINISHED: &str = "scan:finished";

struct ActiveScan {
    id: u64,
    cancel: watch::Sender<bool>,
}

/// Results of the most recent scan, kept in memory (never on disk) for manual export.
struct ScanRecord {
    scan_id: u64,
    info: ScanInfo,
    hosts: HashMap<IpAddr, HostResult>,
}

impl ScanRecord {
    /// All hosts sorted by address, or the given addresses in their order (unknown and
    /// repeated addresses are skipped).
    fn select(&self, ips: Option<&[IpAddr]>) -> Vec<HostResult> {
        match ips {
            None => {
                let mut hosts: Vec<HostResult> = self.hosts.values().cloned().collect();
                hosts.sort_by_key(|host| host.ip);
                hosts
            }
            Some(ips) => {
                let mut seen = HashSet::new();
                ips.iter()
                    .filter(|ip| seen.insert(**ip))
                    .filter_map(|ip| self.hosts.get(ip).cloned())
                    .collect()
            }
        }
    }
}

pub struct AppState {
    backend: Arc<dyn NetBackend>,
    active: Mutex<Option<ActiveScan>>,
    next_scan_id: AtomicU64,
    last_scan: Mutex<Option<ScanRecord>>,
}

impl AppState {
    pub fn new(backend: Arc<dyn NetBackend>) -> Self {
        Self {
            backend,
            active: Mutex::new(None),
            next_scan_id: AtomicU64::new(1),
            last_scan: Mutex::new(None),
        }
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
                record.hosts.insert(host.ip, host);
            }
        }
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
    let config = scan_config(&request)?;
    let total = targets.len() as u32;
    let (scan_id, cancel) = state.begin_scan()?;
    let backend = Arc::clone(&state.backend);
    *state.last_scan() = Some(ScanRecord {
        scan_id,
        info: ScanInfo {
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
        },
        hosts: HashMap::new(),
    });

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
        let probes = Arc::new(NetEnricher::new(&adapters));
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
        // Free the slot first, so the frontend can start a new scan right after the event.
        state.end_scan(scan_id);
        let _ = app.emit(EVENT_SCAN_FINISHED, summary);
    });

    Ok(ScanStarted { scan_id, total })
}

#[tauri::command]
pub fn stop_scan(state: State<'_, AppState>) {
    state.cancel_scan();
}

/// `data/settings.json` next to the exe in portable mode, otherwise in the app config dir.
fn settings_path(app: &AppHandle) -> Result<PathBuf, CommandError> {
    if let Some(dir) = &app.state::<PortableDir>().0 {
        return Ok(dir.join(settings::FILE_NAME));
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
pub async fn save_settings(app: AppHandle, settings: Settings) -> Result<(), CommandError> {
    settings.validate()?;
    let path = settings_path(&app)?;
    tauri::async_runtime::spawn_blocking(move || settings.save(&path))
        .await
        .map_err(internal)?
        .map_err(|e| io_error("settings.io", e))
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
        let last = state.last_scan();
        let record = last.as_ref().ok_or_else(no_results)?;
        (record.info.clone(), record.select(request.ips.as_deref()))
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
        ScanRecord {
            scan_id: 1,
            info: ScanInfo {
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
            },
            hosts,
        }
    }

    fn ip(d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, d))
    }

    #[test]
    fn export_selection() {
        let record = record(&[20, 3, 100, 9]);
        let all: Vec<IpAddr> = record.select(None).iter().map(|h| h.ip).collect();
        assert_eq!(all, [ip(3), ip(9), ip(20), ip(100)]);

        // View order is kept; unknown and repeated addresses are dropped.
        let view = [ip(100), ip(3), ip(77), ip(100), ip(20)];
        let picked: Vec<IpAddr> = record.select(Some(&view)).iter().map(|h| h.ip).collect();
        assert_eq!(picked, [ip(100), ip(3), ip(20)]);
        assert!(record.select(Some(&[])).is_empty());
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
        }
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
