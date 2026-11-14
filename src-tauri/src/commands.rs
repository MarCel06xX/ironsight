//! Tauri commands. All input from the webview is validated here before it reaches the engine.

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::watch;

use crate::actions;
use crate::enrich::NetEnricher;
use crate::error::CommandError;
use crate::mac::MacAddr;
use crate::platform::{self, Adapter, NetBackend};
use crate::scan::engine::run_scan;
use crate::scan::range::TargetSet;
use crate::scan::{DEFAULT_CONCURRENCY, DEFAULT_TIMEOUT_MS, ScanConfig};
use crate::settings::{self, Settings};

pub const EVENT_SCAN_BATCH: &str = "scan:batch";
pub const EVENT_SCAN_FINISHED: &str = "scan:finished";

struct ActiveScan {
    id: u64,
    cancel: watch::Sender<bool>,
}

pub struct AppState {
    backend: Arc<dyn NetBackend>,
    active: Mutex<Option<ActiveScan>>,
    next_scan_id: AtomicU64,
}

impl AppState {
    pub fn new(backend: Arc<dyn NetBackend>) -> Self {
        Self {
            backend,
            active: Mutex::new(None),
            next_scan_id: AtomicU64::new(1),
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
            return Err(CommandError::new(
                "scan.already_running",
                "a scan is already running",
            ));
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
    let targets = TargetSet::parse(&request.targets)?;
    let config = scan_config(&request)?;
    let total = targets.len() as u32;
    let (scan_id, cancel) = state.begin_scan()?;
    let backend = Arc::clone(&state.backend);

    tauri::async_runtime::spawn(async move {
        let emitter = app.clone();
        let on_batch = move |batch| {
            let _ = emitter.emit(EVENT_SCAN_BATCH, batch);
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
        // Free the slot first, so the frontend can start a new scan right after the event.
        app.state::<AppState>().end_scan(scan_id);
        let _ = app.emit(EVENT_SCAN_FINISHED, summary);
    });

    Ok(ScanStarted { scan_id, total })
}

#[tauri::command]
pub fn stop_scan(state: State<'_, AppState>) {
    state.cancel_scan();
}

fn settings_path(app: &AppHandle) -> Result<PathBuf, CommandError> {
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
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
