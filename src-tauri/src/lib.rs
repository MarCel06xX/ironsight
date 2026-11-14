//! Ironsight backend.

mod actions;
mod commands;
mod enrich;
mod error;
mod export;
mod mac;
mod platform;
mod scan;
mod settings;

pub fn run() {
    tauri::Builder::default()
        // Used from Rust only (save dialog for exports); the webview gets no dialog permission.
        .plugin(tauri_plugin_dialog::init())
        .manage(commands::AppState::new(platform::default_backend()))
        .invoke_handler(tauri::generate_handler![
            commands::list_adapters,
            commands::start_scan,
            commands::stop_scan,
            commands::load_settings,
            commands::save_settings,
            commands::open_in_browser,
            commands::open_remote_desktop,
            commands::open_file_share,
            commands::wake_on_lan,
            commands::export_results,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
