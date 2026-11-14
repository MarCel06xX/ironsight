//! Ironsight backend. The export module is added in a later phase.

mod actions;
mod commands;
mod enrich;
mod error;
mod mac;
mod platform;
mod scan;
mod settings;

pub fn run() {
    tauri::Builder::default()
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
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
