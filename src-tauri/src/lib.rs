//! Ironsight backend. The export module is added in a later phase.

mod commands;
mod enrich;
mod error;
mod mac;
mod platform;
mod scan;

pub fn run() {
    tauri::Builder::default()
        .manage(commands::AppState::new(platform::default_backend()))
        .invoke_handler(tauri::generate_handler![
            commands::list_adapters,
            commands::start_scan,
            commands::stop_scan,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
