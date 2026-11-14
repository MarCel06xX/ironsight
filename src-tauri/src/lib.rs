//! Ironsight backend. Modules (scan, platform, enrich, export, commands) are added per phase.

pub fn run() {
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
