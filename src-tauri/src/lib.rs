//! Ironsight backend.

mod actions;
mod commands;
mod enrich;
mod error;
mod export;
mod known;
mod mac;
mod platform;
mod portable;
mod scan;
mod settings;

pub fn run() {
    let portable_paths = portable::paths();
    let webview_dir = portable_paths.as_ref().map(|paths| paths.webview.clone());
    tauri::Builder::default()
        // Used from Rust only (save dialog for exports); the webview gets no dialog permission.
        .plugin(tauri_plugin_dialog::init())
        // Update check/install from the webview (`updater:default`) and restart afterwards.
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .manage(commands::AppState::new(platform::default_backend()))
        .manage(portable::PortableState(portable_paths))
        .setup(move |app| {
            // The window is declared in tauri.conf.json with `create: false` and built here,
            // so the portable build can keep the WebView2 profile next to the executable.
            let config = app
                .config()
                .app
                .windows
                .iter()
                .find(|window| window.label == "main")
                .cloned()
                .ok_or("main window missing in tauri.conf.json")?;
            let mut window = tauri::WebviewWindowBuilder::from_config(app.handle(), &config)?;
            if let Some(dir) = &webview_dir {
                window = window.data_directory(dir.clone());
            }
            window.build()?;
            commands::init_known_devices(app.handle());
            Ok(())
        })
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
            commands::app_info,
            commands::open_release_page,
            commands::import_scan,
            commands::forget_known_devices,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
