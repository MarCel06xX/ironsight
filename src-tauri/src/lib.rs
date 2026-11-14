//! Ironsight backend.

mod actions;
mod commands;
mod enrich;
mod error;
mod export;
mod mac;
mod platform;
mod portable;
mod scan;
mod settings;

pub fn run() {
    let portable_dir = portable::data_dir();
    let webview_dir = portable_dir
        .as_ref()
        .map(|dir| dir.join(portable::WEBVIEW_DIR));
    tauri::Builder::default()
        // Used from Rust only (save dialog for exports); the webview gets no dialog permission.
        .plugin(tauri_plugin_dialog::init())
        .manage(commands::AppState::new(platform::default_backend()))
        .manage(portable::PortableDir(portable_dir))
        .setup(move |app| {
            // The window is declared in tauri.conf.json with `create: false` and built here,
            // so portable mode can move the WebView2 profile next to the executable.
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
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
