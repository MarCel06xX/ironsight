fn main() {
    // Listing the app commands makes them permission-gated: the webview may only call
    // what `capabilities/default.json` allows explicitly.
    let manifest =
        tauri_build::AppManifest::new().commands(&["list_adapters", "start_scan", "stop_scan"]);
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(manifest))
        .expect("failed to run tauri-build");
}
