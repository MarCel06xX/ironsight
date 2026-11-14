//! Portable build (cargo feature `portable`): a single exe that keeps its settings file and
//! the WebView2 profile next to itself instead of in AppData.

use std::fs;
use std::path::{Path, PathBuf};

/// Whether this binary was built with the `portable` feature.
pub const ENABLED: bool = cfg!(feature = "portable");
/// Settings file next to the portable exe.
pub const SETTINGS_FILE: &str = "ironsight-settings.json";
/// WebView2 user data folder next to the portable exe.
pub const WEBVIEW_DIR: &str = "ironsight-webview";

/// Where a portable build keeps its data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortablePaths {
    pub settings: PathBuf,
    pub webview: PathBuf,
}

/// Managed state: `Some` when the running build stores its data next to the exe.
#[derive(Debug, Clone, Default)]
pub struct PortableState(pub Option<PortablePaths>);

/// Paths for the running executable; `None` means "use the normal AppData folders".
pub fn paths() -> Option<PortablePaths> {
    let exe = std::env::current_exe().ok()?;
    paths_for(exe.parent()?, ENABLED)
}

/// Portable paths in `exe_dir`, if this is a portable build and `exe_dir` is writable.
/// Otherwise `None`: fall back to the app config dir.
pub fn paths_for(exe_dir: &Path, portable_build: bool) -> Option<PortablePaths> {
    if !portable_build || !is_writable_dir(exe_dir) {
        return None;
    }
    Some(PortablePaths {
        settings: exe_dir.join(SETTINGS_FILE),
        webview: exe_dir.join(WEBVIEW_DIR),
    })
}

fn is_writable_dir(dir: &Path) -> bool {
    if !dir.is_dir() {
        return false;
    }
    let probe = dir.join(format!(".ironsight-write-test-{}", std::process::id()));
    let writable = fs::write(&probe, b"").is_ok();
    let _ = fs::remove_file(&probe);
    writable
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fresh, empty directory per test inside the system temp dir.
    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("ironsight-portable-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn installed_build_uses_app_data() {
        let dir = temp_dir("installed");
        assert_eq!(paths_for(&dir, false), None);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn portable_build_keeps_data_next_to_the_exe() {
        let dir = temp_dir("portable");
        assert_eq!(
            paths_for(&dir, true),
            Some(PortablePaths {
                settings: dir.join("ironsight-settings.json"),
                webview: dir.join("ironsight-webview"),
            })
        );
        // The write probe is cleaned up and nothing else is created.
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 0);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn unwritable_location_falls_back_to_app_data() {
        let dir = temp_dir("blocked");
        // A file instead of a folder cannot take the settings file.
        let not_a_dir = dir.join("ironsight.exe");
        fs::write(&not_a_dir, b"").unwrap();
        assert_eq!(paths_for(&not_a_dir, true), None);
        assert_eq!(paths_for(&dir.join("missing"), true), None);
        fs::remove_dir_all(dir).unwrap();
    }
}
