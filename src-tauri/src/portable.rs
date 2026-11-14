//! Portable mode: a file named `portable` next to the executable keeps all data (settings and
//! the WebView2 profile) in a `data/` folder beside it instead of the user's AppData.

use std::fs;
use std::path::{Path, PathBuf};

/// Marker file name (no extension).
pub const MARKER: &str = "portable";
/// Data folder created next to the executable.
pub const DATA_DIR: &str = "data";
/// WebView2 user data folder inside the data folder.
pub const WEBVIEW_DIR: &str = "webview";

/// The portable data folder of the running app, if portable mode is active (managed state).
#[derive(Debug, Clone, Default)]
pub struct PortableDir(pub Option<PathBuf>);

/// Data folder for the running executable; `None` means "use the normal AppData folders".
pub fn data_dir() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    data_dir_for(exe.parent()?)
}

/// `<exe_dir>/data` if `<exe_dir>/portable` exists and the data folder can be created and
/// written to; otherwise `None` (fall back to the app config dir).
pub fn data_dir_for(exe_dir: &Path) -> Option<PathBuf> {
    if !exe_dir.join(MARKER).is_file() {
        return None;
    }
    let dir = exe_dir.join(DATA_DIR);
    is_writable_dir(&dir).then_some(dir)
}

fn is_writable_dir(dir: &Path) -> bool {
    if fs::create_dir_all(dir).is_err() {
        return false;
    }
    let probe = dir.join(format!(".write-test-{}", std::process::id()));
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
    fn no_marker_means_normal_mode() {
        let dir = temp_dir("none");
        assert_eq!(data_dir_for(&dir), None);
        assert!(
            !dir.join(DATA_DIR).exists(),
            "nothing is created without the marker"
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn marker_file_enables_portable_mode() {
        let dir = temp_dir("marker");
        fs::write(dir.join(MARKER), b"").unwrap();
        assert_eq!(data_dir_for(&dir), Some(dir.join(DATA_DIR)));
        assert!(dir.join(DATA_DIR).is_dir());
        // The write probe is cleaned up again.
        assert_eq!(fs::read_dir(dir.join(DATA_DIR)).unwrap().count(), 0);
        // An existing data folder is reused.
        assert_eq!(data_dir_for(&dir), Some(dir.join(DATA_DIR)));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn marker_must_be_a_file() {
        let dir = temp_dir("marker-dir");
        fs::create_dir(dir.join(MARKER)).unwrap();
        assert_eq!(data_dir_for(&dir), None);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn unusable_data_folder_falls_back() {
        let dir = temp_dir("blocked");
        fs::write(dir.join(MARKER), b"").unwrap();
        // A file where the folder should be: it can neither be created nor written to.
        fs::write(dir.join(DATA_DIR), b"not a folder").unwrap();
        assert_eq!(data_dir_for(&dir), None);
        fs::remove_dir_all(dir).unwrap();
    }
}
