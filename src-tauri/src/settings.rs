//! User settings - the only data Ironsight persists: a small JSON file in the app config
//! directory. Scan results are never written anywhere automatically.

use std::fs;
use std::io::{self, Read};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::export::Delimiter;
use crate::scan::{ConfigError, DEFAULT_CONCURRENCY, DEFAULT_TIMEOUT_MS, ScanConfig};

pub const FILE_NAME: &str = "settings.json";
const MAX_FILE_SIZE: u64 = 64 * 1024;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Theme {
    #[default]
    Dark,
    Light,
    Blue,
    Terminal,
    Purple,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    /// Follow the system language (English if it is not supported).
    #[default]
    System,
    En,
    De,
}

/// Missing fields (older files) take their default value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Settings {
    pub theme: Theme,
    pub language: Language,
    pub concurrency: u32,
    pub timeout_ms: u32,
    /// Last delimiter used for CSV export.
    pub csv_delimiter: Delimiter,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            theme: Theme::default(),
            language: Language::default(),
            concurrency: DEFAULT_CONCURRENCY,
            timeout_ms: DEFAULT_TIMEOUT_MS,
            csv_delimiter: Delimiter::Semicolon,
        }
    }
}

impl Settings {
    pub fn validate(&self) -> Result<(), ConfigError> {
        ScanConfig::new(self.concurrency, self.timeout_ms).map(drop)
    }

    /// Reads the settings file. A missing, oversized or malformed file yields the defaults;
    /// out-of-range scan limits (e.g. a hand-edited file) are reset individually.
    pub fn load(path: &Path) -> Self {
        let Some(mut settings) = read_limited(path)
            .ok()
            .and_then(|text| serde_json::from_str::<Self>(&text).ok())
        else {
            return Self::default();
        };
        let defaults = Self::default();
        if ScanConfig::new(settings.concurrency, defaults.timeout_ms).is_err() {
            settings.concurrency = defaults.concurrency;
        }
        if ScanConfig::new(defaults.concurrency, settings.timeout_ms).is_err() {
            settings.timeout_ms = defaults.timeout_ms;
        }
        settings
    }

    /// Writes the file via a temporary file, so a crash never leaves half a file behind.
    pub fn save(&self, path: &Path) -> io::Result<()> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let json = serde_json::to_vec_pretty(self).map_err(io::Error::other)?;
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, json)?;
        fs::rename(&tmp, path)
    }
}

fn read_limited(path: &Path) -> io::Result<String> {
    let mut text = String::new();
    fs::File::open(path)?
        .take(MAX_FILE_SIZE + 1)
        .read_to_string(&mut text)?;
    if text.len() as u64 > MAX_FILE_SIZE {
        return Err(io::Error::other("settings file is too large"));
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    /// Fresh directory per test inside the system temp dir.
    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("ironsight-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn save_and_load_round_trip() {
        let dir = temp_dir("roundtrip");
        let path = dir.join("nested").join(FILE_NAME);
        let settings = Settings {
            theme: Theme::Terminal,
            language: Language::De,
            concurrency: 128,
            timeout_ms: 2500,
            csv_delimiter: Delimiter::Comma,
        };
        settings.save(&path).unwrap();
        assert_eq!(Settings::load(&path), settings);
        assert!(!path.with_extension("json.tmp").exists());

        // Saving again replaces the file.
        let changed = Settings {
            theme: Theme::Light,
            ..settings
        };
        changed.save(&path).unwrap();
        assert_eq!(Settings::load(&path), changed);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn json_shape_matches_the_frontend() {
        let json = serde_json::to_value(Settings::default()).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "theme": "dark",
                "language": "system",
                "concurrency": 64,
                "timeoutMs": 1000,
                "csvDelimiter": ";"
            })
        );
    }

    #[test]
    fn missing_or_broken_files_give_defaults() {
        let dir = temp_dir("broken");
        fs::create_dir_all(&dir).unwrap();
        assert_eq!(
            Settings::load(&dir.join("missing.json")),
            Settings::default()
        );

        let path = dir.join(FILE_NAME);
        for content in [
            "",
            "{",
            "[]",
            "null",
            r#"{"theme":"pink"}"#,
            "\u{feff}garbage",
        ] {
            fs::write(&path, content).unwrap();
            assert_eq!(Settings::load(&path), Settings::default(), "{content:?}");
        }

        fs::write(&path, " ".repeat(MAX_FILE_SIZE as usize + 10)).unwrap();
        assert_eq!(Settings::load(&path), Settings::default());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn partial_and_out_of_range_values() {
        let dir = temp_dir("partial");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join(FILE_NAME);

        // Older file without some fields, plus an unknown field from a newer version.
        fs::write(&path, r#"{"theme":"purple","future":1}"#).unwrap();
        let loaded = Settings::load(&path);
        assert_eq!(loaded.theme, Theme::Purple);
        assert_eq!(loaded.concurrency, DEFAULT_CONCURRENCY);
        assert_eq!(loaded.csv_delimiter, Delimiter::Semicolon);

        fs::write(
            &path,
            r#"{"language":"en","concurrency":0,"timeoutMs":99999}"#,
        )
        .unwrap();
        let loaded = Settings::load(&path);
        assert_eq!(loaded.language, Language::En);
        assert_eq!(loaded.concurrency, DEFAULT_CONCURRENCY);
        assert_eq!(loaded.timeout_ms, DEFAULT_TIMEOUT_MS);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn validation() {
        assert!(Settings::default().validate().is_ok());
        let bad = Settings {
            concurrency: 300,
            ..Settings::default()
        };
        assert_eq!(bad.validate(), Err(ConfigError::Concurrency));
        let bad = Settings {
            timeout_ms: 50,
            ..Settings::default()
        };
        assert_eq!(bad.validate(), Err(ConfigError::Timeout));
    }
}
