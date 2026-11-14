//! Texts for exports, read from the frontend's locale files so there is only one catalog.

use std::collections::HashMap;
use std::sync::LazyLock;

use serde::Deserialize;

static EN: LazyLock<HashMap<String, String>> =
    LazyLock::new(|| parse(include_str!("../../../src/locales/en.json")));
static DE: LazyLock<HashMap<String, String>> =
    LazyLock::new(|| parse(include_str!("../../../src/locales/de.json")));

fn parse(json: &str) -> HashMap<String, String> {
    serde_json::from_str(json).unwrap_or_default()
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReportLanguage {
    #[default]
    En,
    De,
}

impl ReportLanguage {
    pub fn tag(self) -> &'static str {
        match self {
            Self::En => "en",
            Self::De => "de",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Labels {
    language: ReportLanguage,
}

impl Labels {
    pub fn new(language: ReportLanguage) -> Self {
        Self { language }
    }

    pub fn language(&self) -> ReportLanguage {
        self.language
    }

    /// Text for `key`, falling back to English and then to the key itself.
    pub fn get<'a>(&self, key: &'a str) -> &'a str {
        let catalog = match self.language {
            ReportLanguage::En => &*EN,
            ReportLanguage::De => &*DE,
        };
        catalog
            .get(key)
            .or_else(|| EN.get(key))
            .map_or(key, String::as_str)
    }

    /// Like [`Labels::get`], with `{name}` placeholders replaced from `params`.
    pub fn fill(&self, key: &str, params: &[(&str, &str)]) -> String {
        let template = self.get(key);
        let mut out = String::with_capacity(template.len());
        let mut rest = template;
        while let Some(open) = rest.find('{') {
            out.push_str(&rest[..open]);
            let after = &rest[open + 1..];
            let replacement = after.find('}').and_then(|close| {
                let name = &after[..close];
                let value = params.iter().find(|(n, _)| *n == name)?.1;
                Some((value, close))
            });
            match replacement {
                Some((value, close)) => {
                    out.push_str(value);
                    rest = &after[close + 1..];
                }
                None => {
                    out.push('{');
                    rest = after;
                }
            }
        }
        out.push_str(rest);
        out
    }

    /// Integer with thousands separators: `65,536` / `65.536`.
    pub fn count(&self, value: u64) -> String {
        let separator = match self.language {
            ReportLanguage::En => ',',
            ReportLanguage::De => '.',
        };
        let digits = value.to_string();
        let mut out = String::with_capacity(digits.len() + digits.len() / 3);
        for (i, digit) in digits.chars().enumerate() {
            if i > 0 && (digits.len() - i).is_multiple_of(3) {
                out.push(separator);
            }
            out.push(digit);
        }
        out
    }

    /// Duration in seconds with one decimal: `12.3 s` / `12,3 s`.
    pub fn seconds(&self, ms: u64) -> String {
        let tenths = (ms + 50) / 100;
        let decimal = match self.language {
            ReportLanguage::En => '.',
            ReportLanguage::De => ',',
        };
        let value = format!("{}{decimal}{}", self.count(tenths / 10), tenths % 10);
        self.fill("export.durationSeconds", &[("seconds", &value)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalogs_load_and_fall_back() {
        assert!(EN.len() > 50 && DE.len() == EN.len());
        let de = Labels::new(ReportLanguage::De);
        assert_eq!(de.get("col.vendor"), "Hersteller");
        assert_eq!(Labels::new(ReportLanguage::En).get("col.vendor"), "Vendor");
        assert_eq!(de.get("no.such.key"), "no.such.key");
    }

    #[test]
    fn placeholders() {
        let en = Labels::new(ReportLanguage::En);
        assert_eq!(
            en.fill(
                "scan.progress",
                &[("scanned", "3"), ("total", "9"), ("online", "1")]
            ),
            "3/9 scanned, 1 online"
        );
        // Unknown or unterminated placeholders stay as they are; values are not re-scanned.
        assert_eq!(en.fill("x {a} {b} {c", &[("a", "{b}")]), "x {b} {b} {c");
    }

    #[test]
    fn numbers_per_language() {
        let en = Labels::new(ReportLanguage::En);
        let de = Labels::new(ReportLanguage::De);
        assert_eq!(en.count(0), "0");
        assert_eq!(en.count(999), "999");
        assert_eq!(en.count(65_536), "65,536");
        assert_eq!(de.count(1_234_567), "1.234.567");
        assert_eq!(en.seconds(12_345), "12.3 s");
        assert_eq!(de.seconds(12_360), "12,4 s");
        assert_eq!(de.seconds(3_600_000), "3.600,0 s");
    }
}
