//! TCP connect port scan: port lists and presets, service names, the probe and the scan
//! engine. Plain sockets only: no admin rights, no raw sockets, no Npcap.

use serde::{Deserialize, Serialize};

use presets::PortPreset;
use spec::{PortSet, PortSpecError};

pub mod banner;
pub mod names;
pub mod presets;
pub mod probe;
pub mod scanner;
pub mod spec;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PortState {
    /// The connection was accepted.
    Open,
    /// The host answered with a reset (connection refused).
    Closed,
    /// No answer within the timeout, or an ICMP "unreachable".
    Filtered,
}

/// Which ports a port scan covers, as chosen by the user. JSON: `{"preset": "top100"}` or
/// `{"custom": "22,80,1000-2000"}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PortSelection {
    Preset(PortPreset),
    /// A port list in the syntax of [`PortSet::parse`].
    Custom(String),
}

impl PortSelection {
    /// The validated port set, and the selection with a custom list in normalized form.
    pub fn resolve(&self) -> Result<(Self, PortSet), PortSpecError> {
        match self {
            Self::Preset(preset) => Ok((self.clone(), preset.ports())),
            Self::Custom(spec) => {
                let set = PortSet::parse(spec)?;
                Ok((Self::Custom(set.to_string()), set))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_json_and_resolution() {
        let preset: PortSelection = serde_json::from_str(r#"{"preset":"top100"}"#).unwrap();
        assert_eq!(preset, PortSelection::Preset(PortPreset::Top100));
        assert_eq!(preset.resolve().unwrap().1.len(), 100);

        let custom: PortSelection =
            serde_json::from_str(r#"{"custom":" 443, 22 ,80,80"}"#).unwrap();
        let (normalized, set) = custom.resolve().unwrap();
        assert_eq!(normalized, PortSelection::Custom("22,80,443".into()));
        assert_eq!(set.len(), 3);
        assert_eq!(
            serde_json::to_value(&normalized).unwrap(),
            serde_json::json!({"custom": "22,80,443"})
        );

        let bad = PortSelection::Custom("22,,80".into());
        assert_eq!(bad.resolve().unwrap_err(), PortSpecError::EmptyEntry);
        for json in [r#"{"preset":"top5"}"#, r#"{"other":"x"}"#, r#""common""#] {
            assert!(
                serde_json::from_str::<PortSelection>(json).is_err(),
                "{json}"
            );
        }
    }
}
