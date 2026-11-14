//! Error type returned by Tauri commands.

use serde::Serialize;

use crate::platform::{LaunchError, NetError};
use crate::scan::ConfigError;
use crate::scan::range::RangeError;

/// `code` is a stable identifier the frontend maps to a localized message (with `detail`
/// filled in, e.g. the offending input); `message` is an English fallback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CommandError {
    pub code: &'static str,
    pub message: String,
    pub detail: Option<String>,
}

impl CommandError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            detail: None,
        }
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

impl From<RangeError> for CommandError {
    fn from(e: RangeError) -> Self {
        Self {
            code: e.code(),
            message: e.to_string(),
            detail: e.detail(),
        }
    }
}

impl From<ConfigError> for CommandError {
    fn from(e: ConfigError) -> Self {
        Self::new(e.code(), e.to_string())
    }
}

impl From<NetError> for CommandError {
    fn from(e: NetError) -> Self {
        let code = match e {
            NetError::Os { .. } => "net.os_error",
            NetError::Unsupported => "net.unsupported",
        };
        Self::new(code, e.to_string()).with_detail(e.to_string())
    }
}

impl From<LaunchError> for CommandError {
    fn from(e: LaunchError) -> Self {
        match &e {
            LaunchError::Ipv6 => Self::new("action.ipv6_unsupported", e.to_string()),
            LaunchError::Spawn { program, .. } => {
                Self::new("action.launch_failed", e.to_string()).with_detail(*program)
            }
            LaunchError::NoSystemDir => Self::new("action.launch_failed", e.to_string()),
            LaunchError::Unsupported => Self::new("net.unsupported", e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_errors_carry_the_offending_input() {
        let e = CommandError::from(RangeError::InvalidAddress("abc".into()));
        assert_eq!(
            (e.code, e.detail.as_deref()),
            ("range.invalid_address", Some("abc"))
        );
        let e = CommandError::from(RangeError::TooManyHosts { count: 70_000 });
        assert_eq!(e.detail.as_deref(), Some("70000"));
        assert_eq!(CommandError::from(RangeError::Empty).detail, None);
    }

    #[test]
    fn serializes_for_the_frontend() {
        let error = CommandError::new("x.y", "msg").with_detail("d");
        let json = serde_json::to_value(error).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"code": "x.y", "message": "msg", "detail": "d"})
        );
    }
}
