//! Error type returned by Tauri commands.

use serde::Serialize;

use crate::platform::NetError;
use crate::scan::range::RangeError;

/// `code` is a stable identifier for localization, `message` an English fallback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CommandError {
    pub code: &'static str,
    pub message: String,
}

impl CommandError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl From<RangeError> for CommandError {
    fn from(e: RangeError) -> Self {
        Self::new(e.code(), e.to_string())
    }
}

impl From<NetError> for CommandError {
    fn from(e: NetError) -> Self {
        let code = match e {
            NetError::Os { .. } => "net.os_error",
            NetError::Unsupported => "net.unsupported",
        };
        Self::new(code, e.to_string())
    }
}
