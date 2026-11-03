use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// Stable error codes. Every front end maps them the same way: a CLI exit code, an MCP
/// `isError` result with structured content, and a UI toast.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema, TS)]
pub enum ErrorCode {
    NotFound,
    UnsupportedFormat,
    UnsupportedOperation,
    PasswordRequired,
    WrongPassword,
    Corrupt,
    OutsideSandbox,
    Conflict,
    LimitExceeded,
    Cancelled,
    BackendUnavailable,
    Io,
    /// The archive contains something BeeZip refuses to extract: an unsafe path, a link leading
    /// out of the destination, or overlapping entries. The safe entries are still extracted.
    Unsafe,
    /// Arguments that fail to deserialise or validate.
    InvalidArgs,
    /// A caught panic or a bug.
    Internal,
}

impl ErrorCode {
    /// The `beezip` process exit code for this error. `2` matches clap's usage errors, `130` is
    /// the usual Ctrl-C status and `70` is `EX_SOFTWARE`.
    pub const fn exit_code(self) -> u8 {
        match self {
            Self::InvalidArgs => 2,
            Self::NotFound => 3,
            Self::UnsupportedFormat => 4,
            Self::UnsupportedOperation => 5,
            Self::PasswordRequired => 6,
            Self::WrongPassword => 7,
            Self::Corrupt => 8,
            Self::OutsideSandbox => 9,
            Self::Conflict => 10,
            Self::LimitExceeded => 11,
            Self::BackendUnavailable => 12,
            Self::Io => 13,
            Self::Unsafe => 14,
            Self::Internal => 70,
            Self::Cancelled => 130,
        }
    }
}

/// An error returned by a command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS, thiserror::Error)]
#[error("{message}")]
pub struct CmdError {
    pub code: ErrorCode,
    pub message: String,
    /// Structured extras: the extract report for `Unsafe`, per-entry errors for `Corrupt`
    /// from `archive.test`, `{ limit, value }` for `LimitExceeded`, `{ param }` for
    /// `PasswordRequired`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub details: Option<serde_json::Value>,
}

impl CmdError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            details: None,
        }
    }

    #[must_use]
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::NotFound, message)
    }

    pub fn invalid_args(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidArgs, message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Internal, message)
    }

    pub fn cancelled() -> Self {
        Self::new(ErrorCode::Cancelled, "cancelled")
    }

    pub const fn exit_code(&self) -> u8 {
        self.code.exit_code()
    }
}

/// Core error kinds are a subset of the codes (docs/M1.md §3.1).
impl From<beezip_core::ErrorKind> for ErrorCode {
    fn from(kind: beezip_core::ErrorKind) -> Self {
        use beezip_core::ErrorKind as K;
        match kind {
            K::NotFound => Self::NotFound,
            K::UnsupportedFormat => Self::UnsupportedFormat,
            K::UnsupportedOperation => Self::UnsupportedOperation,
            K::PasswordRequired => Self::PasswordRequired,
            K::WrongPassword => Self::WrongPassword,
            K::Corrupt => Self::Corrupt,
            K::Unsafe => Self::Unsafe,
            K::Conflict => Self::Conflict,
            K::LimitExceeded => Self::LimitExceeded,
            K::Cancelled => Self::Cancelled,
            K::Io => Self::Io,
            K::InvalidArgs => Self::InvalidArgs,
        }
    }
}

/// Core errors convert 1:1.
impl From<beezip_core::Error> for CmdError {
    fn from(e: beezip_core::Error) -> Self {
        let code = ErrorCode::from(e.kind);
        let details = (code == ErrorCode::PasswordRequired)
            .then(|| serde_json::json!({ "param": "password" }));
        Self {
            code,
            message: e.message,
            details,
        }
    }
}

/// The other way, for errors that come back to core through the `Ctx` adapter (a prompt that
/// failed, a cancelled job).
impl From<CmdError> for beezip_core::Error {
    fn from(e: CmdError) -> Self {
        use beezip_core::ErrorKind as K;
        let kind = match e.code {
            ErrorCode::NotFound => K::NotFound,
            ErrorCode::UnsupportedFormat => K::UnsupportedFormat,
            ErrorCode::UnsupportedOperation | ErrorCode::BackendUnavailable => {
                K::UnsupportedOperation
            }
            ErrorCode::PasswordRequired => K::PasswordRequired,
            ErrorCode::WrongPassword => K::WrongPassword,
            ErrorCode::Corrupt => K::Corrupt,
            ErrorCode::Unsafe | ErrorCode::OutsideSandbox => K::Unsafe,
            ErrorCode::Conflict => K::Conflict,
            ErrorCode::LimitExceeded => K::LimitExceeded,
            ErrorCode::Cancelled => K::Cancelled,
            ErrorCode::Io | ErrorCode::Internal => K::Io,
            ErrorCode::InvalidArgs => K::InvalidArgs,
        };
        beezip_core::Error::new(kind, e.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn details_are_left_out_when_empty() {
        let e = CmdError::invalid_args("bad");
        let v = serde_json::to_value(&e).unwrap();
        assert!(v.get("details").is_none());
        let back: CmdError = serde_json::from_value(v).unwrap();
        assert_eq!(back, e);
        let with = e.with_details(serde_json::json!({ "x": 1 }));
        assert_eq!(serde_json::to_value(&with).unwrap()["details"]["x"], 1);
    }

    #[test]
    fn core_kinds_map_one_to_one() {
        let e: CmdError = beezip_core::Error::new(beezip_core::ErrorKind::Unsafe, "x").into();
        assert_eq!(e.code, ErrorCode::Unsafe);
        assert_eq!(e.exit_code(), 14);
        let e: CmdError =
            beezip_core::Error::new(beezip_core::ErrorKind::PasswordRequired, "x").into();
        assert_eq!(e.details.unwrap()["param"], "password");
    }
}
