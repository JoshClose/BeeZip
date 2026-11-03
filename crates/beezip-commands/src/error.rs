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
}

impl CmdError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
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
