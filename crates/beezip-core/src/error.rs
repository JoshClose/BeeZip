//! Core errors. Each [`ErrorKind`] is one of the `CmdError` codes core can produce, so
//! `beezip-commands` converts them 1:1 (docs/M1.md §3.1).

use std::{fmt, io};

/// What went wrong, as one of the stable codes the front ends show.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    NotFound,
    UnsupportedFormat,
    UnsupportedOperation,
    PasswordRequired,
    WrongPassword,
    Corrupt,
    /// The archive holds something BeeZip refuses to extract, such as overlapping entries.
    Unsafe,
    Conflict,
    LimitExceeded,
    Cancelled,
    Io,
    InvalidArgs,
}

/// A core error: a kind and a message for people.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    pub kind: ErrorKind,
    pub message: String,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

impl Error {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub fn corrupt(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Corrupt, message)
    }

    pub fn unsupported_format(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::UnsupportedFormat, message)
    }

    pub fn unsupported(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::UnsupportedOperation, message)
    }

    pub fn invalid_args(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::InvalidArgs, message)
    }

    pub fn limit(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::LimitExceeded, message)
    }

    pub fn cancelled() -> Self {
        Self::new(ErrorKind::Cancelled, "cancelled")
    }

    /// An I/O error with what was being done, e.g. `("reading", path)`.
    pub fn io(context: impl fmt::Display, err: &io::Error) -> Self {
        let mut e = Self::from_io(err);
        e.message = format!("{context}: {}", e.message);
        e
    }

    /// Converts an I/O error. An [`Error`] that was smuggled through `io::Error` (see
    /// [`Error::into_io`]) comes back unchanged; otherwise the kind is chosen from the I/O kind.
    pub fn from_io(err: &io::Error) -> Self {
        if let Some(inner) = err.get_ref().and_then(|e| e.downcast_ref::<Error>()) {
            return inner.clone();
        }
        let kind = match err.kind() {
            io::ErrorKind::NotFound => ErrorKind::NotFound,
            io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof => ErrorKind::Corrupt,
            io::ErrorKind::Unsupported => ErrorKind::UnsupportedOperation,
            io::ErrorKind::OutOfMemory => ErrorKind::LimitExceeded,
            io::ErrorKind::Interrupted => ErrorKind::Cancelled,
            _ => ErrorKind::Io,
        };
        Self::new(kind, err.to_string())
    }

    /// Wraps this error in an `io::Error`, for code that has to fail inside a `Read` or `Write`.
    /// [`Error::from_io`] recovers it.
    pub fn into_io(self) -> io::Error {
        let kind = match self.kind {
            ErrorKind::Corrupt => io::ErrorKind::InvalidData,
            ErrorKind::NotFound => io::ErrorKind::NotFound,
            _ => io::ErrorKind::Other,
        };
        io::Error::new(kind, self)
    }

    /// Prefixes the message, e.g. with the entry being read.
    #[must_use]
    pub fn context(mut self, context: impl fmt::Display) -> Self {
        self.message = format!("{context}: {}", self.message);
        self
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Self::from_io(&err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_survive_a_trip_through_io() {
        let e = Error::limit("too big");
        let back = Error::from(e.clone().into_io());
        assert_eq!(back, e);
    }

    #[test]
    fn io_kinds_map_to_codes() {
        let eof = io::Error::new(io::ErrorKind::UnexpectedEof, "short");
        assert_eq!(Error::from(eof).kind, ErrorKind::Corrupt);
        let nf = io::Error::new(io::ErrorKind::NotFound, "gone");
        assert_eq!(Error::io("opening x", &nf).kind, ErrorKind::NotFound);
    }
}
