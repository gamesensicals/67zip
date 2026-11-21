//! Error type shared by the whole engine.

use std::fmt;
use std::io;

/// Everything that can go wrong while reading or writing archives.
#[derive(Debug)]
pub enum Error {
    /// Operating-system level I/O error.
    Io(io::Error),
    /// The file is not an archive format 67zip understands.
    UnsupportedFormat,
    /// The archive uses a feature 67zip does not implement (yet).
    Unsupported(String),
    /// The archive structure is damaged or deliberately malformed.
    Corrupt(String),
    /// The archive (or an entry in it) is encrypted and no password was given.
    PasswordRequired,
    /// The password given does not decrypt the data.
    WrongPassword,
    /// Data decoded fine but does not match its stored checksum.
    Checksum(String),
    /// The user cancelled the operation.
    Cancelled,
    /// A safety limit (size, count, memory, ratio) was hit.
    LimitExceeded(String),
    /// An entry path tries to escape the destination folder.
    UnsafePath(String),
    /// Invalid arguments given by the caller.
    InvalidInput(String),
}

/// Result alias used throughout the engine.
pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn corrupt(msg: impl Into<String>) -> Self {
        Error::Corrupt(msg.into())
    }
    pub fn unsupported(msg: impl Into<String>) -> Self {
        Error::Unsupported(msg.into())
    }
    pub fn invalid(msg: impl Into<String>) -> Self {
        Error::InvalidInput(msg.into())
    }
    pub fn limit(msg: impl Into<String>) -> Self {
        Error::LimitExceeded(msg.into())
    }

    /// True when retrying with another password could help.
    pub fn is_password_problem(&self) -> bool {
        matches!(self, Error::PasswordRequired | Error::WrongPassword)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "{e}"),
            Error::UnsupportedFormat => write!(f, "not a supported archive"),
            Error::Unsupported(s) => write!(f, "unsupported: {s}"),
            Error::Corrupt(s) => write!(f, "archive is damaged: {s}"),
            Error::PasswordRequired => write!(f, "a password is required"),
            Error::WrongPassword => write!(f, "wrong password"),
            Error::Checksum(s) => write!(f, "checksum error in {s}"),
            Error::Cancelled => write!(f, "cancelled"),
            Error::LimitExceeded(s) => write!(f, "safety limit reached: {s}"),
            Error::UnsafePath(s) => write!(f, "unsafe path blocked: {s}"),
            Error::InvalidInput(s) => write!(f, "{s}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        // Errors of our own type travel through `std::io::Read` chains wrapped
        // in an `io::Error`; unwrap them again so callers see the real cause.
        if e.get_ref().is_some_and(|inner| inner.is::<Error>()) {
            if let Some(inner) = e.into_inner() {
                if let Ok(ours) = inner.downcast::<Error>() {
                    return *ours;
                }
            }
            return Error::Io(io::Error::other("unknown error"));
        }
        if e.kind() == io::ErrorKind::UnexpectedEof {
            return Error::Corrupt("unexpected end of data".into());
        }
        Error::Io(e)
    }
}

impl From<Error> for io::Error {
    fn from(e: Error) -> Self {
        match e {
            Error::Io(e) => e,
            other => io::Error::other(other),
        }
    }
}
