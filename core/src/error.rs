//! The SDK error type. Every fallible public API returns [`Result`].

use std::fmt;

/// The error type returned by all fallible SDK operations.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The device replied with a non-OK status code.
    Device { code: u8, message: String },
    /// A blocking read hit the serial timeout before data arrived. A capture
    /// loop can treat this as "no data yet" and continue.
    Timeout,
    /// The serial link closed unexpectedly.
    Closed,
    /// Serial port I/O error.
    Io(std::io::Error),
    /// Underlying serial-port library error.
    Serial(serialport::Error),
    /// Failed to (de)serialize JSON exchanged with the device.
    Json(serde_json::Error),
    /// Any other error, with a human-readable message.
    Other(String),
}

impl Error {
    /// Build an [`Error::Other`] from any displayable value.
    pub fn msg(message: impl fmt::Display) -> Self {
        Error::Other(message.to_string())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Device { code, message } => write!(f, "device error {code}: {message}"),
            Error::Timeout => f.write_str("timed out waiting for the device"),
            Error::Closed => f.write_str("connection closed"),
            Error::Io(e) => write!(f, "{e}"),
            Error::Serial(e) => write!(f, "{e}"),
            Error::Json(e) => write!(f, "{e}"),
            Error::Other(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            Error::Serial(e) => Some(e),
            Error::Json(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<serialport::Error> for Error {
    fn from(e: serialport::Error) -> Self {
        Error::Serial(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Json(e)
    }
}

impl From<std::num::ParseIntError> for Error {
    fn from(e: std::num::ParseIntError) -> Self {
        Error::Other(e.to_string())
    }
}

impl From<std::string::FromUtf8Error> for Error {
    fn from(e: std::string::FromUtf8Error) -> Self {
        Error::Other(e.to_string())
    }
}

/// The SDK result type: `Result<T, `[`Error`]`>`.
pub type Result<T> = std::result::Result<T, Error>;

/// Attach context to a fallible value, mirroring the familiar `.context()` /
/// `.with_context()` ergonomics.
pub trait Context<T> {
    /// Wrap the error with a fixed context message.
    fn context(self, context: impl fmt::Display) -> Result<T>;
    /// Wrap the error with a lazily-computed context message.
    fn with_context<C: fmt::Display>(self, f: impl FnOnce() -> C) -> Result<T>;
}

impl<T, E: fmt::Display> Context<T> for std::result::Result<T, E> {
    fn context(self, context: impl fmt::Display) -> Result<T> {
        self.map_err(|e| Error::Other(format!("{context}: {e}")))
    }
    fn with_context<C: fmt::Display>(self, f: impl FnOnce() -> C) -> Result<T> {
        self.map_err(|e| Error::Other(format!("{}: {e}", f())))
    }
}

impl<T> Context<T> for Option<T> {
    fn context(self, context: impl fmt::Display) -> Result<T> {
        self.ok_or_else(|| Error::Other(context.to_string()))
    }
    fn with_context<C: fmt::Display>(self, f: impl FnOnce() -> C) -> Result<T> {
        self.ok_or_else(|| Error::Other(f().to_string()))
    }
}

/// Return early with an [`Error::Other`] formatted like `format!`.
macro_rules! bail {
    ($($arg:tt)*) => {
        return ::core::result::Result::Err($crate::Error::msg(format!($($arg)*)))
    };
}

/// Return early with an [`Error::Other`] when `$cond` is false.
#[allow(unused_macros)]
macro_rules! ensure {
    ($cond:expr, $($arg:tt)*) => {
        if !($cond) {
            return ::core::result::Result::Err($crate::Error::msg(format!($($arg)*)));
        }
    };
}
