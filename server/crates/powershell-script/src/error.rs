use std::fmt;
use std::io;

use crate::output::Output;

#[derive(Debug)]
pub enum PsError {
    /// An error in the PowerShell script.
    Powershell(Output),
    /// Unable to create temporary file
    TempFileFailed,
    /// An I/O error related to the child process.
    Io(io::Error),
    // Failed to find PowerShell in this system
    PowershellNotFound,
    /// Failed to retrieve a handle to `stdin` for the child process
    ChildStdinNotFound,
}

impl std::error::Error for PsError {}

impl fmt::Display for PsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use PsError::*;
        match self {
            Powershell(out) => write!(f, "{}", out)?,
            TempFileFailed => write!(f, "INTERNAL ERROR: unable to create temporary file")?,
            Io(e) => write!(f, "{}", e)?,
            PowershellNotFound => write!(f, "Failed to find powershell on this system")?,
            ChildStdinNotFound => write!(
                f,
                "Failed to acquire a handle to stdin in the child process."
            )?,
        }
        Ok(())
    }
}

impl From<async_tempfile::Error> for PsError {
    fn from(value: async_tempfile::Error) -> Self {
        match value {
            async_tempfile::Error::InvalidDirectory => Self::TempFileFailed,
            async_tempfile::Error::InvalidFile => Self::TempFileFailed,
            async_tempfile::Error::Io(e) => Self::Io(e),
        }
    }
}

impl From<io::Error> for PsError {
    fn from(io: io::Error) -> PsError {
        PsError::Io(io)
    }
}
