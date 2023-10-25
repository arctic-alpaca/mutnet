use crate::error::UnexpectedBufferEndError;

use core::fmt::{Debug, Display, Formatter};

#[cfg(all(feature = "error_trait", not(feature = "std")))]
use core::error;

#[cfg(feature = "std")]
use std::error;

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum ParseArpError {
    UnexpectedBufferEnd(UnexpectedBufferEndError),
    UnsupportedHardwareOrProtocolFields,
    InvalidOperationCode { operation_code: u16 },
}

impl From<UnexpectedBufferEndError> for ParseArpError {
    #[inline]
    fn from(value: UnexpectedBufferEndError) -> Self {
        Self::UnexpectedBufferEnd(value)
    }
}

impl Display for ParseArpError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedHardwareOrProtocolFields => {
                write!(
                    f,
                    "Hardware/protocol type or length do not fit IPv4 over ethernet"
                )
            }
            Self::UnexpectedBufferEnd(err) => {
                write!(f, "{err}")
            }
            Self::InvalidOperationCode { operation_code } => {
                write!(
                    f,
                    "Invalid operation code, only request(1) and reply(2) are supported, was: {operation_code}"
                )
            }
        }
    }
}

#[cfg(feature = "error_trait")]
impl error::Error for ParseArpError {}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct NoRecognizedOperationCodeError {
    pub operation_code: u16,
}

impl Display for NoRecognizedOperationCodeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "No valid or supported operation code, was: {}",
            self.operation_code
        )
    }
}

#[cfg(feature = "error_trait")]
impl error::Error for NoRecognizedOperationCodeError {}
