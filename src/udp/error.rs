use crate::error::{UnexpectedBufferEndError, WrongChecksumError};

use core::fmt::{Debug, Display, Formatter};

#[cfg(all(feature = "error_trait", not(feature = "std")))]
use core::error;

#[cfg(feature = "std")]
use std::error;

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum ParseUdpError {
    UnexpectedBufferEnd(UnexpectedBufferEndError),
    WrongChecksum(WrongChecksumError),
    LengthHeaderTooSmall { length_header: usize },
    LengthHeaderTooLarge { expected: usize, actual: usize },
}

impl From<UnexpectedBufferEndError> for ParseUdpError {
    #[inline]
    fn from(value: UnexpectedBufferEndError) -> Self {
        Self::UnexpectedBufferEnd(value)
    }
}

impl From<WrongChecksumError> for ParseUdpError {
    #[inline]
    fn from(value: WrongChecksumError) -> Self {
        Self::WrongChecksum(value)
    }
}

impl Display for ParseUdpError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnexpectedBufferEnd(err) => {
                write!(f, "{err}")
            }
            Self::WrongChecksum(err) => {
                write!(f, "{err}")
            }
            Self::LengthHeaderTooSmall { length_header } => {
                write!(
                    f,
                    "Length header is {length_header} but was expected to be at least 8"
                )
            }
            Self::LengthHeaderTooLarge { expected, actual } => {
                write!(
                    f,
                    "Length header expected to be at most {expected} but was {actual}"
                )
            }
        }
    }
}

#[cfg(feature = "error_trait")]
impl error::Error for ParseUdpError {}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum SetLengthError {
    UnexpectedBufferEnd(UnexpectedBufferEndError),
    LengthTooSmall { length: usize },
}

impl From<UnexpectedBufferEndError> for SetLengthError {
    #[inline]
    fn from(value: UnexpectedBufferEndError) -> Self {
        Self::UnexpectedBufferEnd(value)
    }
}

impl Display for SetLengthError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnexpectedBufferEnd(err) => {
                write!(f, "{err}")
            }
            Self::LengthTooSmall { length } => {
                write!(
                    f,
                    "Provided length header is {length} but has to be at least 8"
                )
            }
        }
    }
}

#[cfg(feature = "error_trait")]
impl error::Error for SetLengthError {}
