use crate::error::{UnexpectedBufferEndError, WrongChecksumError};
#[cfg(all(feature = "error_trait", not(feature = "std")))]
use core::error;
use core::fmt::{Debug, Display, Formatter};
#[cfg(feature = "std")]
use std::error;

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum ParseUdpError {
    UnexpectedBufferEnd(UnexpectedBufferEndError),
    WrongChecksum(WrongChecksumError),
    LengthHeaderTooSmall {
        length_header: usize,
    },
    LengthHeaderTooLarge {
        data_length: usize,
        length_header: usize,
    },
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
            Self::LengthHeaderTooLarge {
                data_length,
                length_header,
            } => {
                write!(
                    f,
                    "Length header expected to be at most {data_length} but was {length_header}"
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
