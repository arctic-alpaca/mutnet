//! UDP specific errors.

use core::error;
use core::fmt::{Debug, Display, Formatter};

use crate::error::{
    InvalidChecksumError, LengthExceedsAvailableSpaceError, UnexpectedBufferEndError,
};

/// Error returned when parsing a UDP header.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum ParseUdpError {
    /// The data buffer ended unexpectedly.
    UnexpectedBufferEnd(UnexpectedBufferEndError),
    /// Invalid checksum.
    InvalidChecksum(InvalidChecksumError),
    /// Length header value is smaller than the required eight bytes.
    LengthHeaderTooSmall {
        /// Length header value.
        length_header: usize,
    },
}

impl From<UnexpectedBufferEndError> for ParseUdpError {
    #[inline]
    fn from(value: UnexpectedBufferEndError) -> Self {
        Self::UnexpectedBufferEnd(value)
    }
}

impl From<InvalidChecksumError> for ParseUdpError {
    #[inline]
    fn from(value: InvalidChecksumError) -> Self {
        Self::InvalidChecksum(value)
    }
}

impl Display for ParseUdpError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnexpectedBufferEnd(err) => {
                write!(f, "{err}")
            }
            Self::InvalidChecksum(err) => {
                write!(f, "{err}")
            }
            Self::LengthHeaderTooSmall { length_header } => {
                write!(
                    f,
                    "Length header is {length_header} but was expected to be at least 8"
                )
            }
        }
    }
}

impl error::Error for ParseUdpError {}

/// Error returned by methods manipulating the length header.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum SetLengthError {
    /// The supplied length exceeds the available space.
    LengthExceedsAvailableSpace(LengthExceedsAvailableSpaceError),
    /// Supplied length is smaller than the required 8 bytes.
    LengthTooSmall {
        /// Supplied length.
        length: usize,
    },
}

impl From<LengthExceedsAvailableSpaceError> for SetLengthError {
    #[inline]
    fn from(value: LengthExceedsAvailableSpaceError) -> Self {
        Self::LengthExceedsAvailableSpace(value)
    }
}

impl Display for SetLengthError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::LengthExceedsAvailableSpace(err) => {
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

impl error::Error for SetLengthError {}
