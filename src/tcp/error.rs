//! TCP specific errors.

#[cfg(all(feature = "error_trait", not(feature = "std")))]
use core::error;
use core::fmt::{Debug, Display, Formatter};
#[cfg(feature = "std")]
use std::error;

use crate::error::{InvalidChecksumError, NotEnoughHeadroomError, UnexpectedBufferEndError};

/// Error returned when parsing a TCP header.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum ParseTcpError {
    /// The data buffer ended unexpectedly.
    UnexpectedBufferEnd(UnexpectedBufferEndError),
    /// Invalid checksum.
    InvalidChecksum(InvalidChecksumError),
    /// Data offset header smaller than minimum (5).
    DataOffsetHeaderValueTooSmall {
        /// Found data offset header value.
        data_offset_header: usize,
    },
}

impl From<UnexpectedBufferEndError> for ParseTcpError {
    #[inline]
    fn from(value: UnexpectedBufferEndError) -> Self {
        Self::UnexpectedBufferEnd(value)
    }
}

impl From<InvalidChecksumError> for ParseTcpError {
    #[inline]
    fn from(value: InvalidChecksumError) -> Self {
        Self::InvalidChecksum(value)
    }
}

impl Display for ParseTcpError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnexpectedBufferEnd(err) => {
                write!(f, "{err}")
            }
            Self::InvalidChecksum(err) => {
                write!(f, "{err}")
            }
            Self::DataOffsetHeaderValueTooSmall { data_offset_header } => {
                write!(
                    f,
                    "Data offset header value too small, minimum 5 expected, was: {data_offset_header}"
                )
            }
        }
    }
}

#[cfg(feature = "error_trait")]
impl error::Error for ParseTcpError {}

/// Error returned by methods manipulating the data offset.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum SetDataOffsetError {
    /// Data offset is not within required bounds (5..=15).
    InvalidDataOffset {
        /// Invalid data offset.
        data_offset: usize,
    },
    /// Not enough headroom available.
    NotEnoughHeadroom(NotEnoughHeadroomError),
}

impl Display for SetDataOffsetError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidDataOffset { data_offset } => {
                write!(
                    f,
                    "Data offset header value invalid, expected to be between 5 and 15 (inclusive): {data_offset}"
                )
            }
            Self::NotEnoughHeadroom(err) => {
                write!(f, "{err}")
            }
        }
    }
}

impl From<NotEnoughHeadroomError> for SetDataOffsetError {
    #[inline]
    fn from(value: NotEnoughHeadroomError) -> Self {
        Self::NotEnoughHeadroom(value)
    }
}

#[cfg(feature = "error_trait")]
impl error::Error for SetDataOffsetError {}
