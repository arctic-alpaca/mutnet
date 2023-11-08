//! IPv6 specific errors.

use crate::error::{LengthExceedsAvailableSpaceError, UnexpectedBufferEndError};
#[cfg(all(feature = "error_trait", not(feature = "std")))]
use core::error;
use core::fmt::{Debug, Display, Formatter};
#[cfg(feature = "std")]
use std::error;

/// Error returned when parsing an IPv6 header.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum ParseIpv6Error {
    /// The data buffer ended unexpectedly.
    UnexpectedBufferEnd(UnexpectedBufferEndError),
    /// Version header value is not six.
    VersionHeaderValueNotSix,
}

impl From<UnexpectedBufferEndError> for ParseIpv6Error {
    fn from(value: UnexpectedBufferEndError) -> Self {
        Self::UnexpectedBufferEnd(value)
    }
}
impl From<LengthExceedsAvailableSpaceError> for ParseIpv6Error {
    #[inline]
    fn from(value: LengthExceedsAvailableSpaceError) -> Self {
        Self::UnexpectedBufferEnd(UnexpectedBufferEndError {
            expected_length: value.required_space,
            actual_length: value.available_space,
        })
    }
}

impl Display for ParseIpv6Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnexpectedBufferEnd(err) => {
                write!(f, "{err}")
            }
            Self::VersionHeaderValueNotSix => {
                write!(f, "Version is not 6")
            }
        }
    }
}

#[cfg(feature = "error_trait")]
impl error::Error for ParseIpv6Error {}

/// Error returned by methods manipulating the payload length header.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum SetPayloadLengthError {
    /// The supplied length exceeds the available space.
    LengthExceedsAvailableSpace(LengthExceedsAvailableSpaceError),
    /// The operation would cut parts of an already parsed upper layer.
    CannotCutUpperLayerHeader,
}

impl From<LengthExceedsAvailableSpaceError> for SetPayloadLengthError {
    fn from(value: LengthExceedsAvailableSpaceError) -> Self {
        Self::LengthExceedsAvailableSpace(value)
    }
}

impl Display for SetPayloadLengthError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::LengthExceedsAvailableSpace(err) => {
                write!(f, "{err}")
            }
            Self::CannotCutUpperLayerHeader => {
                write!(
                    f,
                    "Provided length would cut off already parsed upper layer"
                )
            }
        }
    }
}

#[cfg(feature = "error_trait")]
impl error::Error for SetPayloadLengthError {}
