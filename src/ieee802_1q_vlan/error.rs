//! IEEE 802.1Q specific errors.

#[cfg(all(feature = "error_trait", not(feature = "std")))]
use core::error;
use core::fmt::{Debug, Display, Formatter};
#[cfg(feature = "std")]
use std::error;

use crate::error::UnexpectedBufferEndError;

/// Error returned when parsing a IEEE802.1Q header.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum ParseIeee802_1QError {
    /// The data buffer ended unexpectedly.
    UnexpectedBufferEnd(UnexpectedBufferEndError),
    /// Found service tag without client tag (header is indicated to be double tagged but is not).
    STagWithoutCTag,
}

impl From<UnexpectedBufferEndError> for ParseIeee802_1QError {
    #[inline]
    fn from(value: UnexpectedBufferEndError) -> Self {
        Self::UnexpectedBufferEnd(value)
    }
}

impl Display for ParseIeee802_1QError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::STagWithoutCTag => {
                write!(
                    f,
                    "Ethernet frame has service tag without client tag in IEEE802.1Q header"
                )
            }
            Self::UnexpectedBufferEnd(err) => {
                write!(f, "{err}")
            }
        }
    }
}

#[cfg(feature = "error_trait")]
impl error::Error for ParseIeee802_1QError {}

/// Header returned by methods expecting a double tagged packet.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct NotDoubleTaggedError;

impl Display for NotDoubleTaggedError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "Not double tagged")
    }
}

#[cfg(feature = "error_trait")]
impl error::Error for NotDoubleTaggedError {}
