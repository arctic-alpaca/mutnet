use crate::error::UnexpectedBufferEndError;
#[cfg(all(feature = "error_trait", not(feature = "std")))]
use core::error;
use core::fmt::{Debug, Display, Formatter};
#[cfg(feature = "std")]
use std::error;

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum ParseIpv6Error {
    UnexpectedBufferEnd(UnexpectedBufferEndError),
    VersionHeaderValueNotSix,
}

impl From<UnexpectedBufferEndError> for ParseIpv6Error {
    fn from(value: UnexpectedBufferEndError) -> Self {
        Self::UnexpectedBufferEnd(value)
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

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum SetPayloadLengthError {
    UnexpectedBufferEnd(UnexpectedBufferEndError),
    CannotCutUpperLayerHeader,
}

impl From<UnexpectedBufferEndError> for SetPayloadLengthError {
    fn from(value: UnexpectedBufferEndError) -> Self {
        Self::UnexpectedBufferEnd(value)
    }
}

impl Display for SetPayloadLengthError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnexpectedBufferEnd(err) => {
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
