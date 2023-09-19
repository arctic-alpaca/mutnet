#[cfg(all(feature = "error_trait", not(feature = "std")))]
use core::error;

use core::fmt::{Debug, Display, Formatter};

#[cfg(feature = "std")]
use std::error;

use crate::error::UnexpectedBufferEndError;

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum ParseIeee802_1QError {
    UnexpectedBufferEnd(UnexpectedBufferEndError),
    STagWithoutCTag(STagWithoutCTagError),
}

impl From<UnexpectedBufferEndError> for ParseIeee802_1QError {
    #[inline]
    fn from(value: UnexpectedBufferEndError) -> Self {
        Self::UnexpectedBufferEnd(value)
    }
}

impl From<STagWithoutCTagError> for ParseIeee802_1QError {
    #[inline]
    fn from(value: STagWithoutCTagError) -> Self {
        Self::STagWithoutCTag(value)
    }
}

impl Display for ParseIeee802_1QError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::STagWithoutCTag(err) => {
                write!(f, "{err}")
            }
            Self::UnexpectedBufferEnd(err) => {
                write!(f, "{err}")
            }
        }
    }
}

#[cfg(feature = "error_trait")]
impl error::Error for ParseIeee802_1QError {}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct STagWithoutCTagError;

impl Display for STagWithoutCTagError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "Ethernet frame has S tag without C tag")
    }
}

#[cfg(feature = "error_trait")]
impl error::Error for STagWithoutCTagError {}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct NotDoubleTaggedError;

impl Display for NotDoubleTaggedError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "Not double tagged")
    }
}

#[cfg(feature = "error_trait")]
impl error::Error for NotDoubleTaggedError {}
