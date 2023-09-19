use crate::error::UnexpectedBufferEndError;
use crate::ether_type::NoRecognizedEtherTypeError;
#[cfg(all(feature = "error_trait", not(feature = "std")))]
use core::error;

use core::fmt::{Debug, Display, Formatter};
#[cfg(feature = "std")]
use std::error;

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum EthernetError {
    UnexpectedBufferEnd(UnexpectedBufferEndError),
    NoRecognizedEtherType(NoRecognizedEtherTypeError),
    NotVlanTagged(NotVlanTaggedError),
}

impl Display for EthernetError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnexpectedBufferEnd(err) => {
                write!(f, "{err}")
            }
            Self::NoRecognizedEtherType(err) => {
                write!(f, "{err}")
            }
            Self::NotVlanTagged(err) => {
                write!(f, "{err}")
            }
        }
    }
}

impl From<UnexpectedBufferEndError> for EthernetError {
    #[inline]
    fn from(value: UnexpectedBufferEndError) -> Self {
        Self::UnexpectedBufferEnd(value)
    }
}

impl From<NoRecognizedEtherTypeError> for EthernetError {
    #[inline]
    fn from(value: NoRecognizedEtherTypeError) -> Self {
        Self::NoRecognizedEtherType(value)
    }
}

impl From<NotVlanTaggedError> for EthernetError {
    #[inline]
    fn from(value: NotVlanTaggedError) -> Self {
        Self::NotVlanTagged(value)
    }
}

#[cfg(feature = "error_trait")]
impl error::Error for EthernetError {}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct NotVlanTaggedError;

impl Display for NotVlanTaggedError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "Ethernet frame is not VLAN tagged.")
    }
}

#[cfg(feature = "error_trait")]
impl error::Error for NotVlanTaggedError {}
