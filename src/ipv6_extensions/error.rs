use core::fmt::{Debug, Display, Formatter};

#[cfg(all(feature = "error_trait", not(feature = "std")))]
use core::error;

#[cfg(feature = "std")]
use std::error;

use crate::error::{NotEnoughHeadroomError, UnexpectedBufferEndError};
use crate::internet_protocol::NoRecognizedInternetProtocolNumberError;
use crate::ipv6_extensions::NoRecognizedIpv6ExtensionError;

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct Ipv6ExtensionIndexOutOfBoundsError {
    pub used_index: usize,
    pub extension_amount: usize,
}

impl Display for Ipv6ExtensionIndexOutOfBoundsError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Requested IPv6 extension {} but only found {} extensions",
            self.used_index, self.extension_amount
        )
    }
}

#[cfg(feature = "error_trait")]
impl error::Error for Ipv6ExtensionIndexOutOfBoundsError {}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum Ipv6ExtFieldError {
    Ipv6ExtensionIndexOutOfBounds(Ipv6ExtensionIndexOutOfBoundsError),
    FieldDoesNotExist,
}

impl Display for Ipv6ExtFieldError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Ipv6ExtensionIndexOutOfBounds(err) => {
                write!(f, "{err}")
            }
            Self::FieldDoesNotExist => {
                write!(
                    f,
                    "This data field does not exist for the requested extension type"
                )
            }
        }
    }
}

impl From<Ipv6ExtensionIndexOutOfBoundsError> for Ipv6ExtFieldError {
    fn from(value: Ipv6ExtensionIndexOutOfBoundsError) -> Self {
        Self::Ipv6ExtensionIndexOutOfBounds(value)
    }
}

#[cfg(feature = "error_trait")]
impl error::Error for Ipv6ExtFieldError {}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum Ipv6ExtSetFieldError {
    Ipv6ExtensionIndexOutOfBounds(Ipv6ExtensionIndexOutOfBoundsError),
    FieldDoesNotExist,
    NotEnoughHeadroom(NotEnoughHeadroomError),
}

impl Display for Ipv6ExtSetFieldError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Ipv6ExtensionIndexOutOfBounds(err) => {
                write!(f, "{err}")
            }
            Self::FieldDoesNotExist => {
                write!(
                    f,
                    "This data field does not exist for the requested extension type"
                )
            }
            Self::NotEnoughHeadroom(err) => {
                write!(f, "{err}")
            }
        }
    }
}

impl From<Ipv6ExtensionIndexOutOfBoundsError> for Ipv6ExtSetFieldError {
    fn from(value: Ipv6ExtensionIndexOutOfBoundsError) -> Self {
        Self::Ipv6ExtensionIndexOutOfBounds(value)
    }
}

impl From<NotEnoughHeadroomError> for Ipv6ExtSetFieldError {
    fn from(value: NotEnoughHeadroomError) -> Self {
        Self::NotEnoughHeadroom(value)
    }
}

#[cfg(feature = "error_trait")]
impl error::Error for Ipv6ExtSetFieldError {}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum ParseIpv6ExtensionsError {
    UnexpectedBufferEnd(UnexpectedBufferEndError),
    NoRecognizedIpv6Extension(NoRecognizedIpv6ExtensionError),
    ExtensionLimitReached,
    InvalidHopByHopPosition,
}

impl From<UnexpectedBufferEndError> for ParseIpv6ExtensionsError {
    fn from(value: UnexpectedBufferEndError) -> Self {
        Self::UnexpectedBufferEnd(value)
    }
}

impl From<NoRecognizedIpv6ExtensionError> for ParseIpv6ExtensionsError {
    fn from(value: NoRecognizedIpv6ExtensionError) -> Self {
        Self::NoRecognizedIpv6Extension(value)
    }
}

impl Display for ParseIpv6ExtensionsError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnexpectedBufferEnd(err) => {
                write!(f, "{err}")
            }
            Self::NoRecognizedIpv6Extension(err) => {
                write!(f, "{err}")
            }
            Self::ExtensionLimitReached => {
                write!(f, "More extensions than MAX_EXTENSION")
            }
            Self::InvalidHopByHopPosition => {
                write!(f, "Hop by hop extension was not the first extension")
            }
        }
    }
}

#[cfg(feature = "error_trait")]
impl error::Error for ParseIpv6ExtensionsError {}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum Ipv6ExtTypedHeader {
    Ipv6ExtensionIndexOutOfBounds(Ipv6ExtensionIndexOutOfBoundsError),
    NoRecognizedInternetProtocolNumber(NoRecognizedInternetProtocolNumberError),
}

impl From<Ipv6ExtensionIndexOutOfBoundsError> for Ipv6ExtTypedHeader {
    fn from(value: Ipv6ExtensionIndexOutOfBoundsError) -> Self {
        Self::Ipv6ExtensionIndexOutOfBounds(value)
    }
}

impl From<NoRecognizedInternetProtocolNumberError> for Ipv6ExtTypedHeader {
    fn from(value: NoRecognizedInternetProtocolNumberError) -> Self {
        Self::NoRecognizedInternetProtocolNumber(value)
    }
}

impl Display for Ipv6ExtTypedHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Ipv6ExtensionIndexOutOfBounds(err) => {
                write!(f, "{err}")
            }
            Self::NoRecognizedInternetProtocolNumber(err) => {
                write!(f, "{err}")
            }
        }
    }
}

#[cfg(feature = "error_trait")]
impl error::Error for Ipv6ExtTypedHeader {}
