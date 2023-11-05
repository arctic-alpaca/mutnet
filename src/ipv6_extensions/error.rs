use crate::error::{NotEnoughHeadroomError, UnexpectedBufferEndError};
use crate::typed_protocol_headers::UnrecognizedInternetProtocolNumberError;
use crate::typed_protocol_headers::UnrecognizedIpv6ExtensionError;
#[cfg(all(feature = "error_trait", not(feature = "std")))]
use core::error;
use core::fmt::{Debug, Display, Formatter};
#[cfg(feature = "std")]
use std::error;

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
    UnrecognizedIpv6Extension(UnrecognizedIpv6ExtensionError),
    ExtensionLimitReached,
    InvalidHopByHopPosition,
}

impl From<UnexpectedBufferEndError> for ParseIpv6ExtensionsError {
    fn from(value: UnexpectedBufferEndError) -> Self {
        Self::UnexpectedBufferEnd(value)
    }
}

impl From<UnrecognizedIpv6ExtensionError> for ParseIpv6ExtensionsError {
    fn from(value: UnrecognizedIpv6ExtensionError) -> Self {
        Self::UnrecognizedIpv6Extension(value)
    }
}

impl Display for ParseIpv6ExtensionsError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnexpectedBufferEnd(err) => {
                write!(f, "{err}")
            }
            Self::UnrecognizedIpv6Extension(err) => {
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
pub enum Ipv6ExtTypedHeaderError {
    Ipv6ExtensionIndexOutOfBounds(Ipv6ExtensionIndexOutOfBoundsError),
    UnrecognizedInternetProtocolNumber(UnrecognizedInternetProtocolNumberError),
}

impl From<Ipv6ExtensionIndexOutOfBoundsError> for Ipv6ExtTypedHeaderError {
    fn from(value: Ipv6ExtensionIndexOutOfBoundsError) -> Self {
        Self::Ipv6ExtensionIndexOutOfBounds(value)
    }
}

impl From<UnrecognizedInternetProtocolNumberError> for Ipv6ExtTypedHeaderError {
    fn from(value: UnrecognizedInternetProtocolNumberError) -> Self {
        Self::UnrecognizedInternetProtocolNumber(value)
    }
}

impl Display for Ipv6ExtTypedHeaderError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Ipv6ExtensionIndexOutOfBounds(err) => {
                write!(f, "{err}")
            }
            Self::UnrecognizedInternetProtocolNumber(err) => {
                write!(f, "{err}")
            }
        }
    }
}

#[cfg(feature = "error_trait")]
impl error::Error for Ipv6ExtTypedHeaderError {}
