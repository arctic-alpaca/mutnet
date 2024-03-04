//! IPv6 extensions specific errors.

#[cfg(all(feature = "error_trait", not(feature = "std")))]
use core::error;
use core::fmt::{Debug, Display, Formatter};
#[cfg(feature = "std")]
use std::error;

use crate::error::{NotEnoughHeadroomError, UnexpectedBufferEndError};
use crate::typed_protocol_headers::UnrecognizedInternetProtocolNumberError;

/// Error returned when parsing IPv6 extension headers.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum ParseIpv6ExtensionsError {
    /// The data buffer ended unexpectedly.
    UnexpectedBufferEnd(UnexpectedBufferEndError),
    /// The extension limit is reached.
    ExtensionLimitReached,
    /// A hop by hop extension header was found anywhere else but the first extension header.
    InvalidHopByHopPosition,
}

impl From<UnexpectedBufferEndError> for ParseIpv6ExtensionsError {
    fn from(value: UnexpectedBufferEndError) -> Self {
        Self::UnexpectedBufferEnd(value)
    }
}

impl Display for ParseIpv6ExtensionsError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnexpectedBufferEnd(err) => {
                write!(f, "{err}")
            }
            Self::ExtensionLimitReached => {
                write!(f, "More extensions than MAX_EXTENSION")
            }
            Self::InvalidHopByHopPosition => {
                write!(f, "A hop by hop extension was not the first extension")
            }
        }
    }
}

#[cfg(feature = "error_trait")]
impl error::Error for ParseIpv6ExtensionsError {}

/// Error returned by methods accessing the IPv6 extensions list with an index out of bounds.
///
/// This happens when requesting the third extension when only two extension where found when parsing.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct Ipv6ExtensionIndexOutOfBoundsError {
    /// Index requested.
    pub used_index: usize,
    /// Amount of IPv6 extensions parsed.
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

/// Error returned by methods accessing IPv6 extension header fields.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum Ipv6ExtFieldError {
    /// The requested IPv6 extension does not exist.
    Ipv6ExtensionIndexOutOfBounds(Ipv6ExtensionIndexOutOfBoundsError),
    /// The requested header field does not exist for this IPv6 extension type.
    HeaderFieldDoesNotExist,
}

impl Display for Ipv6ExtFieldError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Ipv6ExtensionIndexOutOfBounds(err) => {
                write!(f, "{err}")
            }
            Self::HeaderFieldDoesNotExist => {
                write!(
                    f,
                    "This header field does not exist for the requested IPv6 extension type"
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

/// Error returned by methods manipulating the length header field of IPv6 extensions.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum Ipv6ExtSetFieldError {
    /// The requested IPv6 extension does not exist.
    Ipv6ExtensionIndexOutOfBounds(Ipv6ExtensionIndexOutOfBoundsError),
    /// The requested header field does not exist for this IPv6 extension type.
    HeaderFieldDoesNotExist,
    /// Not enough headroom available.
    NotEnoughHeadroom(NotEnoughHeadroomError),
}

impl Display for Ipv6ExtSetFieldError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Ipv6ExtensionIndexOutOfBounds(err) => {
                write!(f, "{err}")
            }
            Self::HeaderFieldDoesNotExist => {
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

/// Error returned by IPv6 extension methods returning a typed internet protocol number.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum Ipv6ExtTypedHeaderError {
    /// The requested IPv6 extension does not exist.
    Ipv6ExtensionIndexOutOfBounds(Ipv6ExtensionIndexOutOfBoundsError),
    /// Internet protocol number is not recognized.
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
