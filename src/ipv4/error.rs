//! IPv4 specific errors.

#[cfg(all(feature = "error_trait", not(feature = "std")))]
use core::error;
use core::fmt::{Debug, Display, Formatter};
#[cfg(feature = "std")]
use std::error;

use crate::error::{
    InvalidChecksumError, LengthExceedsAvailableSpaceError, NotEnoughHeadroomError,
    UnexpectedBufferEndError,
};
use crate::typed_protocol_headers::UnrecognizedInternetProtocolNumberError;

/// Error returned when parsing an IPv4 header.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum ParseIpv4Error {
    /// The data buffer ended unexpectedly.
    UnexpectedBufferEnd(UnexpectedBufferEndError),
    /// Version header value is not four.
    VersionHeaderValueNotFour,
    /// IHL header value is smaller than 5.
    IhlHeaderValueTooSmall {
        /// Invalid IHL value.
        ihl: usize,
    },
    /// The packet is shorter than the total length header specifies.
    PacketShorterThanTotalLengthHeaderValue {
        /// Total length header value.
        total_length_header: usize,
        /// Actual length of the packet.
        actual_packet_length: usize,
    },
    /// The total length header value is smaller than the packet length specified by the IHL header.
    TotalLengthHeaderValueSmallerThanIhlHeaderValue {
        /// Total length header value.
        total_length_header: usize,
        /// Length specified by the IHL header in bytes (IHL header specifies amount of 32 bit words).
        ihl_header_in_bytes: usize,
    },
    /// The packet is shorter than the length specified by the IHL header.
    PacketShorterThanIhlHeaderValue {
        /// Length specified by the IHL header in bytes (IHL header specifies amount of 32 bit words).
        ihl_header_in_bytes: usize,
        /// Actual length of the packet.
        actual_packet_length: usize,
    },
    /// Internet protocol number is recognized.
    UnrecognizedInternetProtocolNumber(UnrecognizedInternetProtocolNumberError),
    /// Invalid checksum.
    InvalidChecksum(InvalidChecksumError),
}

impl From<UnrecognizedInternetProtocolNumberError> for ParseIpv4Error {
    #[inline]
    fn from(value: UnrecognizedInternetProtocolNumberError) -> Self {
        Self::UnrecognizedInternetProtocolNumber(value)
    }
}

impl From<UnexpectedBufferEndError> for ParseIpv4Error {
    #[inline]
    fn from(value: UnexpectedBufferEndError) -> Self {
        Self::UnexpectedBufferEnd(value)
    }
}

impl From<LengthExceedsAvailableSpaceError> for ParseIpv4Error {
    #[inline]
    fn from(value: LengthExceedsAvailableSpaceError) -> Self {
        Self::UnexpectedBufferEnd(UnexpectedBufferEndError {
            expected_length: value.required_space,
            actual_length: value.available_space,
        })
    }
}

impl From<InvalidChecksumError> for ParseIpv4Error {
    #[inline]
    fn from(value: InvalidChecksumError) -> Self {
        Self::InvalidChecksum(value)
    }
}

impl Display for ParseIpv4Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::VersionHeaderValueNotFour => {
                write!(f, "Version header is not 4")
            }
            Self::IhlHeaderValueTooSmall { ihl } => {
                write!(
                    f,
                    "IHL header value invalid, expected to be between 5 and 15 (inclusive): {ihl}"
                )
            }
            Self::PacketShorterThanTotalLengthHeaderValue {
                total_length_header: total_length,
                actual_packet_length: actual_length,
            } => {
                write!(
                    f,
                    "Total length does not match actual length, total length: {total_length} bytes - actual length: {actual_length} bytes"
                )
            }
            Self::TotalLengthHeaderValueSmallerThanIhlHeaderValue {
                total_length_header,
                ihl_header_in_bytes,
            } => {
                write!(
                    f,
                    "Total length expected to be the same or larger than header length (IHL), total was: {total_length_header} bytes header was: {ihl_header_in_bytes} bytes"
                )
            }
            Self::UnrecognizedInternetProtocolNumber(err) => {
                write!(f, "{err}")
            }
            Self::UnexpectedBufferEnd(err) => {
                write!(f, "{err}")
            }
            Self::InvalidChecksum(err) => {
                write!(f, "{err}")
            }
            Self::PacketShorterThanIhlHeaderValue {
                ihl_header_in_bytes,
                actual_packet_length,
            } => {
                write!(
                    f,
                    "Packet length expected to be larger than IHL header length, packet length was: {actual_packet_length} bytes, IHL header was: {ihl_header_in_bytes} bytes"
                )
            }
        }
    }
}

#[cfg(feature = "error_trait")]
impl error::Error for ParseIpv4Error {}

/// Error returned by methods manipulating the total length header.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum SetTotalLengthError {
    /// Total length cannot be set to less than the header length specified by the IHL header.
    SmallerThanIhl,
    /// The supplied length exceeds the available space.
    LengthExceedsAvailableSpace(LengthExceedsAvailableSpaceError),
    /// The operation would cut parts of an already parsed upper layer.
    CannotCutUpperLayerHeader,
}

impl Display for SetTotalLengthError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SmallerThanIhl => {
                write!(f, "Provided value is smaller than IHL header value")
            }
            Self::CannotCutUpperLayerHeader => {
                write!(
                    f,
                    "Provided length would cut off already parsed upper layer"
                )
            }
            Self::LengthExceedsAvailableSpace(err) => {
                write!(f, "{err}")
            }
        }
    }
}

impl From<LengthExceedsAvailableSpaceError> for SetTotalLengthError {
    #[inline]
    fn from(value: LengthExceedsAvailableSpaceError) -> Self {
        Self::LengthExceedsAvailableSpace(value)
    }
}

#[cfg(feature = "error_trait")]
impl error::Error for SetTotalLengthError {}

/// Error returned by methods manipulating the IHL header.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum SetIhlError {
    /// Invalid IHL supplied.
    InvalidIhl {
        /// The supplied invalid IHL.
        ihl: usize,
    },
    /// Not enough headroom available.
    NotEnoughHeadroom(NotEnoughHeadroomError),
}

impl Display for SetIhlError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidIhl { ihl } => {
                write!(
                    f,
                    "IHL header value invalid, expected to be between 5 and 20 (inclusive): {ihl}"
                )
            }
            Self::NotEnoughHeadroom(err) => {
                write!(f, "{err}")
            }
        }
    }
}

impl From<NotEnoughHeadroomError> for SetIhlError {
    #[inline]
    fn from(value: NotEnoughHeadroomError) -> Self {
        Self::NotEnoughHeadroom(value)
    }
}

#[cfg(feature = "error_trait")]
impl error::Error for SetIhlError {}
