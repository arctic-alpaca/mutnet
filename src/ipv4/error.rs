use crate::error::{NotEnoughHeadroomError, UnexpectedBufferEndError, WrongChecksumError};

use core::fmt::{Debug, Display, Formatter};

#[cfg(all(feature = "error_trait", not(feature = "std")))]
use core::error;

use crate::internet_protocol::NoRecognizedInternetProtocolNumberError;
#[cfg(feature = "std")]
use std::error;

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum Ipv4Error {
    ParseIpv4(ParseIpv4Error),
    Checksum(ChecksumError),
}

impl Display for Ipv4Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ParseIpv4(err) => {
                write!(f, "{err}")
            }
            Self::Checksum(err) => {
                write!(f, "{err}")
            }
        }
    }
}

impl From<ParseIpv4Error> for Ipv4Error {
    #[inline]
    fn from(value: ParseIpv4Error) -> Self {
        Self::ParseIpv4(value)
    }
}

impl From<ChecksumError> for Ipv4Error {
    #[inline]
    fn from(value: ChecksumError) -> Self {
        Self::Checksum(value)
    }
}

#[cfg(feature = "error_trait")]
impl error::Error for Ipv4Error {}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum ParseIpv4Error {
    UnexpectedBufferEnd(UnexpectedBufferEndError),
    VersionHeaderValueNotFour,
    IhlHeaderValueTooSmall {
        ihl: usize,
    },
    PacketShorterThanTotalLengthHeaderValue {
        total_length_header: usize,
        actual_packet_length: usize,
    },
    TotalLengthHeaderValueSmallerThanIhlHeaderValue {
        total_length_header: usize,
        ihl_header_in_bytes: usize,
    },
    PacketShorterThanIhlHeaderValue {
        ihl_header_in_bytes: usize,
        actual_packet_length: usize,
    },
    NoRecognizedInternetProtocolNumber(NoRecognizedInternetProtocolNumberError),
    WrongChecksum(WrongChecksumError),
}

impl From<NoRecognizedInternetProtocolNumberError> for ParseIpv4Error {
    #[inline]
    fn from(value: NoRecognizedInternetProtocolNumberError) -> Self {
        Self::NoRecognizedInternetProtocolNumber(value)
    }
}

impl From<UnexpectedBufferEndError> for ParseIpv4Error {
    #[inline]
    fn from(value: UnexpectedBufferEndError) -> Self {
        Self::UnexpectedBufferEnd(value)
    }
}

impl From<WrongChecksumError> for ParseIpv4Error {
    #[inline]
    fn from(value: WrongChecksumError) -> Self {
        Self::WrongChecksum(value)
    }
}

impl Display for ParseIpv4Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::VersionHeaderValueNotFour => {
                write!(f, "Version is not 4")
            }
            Self::IhlHeaderValueTooSmall { ihl } => {
                write!(
                    f,
                    "IHL header value invalid, expected to be between 5 and 20 (inclusive): {ihl}"
                )
            }
            Self::PacketShorterThanTotalLengthHeaderValue {
                total_length_header: total_length,
                actual_packet_length: actual_length,
            } => {
                write!(
                    f,
                    "Total length does not match actual length, total: {total_length} - actual: {actual_length}"
                )
            }
            Self::TotalLengthHeaderValueSmallerThanIhlHeaderValue {
                total_length_header,
                ihl_header_in_bytes,
            } => {
                write!(
                    f,
                    "Total length expected to be larger than header length, total was: {total_length_header} header was: {ihl_header_in_bytes}"
                )
            }
            Self::NoRecognizedInternetProtocolNumber(err) => {
                write!(f, "{err}")
            }
            Self::UnexpectedBufferEnd(err) => {
                write!(f, "{err}")
            }
            Self::WrongChecksum(err) => {
                write!(f, "{err}")
            }
            Self::PacketShorterThanIhlHeaderValue {
                ihl_header_in_bytes,
                actual_packet_length,
            } => {
                write!(
                    f,
                    "Packet length expected to be larger than ihl header length in bytes, packet length was: {actual_packet_length} ihl header in bytes was: {ihl_header_in_bytes}"
                )
            }
        }
    }
}

#[cfg(feature = "error_trait")]
impl error::Error for ParseIpv4Error {}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum ChecksumError {
    IhlHeaderValueTooSmall {
        ihl: usize,
    },
    PacketShorterThanIhlHeaderValue {
        ihl_header_in_bytes: usize,
        actual_packet_length: usize,
    },
}

impl Display for ChecksumError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::IhlHeaderValueTooSmall { ihl } => {
                write!(
                    f,
                    "IHL header value invalid, expected to be between 5 and 20 (inclusive): {ihl}"
                )
            }
            Self::PacketShorterThanIhlHeaderValue {
                ihl_header_in_bytes,
                actual_packet_length,
            } => {
                write!(
                    f,
                    "Packet length expected to be larger than ihl header length in bytes, packet length was: {actual_packet_length} ihl header in bytes was: {ihl_header_in_bytes}"
                )
            }
        }
    }
}

#[cfg(feature = "error_trait")]
impl error::Error for ChecksumError {}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum SetOptionsError {
    NotMultipleOf4Bytes,
    OptionsTooLong { options_len: usize },
    NotEnoughHeadroom(NotEnoughHeadroomError),
    UnexpectedBufferEnd(UnexpectedBufferEndError),
}

impl Display for SetOptionsError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotMultipleOf4Bytes => {
                write!(f, "Options were not multiple of 4 bytes (32 bits)")
            }
            Self::OptionsTooLong { options_len } => {
                write!(f, "Options longer than 60 bytes: {:?}", options_len)
            }
            Self::NotEnoughHeadroom(err) => {
                write!(f, "{err}")
            }
            Self::UnexpectedBufferEnd(err) => {
                write!(f, "{err}")
            }
        }
    }
}

impl From<NotEnoughHeadroomError> for SetOptionsError {
    #[inline]
    fn from(value: NotEnoughHeadroomError) -> Self {
        Self::NotEnoughHeadroom(value)
    }
}

impl From<UnexpectedBufferEndError> for SetOptionsError {
    #[inline]
    fn from(value: UnexpectedBufferEndError) -> Self {
        Self::UnexpectedBufferEnd(value)
    }
}

#[cfg(feature = "error_trait")]
impl error::Error for SetOptionsError {}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum SetTotalLengthError {
    SmallerThanIhl,
    UnexpectedBufferEnd(UnexpectedBufferEndError),
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
            Self::UnexpectedBufferEnd(err) => {
                write!(f, "{err}")
            }
        }
    }
}

impl From<UnexpectedBufferEndError> for SetTotalLengthError {
    #[inline]
    fn from(value: UnexpectedBufferEndError) -> Self {
        Self::UnexpectedBufferEnd(value)
    }
}

#[cfg(feature = "error_trait")]
impl error::Error for SetTotalLengthError {}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum SetIhlError {
    InvalidIhl { ihl: usize },
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
