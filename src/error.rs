//! Non-protocol specific errors.
use crate::arp::ParseArpError;
use crate::ieee802_1q_vlan::ParseIeee802_1QError;
use crate::ipv4::ParseIpv4Error;
use crate::ipv6::ParseIpv6Error;
use crate::ipv6_extensions::ParseIpv6ExtensionsError;
use crate::tcp::ParseTcpError;
use crate::typed_protocol_headers::UnrecognizedEtherTypeError;
use crate::typed_protocol_headers::UnrecognizedInternetProtocolNumberError;
use crate::udp::ParseUdpError;
#[cfg(all(feature = "error_trait", not(feature = "std")))]
use core::error;
use core::fmt::{Debug, Display, Formatter};
#[cfg(feature = "std")]
use std::error;

/// Error returned if the data buffer is expected to be longer than it actually is.
///
/// This error can occur when a length value is read from a packet header and the actual packet is
/// shorter than the length header value indicates.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct UnexpectedBufferEndError {
    /// The length expected.
    pub expected_length: usize,
    /// The actual length.
    pub actual_length: usize,
}

impl Display for UnexpectedBufferEndError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Data buffer ended unexpectedly, expected {} bytes but found {} bytes",
            self.expected_length, self.actual_length
        )
    }
}

#[cfg(feature = "error_trait")]
impl error::Error for UnexpectedBufferEndError {}

/// Error returned if the available headroom is too not enough for the attempted operation.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct NotEnoughHeadroomError {
    /// Headroom required for the attempted operation.
    pub required: usize,
    /// Headroom actually available.
    pub available: usize,
}

impl Display for NotEnoughHeadroomError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Not enough headroom to insert data, {} bytes required, {} bytes available.",
            self.required, self.available
        )
    }
}

#[cfg(feature = "error_trait")]
impl error::Error for NotEnoughHeadroomError {}

/// Error returned if the calculated checksum does not match the expected one.
///
/// This is generally the case when the checksum calculated for IPv4 or UDP/TCP is not 0.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct InvalidChecksumError {
    /// Result of the checksum calculation.
    pub calculated_checksum: u16,
}

impl Display for InvalidChecksumError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Invalid checksum, calculated: {}",
            self.calculated_checksum
        )
    }
}

#[cfg(feature = "error_trait")]
impl error::Error for InvalidChecksumError {}

/// Error returned by [`parse_network_data()`](crate::multi_step_parser::parse_network_data()).
///
/// Encompasses all parsing errors possibly encountered when trying to parse network data.
/// This is basically a collection of all individual protocol parsing errors.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum ParseNetworkDataError {
    /// Unrecognized ether type.
    UnrecognizedEtherType(UnrecognizedEtherTypeError),
    /// Unrecognized internet protocol number.
    UnrecognizedInternetProtocolNumber(UnrecognizedInternetProtocolNumberError),
    /// Error parsing IEEE802.1Q header.
    ParseIeee802_1Q(ParseIeee802_1QError),
    /// Error parsing ARP header.
    ParseArp(ParseArpError),
    /// Error parsing IPv4 header.
    ParseIpv4(ParseIpv4Error),
    /// Error parsing IPv6 header.
    ParseIpv6(ParseIpv6Error),
    /// Error parsing IPv6 extension headers.
    ParseIpv6Extensions(ParseIpv6ExtensionsError),
    /// Error parsing TCP header.
    ParseTcp(ParseTcpError),
    /// Error parsing UDP header.
    ParseUdp(ParseUdpError),
    /// The data buffer ended unexpectedly.
    UnexpectedBufferEnd(UnexpectedBufferEndError),
}

impl From<UnrecognizedEtherTypeError> for ParseNetworkDataError {
    #[inline]
    fn from(value: UnrecognizedEtherTypeError) -> Self {
        Self::UnrecognizedEtherType(value)
    }
}

impl From<UnrecognizedInternetProtocolNumberError> for ParseNetworkDataError {
    #[inline]
    fn from(value: UnrecognizedInternetProtocolNumberError) -> Self {
        Self::UnrecognizedInternetProtocolNumber(value)
    }
}

impl From<ParseIeee802_1QError> for ParseNetworkDataError {
    #[inline]
    fn from(value: ParseIeee802_1QError) -> Self {
        Self::ParseIeee802_1Q(value)
    }
}

impl From<ParseArpError> for ParseNetworkDataError {
    #[inline]
    fn from(value: ParseArpError) -> Self {
        Self::ParseArp(value)
    }
}

impl From<ParseIpv4Error> for ParseNetworkDataError {
    #[inline]
    fn from(value: ParseIpv4Error) -> Self {
        Self::ParseIpv4(value)
    }
}

impl From<ParseIpv6Error> for ParseNetworkDataError {
    #[inline]
    fn from(value: ParseIpv6Error) -> Self {
        Self::ParseIpv6(value)
    }
}

impl From<ParseIpv6ExtensionsError> for ParseNetworkDataError {
    #[inline]
    fn from(value: ParseIpv6ExtensionsError) -> Self {
        Self::ParseIpv6Extensions(value)
    }
}

impl From<ParseTcpError> for ParseNetworkDataError {
    #[inline]
    fn from(value: ParseTcpError) -> Self {
        Self::ParseTcp(value)
    }
}

impl From<ParseUdpError> for ParseNetworkDataError {
    #[inline]
    fn from(value: ParseUdpError) -> Self {
        Self::ParseUdp(value)
    }
}

impl From<UnexpectedBufferEndError> for ParseNetworkDataError {
    #[inline]
    fn from(value: UnexpectedBufferEndError) -> Self {
        Self::UnexpectedBufferEnd(value)
    }
}

impl Display for ParseNetworkDataError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnrecognizedEtherType(err) => {
                write!(f, "{err}")
            }
            Self::UnrecognizedInternetProtocolNumber(err) => {
                write!(f, "{err}")
            }
            Self::ParseIeee802_1Q(err) => {
                write!(f, "{err}")
            }
            Self::ParseArp(err) => {
                write!(f, "{err}")
            }
            Self::ParseIpv4(err) => {
                write!(f, "{err}")
            }
            Self::ParseIpv6(err) => {
                write!(f, "{err}")
            }
            Self::ParseIpv6Extensions(err) => {
                write!(f, "{err}")
            }
            Self::UnexpectedBufferEnd(err) => {
                write!(f, "{err}")
            }
            Self::ParseTcp(err) => {
                write!(f, "{err}")
            }
            Self::ParseUdp(err) => {
                write!(f, "{err}")
            }
        }
    }
}

#[cfg(feature = "error_trait")]
impl error::Error for ParseNetworkDataError {}

/// Error returned by methods manipulating header field affecting the payload length.
///
/// Methods like setting the IPv6 payload length return this error if the supplied new length
/// does not fit within the data buffer.
/// For this, headroom is not considered available space as this would require copying the whole
/// network data within the buffer.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct LengthExceedsAvailableSpaceError {
    /// The required space in bytes.
    pub required_space: usize,
    /// The space available in bytes.
    pub available_space: usize,
}

impl Display for LengthExceedsAvailableSpaceError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Cannot change data length, required space {}, available space: {}",
            self.required_space, self.available_space
        )
    }
}

#[cfg(feature = "error_trait")]
impl error::Error for LengthExceedsAvailableSpaceError {}
