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

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct UnexpectedBufferEndError {
    pub expected_length: usize,
    pub actual_length: usize,
}

impl Display for UnexpectedBufferEndError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Data was expected to be at least {} bytes long but was {} bytes",
            self.expected_length, self.actual_length
        )
    }
}

#[cfg(feature = "error_trait")]
impl error::Error for UnexpectedBufferEndError {}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct NotEnoughHeadroomError {
    pub required: usize,
    pub available: usize,
}

impl Display for NotEnoughHeadroomError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Not enough headroom to insert data, required {} bytes but only {} bytes available.",
            self.required, self.available
        )
    }
}

#[cfg(feature = "error_trait")]
impl error::Error for NotEnoughHeadroomError {}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct WrongChecksumError {
    pub calculated_checksum: u16,
}

impl Display for WrongChecksumError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Wrong checksum, calculated: {}",
            self.calculated_checksum
        )
    }
}

#[cfg(feature = "error_trait")]
impl error::Error for WrongChecksumError {}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum ParseNetworkDataError {
    UnrecognizedEtherType(UnrecognizedEtherTypeError),
    UnrecognizedInternetProtocolNumber(UnrecognizedInternetProtocolNumberError),
    ParseIeee802_1Q(ParseIeee802_1QError),
    ParseArp(ParseArpError),
    ParseIpv4(ParseIpv4Error),
    ParseIpv6(ParseIpv6Error),
    ParseIpv6Extensions(ParseIpv6ExtensionsError),
    ParseTcp(ParseTcpError),
    ParseUdp(ParseUdpError),
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
