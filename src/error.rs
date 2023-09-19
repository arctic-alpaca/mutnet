use crate::arp::ParseArpError;
use crate::ether_type::NoRecognizedEtherTypeError;
use crate::ethernet::EthernetError;
use crate::ieee802_1q_vlan::ParseIeee802_1QError;
use crate::internet_protocol::NoRecognizedInternetProtocolNumberError;
use crate::ipv4::{Ipv4Error, ParseIpv4Error};
use crate::ipv6::ParseIpv6Error;
use crate::ipv6_extensions::ParseIpv6ExtensionsError;
use crate::tcp::ParseTcpError;

#[cfg(all(feature = "error_trait", not(feature = "std")))]
use core::error;

use core::fmt::{Debug, Display, Formatter};
#[cfg(feature = "std")]
use std::error;

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum Error {
    Ethernet(EthernetError),
    Arp(ParseArpError),
    IpV4(Ipv4Error),
    ParseTcp(ParseTcpError),
    ParseIpv4(ParseIpv4Error),
    ParseIpv6(ParseIpv6Error),
    UnexpectedBufferEnd(UnexpectedBufferEndError),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Ethernet(err) => {
                write!(f, "{err}")
            }
            Self::Arp(err) => {
                write!(f, "{err}")
            }
            Self::IpV4(err) => {
                write!(f, "{err}")
            }
            Self::UnexpectedBufferEnd(err) => {
                write!(f, "{err}")
            }
            Self::ParseTcp(err) => {
                write!(f, "{err}")
            }
            Self::ParseIpv4(err) => {
                write!(f, "{err}")
            }
            Self::ParseIpv6(err) => {
                write!(f, "{err}")
            }
        }
    }
}

impl From<EthernetError> for Error {
    #[inline]
    fn from(value: EthernetError) -> Self {
        Self::Ethernet(value)
    }
}

impl From<ParseArpError> for Error {
    #[inline]
    fn from(value: ParseArpError) -> Self {
        Self::Arp(value)
    }
}
impl From<Ipv4Error> for Error {
    #[inline]
    fn from(value: Ipv4Error) -> Self {
        Self::IpV4(value)
    }
}
impl From<UnexpectedBufferEndError> for Error {
    #[inline]
    fn from(value: UnexpectedBufferEndError) -> Self {
        Self::UnexpectedBufferEnd(value)
    }
}
impl From<ParseTcpError> for Error {
    #[inline]
    fn from(value: ParseTcpError) -> Self {
        Self::ParseTcp(value)
    }
}
impl From<ParseIpv4Error> for Error {
    #[inline]
    fn from(value: ParseIpv4Error) -> Self {
        Self::ParseIpv4(value)
    }
}
impl From<ParseIpv6Error> for Error {
    #[inline]
    fn from(value: ParseIpv6Error) -> Self {
        Self::ParseIpv6(value)
    }
}

#[cfg(feature = "error_trait")]
impl error::Error for Error {}

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
pub enum ParseEthernetIpv4TcpError {
    ParseIpv4(ParseIpv4Error),
    ParseTcp(ParseTcpError),
    UnexpectedBufferEnd(UnexpectedBufferEndError),
}

impl From<ParseIpv4Error> for ParseEthernetIpv4TcpError {
    #[inline]
    fn from(value: ParseIpv4Error) -> Self {
        Self::ParseIpv4(value)
    }
}

impl From<ParseTcpError> for ParseEthernetIpv4TcpError {
    #[inline]
    fn from(value: ParseTcpError) -> Self {
        Self::ParseTcp(value)
    }
}
impl From<UnexpectedBufferEndError> for ParseEthernetIpv4TcpError {
    #[inline]
    fn from(value: UnexpectedBufferEndError) -> Self {
        Self::UnexpectedBufferEnd(value)
    }
}

impl Display for ParseEthernetIpv4TcpError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ParseIpv4(err) => {
                write!(f, "{err}")
            }
            Self::ParseTcp(err) => {
                write!(f, "{err}")
            }
            Self::UnexpectedBufferEnd(err) => {
                write!(f, "{err}")
            }
        }
    }
}

#[cfg(feature = "error_trait")]
impl error::Error for ParseEthernetIpv4TcpError {}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum ParseNetworkDataError {
    NoRecognizedEtherType(NoRecognizedEtherTypeError),
    NoRecognizedInternetProtocolNumber(NoRecognizedInternetProtocolNumberError),
    ParseIeee802_1Q(ParseIeee802_1QError),
    ParseArp(ParseArpError),
    ParseIpv4(ParseIpv4Error),
    ParseIpv6(ParseIpv6Error),
    ParseIpv6Extensions(ParseIpv6ExtensionsError),
    ParseTcp(ParseTcpError),
    UnexpectedBufferEnd(UnexpectedBufferEndError),
}

impl From<NoRecognizedEtherTypeError> for ParseNetworkDataError {
    #[inline]
    fn from(value: NoRecognizedEtherTypeError) -> Self {
        Self::NoRecognizedEtherType(value)
    }
}

impl From<NoRecognizedInternetProtocolNumberError> for ParseNetworkDataError {
    #[inline]
    fn from(value: NoRecognizedInternetProtocolNumberError) -> Self {
        Self::NoRecognizedInternetProtocolNumber(value)
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

impl From<UnexpectedBufferEndError> for ParseNetworkDataError {
    #[inline]
    fn from(value: UnexpectedBufferEndError) -> Self {
        Self::UnexpectedBufferEnd(value)
    }
}

impl Display for ParseNetworkDataError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoRecognizedEtherType(err) => {
                write!(f, "{err}")
            }
            Self::NoRecognizedInternetProtocolNumber(err) => {
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
        }
    }
}

#[cfg(feature = "error_trait")]
impl error::Error for ParseNetworkDataError {}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum SetDataOffsetError {
    InvalidDataOffset { data_offset: usize },
    NotEnoughHeadroom(NotEnoughHeadroomError),
}

impl Display for SetDataOffsetError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidDataOffset { data_offset } => {
                write!(
                    f,
                    "Data offset header value invalid, expected to be between 5 and 20 (inclusive): {data_offset}"
                )
            }
            Self::NotEnoughHeadroom(err) => {
                write!(f, "{err}")
            }
        }
    }
}

impl From<NotEnoughHeadroomError> for SetDataOffsetError {
    #[inline]
    fn from(value: NotEnoughHeadroomError) -> Self {
        Self::NotEnoughHeadroom(value)
    }
}

#[cfg(feature = "error_trait")]
impl error::Error for SetDataOffsetError {}
