/// Sources:
/// <https://en.wikipedia.org/wiki/IPv6_packet#Extension_headers>
#[repr(u8)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum Ipv6Extension {
    HopByHop = 0,
    Routing = 43,
    Fragment = 44,
    DestinationOptions = 60,
}

impl core::fmt::Display for Ipv6Extension {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!("{:?}", self))
    }
}
impl TryFrom<u8> for Ipv6Extension {
    type Error = NoRecognizedIpv6ExtensionError;

    #[inline]
    fn try_from(value: u8) -> Result<Self, NoRecognizedIpv6ExtensionError> {
        match value {
            0 => Ok(Ipv6Extension::HopByHop),
            43 => Ok(Ipv6Extension::Routing),
            44 => Ok(Ipv6Extension::Fragment),
            60 => Ok(Ipv6Extension::DestinationOptions),
            _ => Err(NoRecognizedIpv6ExtensionError {
                ipv6_extension: value,
            }),
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct NoRecognizedIpv6ExtensionError {
    pub ipv6_extension: u8,
}

impl core::fmt::Display for NoRecognizedIpv6ExtensionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(::core::format_args!(
            "Not a valid header value , was: {:?}",
            self.ipv6_extension
        ))
    }
}

#[cfg(all(feature = "error_trait", not(feature = "std")))]
impl core::error::Error for NoRecognizedIpv6ExtensionError {}

#[cfg(feature = "std")]
impl std::error::Error for NoRecognizedIpv6ExtensionError {}

#[cfg(kani)]
mod ipv6extension_verification {
    use super::*;

    #[kani::proof]
    fn ipv6_extension_proof() {
        let try_value = kani::any::<u8>();
        match Ipv6Extension::try_from(try_value) {
            Ok(enum_value) => {
                assert_eq!(enum_value as u8, try_value);
            }
            Err(err) => {
                assert_eq!(
                    NoRecognizedIpv6ExtensionError {
                        ipv6_extension: try_value
                    },
                    err
                );
            }
        }
    }
}
