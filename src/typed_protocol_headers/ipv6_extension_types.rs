//! Typed versions of IPv6 extension type protocol header fields.

/// Sources:
/// <https://en.wikipedia.org/wiki/IPv6_packet#Extension_headers>
#[repr(u8)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum Ipv6ExtensionType {
    /// Hop-by-hop
    HopByHop = 0,
    /// Routing
    Routing = 43,
    /// Fragment
    Fragment = 44,
    /// Destination options
    DestinationOptions = 60,
}

impl core::fmt::Display for Ipv6ExtensionType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!("{self:?}"))
    }
}
impl TryFrom<u8> for Ipv6ExtensionType {
    type Error = UnrecognizedIpv6ExtensionError;

    #[inline]
    fn try_from(value: u8) -> Result<Self, UnrecognizedIpv6ExtensionError> {
        match value {
            0 => Ok(Ipv6ExtensionType::HopByHop),
            43 => Ok(Ipv6ExtensionType::Routing),
            44 => Ok(Ipv6ExtensionType::Fragment),
            60 => Ok(Ipv6ExtensionType::DestinationOptions),
            _ => Err(UnrecognizedIpv6ExtensionError {
                ipv6_extension: value,
            }),
        }
    }
}

/// Error returned by [`Ipv6ExtensionType::try_from()`].
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct UnrecognizedIpv6ExtensionError {
    /// The unrecognized IPv6 extension type value.
    pub ipv6_extension: u8,
}

impl core::fmt::Display for UnrecognizedIpv6ExtensionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!(
            "Unrecognized IPv6 extension, was: {:?}",
            self.ipv6_extension
        ))
    }
}

impl core::error::Error for UnrecognizedIpv6ExtensionError {}

#[cfg(kani)]
mod ipv6extension_verification {
    use super::*;

    #[kani::proof]
    fn ipv6_extension_proof() {
        let try_value = kani::any::<u8>();
        match Ipv6ExtensionType::try_from(try_value) {
            Ok(enum_value) => {
                assert_eq!(enum_value as u8, try_value);
            }
            Err(err) => {
                assert_eq!(
                    UnrecognizedIpv6ExtensionError {
                        ipv6_extension: try_value
                    },
                    err
                );
            }
        }
    }
}
