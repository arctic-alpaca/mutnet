/// Sources:
/// <https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml#ipv6-parameters-3>
#[repr(u8)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum RoutingType {
    SourceRoute = 0,
    Nimrod = 1,
    Type2RoutingHeader = 2,
    RplSourceRouteHeader = 3,
    SegmentRoutingHeader = 4,
    Rfc3692StyleExperiment1 = 253,
    Rfc3692StyleExperiment2 = 254,
    Reserved = 255,
}

impl core::fmt::Display for RoutingType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!("{:?}", self))
    }
}

impl TryFrom<u8> for RoutingType {
    type Error = UnrecognizedRoutingTypeError;

    #[inline]
    fn try_from(value: u8) -> Result<Self, UnrecognizedRoutingTypeError> {
        match value {
            0 => Ok(RoutingType::SourceRoute),
            1 => Ok(RoutingType::Nimrod),
            2 => Ok(RoutingType::Type2RoutingHeader),
            3 => Ok(RoutingType::RplSourceRouteHeader),
            4 => Ok(RoutingType::SegmentRoutingHeader),
            253 => Ok(RoutingType::Rfc3692StyleExperiment1),
            254 => Ok(RoutingType::Rfc3692StyleExperiment2),
            255 => Ok(RoutingType::Reserved),
            _ => Err(UnrecognizedRoutingTypeError {
                routing_type: value,
            }),
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct UnrecognizedRoutingTypeError {
    pub routing_type: u8,
}

impl core::fmt::Display for UnrecognizedRoutingTypeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!(
            "Unrecognized routing type, was: {:?}",
            self.routing_type
        ))
    }
}

#[cfg(all(feature = "error_trait", not(feature = "std")))]
impl core::error::Error for UnrecognizedRoutingTypeError {}

#[cfg(feature = "std")]
impl std::error::Error for UnrecognizedRoutingTypeError {}

#[cfg(kani)]
mod routingtype_verification {
    use super::*;

    #[kani::proof]
    fn routing_type_proof() {
        let try_value = kani::any::<u8>();
        match RoutingType::try_from(try_value) {
            Ok(enum_value) => {
                assert_eq!(enum_value as u8, try_value);
            }
            Err(err) => {
                assert_eq!(
                    UnrecognizedRoutingTypeError {
                        routing_type: try_value
                    },
                    err
                );
            }
        }
    }
}
