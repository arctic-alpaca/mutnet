//! Typed versions of IPv4 ECN protocol header fields.

/// Sources:
/// <https://en.wikipedia.org/wiki/Explicit_Congestion_Notification>
/// <https://www.iana.org/assignments/dscp-registry/dscp-registry.xhtml>
#[allow(clippy::unusual_byte_groupings)]
#[repr(u8)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum Ecn {
    /// Not-ECT (Not ECN-Capable Transport)
    NotEct = 0b0000_00_00,
    /// ECT(1) (ECN-Capable Transport(1))
    Ect1 = 0b0000_00_01,
    /// ECT(0) (ECN-Capable Transport(0))
    Ect0 = 0b0000_00_10,
    /// CE (Congestion Experienced)
    Ce = 0b0000_00_11,
}

impl core::fmt::Display for Ecn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!("{self:?}"))
    }
}
impl TryFrom<u8> for Ecn {
    type Error = UnrecognizedEcnError;

    #[allow(clippy::unusual_byte_groupings)]
    #[inline]
    fn try_from(value: u8) -> Result<Self, UnrecognizedEcnError> {
        match value {
            0b0000_00_00 => Ok(Ecn::NotEct),
            0b0000_00_01 => Ok(Ecn::Ect1),
            0b0000_00_10 => Ok(Ecn::Ect0),
            0b0000_00_11 => Ok(Ecn::Ce),
            _ => Err(UnrecognizedEcnError { ecn: value }),
        }
    }
}

/// Error returned by [`Ecn::try_from()`].
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct UnrecognizedEcnError {
    /// The unrecognized ECN value.
    pub ecn: u8,
}

impl core::fmt::Display for UnrecognizedEcnError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!("Unrecognized ECN value, was: {:?}", self.ecn))
    }
}

impl core::error::Error for UnrecognizedEcnError {}

#[cfg(kani)]
mod ecn_verification {
    use super::*;

    #[kani::proof]
    fn ecn_proof() {
        let try_value = kani::any::<u8>();
        match Ecn::try_from(try_value) {
            Ok(enum_value) => {
                assert_eq!(enum_value as u8, try_value);
            }
            Err(err) => {
                assert_eq!(UnrecognizedEcnError { ecn: try_value }, err);
            }
        }
    }
}
