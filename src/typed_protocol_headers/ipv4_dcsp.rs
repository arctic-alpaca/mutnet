//! Typed versions of IPv4 DCSP header fields.

/// Sources:
/// <https://en.wikipedia.org/wiki/Differentiated_services>
/// <https://www.iana.org/assignments/dscp-registry/dscp-registry.xhtml>
#[allow(clippy::unusual_byte_groupings)]
#[repr(u8)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum Dscp {
    /// CS0
    Cs0 = 0b00_00_0000,
    /// CS1
    Cs1 = 0b00_00_1000,
    /// CS2
    Cs2 = 0b00_01_0000,
    /// CS3
    Cs3 = 0b00_01_1000,
    /// CS4
    Cs4 = 0b00_10_0000,
    /// CS5
    Cs5 = 0b00_10_1000,
    /// CS6
    Cs6 = 0b00_11_0000,
    /// CS7
    Cs7 = 0b00_11_1000,
    /// AF11
    Af11 = 0b00_00_1010,
    /// AF12
    Af12 = 0b00_00_1100,
    /// AF13
    Af13 = 0b00_00_1110,
    /// AF21
    Af21 = 0b00_01_0010,
    /// AF22
    Af22 = 0b00_01_0100,
    /// AF23
    Af23 = 0b00_01_0110,
    /// AF31
    Af31 = 0b00_01_1010,
    /// AF32
    Af32 = 0b00_01_1100,
    /// AF33
    Af33 = 0b00_01_1110,
    /// AF41
    Af41 = 0b00_10_0010,
    /// AF42
    Af42 = 0b00_10_0100,
    /// AF43
    Af43 = 0b00_10_0110,
    /// EF
    Ef = 0b00_10_1110,
    /// VOICE-ADMIT
    VoiceAdmit = 0b00_10_1100,
    /// LE
    Le = 0b00_00_0001,
}
impl core::fmt::Display for Dscp {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!("{self:?}"))
    }
}
impl TryFrom<u8> for Dscp {
    type Error = UnrecognizedDscpError;

    #[allow(clippy::unusual_byte_groupings)]
    #[inline]
    fn try_from(value: u8) -> Result<Self, UnrecognizedDscpError> {
        match value {
            0b00_00_0000 => Ok(Dscp::Cs0),
            0b00_00_1000 => Ok(Dscp::Cs1),
            0b00_01_0000 => Ok(Dscp::Cs2),
            0b00_01_1000 => Ok(Dscp::Cs3),
            0b00_10_0000 => Ok(Dscp::Cs4),
            0b00_10_1000 => Ok(Dscp::Cs5),
            0b00_11_0000 => Ok(Dscp::Cs6),
            0b00_11_1000 => Ok(Dscp::Cs7),
            0b00_00_1010 => Ok(Dscp::Af11),
            0b00_00_1100 => Ok(Dscp::Af12),
            0b00_00_1110 => Ok(Dscp::Af13),
            0b00_01_0010 => Ok(Dscp::Af21),
            0b00_01_0100 => Ok(Dscp::Af22),
            0b00_01_0110 => Ok(Dscp::Af23),
            0b00_01_1010 => Ok(Dscp::Af31),
            0b00_01_1100 => Ok(Dscp::Af32),
            0b00_01_1110 => Ok(Dscp::Af33),
            0b00_10_0010 => Ok(Dscp::Af41),
            0b00_10_0100 => Ok(Dscp::Af42),
            0b00_10_0110 => Ok(Dscp::Af43),
            0b00_10_1110 => Ok(Dscp::Ef),
            0b00_10_1100 => Ok(Dscp::VoiceAdmit),
            0b00_00_0001 => Ok(Dscp::Le),
            _ => Err(UnrecognizedDscpError { dscp: value }),
        }
    }
}

/// Error returned by [`Dscp::try_from()`].
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct UnrecognizedDscpError {
    /// The unrecognized DSCP value.
    pub dscp: u8,
}

impl core::fmt::Display for UnrecognizedDscpError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!(
            "Unrecognized DSCP value, was: {:?}",
            self.dscp
        ))
    }
}

impl core::error::Error for UnrecognizedDscpError {}

#[cfg(kani)]
mod dscp_verification {
    use super::*;

    #[kani::proof]
    fn dscp_proof() {
        let try_value = kani::any::<u8>();
        match Dscp::try_from(try_value) {
            Ok(enum_value) => {
                assert_eq!(enum_value as u8, try_value);
            }
            Err(err) => {
                assert_eq!(UnrecognizedDscpError { dscp: try_value }, err);
            }
        }
    }
}
