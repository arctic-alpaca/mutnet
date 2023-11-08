/// Sources:
/// <https://en.wikipedia.org/wiki/Internet_Protocol_version_4#Options>
/// <https://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml#ip-parameters-1>
#[repr(u8)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum OptionType {
    /// End of Option List
    Eool = 0x00,
    /// No Operation
    Nop = 0x01,
    /// Security (defunct)
    Sec = 0x02,
    /// Record Route
    Rr = 0x07,
    /// Experimental Measurement
    Zsu = 0x0A,
    /// MTU Probe
    Mtup = 0x0B,
    /// MTU Reply
    Mtur = 0x0C,
    /// ENCODE
    Encode = 0x0F,
    /// Quick-Start
    Qs = 0x19,
    /// RFC3692-style Experiment
    Exp = 0x1E,
    /// Time Stamp
    Ts = 0x44,
    /// Traceroute
    Tr = 0x52,
    /// RFC3692-style Experiment
    Exp1 = 0x5E,
    /// Security (RIPSO)
    Sec1 = 0x82,
    /// Loose Source Route
    Lsr = 0x83,
    /// Extended Security (RIPSO)
    ESec = 0x85,
    /// Commercial IP Security Option
    Cipso = 0x86,
    /// Stream ID
    Sid = 0x88,
    /// Strict Source Route
    Ssr = 0x89,
    /// Experimental Access Control
    Visa = 0x8E,
    /// IMI Traffic Descriptor
    Imitd = 0x90,
    /// Extended Internet Protocol
    Eip = 0x91,
    /// Address Extension
    Addrext = 0x93,
    /// Router Alert
    Rtralt = 0x94,
    /// Selective Directed Broadcast
    Sdb = 0x95,
    /// Dynamic Packet State
    Dps = 0x97,
    /// Upstream Multicast Packet
    Ump = 0x98,
    /// RFC3692-style Experiment
    Exp2 = 0x9E,
    /// Experimental Flow Control
    Finn = 0xCD,
    /// RFC3692-style Experiment
    Exp3 = 0xDE,
}

impl core::fmt::Display for OptionType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!("{self:?}"))
    }
}

impl TryFrom<u8> for OptionType {
    type Error = UnrecognizedOptionTypeError;

    #[inline]
    fn try_from(value: u8) -> Result<Self, UnrecognizedOptionTypeError> {
        match value {
            0x00 => Ok(OptionType::Eool),
            0x01 => Ok(OptionType::Nop),
            0x02 => Ok(OptionType::Sec),
            0x07 => Ok(OptionType::Rr),
            0x0A => Ok(OptionType::Zsu),
            0x0B => Ok(OptionType::Mtup),
            0x0C => Ok(OptionType::Mtur),
            0x0F => Ok(OptionType::Encode),
            0x19 => Ok(OptionType::Qs),
            0x1E => Ok(OptionType::Exp),
            0x44 => Ok(OptionType::Ts),
            0x52 => Ok(OptionType::Tr),
            0x5E => Ok(OptionType::Exp1),
            0x82 => Ok(OptionType::Sec1),
            0x83 => Ok(OptionType::Lsr),
            0x85 => Ok(OptionType::ESec),
            0x86 => Ok(OptionType::Cipso),
            0x88 => Ok(OptionType::Sid),
            0x89 => Ok(OptionType::Ssr),
            0x8E => Ok(OptionType::Visa),
            0x90 => Ok(OptionType::Imitd),
            0x91 => Ok(OptionType::Eip),
            0x93 => Ok(OptionType::Addrext),
            0x94 => Ok(OptionType::Rtralt),
            0x95 => Ok(OptionType::Sdb),
            0x97 => Ok(OptionType::Dps),
            0x98 => Ok(OptionType::Ump),
            0x9E => Ok(OptionType::Exp2),
            0xCD => Ok(OptionType::Finn),
            0xDE => Ok(OptionType::Exp3),
            _ => Err(UnrecognizedOptionTypeError { option_type: value }),
        }
    }
}

/// Error returned by [`OptionType::try_from()`].
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct UnrecognizedOptionTypeError {
    /// The unrecognized option type value.
    pub option_type: u8,
}

impl core::fmt::Display for UnrecognizedOptionTypeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!(
            "Unrecognized option type, was: {:?}",
            self.option_type
        ))
    }
}

#[cfg(all(feature = "error_trait", not(feature = "std")))]
impl core::error::Error for UnrecognizedOptionTypeError {}

#[cfg(feature = "std")]
impl std::error::Error for UnrecognizedOptionTypeError {}

#[cfg(kani)]
mod optiontype_verification {
    use super::*;

    #[kani::proof]
    fn option_type_proof() {
        let try_value = kani::any::<u8>();
        match OptionType::try_from(try_value) {
            Ok(enum_value) => {
                assert_eq!(enum_value as u8, try_value);
            }
            Err(err) => {
                assert_eq!(
                    UnrecognizedOptionTypeError {
                        option_type: try_value
                    },
                    err
                );
            }
        }
    }
}
