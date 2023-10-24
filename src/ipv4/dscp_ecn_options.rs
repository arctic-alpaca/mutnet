#![allow(clippy::unusual_byte_groupings)]

/// Sources:
/// <https://en.wikipedia.org/wiki/Differentiated_services>
/// <https://www.iana.org/assignments/dscp-registry/dscp-registry.xhtml>
#[repr(u8)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum Dscp {
    Cs0 = 0b00_00_0000,
    Cs1 = 0b00_00_1000,
    Cs2 = 0b00_01_0000,
    Cs3 = 0b00_01_1000,
    Cs4 = 0b00_10_0000,
    Cs5 = 0b00_10_1000,
    Cs6 = 0b00_11_0000,
    Cs7 = 0b00_11_1000,
    Af11 = 0b00_00_1010,
    Af12 = 0b00_00_1100,
    Af13 = 0b00_00_1110,
    Af21 = 0b00_01_0010,
    Af22 = 0b00_01_0100,
    Af23 = 0b00_01_0110,
    Af31 = 0b00_01_1010,
    Af32 = 0b00_01_1100,
    Af33 = 0b00_01_1110,
    Af41 = 0b00_10_0010,
    Af42 = 0b00_10_0100,
    Af43 = 0b00_10_0110,
    Ef = 0b00_10_1110,
    VoiceAdmit = 0b00_10_1100,
    Le = 0b00_00_0001,
}
impl core::fmt::Display for Dscp {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!("{:?}", self))
    }
}
impl TryFrom<u8> for Dscp {
    type Error = NoRecognizedDscpError;

    #[inline]
    fn try_from(value: u8) -> Result<Self, NoRecognizedDscpError> {
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
            _ => Err(NoRecognizedDscpError { dscp: value }),
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct NoRecognizedDscpError {
    pub dscp: u8,
}

impl core::fmt::Display for NoRecognizedDscpError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(::core::format_args!(
            "Not a valid header value , was: {:?}",
            self.dscp
        ))
    }
}

#[cfg(all(feature = "error_trait", not(feature = "std")))]
impl core::error::Error for NoRecognizedDscpError {}

#[cfg(feature = "std")]
impl std::error::Error for NoRecognizedDscpError {}

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
                assert_eq!(NoRecognizedDscpError { dscp: try_value }, err);
            }
        }
    }
}

/// Sources:
/// <https://en.wikipedia.org/wiki/Explicit_Congestion_Notification>
/// <https://www.iana.org/assignments/dscp-registry/dscp-registry.xhtml>
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
        f.write_fmt(::core::format_args!("{:?}", self))
    }
}
impl TryFrom<u8> for Ecn {
    type Error = NoRecognizedEcnError;

    #[inline]
    fn try_from(value: u8) -> Result<Self, NoRecognizedEcnError> {
        match value {
            0b0000_00_00 => Ok(Ecn::NotEct),
            0b0000_00_01 => Ok(Ecn::Ect1),
            0b0000_00_10 => Ok(Ecn::Ect0),
            0b0000_00_11 => Ok(Ecn::Ce),
            _ => Err(NoRecognizedEcnError { ecn: value }),
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct NoRecognizedEcnError {
    pub ecn: u8,
}

impl core::fmt::Display for NoRecognizedEcnError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(::core::format_args!(
            "Not a valid header value , was: {:?}",
            self.ecn
        ))
    }
}

#[cfg(all(feature = "error_trait", not(feature = "std")))]
impl core::error::Error for NoRecognizedEcnError {}

#[cfg(feature = "std")]
impl std::error::Error for NoRecognizedEcnError {}

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
                assert_eq!(NoRecognizedEcnError { ecn: try_value }, err);
            }
        }
    }
}

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
        f.write_fmt(::core::format_args!("{:?}", self))
    }
}

impl TryFrom<u8> for OptionType {
    type Error = NoRecognizedOptionTypeError;

    #[inline]
    fn try_from(value: u8) -> Result<Self, NoRecognizedOptionTypeError> {
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
            _ => Err(NoRecognizedOptionTypeError { option_type: value }),
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct NoRecognizedOptionTypeError {
    pub option_type: u8,
}

impl core::fmt::Display for NoRecognizedOptionTypeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(::core::format_args!(
            "Not a valid header value , was: {:?}",
            self.option_type
        ))
    }
}

#[cfg(all(feature = "error_trait", not(feature = "std")))]
impl core::error::Error for NoRecognizedOptionTypeError {}

#[cfg(feature = "std")]
impl std::error::Error for NoRecognizedOptionTypeError {}

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
                    NoRecognizedOptionTypeError {
                        option_type: try_value
                    },
                    err
                );
            }
        }
    }
}
