/// Sources:
/// <https://en.wikipedia.org/wiki/EtherType>
/// <https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml>
/// <https://standards-oui.ieee.org/ethertype/eth.txt>
#[repr(u16)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum EtherType {
    /// Internet Protocol v4
    Ipv4 = 0x0800,
    /// Address Resolution Protocol
    Arp = 0x0806,
    /// Wake on lan
    WakeOnLan = 0x0842,
    /// Audio Video Transport Protocol
    Avtp = 0x22F0,
    /// Stream Reservation Protocol
    Srp = 0x22EA,
    /// Reverse Address Resolution Protocol
    Rarp = 0x8035,
    /// Apple talk
    AppleTalk = 0x809B,
    /// AppleTalk Address Resolution Protocol
    Aarp = 0x80F3,
    /// Customer VLAN Tag Type (C-Tag, formerly called the Q-Tag)
    CustomerTag = 0x8100,
    ///Simple Loop Prevention Protocol
    Slpp = 0x8102,
    /// Virtual Link Aggregation Control Protocol
    Vlacp = 0x8103,
    /// Internetwork Packet Exchange
    Ipx = 0x8137,
    /// QNX Qnet
    QnxQnet = 0x8204,
    /// Internet Protocol v6
    Ipv6 = 0x86DD,
    /// Ethernet flow control
    EthernetFlowControl = 0x8808,
    /// Ethernet slow protocols
    EthernetSlowProtocols = 0x8809,
    /// CobraNet
    CobraNet = 0x8819,
    /// MPLS unicast
    MplsUnicast = 0x8847,
    /// MPLS multicast
    MplsMulticast = 0x8848,
    /// PPPOE discovery stage
    PppoeDiscoveryStage = 0x8863,
    /// PPPOE session stage
    PppoeSessionStage = 0x8864,
    /// HomePlug 1.0 MME
    HomePlug1_0Mme = 0x887B,
    /// EAP over LAN
    EapOverLan = 0x888E,
    /// PROFINET
    Profinet = 0x8892,
    ///HyperSCSI
    HyperScsi = 0x889A,
    /// ATA over ethernet
    AtaOverEthernet = 0x88A2,
    /// EtherCAT
    EtherCat = 0x88A4,
    /// IEEE Std 802.1Q - Service VLAN tag identifier (S-Tag)
    ServiceTag = 0x88A8,
    /// Ethernet powerlink
    EthernetPowerlink = 0x88AB,
    /// Generic Object Oriented Substation Event
    Goose = 0x88B8,
    /// Generic Substation Events Management Services
    GseManagementServices = 0x88B9,
    /// Sampled Value
    Sv = 0x88BA,
    /// Link Layer Discovery Protocol
    Lldp = 0x88CC,
    /// SERCOS III
    Sercos3 = 0x88CD,
    /// HomePlug green PHY
    HomePlugGreenPhy = 0x88E1,
    /// Media redundancy protocol
    MediaRedundancyProtocol = 0x88E3,
    /// MACsec
    MacSec = 0x88E5,
    /// Provider Backbone Bridges
    Pbb = 0x88E7,
    /// Precision Time Protocol
    Ptp = 0x88F7,
    /// Network Controller Sideband Interface
    NcSi = 0x88F8,
    /// Parallel Redundancy Protocol
    Prp = 0x88FB,
    /// Fibre Channel Over Ethernet
    Fcoe = 0x8906,
    /// Mediaxtream
    Mediaxtream = 0x8912,
    /// Fibre Channel Over Ethernet Initialization Protocol
    FcoeInitializationProtocol = 0x8914,
    /// RDMA over Converged Ethernet
    Roce = 0x8915,
    /// TTEthernet Protocol Control Frame
    Tte = 0x891D,
    /// High-Availability Seamless Redundancy
    Hsr = 0x892F,
    /// Ethernet configuration testing protocol
    EthernetConfigurationTestingProtocol = 0x9000,
    /// Redundancy Tag (IEEE 802.1CB)
    RTag = 0xF1C1,
}

impl core::fmt::Display for EtherType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Error returned by [`EtherType::try_from()`].
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct UnrecognizedEtherTypeError {
    /// The unrecognized ether type.
    pub ether_type: u16,
}

impl core::fmt::Display for UnrecognizedEtherTypeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Unrecognized ether type, was: {:?}", self.ether_type)
    }
}

#[cfg(all(feature = "error_trait", not(feature = "std")))]
impl core::error::Error for UnrecognizedEtherTypeError {}

#[cfg(feature = "std")]
impl std::error::Error for UnrecognizedEtherTypeError {}

impl TryFrom<u16> for EtherType {
    type Error = UnrecognizedEtherTypeError;
    #[inline]
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0800 => Ok(EtherType::Ipv4),
            0x0806 => Ok(EtherType::Arp),
            0x0842 => Ok(EtherType::WakeOnLan),
            0x22F0 => Ok(EtherType::Avtp),
            0x22EA => Ok(EtherType::Srp),
            0x8035 => Ok(EtherType::Rarp),
            0x809B => Ok(EtherType::AppleTalk),
            0x80F3 => Ok(EtherType::Aarp),
            0x8100 => Ok(EtherType::CustomerTag),
            0x8102 => Ok(EtherType::Slpp),
            0x8103 => Ok(EtherType::Vlacp),
            0x8137 => Ok(EtherType::Ipx),
            0x8204 => Ok(EtherType::QnxQnet),
            0x86DD => Ok(EtherType::Ipv6),
            0x8808 => Ok(EtherType::EthernetFlowControl),
            0x8809 => Ok(EtherType::EthernetSlowProtocols),
            0x8819 => Ok(EtherType::CobraNet),
            0x8847 => Ok(EtherType::MplsUnicast),
            0x8848 => Ok(EtherType::MplsMulticast),
            0x8863 => Ok(EtherType::PppoeDiscoveryStage),
            0x8864 => Ok(EtherType::PppoeSessionStage),
            0x887B => Ok(EtherType::HomePlug1_0Mme),
            0x888E => Ok(EtherType::EapOverLan),
            0x8892 => Ok(EtherType::Profinet),
            0x889A => Ok(EtherType::HyperScsi),
            0x88A2 => Ok(EtherType::AtaOverEthernet),
            0x88A4 => Ok(EtherType::EtherCat),
            0x88A8 => Ok(EtherType::ServiceTag),
            0x88AB => Ok(EtherType::EthernetPowerlink),
            0x88B8 => Ok(EtherType::Goose),
            0x88B9 => Ok(EtherType::GseManagementServices),
            0x88BA => Ok(EtherType::Sv),
            0x88CC => Ok(EtherType::Lldp),
            0x88CD => Ok(EtherType::Sercos3),
            0x88E1 => Ok(EtherType::HomePlugGreenPhy),
            0x88E3 => Ok(EtherType::MediaRedundancyProtocol),
            0x88E5 => Ok(EtherType::MacSec),
            0x88E7 => Ok(EtherType::Pbb),
            0x88F7 => Ok(EtherType::Ptp),
            0x88F8 => Ok(EtherType::NcSi),
            0x88FB => Ok(EtherType::Prp),
            0x8906 => Ok(EtherType::Fcoe),
            0x8912 => Ok(EtherType::Mediaxtream),
            0x8914 => Ok(EtherType::FcoeInitializationProtocol),
            0x8915 => Ok(EtherType::Roce),
            0x891D => Ok(EtherType::Tte),
            0x892F => Ok(EtherType::Hsr),
            0x9000 => Ok(EtherType::EthernetConfigurationTestingProtocol),
            0xF1C1 => Ok(EtherType::RTag),

            _ => Err(UnrecognizedEtherTypeError { ether_type: value }),
        }
    }
}

// Kani verification to ensure the code does not panic on any input.
#[cfg(kani)]
mod ether_type_verification {
    use super::*;

    #[kani::proof]
    fn ether_type_proof() {
        let try_value = kani::any::<u16>();
        match EtherType::try_from(try_value) {
            Ok(ether_type) => {
                assert_eq!(ether_type as u16, try_value);
            }
            Err(err) => {
                assert_eq!(
                    UnrecognizedEtherTypeError {
                        ether_type: try_value
                    },
                    err
                );
            }
        }
    }
}
