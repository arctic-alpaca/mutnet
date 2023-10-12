//! Constants used to match ether type, internet protocol and IPv6 extensions

use crate::ether_type::EtherType;
use crate::internet_protocol::InternetProtocolNumber;
use crate::ipv6_extensions::Ipv6Extension;

// EtherType
/// Internet Protocol v4
pub(crate) const IPV4: u16 = EtherType::Ipv4 as u16;
/// Address Resolution Protocol
pub(crate) const ARP: u16 = EtherType::Arp as u16;
/// Customer VLAN Tag Type (C-Tag, formerly called the Q-Tag)
pub(crate) const CUSTOMER_TAG_802_1Q: u16 = EtherType::CustomerTag as u16;
/// Internet Protocol v6
pub(crate) const IPV6: u16 = EtherType::Ipv6 as u16;
/// IEEE Std 802.1Q - Service VLAN tag identifier (S-Tag)
pub(crate) const SERVICE_TAG_802_1Q: u16 = EtherType::ServiceTag as u16;

// Internet Protocol
pub(crate) const TCP: u8 = InternetProtocolNumber::Tcp as u8;
pub(crate) const UDP: u8 = InternetProtocolNumber::Udp as u8;

// IPv6 extensions
pub(crate) const FRAGMENTATION_EXT: u8 = Ipv6Extension::Fragment as u8;
pub(crate) const DESTINATION_OPTIONS_EXT: u8 = Ipv6Extension::DestinationOptions as u8;
pub(crate) const HOP_BY_HOP_EXT: u8 = Ipv6Extension::HopByHop as u8;
pub(crate) const ROUTING_EXT: u8 = Ipv6Extension::Routing as u8;
