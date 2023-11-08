use crate::typed_protocol_headers::{EtherType, InternetProtocolNumber, Ipv6ExtensionType};

// EtherType
/// IPv4 ether type.
pub(crate) const IPV4: u16 = EtherType::Ipv4 as u16;
/// ARP ether type.
pub(crate) const ARP: u16 = EtherType::Arp as u16;
/// Customer VLAN tag ether type (IEEE Std 802.1Q).
pub(crate) const CUSTOMER_TAG_802_1Q: u16 = EtherType::CustomerTag as u16;
/// IPv6 ether type.
pub(crate) const IPV6: u16 = EtherType::Ipv6 as u16;
/// Service VLAN tag ether type (IEEE Std 802.1Q).
pub(crate) const SERVICE_TAG_802_1Q: u16 = EtherType::ServiceTag as u16;

// Internet Protocol
/// TCP internet protocol number.
pub(crate) const TCP: u8 = InternetProtocolNumber::Tcp as u8;
/// UDP internet protocol number.
pub(crate) const UDP: u8 = InternetProtocolNumber::Udp as u8;

// IPv6 extensions
/// IPv6 fragment extension header internet protocol number.
pub(crate) const FRAGMENT_EXT: u8 = Ipv6ExtensionType::Fragment as u8;
/// IPv6 destination options extension header internet protocol number.
pub(crate) const DESTINATION_OPTIONS_EXT: u8 = Ipv6ExtensionType::DestinationOptions as u8;
/// IPv6 hop-by-hop extension header internet protocol number.
pub(crate) const HOP_BY_HOP_EXT: u8 = Ipv6ExtensionType::HopByHop as u8;
/// IPv6 routing extension header internet protocol number.
pub(crate) const ROUTING_EXT: u8 = Ipv6ExtensionType::Routing as u8;
