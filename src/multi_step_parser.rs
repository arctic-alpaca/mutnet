//! Combination of protocol parsing steps into one method.

use crate::arp::Arp;
use crate::data_buffer::DataBuffer;
use crate::error::ParseNetworkDataError;
use crate::ethernet::{Eth, EthernetMethods};
use crate::ieee802_1q_vlan::{Ieee802_1QMethods, Ieee802_1QVlan, Vlan};
use crate::ipv4::{Ipv4, Ipv4Methods};
use crate::ipv6::{Ipv6, Ipv6Methods};
use crate::ipv6_extensions::{Ipv6ExtMethods, Ipv6Extensions};
use crate::tcp::Tcp;
use crate::typed_protocol_headers::constants;
use crate::typed_protocol_headers::Ipv6ExtensionType;
use crate::udp::Udp;

/// Possible results of [`parse_network_data()`].
#[derive(Eq, PartialEq, Hash, Debug)]
pub enum MultiStepParserResult<B, const MAX_EXTENSIONS: usize>
where
    B: AsRef<[u8]>,
{
    /// Ethernet
    Ethernet(DataBuffer<B, Eth>),
    /// Ethernet Vlan
    VlanEth(DataBuffer<B, Ieee802_1QVlan<Eth>>),
    /// Ethernet ARP
    ArpEth(DataBuffer<B, Arp<Eth>>),
    /// Ethernet Vlan Arp
    ArpVlanEth(DataBuffer<B, Arp<Ieee802_1QVlan<Eth>>>),
    /// Ethernet IPv4
    Ipv4Eth(DataBuffer<B, Ipv4<Eth>>),
    /// Ethernet IPv4 Fragment
    FragmentIpv4Eth(DataBuffer<B, Ipv4<Eth>>),
    /// Ethernet IPv4 TCP
    TcpIpv4Eth(DataBuffer<B, Tcp<Ipv4<Eth>>>),
    /// Ethernet IPv4 UDP
    UdpIpv4Eth(DataBuffer<B, Udp<Ipv4<Eth>>>),
    /// Ethernet Vlan IPv4
    Ipv4VlanEth(DataBuffer<B, Ipv4<Ieee802_1QVlan<Eth>>>),
    /// Ethernet Vlan IPv4 Fragment
    FragmentIpv4VlanEth(DataBuffer<B, Ipv4<Ieee802_1QVlan<Eth>>>),
    /// Ethernet Vlan Ipv4 TCP
    TcpIpv4VlanEth(DataBuffer<B, Tcp<Ipv4<Ieee802_1QVlan<Eth>>>>),
    /// Ethernet Vlan Ipv4 UDP
    UdpIpv4VlanEth(DataBuffer<B, Udp<Ipv4<Ieee802_1QVlan<Eth>>>>),
    /// Ethernet IPv6
    Ipv6Eth(DataBuffer<B, Ipv6<Eth>>),
    /// Ethernet IPv6 TCP
    TcpIpv6Eth(DataBuffer<B, Tcp<Ipv6<Eth>>>),
    /// Ethernet IPv6 UDP
    UdpIpv6Eth(DataBuffer<B, Udp<Ipv6<Eth>>>),
    /// Ethernet Vlan IPv6
    Ipv6VlanEth(DataBuffer<B, Ipv6<Ieee802_1QVlan<Eth>>>),
    /// Ethernet Vlan IPv6 TCP
    TcpIpv6VlanEth(DataBuffer<B, Tcp<Ipv6<Ieee802_1QVlan<Eth>>>>),
    /// Ethernet Vlan IPv6 UDP
    UdpIpv6VlanEth(DataBuffer<B, Udp<Ipv6<Ieee802_1QVlan<Eth>>>>),
    /// Ethernet IPv6 IPv6 Extensions
    Ipv6ExtsIpv6Eth(DataBuffer<B, Ipv6Extensions<Ipv6<Eth>, MAX_EXTENSIONS>>),
    /// Ethernet IPv6 IPv6 Extensions (Fragment)
    FragmentIpv6ExtsIpv6Eth(DataBuffer<B, Ipv6Extensions<Ipv6<Eth>, MAX_EXTENSIONS>>),
    /// Ethernet IPv6 IPv6 Extensions TCP
    TcpIpv6ExtsIpv6Eth(DataBuffer<B, Tcp<Ipv6Extensions<Ipv6<Eth>, MAX_EXTENSIONS>>>),
    /// Ethernet IPv6 IPv6 Extensions UDP
    UdpIpv6ExtsIpv6Eth(DataBuffer<B, Udp<Ipv6Extensions<Ipv6<Eth>, MAX_EXTENSIONS>>>),
    /// Ethernet Vlan IPv6 IPv6 Extensions
    Ipv6ExtsIpv6VlanEth(DataBuffer<B, Ipv6Extensions<Ipv6<Ieee802_1QVlan<Eth>>, MAX_EXTENSIONS>>),
    /// Ethernet Vlan IPv6 IPv6 Extensions (Fragment)
    FragmentIpv6ExtsIpv6VlanEth(
        DataBuffer<B, Ipv6Extensions<Ipv6<Ieee802_1QVlan<Eth>>, MAX_EXTENSIONS>>,
    ),
    /// Ethernet Vlan IPv6 IPv6 Extensions TCP
    TcpIpv6ExtsIpv6VlanEth(
        DataBuffer<B, Tcp<Ipv6Extensions<Ipv6<Ieee802_1QVlan<Eth>>, MAX_EXTENSIONS>>>,
    ),
    /// Ethernet Vlan IPv6 IPv6 Extensions UDP
    UdpIpv6ExtsIpv6VlanEth(
        DataBuffer<B, Udp<Ipv6Extensions<Ipv6<Ieee802_1QVlan<Eth>>, MAX_EXTENSIONS>>>,
    ),
}

/// Parses the supplied data into a [`DataBuffer`] with appropriate layers.
///
/// # Errors
///
/// Please see [`ParseNetworkDataError`] for possible errors.
pub fn parse_network_data<B, const MAX_EXTENSIONS: usize>(
    data: B,
    headroom: usize,
    check_ipv4_checksum: bool,
    check_tcp_checksum: bool,
    check_udp_checksum: bool,
) -> Result<MultiStepParserResult<B, MAX_EXTENSIONS>, ParseNetworkDataError>
where
    B: AsRef<[u8]>,
{
    let ethernet = DataBuffer::<_, Eth>::parse_ethernet_layer(data, headroom)?;
    match ethernet.ethernet_ether_type() {
        constants::CUSTOMER_TAG_802_1Q => parse_vlan_eth(
            ethernet,
            check_ipv4_checksum,
            check_tcp_checksum,
            check_udp_checksum,
            Vlan::SingleTagged,
        ),
        constants::SERVICE_TAG_802_1Q => parse_vlan_eth(
            ethernet,
            check_ipv4_checksum,
            check_tcp_checksum,
            check_udp_checksum,
            Vlan::DoubleTagged,
        ),
        constants::ARP => Ok(MultiStepParserResult::ArpEth(
            DataBuffer::<B, Arp<Eth>>::parse_arp_layer(ethernet)?,
        )),
        constants::IPV4 => {
            let ipv4_eth =
                DataBuffer::<B, Ipv4<Eth>>::parse_ipv4_layer(ethernet, check_ipv4_checksum)?;
            if ipv4_eth.ipv4_more_fragments_flag()
                || (!ipv4_eth.ipv4_more_fragments_flag() && ipv4_eth.ipv4_fragment_offset() != 0)
            {
                return Ok(MultiStepParserResult::FragmentIpv4Eth(ipv4_eth));
            }
            match ipv4_eth.ipv4_protocol() {
                constants::TCP => Ok(MultiStepParserResult::TcpIpv4Eth(DataBuffer::<
                    B,
                    Tcp<Ipv4<Eth>>,
                >::parse_tcp_layer(
                    ipv4_eth,
                    check_tcp_checksum,
                )?)),
                constants::UDP => Ok(MultiStepParserResult::UdpIpv4Eth(DataBuffer::<
                    B,
                    Udp<Ipv4<Eth>>,
                >::parse_udp_layer(
                    ipv4_eth,
                    check_udp_checksum,
                )?)),
                _ => Ok(MultiStepParserResult::Ipv4Eth(ipv4_eth)),
            }
        }
        constants::IPV6 => {
            let ipv6_eth = DataBuffer::<B, Ipv6<Eth>>::parse_ipv6_layer(ethernet)?;
            match ipv6_eth.ipv6_next_header() {
                constants::TCP => Ok(MultiStepParserResult::TcpIpv6Eth(DataBuffer::<
                    B,
                    Tcp<Ipv6<Eth>>,
                >::parse_tcp_layer(
                    ipv6_eth,
                    check_tcp_checksum,
                )?)),
                constants::UDP => Ok(MultiStepParserResult::UdpIpv6Eth(DataBuffer::<
                    B,
                    Udp<Ipv6<Eth>>,
                >::parse_udp_layer(
                    ipv6_eth,
                    check_udp_checksum,
                )?)),
                constants::FRAGMENT_EXT => parse_ipv6_ext(
                    ipv6_eth,
                    check_tcp_checksum,
                    check_udp_checksum,
                    Ipv6ExtensionType::Fragment,
                ),
                constants::DESTINATION_OPTIONS_EXT => parse_ipv6_ext(
                    ipv6_eth,
                    check_tcp_checksum,
                    check_udp_checksum,
                    Ipv6ExtensionType::DestinationOptions,
                ),
                constants::HOP_BY_HOP_EXT => parse_ipv6_ext(
                    ipv6_eth,
                    check_tcp_checksum,
                    check_udp_checksum,
                    Ipv6ExtensionType::HopByHop,
                ),
                constants::ROUTING_EXT => parse_ipv6_ext(
                    ipv6_eth,
                    check_tcp_checksum,
                    check_udp_checksum,
                    Ipv6ExtensionType::Routing,
                ),
                _ => Ok(MultiStepParserResult::Ipv6Eth(ipv6_eth)),
            }
        }

        _ => Ok(MultiStepParserResult::Ethernet(ethernet)),
    }
}

#[inline]
fn parse_ipv6_ext_vlan<B, const MAX_EXTENSIONS: usize>(
    ipv6_vlan_eth: DataBuffer<B, Ipv6<Ieee802_1QVlan<Eth>>>,
    check_tcp_checksum: bool,
    check_udp_checksum: bool,
    first_extension: Ipv6ExtensionType,
) -> Result<MultiStepParserResult<B, MAX_EXTENSIONS>, ParseNetworkDataError>
where
    B: AsRef<[u8]>,
{
    let (ipv6exts_ipv6_vlan_eth, has_fragment) = DataBuffer::<
        B,
        Ipv6Extensions<Ipv6<Ieee802_1QVlan<Eth>>, MAX_EXTENSIONS>,
    >::parse_ipv6_extensions_layer(
        ipv6_vlan_eth, first_extension
    )?;
    if has_fragment {
        return Ok(MultiStepParserResult::FragmentIpv6ExtsIpv6VlanEth(
            ipv6exts_ipv6_vlan_eth,
        ));
    }
    match ipv6exts_ipv6_vlan_eth.ipv6_ext_next_header() {
        Ok(constants::TCP) => Ok(
            MultiStepParserResult::TcpIpv6ExtsIpv6VlanEth(DataBuffer::<
                B,
                Tcp<Ipv6Extensions<Ipv6<Ieee802_1QVlan<Eth>>, MAX_EXTENSIONS>>,
            >::parse_tcp_layer(
                ipv6exts_ipv6_vlan_eth,
                check_tcp_checksum,
            )?),
        ),
        Ok(constants::UDP) => Ok(
            MultiStepParserResult::UdpIpv6ExtsIpv6VlanEth(DataBuffer::<
                B,
                Udp<Ipv6Extensions<Ipv6<Ieee802_1QVlan<Eth>>, MAX_EXTENSIONS>>,
            >::parse_udp_layer(
                ipv6exts_ipv6_vlan_eth,
                check_udp_checksum,
            )?),
        ),
        _ => Ok(MultiStepParserResult::Ipv6ExtsIpv6VlanEth(
            ipv6exts_ipv6_vlan_eth,
        )),
    }
}

#[inline]
fn parse_ipv6_ext<B, const MAX_EXTENSIONS: usize>(
    ipv6_eth: DataBuffer<B, Ipv6<Eth>>,
    check_tcp_checksum: bool,
    check_udp_checksum: bool,
    first_extension: Ipv6ExtensionType,
) -> Result<MultiStepParserResult<B, MAX_EXTENSIONS>, ParseNetworkDataError>
where
    B: AsRef<[u8]>,
{
    let (ipv6_exts_ipv6_eth, has_fragment) =
        DataBuffer::<B, Ipv6Extensions<Ipv6<Eth>, MAX_EXTENSIONS>>::parse_ipv6_extensions_layer(
            ipv6_eth,
            first_extension,
        )?;
    if has_fragment {
        return Ok(MultiStepParserResult::FragmentIpv6ExtsIpv6Eth(
            ipv6_exts_ipv6_eth,
        ));
    }

    match ipv6_exts_ipv6_eth.ipv6_ext_next_header() {
        Ok(constants::TCP) => Ok(MultiStepParserResult::TcpIpv6ExtsIpv6Eth(DataBuffer::<
            B,
            Tcp<Ipv6Extensions<Ipv6<Eth>, MAX_EXTENSIONS>>,
        >::parse_tcp_layer(
            ipv6_exts_ipv6_eth,
            check_tcp_checksum,
        )?)),
        Ok(constants::UDP) => Ok(MultiStepParserResult::UdpIpv6ExtsIpv6Eth(DataBuffer::<
            B,
            Udp<Ipv6Extensions<Ipv6<Eth>, MAX_EXTENSIONS>>,
        >::parse_udp_layer(
            ipv6_exts_ipv6_eth,
            check_udp_checksum,
        )?)),
        _ => Ok(MultiStepParserResult::Ipv6ExtsIpv6Eth(ipv6_exts_ipv6_eth)),
    }
}

#[inline]
fn parse_vlan_eth<B, const MAX_EXTENSIONS: usize>(
    ethernet: DataBuffer<B, Eth>,
    check_ipv4_checksum: bool,
    check_tcp_checksum: bool,
    check_udp_checksum: bool,
    vlan: Vlan,
) -> Result<MultiStepParserResult<B, MAX_EXTENSIONS>, ParseNetworkDataError>
where
    B: AsRef<[u8]>,
{
    let vlan_eth = DataBuffer::<B, Ieee802_1QVlan<Eth>>::parse_ieee802_1q_layer(ethernet, vlan)?;
    match vlan_eth.ieee802_1q_ether_type() {
        constants::ARP => Ok(MultiStepParserResult::ArpVlanEth(DataBuffer::<
            B,
            Arp<Ieee802_1QVlan<Eth>>,
        >::parse_arp_layer(
            vlan_eth
        )?)),
        constants::IPV4 => {
            let ipv4_vlan_eth = DataBuffer::<B, Ipv4<Ieee802_1QVlan<Eth>>>::parse_ipv4_layer(
                vlan_eth,
                check_ipv4_checksum,
            )?;
            if ipv4_vlan_eth.ipv4_more_fragments_flag()
                || (!ipv4_vlan_eth.ipv4_more_fragments_flag()
                    && ipv4_vlan_eth.ipv4_fragment_offset() != 0)
            {
                return Ok(MultiStepParserResult::FragmentIpv4VlanEth(ipv4_vlan_eth));
            }
            match ipv4_vlan_eth.ipv4_protocol() {
                constants::TCP => Ok(MultiStepParserResult::TcpIpv4VlanEth(DataBuffer::<
                    B,
                    Tcp<Ipv4<Ieee802_1QVlan<Eth>>>,
                >::parse_tcp_layer(
                    ipv4_vlan_eth,
                    check_tcp_checksum,
                )?)),
                constants::UDP => Ok(MultiStepParserResult::UdpIpv4VlanEth(DataBuffer::<
                    B,
                    Udp<Ipv4<Ieee802_1QVlan<Eth>>>,
                >::parse_udp_layer(
                    ipv4_vlan_eth,
                    check_udp_checksum,
                )?)),
                _ => Ok(MultiStepParserResult::Ipv4VlanEth(ipv4_vlan_eth)),
            }
        }
        constants::IPV6 => {
            let ipv6_vlan_eth =
                DataBuffer::<B, Ipv6<Ieee802_1QVlan<Eth>>>::parse_ipv6_layer(vlan_eth)?;
            match ipv6_vlan_eth.ipv6_next_header() {
                constants::TCP => Ok(MultiStepParserResult::TcpIpv6VlanEth(DataBuffer::<
                    B,
                    Tcp<Ipv6<Ieee802_1QVlan<Eth>>>,
                >::parse_tcp_layer(
                    ipv6_vlan_eth,
                    check_tcp_checksum,
                )?)),
                constants::UDP => Ok(MultiStepParserResult::UdpIpv6VlanEth(DataBuffer::<
                    B,
                    Udp<Ipv6<Ieee802_1QVlan<Eth>>>,
                >::parse_udp_layer(
                    ipv6_vlan_eth,
                    check_udp_checksum,
                )?)),
                constants::FRAGMENT_EXT => parse_ipv6_ext_vlan(
                    ipv6_vlan_eth,
                    check_tcp_checksum,
                    check_udp_checksum,
                    Ipv6ExtensionType::Fragment,
                ),
                constants::DESTINATION_OPTIONS_EXT => parse_ipv6_ext_vlan(
                    ipv6_vlan_eth,
                    check_tcp_checksum,
                    check_udp_checksum,
                    Ipv6ExtensionType::DestinationOptions,
                ),
                constants::HOP_BY_HOP_EXT => parse_ipv6_ext_vlan(
                    ipv6_vlan_eth,
                    check_tcp_checksum,
                    check_udp_checksum,
                    Ipv6ExtensionType::HopByHop,
                ),
                constants::ROUTING_EXT => parse_ipv6_ext_vlan(
                    ipv6_vlan_eth,
                    check_tcp_checksum,
                    check_udp_checksum,
                    Ipv6ExtensionType::Routing,
                ),
                _ => Ok(MultiStepParserResult::Ipv6VlanEth(ipv6_vlan_eth)),
            }
        }
        _ => Ok(MultiStepParserResult::VlanEth(vlan_eth)),
    }
}
