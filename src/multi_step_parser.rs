use crate::arp::Arp;
use crate::constants::*;
use crate::data_buffer::DataBuffer;
use crate::error::ParseNetworkDataError;
use crate::ethernet::{Eth, EthernetMethods};
use crate::ieee802_1q_vlan::{Ieee802_1QMethods, Ieee802_1QVlan};
use crate::ipv4::{Ipv4, Ipv4Methods};
use crate::ipv6::{Ipv6, Ipv6Methods};
use crate::ipv6_extensions::{Ipv6ExtMethods, Ipv6Extension, Ipv6Extensions};
use crate::tcp::Tcp;
use crate::vlan::Vlan;

pub enum EthernetMultiStepParserResult<B, const MAX_EXTENSIONS: usize>
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
    /// Ethernet IPv4 TCP
    TcpIpv4Eth(DataBuffer<B, Tcp<Ipv4<Eth>>>),
    /// Ethernet Vlan IPv4
    Ipv4VlanEth(DataBuffer<B, Ipv4<Ieee802_1QVlan<Eth>>>),
    /// Ethernet Vlan Ipv4 Tcp
    TcpIpv4VlanEth(DataBuffer<B, Tcp<Ipv4<Ieee802_1QVlan<Eth>>>>),
    /// Ethernet IPv6
    Ipv6Eth(DataBuffer<B, Ipv6<Eth>>),
    /// Ethernet IPv6 TCP
    TcpIpv6Eth(DataBuffer<B, Tcp<Ipv6<Eth>>>),
    /// Ethernet Vlan IPv6
    Ipv6VlanEth(DataBuffer<B, Ipv6<Ieee802_1QVlan<Eth>>>),
    /// Ethernet Vlan IPv6 Tcp
    TcpIpv6VlanEth(DataBuffer<B, Tcp<Ipv6<Ieee802_1QVlan<Eth>>>>),
    /// Ethernet IPv6 IPv6 Extensions
    Ipv6ExtsIpv6Eth(DataBuffer<B, Ipv6Extensions<Ipv6<Eth>, MAX_EXTENSIONS>>),
    /// Ethernet IPv6 IPv6 Extensions (Fragment)
    FragmentIpv6ExtsIpv6Eth(DataBuffer<B, Ipv6Extensions<Ipv6<Eth>, MAX_EXTENSIONS>>),
    /// Ethernet IPv6 IPv6 Extensions Tcp
    TcpIpv6ExtsIpv6Eth(DataBuffer<B, Tcp<Ipv6Extensions<Ipv6<Eth>, MAX_EXTENSIONS>>>),
    /// Ethernet Vlan IPv6 IPv6 Extensions
    Ipv6ExtsIpv6VlanEth(DataBuffer<B, Ipv6Extensions<Ipv6<Ieee802_1QVlan<Eth>>, MAX_EXTENSIONS>>),
    /// Ethernet Vlan IPv6 IPv6 Extensions (Fragment)
    FragmentIpv6ExtsIpv6VlanEth(
        DataBuffer<B, Ipv6Extensions<Ipv6<Ieee802_1QVlan<Eth>>, MAX_EXTENSIONS>>,
    ),
    /// Ethernet Vlan IPv6 IPv6 Extensions Tcp
    TcpIpv6ExtsIpv6VlanEth(
        DataBuffer<B, Tcp<Ipv6Extensions<Ipv6<Ieee802_1QVlan<Eth>>, MAX_EXTENSIONS>>>,
    ),
}

pub fn parse_network_data<B, const MAX_EXTENSIONS: usize>(
    data: B,
    headroom: usize,
    check_ipv4_checksum: bool,
    check_tcp_checksum: bool,
) -> Result<EthernetMultiStepParserResult<B, MAX_EXTENSIONS>, ParseNetworkDataError>
where
    B: AsRef<[u8]>,
{
    let ethernet = DataBuffer::<_, Eth>::new(data, headroom)?;
    match ethernet.ethernet_ether_type() {
        CUSTOMER_TAG_802_1Q => parse_vlan_eth(
            ethernet,
            check_ipv4_checksum,
            check_tcp_checksum,
            Vlan::SingleTagged,
        ),
        SERVICE_TAG_802_1Q => parse_vlan_eth(
            ethernet,
            check_ipv4_checksum,
            check_tcp_checksum,
            Vlan::DoubleTagged,
        ),
        ARP => Ok(EthernetMultiStepParserResult::ArpEth(DataBuffer::<
            B,
            Arp<Eth>,
        >::new_from_lower(
            ethernet
        )?)),
        IPV4 => {
            let ipv4_eth =
                DataBuffer::<B, Ipv4<Eth>>::new_from_lower(ethernet, check_ipv4_checksum)?;
            match ipv4_eth.ipv4_protocol() {
                TCP => Ok(EthernetMultiStepParserResult::TcpIpv4Eth(DataBuffer::<
                    B,
                    Tcp<Ipv4<Eth>>,
                >::new_from_lower(
                    ipv4_eth,
                    check_tcp_checksum,
                )?)),
                _ => Ok(EthernetMultiStepParserResult::Ipv4Eth(ipv4_eth)),
            }
        }
        IPV6 => {
            let ipv6_eth = DataBuffer::<B, Ipv6<Eth>>::new_from_lower(ethernet)?;
            match ipv6_eth.ipv6_next_header() {
                TCP => Ok(EthernetMultiStepParserResult::TcpIpv6Eth(DataBuffer::<
                    B,
                    Tcp<Ipv6<Eth>>,
                >::new_from_lower(
                    ipv6_eth,
                    check_tcp_checksum,
                )?)),
                FRAGMENTATION_EXT => {
                    parse_ipv6_ext(ipv6_eth, check_tcp_checksum, Ipv6Extension::Fragment)
                }
                DESTINATION_OPTIONS_EXT => parse_ipv6_ext(
                    ipv6_eth,
                    check_tcp_checksum,
                    Ipv6Extension::DestinationOptions,
                ),
                HOP_BY_HOP_EXT => {
                    parse_ipv6_ext(ipv6_eth, check_tcp_checksum, Ipv6Extension::HopByHop)
                }
                ROUTING_EXT => parse_ipv6_ext(ipv6_eth, check_tcp_checksum, Ipv6Extension::Routing),
                _ => Ok(EthernetMultiStepParserResult::Ipv6Eth(ipv6_eth)),
            }
        }

        _ => Ok(EthernetMultiStepParserResult::Ethernet(ethernet)),
    }
}

#[inline]
fn parse_ipv6_ext_vlan<B, const MAX_EXTENSIONS: usize>(
    ipv6_vlan_eth: DataBuffer<B, Ipv6<Ieee802_1QVlan<Eth>>>,
    check_tcp_checksum: bool,
    first_extension: Ipv6Extension,
) -> Result<EthernetMultiStepParserResult<B, MAX_EXTENSIONS>, ParseNetworkDataError>
where
    B: AsRef<[u8]>,
{
    let (ipv6exts_ipv6_vlan_eth, has_fragment) =
        DataBuffer::<B, Ipv6Extensions<Ipv6<Ieee802_1QVlan<Eth>>, MAX_EXTENSIONS>>::new_from_lower(
            ipv6_vlan_eth,
            first_extension,
        )?;
    if has_fragment {
        return Ok(EthernetMultiStepParserResult::FragmentIpv6ExtsIpv6VlanEth(
            ipv6exts_ipv6_vlan_eth,
        ));
    }
    match ipv6exts_ipv6_vlan_eth.ipv6_ext_next_header() {
        Ok(TCP) => Ok(
            EthernetMultiStepParserResult::TcpIpv6ExtsIpv6VlanEth(DataBuffer::<
                B,
                Tcp<Ipv6Extensions<Ipv6<Ieee802_1QVlan<Eth>>, MAX_EXTENSIONS>>,
            >::new_from_lower(
                ipv6exts_ipv6_vlan_eth,
                check_tcp_checksum,
            )?),
        ),
        _ => Ok(EthernetMultiStepParserResult::Ipv6ExtsIpv6VlanEth(
            ipv6exts_ipv6_vlan_eth,
        )),
    }
}

#[inline]
fn parse_ipv6_ext<B, const MAX_EXTENSIONS: usize>(
    ipv6_eth: DataBuffer<B, Ipv6<Eth>>,
    check_tcp_checksum: bool,
    first_extension: Ipv6Extension,
) -> Result<EthernetMultiStepParserResult<B, MAX_EXTENSIONS>, ParseNetworkDataError>
where
    B: AsRef<[u8]>,
{
    let (ipv6exts_ipv6_eth, has_fragment) = DataBuffer::<
        B,
        Ipv6Extensions<Ipv6<Eth>, MAX_EXTENSIONS>,
    >::new_from_lower(ipv6_eth, first_extension)?;
    if has_fragment {
        return Ok(EthernetMultiStepParserResult::FragmentIpv6ExtsIpv6Eth(
            ipv6exts_ipv6_eth,
        ));
    }

    match ipv6exts_ipv6_eth.ipv6_ext_next_header() {
        Ok(TCP) => Ok(EthernetMultiStepParserResult::TcpIpv6ExtsIpv6Eth(
            DataBuffer::<B, Tcp<Ipv6Extensions<Ipv6<Eth>, MAX_EXTENSIONS>>>::new_from_lower(
                ipv6exts_ipv6_eth,
                check_tcp_checksum,
            )?,
        )),
        _ => Ok(EthernetMultiStepParserResult::Ipv6ExtsIpv6Eth(
            ipv6exts_ipv6_eth,
        )),
    }
}

#[inline]
fn parse_vlan_eth<B, const MAX_EXTENSIONS: usize>(
    ethernet: DataBuffer<B, Eth>,
    check_ipv4_checksum: bool,
    check_tcp_checksum: bool,
    vlan: Vlan,
) -> Result<EthernetMultiStepParserResult<B, MAX_EXTENSIONS>, ParseNetworkDataError>
where
    B: AsRef<[u8]>,
{
    let vlan_eth = DataBuffer::<B, Ieee802_1QVlan<Eth>>::new_from_lower(ethernet, vlan)?;
    match vlan_eth.ieee802_1q_ether_type() {
        ARP => Ok(EthernetMultiStepParserResult::ArpVlanEth(DataBuffer::<
            B,
            Arp<Ieee802_1QVlan<Eth>>,
        >::new_from_lower(
            vlan_eth
        )?)),
        IPV4 => {
            let ipv4_vlan_eth = DataBuffer::<B, Ipv4<Ieee802_1QVlan<Eth>>>::new_from_lower(
                vlan_eth,
                check_ipv4_checksum,
            )?;
            match ipv4_vlan_eth.ipv4_protocol() {
                TCP => Ok(EthernetMultiStepParserResult::TcpIpv4VlanEth(
                    DataBuffer::<B, Tcp<Ipv4<Ieee802_1QVlan<Eth>>>>::new_from_lower(
                        ipv4_vlan_eth,
                        check_tcp_checksum,
                    )?,
                )),
                _ => Ok(EthernetMultiStepParserResult::Ipv4VlanEth(ipv4_vlan_eth)),
            }
        }
        IPV6 => {
            let ipv6_vlan_eth =
                DataBuffer::<B, Ipv6<Ieee802_1QVlan<Eth>>>::new_from_lower(vlan_eth)?;
            match ipv6_vlan_eth.ipv6_next_header() {
                TCP => Ok(EthernetMultiStepParserResult::TcpIpv6VlanEth(
                    DataBuffer::<B, Tcp<Ipv6<Ieee802_1QVlan<Eth>>>>::new_from_lower(
                        ipv6_vlan_eth,
                        check_tcp_checksum,
                    )?,
                )),
                FRAGMENTATION_EXT => {
                    parse_ipv6_ext_vlan(ipv6_vlan_eth, check_tcp_checksum, Ipv6Extension::Fragment)
                }
                DESTINATION_OPTIONS_EXT => parse_ipv6_ext_vlan(
                    ipv6_vlan_eth,
                    check_tcp_checksum,
                    Ipv6Extension::DestinationOptions,
                ),
                HOP_BY_HOP_EXT => {
                    parse_ipv6_ext_vlan(ipv6_vlan_eth, check_tcp_checksum, Ipv6Extension::HopByHop)
                }
                ROUTING_EXT => {
                    parse_ipv6_ext_vlan(ipv6_vlan_eth, check_tcp_checksum, Ipv6Extension::Routing)
                }
                _ => Ok(EthernetMultiStepParserResult::Ipv6VlanEth(ipv6_vlan_eth)),
            }
        }
        _ => Ok(EthernetMultiStepParserResult::VlanEth(vlan_eth)),
    }
}