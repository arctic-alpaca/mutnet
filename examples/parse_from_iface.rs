// Formatting and printing data to the default output may lead to dropped packets as this can be slow.
// This example should not be used to judge performance but rather to see how mutnet can be used.

use std::error::Error;
use std::fmt;
use std::fmt::Display;
use std::io::{stdout, Write};
use std::net::{Ipv4Addr, Ipv6Addr};

use mutnet::arp::ArpMethods;
use mutnet::ethernet::EthernetMethods;
use mutnet::ipv4::Ipv4Methods;
use mutnet::ipv6::Ipv6Methods;
use mutnet::multi_step_parser::{parse_network_data, MultiStepParserResult};
use mutnet::tcp::TcpMethods;
use mutnet::typed_protocol_headers::EtherType;
use mutnet::typed_protocol_headers::InternetProtocolNumber;
use mutnet::typed_protocol_headers::OperationCode;
use mutnet::udp::UdpMethods;

#[derive(Debug, Default)]
struct Data {
    dropped_packets: u32,
    eth_ether_type: Option<EtherType>,
    arp_op_code: Option<OperationCode>,
    arp_sender_prot_addr: Option<Ipv4Addr>,
    ipv4_prot: Option<InternetProtocolNumber>,
    ipv4_src: Option<Ipv4Addr>,
    ipv4_dst: Option<Ipv4Addr>,
    ipv6_next_hdr: Option<InternetProtocolNumber>,
    ipv6_src: Option<Ipv6Addr>,
    ipv6_dst: Option<Ipv6Addr>,
    fragment: Option<bool>,
    tcp_source_port: Option<u16>,
    tcp_destination_port: Option<u16>,
    udp_source_port: Option<u16>,
    udp_destination_port: Option<u16>,
    err: Option<Box<dyn Error + Send>>,
}

impl Display for Data {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(eth_ether_type) = self.eth_ether_type {
            writeln!(f, "Ethernet ether type: {eth_ether_type}")?;
        }
        if let Some(arp_op_code) = self.arp_op_code {
            writeln!(f, "ARP operation code: {arp_op_code}")?;
        }
        if let Some(arp_sender_prot_addr) = self.arp_sender_prot_addr {
            writeln!(f, "ARP sender protocol address: {arp_sender_prot_addr:?}")?;
        }
        if let Some(ipv4_prot) = self.ipv4_prot {
            writeln!(f, "IPv4 protocol: {ipv4_prot:?}")?;
        }
        if let Some(ipv4_src) = self.ipv4_src {
            writeln!(f, "IPv4 source: {ipv4_src:?}")?;
        }
        if let Some(ipv4_dst) = self.ipv4_dst {
            writeln!(f, "IPv4 destination: {ipv4_dst:?}")?;
        }
        if let Some(ipv6_next_hdr) = self.ipv6_next_hdr {
            writeln!(f, "IPv6 next header: {ipv6_next_hdr:?}")?;
        }
        if let Some(ipv6_src) = self.ipv6_src {
            writeln!(f, "IPv6 source: {ipv6_src:?}")?;
        }
        if let Some(ipv6_dst) = self.ipv6_dst {
            writeln!(f, "IPv6 destination: {ipv6_dst:?}")?;
        }
        if let Some(fragment) = self.fragment {
            writeln!(f, "Fragment: {fragment}")?;
        }
        if let Some(tcp_source_port) = self.tcp_source_port {
            writeln!(f, "TCP source port: {tcp_source_port}")?;
        }
        if let Some(tcp_destination_port) = self.tcp_destination_port {
            writeln!(f, "TCP destination port: {tcp_destination_port}")?;
        }
        if let Some(udp_source_port) = self.udp_source_port {
            writeln!(f, "UDP source port: {udp_source_port}")?;
        }
        if let Some(udp_destination_port) = self.udp_destination_port {
            writeln!(f, "UDP destination port: {udp_destination_port}")?;
        }
        if let Some(err) = &self.err {
            writeln!(f, "ERROR: {err:?}")?;
        }

        writeln!(f, "Dropped packets {}", self.dropped_packets)?;
        writeln!(f, "------------------")
    }
}

fn main() {
    let device = pcap::Device::lookup().unwrap().unwrap();

    let mut cap = pcap::Capture::from_device(device)
        .unwrap()
        .immediate_mode(true)
        .open()
        .unwrap();

    let mut lock = stdout().lock();
    loop {
        let mut output = Data {
            dropped_packets: cap.stats().unwrap().dropped,
            ..Default::default()
        };

        match cap.next_packet() {
            Ok(packet) => {
                // Skip checksum validation to allow capturing outgoing data even when checksum offloading
                // is active. Checksum offloading offloads the checksum calculation to the hardware
                // results in invalid checksums on the software level for outgoing data.
                match parse_network_data::<_, 10>(packet.data, 0, false, false, false) {
                    Ok(MultiStepParserResult::Ethernet(data_buffer)) => {
                        log_ethernet(&data_buffer, &mut output);
                    }
                    Ok(MultiStepParserResult::VlanEth(data_buffer)) => {
                        log_ethernet(&data_buffer, &mut output);
                    }
                    Ok(MultiStepParserResult::ArpEth(data_buffer)) => {
                        log_ethernet(&data_buffer, &mut output);
                        log_arp(&data_buffer, &mut output);
                    }
                    Ok(MultiStepParserResult::ArpVlanEth(data_buffer)) => {
                        log_ethernet(&data_buffer, &mut output);
                        log_arp(&data_buffer, &mut output);
                    }
                    Ok(MultiStepParserResult::Ipv4Eth(data_buffer)) => {
                        log_ethernet(&data_buffer, &mut output);
                        log_ipv4(&data_buffer, &mut output);
                    }
                    Ok(MultiStepParserResult::FragmentIpv4Eth(data_buffer)) => {
                        log_ethernet(&data_buffer, &mut output);
                        log_ipv4(&data_buffer, &mut output);
                        log_fragment(&mut output);
                    }
                    Ok(MultiStepParserResult::TcpIpv4Eth(data_buffer)) => {
                        log_ethernet(&data_buffer, &mut output);
                        log_ipv4(&data_buffer, &mut output);
                        log_tcp(&data_buffer, &mut output);
                    }
                    Ok(MultiStepParserResult::UdpIpv4Eth(data_buffer)) => {
                        log_ethernet(&data_buffer, &mut output);
                        log_ipv4(&data_buffer, &mut output);
                        log_udp(&data_buffer, &mut output);
                    }
                    Ok(MultiStepParserResult::Ipv4VlanEth(data_buffer)) => {
                        log_ethernet(&data_buffer, &mut output);
                        log_ipv4(&data_buffer, &mut output);
                    }
                    Ok(MultiStepParserResult::FragmentIpv4VlanEth(data_buffer)) => {
                        log_ethernet(&data_buffer, &mut output);
                        log_ipv4(&data_buffer, &mut output);
                        log_fragment(&mut output);
                    }
                    Ok(MultiStepParserResult::TcpIpv4VlanEth(data_buffer)) => {
                        log_ethernet(&data_buffer, &mut output);
                        log_ipv4(&data_buffer, &mut output);
                        log_tcp(&data_buffer, &mut output);
                    }
                    Ok(MultiStepParserResult::UdpIpv4VlanEth(data_buffer)) => {
                        log_ethernet(&data_buffer, &mut output);
                        log_ipv4(&data_buffer, &mut output);
                        log_udp(&data_buffer, &mut output);
                    }
                    Ok(MultiStepParserResult::Ipv6Eth(data_buffer)) => {
                        log_ethernet(&data_buffer, &mut output);
                        log_ipv6(&data_buffer, &mut output);
                    }
                    Ok(MultiStepParserResult::TcpIpv6Eth(data_buffer)) => {
                        log_ethernet(&data_buffer, &mut output);
                        log_ipv6(&data_buffer, &mut output);
                        log_tcp(&data_buffer, &mut output);
                    }
                    Ok(MultiStepParserResult::UdpIpv6Eth(data_buffer)) => {
                        log_ethernet(&data_buffer, &mut output);
                        log_ipv6(&data_buffer, &mut output);
                        log_udp(&data_buffer, &mut output);
                    }
                    Ok(MultiStepParserResult::Ipv6VlanEth(data_buffer)) => {
                        log_ethernet(&data_buffer, &mut output);
                        log_ipv6(&data_buffer, &mut output);
                    }
                    Ok(MultiStepParserResult::TcpIpv6VlanEth(data_buffer)) => {
                        log_ethernet(&data_buffer, &mut output);
                        log_ipv6(&data_buffer, &mut output);
                        log_tcp(&data_buffer, &mut output);
                    }
                    Ok(MultiStepParserResult::UdpIpv6VlanEth(data_buffer)) => {
                        log_ethernet(&data_buffer, &mut output);
                        log_ipv6(&data_buffer, &mut output);
                        log_udp(&data_buffer, &mut output);
                    }
                    Ok(MultiStepParserResult::Ipv6ExtsIpv6Eth(data_buffer)) => {
                        log_ethernet(&data_buffer, &mut output);
                        log_ipv6(&data_buffer, &mut output);
                    }
                    Ok(MultiStepParserResult::TcpIpv6ExtsIpv6Eth(data_buffer)) => {
                        log_ethernet(&data_buffer, &mut output);
                        log_ipv6(&data_buffer, &mut output);
                        log_tcp(&data_buffer, &mut output);
                    }
                    Ok(MultiStepParserResult::UdpIpv6ExtsIpv6Eth(data_buffer)) => {
                        log_ethernet(&data_buffer, &mut output);
                        log_ipv6(&data_buffer, &mut output);
                        log_udp(&data_buffer, &mut output);
                    }
                    Ok(MultiStepParserResult::Ipv6ExtsIpv6VlanEth(data_buffer)) => {
                        log_ethernet(&data_buffer, &mut output);
                        log_ipv6(&data_buffer, &mut output);
                    }
                    Ok(MultiStepParserResult::TcpIpv6ExtsIpv6VlanEth(data_buffer)) => {
                        log_ethernet(&data_buffer, &mut output);
                        log_ipv6(&data_buffer, &mut output);
                        log_tcp(&data_buffer, &mut output);
                    }
                    Ok(MultiStepParserResult::UdpIpv6ExtsIpv6VlanEth(data_buffer)) => {
                        log_ethernet(&data_buffer, &mut output);
                        log_ipv6(&data_buffer, &mut output);
                        log_udp(&data_buffer, &mut output);
                    }
                    Ok(MultiStepParserResult::FragmentIpv6ExtsIpv6Eth(data_buffer)) => {
                        log_ethernet(&data_buffer, &mut output);
                        log_ipv6(&data_buffer, &mut output);
                        log_fragment(&mut output);
                    }
                    Ok(MultiStepParserResult::FragmentIpv6ExtsIpv6VlanEth(data_buffer)) => {
                        log_ethernet(&data_buffer, &mut output);
                        log_ipv6(&data_buffer, &mut output);
                        log_fragment(&mut output);
                    }
                    // Checksum errors are normal for outgoing packets if your system is using
                    // hardware offload.
                    Err(err) => {
                        eprintln!("{err}");
                    }
                }
            }
            Err(err) => {
                eprintln!("{err}");
                return;
            }
        }
        writeln!(lock, "{output}").unwrap();
    }
}

fn log_ethernet(packet: &impl EthernetMethods, data: &mut Data) {
    data.eth_ether_type = Some(packet.ethernet_typed_ether_type().unwrap())
}

fn log_arp(packet: &impl ArpMethods, data: &mut Data) {
    data.arp_op_code = Some(packet.arp_typed_operation_code().unwrap());
    data.arp_sender_prot_addr = Some(packet.arp_sender_protocol_address());
}

fn log_ipv4(packet: &impl Ipv4Methods, data: &mut Data) {
    data.ipv4_prot = Some(packet.ipv4_typed_protocol().unwrap());
    data.ipv4_src = Some(packet.ipv4_source());
    data.ipv4_dst = Some(packet.ipv4_destination());
}

fn log_fragment(data: &mut Data) {
    data.fragment = Some(true);
}

fn log_ipv6(packet: &impl Ipv6Methods, data: &mut Data) {
    data.ipv6_next_hdr = Some(packet.ipv6_typed_next_header().unwrap());
    data.ipv6_src = Some(packet.ipv6_source());
    data.ipv6_dst = Some(packet.ipv6_destination());
}

fn log_tcp(packet: &impl TcpMethods, data: &mut Data) {
    data.tcp_source_port = Some(packet.tcp_source_port());
    data.tcp_destination_port = Some(packet.tcp_destination_port());
}

fn log_udp(packet: &impl UdpMethods, data: &mut Data) {
    data.udp_source_port = Some(packet.udp_source_port());
    data.udp_destination_port = Some(packet.udp_destination_port());
}
