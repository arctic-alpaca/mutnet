use mutnet::addresses::ipv4::Ipv4Address;
use mutnet::addresses::ipv6::Ipv6Addr;
use mutnet::arp::ArpMethods;
use mutnet::ethernet::EthernetMethods;
use mutnet::ipv4::Ipv4Methods;
use mutnet::ipv6::Ipv6Methods;
use mutnet::multi_step_parser::{parse_network_data, EthernetMultiStepParserResult};
use mutnet::tcp::TcpMethods;
use mutnet::typed_protocol_headers::EtherType;
use mutnet::typed_protocol_headers::InternetProtocolNumber;
use mutnet::typed_protocol_headers::OperationCode;
use mutnet::udp::UdpMethods;
use std::io::{stdout, Write};

#[derive(Copy, Clone, Debug, Default)]
struct Data {
    dropped_packets: u32,
    arp_op_code: Option<OperationCode>,
    arp_sender_prot_addr: Option<Ipv4Address>,
    ipv4_prot: Option<InternetProtocolNumber>,
    ipv4_ihl: Option<u8>,
    ipv4_src: Option<Ipv4Address>,
    ipv4_dst: Option<Ipv4Address>,
    ipv6_next_hdr: Option<InternetProtocolNumber>,
    ipv6_src: Option<Ipv6Addr>,
    fragment: Option<bool>,
    eth_ether_type: Option<EtherType>,
    tcp_source_port: Option<u16>,
    tcp_destination_port: Option<u16>,
    udp_source_port: Option<u16>,
    udp_destination_port: Option<u16>,
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
                match parse_network_data::<_, 10>(packet.data, 0, true, true, true) {
                    Ok(EthernetMultiStepParserResult::Ethernet(data_buffer)) => {
                        log_ethernet(&data_buffer, &mut output);
                    }
                    Ok(EthernetMultiStepParserResult::VlanEth(data_buffer)) => {
                        log_ethernet(&data_buffer, &mut output);
                    }
                    Ok(EthernetMultiStepParserResult::ArpEth(data_buffer)) => {
                        log_ethernet(&data_buffer, &mut output);
                        log_arp(&data_buffer, &mut output);
                    }
                    Ok(EthernetMultiStepParserResult::ArpVlanEth(data_buffer)) => {
                        log_ethernet(&data_buffer, &mut output);
                        log_arp(&data_buffer, &mut output);
                    }
                    Ok(EthernetMultiStepParserResult::Ipv4Eth(data_buffer)) => {
                        log_ethernet(&data_buffer, &mut output);
                        log_ipv4(&data_buffer, &mut output);
                    }
                    Ok(EthernetMultiStepParserResult::FragmentIpv4Eth(data_buffer)) => {
                        log_ethernet(&data_buffer, &mut output);
                        log_ipv4(&data_buffer, &mut output);
                        log_fragment(&mut output);
                    }
                    Ok(EthernetMultiStepParserResult::TcpIpv4Eth(data_buffer)) => {
                        log_ethernet(&data_buffer, &mut output);
                        log_ipv4(&data_buffer, &mut output);
                        log_tcp(&data_buffer, &mut output);
                    }
                    Ok(EthernetMultiStepParserResult::UdpIpv4Eth(data_buffer)) => {
                        log_ethernet(&data_buffer, &mut output);
                        log_ipv4(&data_buffer, &mut output);
                        log_udp(&data_buffer, &mut output);
                    }
                    Ok(EthernetMultiStepParserResult::Ipv4VlanEth(data_buffer)) => {
                        log_ethernet(&data_buffer, &mut output);
                        log_ipv4(&data_buffer, &mut output);
                    }
                    Ok(EthernetMultiStepParserResult::FragmentIpv4VlanEth(data_buffer)) => {
                        log_ethernet(&data_buffer, &mut output);
                        log_ipv4(&data_buffer, &mut output);
                        log_fragment(&mut output);
                    }
                    Ok(EthernetMultiStepParserResult::TcpIpv4VlanEth(data_buffer)) => {
                        log_ethernet(&data_buffer, &mut output);
                        log_ipv4(&data_buffer, &mut output);
                        log_tcp(&data_buffer, &mut output);
                    }
                    Ok(EthernetMultiStepParserResult::UdpIpv4VlanEth(data_buffer)) => {
                        log_ethernet(&data_buffer, &mut output);
                        log_ipv4(&data_buffer, &mut output);
                        log_udp(&data_buffer, &mut output);
                    }
                    Ok(EthernetMultiStepParserResult::Ipv6Eth(data_buffer)) => {
                        log_ethernet(&data_buffer, &mut output);
                        log_ipv6(&data_buffer, &mut output);
                    }
                    Ok(EthernetMultiStepParserResult::TcpIpv6Eth(data_buffer)) => {
                        log_ethernet(&data_buffer, &mut output);
                        log_ipv6(&data_buffer, &mut output);
                        log_tcp(&data_buffer, &mut output);
                    }
                    Ok(EthernetMultiStepParserResult::UdpIpv6Eth(data_buffer)) => {
                        log_ethernet(&data_buffer, &mut output);
                        log_ipv6(&data_buffer, &mut output);
                        log_udp(&data_buffer, &mut output);
                    }
                    Ok(EthernetMultiStepParserResult::Ipv6VlanEth(data_buffer)) => {
                        log_ethernet(&data_buffer, &mut output);
                        log_ipv6(&data_buffer, &mut output);
                    }
                    Ok(EthernetMultiStepParserResult::TcpIpv6VlanEth(data_buffer)) => {
                        log_ethernet(&data_buffer, &mut output);
                        log_ipv6(&data_buffer, &mut output);
                        log_tcp(&data_buffer, &mut output);
                    }
                    Ok(EthernetMultiStepParserResult::UdpIpv6VlanEth(data_buffer)) => {
                        log_ethernet(&data_buffer, &mut output);
                        log_ipv6(&data_buffer, &mut output);
                        log_udp(&data_buffer, &mut output);
                    }
                    Ok(EthernetMultiStepParserResult::Ipv6ExtsIpv6Eth(data_buffer)) => {
                        log_ethernet(&data_buffer, &mut output);
                        log_ipv6(&data_buffer, &mut output);
                    }
                    Ok(EthernetMultiStepParserResult::TcpIpv6ExtsIpv6Eth(data_buffer)) => {
                        log_ethernet(&data_buffer, &mut output);
                        log_ipv6(&data_buffer, &mut output);
                        log_tcp(&data_buffer, &mut output);
                    }
                    Ok(EthernetMultiStepParserResult::UdpIpv6ExtsIpv6Eth(data_buffer)) => {
                        log_ethernet(&data_buffer, &mut output);
                        log_ipv6(&data_buffer, &mut output);
                        log_udp(&data_buffer, &mut output);
                    }
                    Ok(EthernetMultiStepParserResult::Ipv6ExtsIpv6VlanEth(data_buffer)) => {
                        log_ethernet(&data_buffer, &mut output);
                        log_ipv6(&data_buffer, &mut output);
                    }
                    Ok(EthernetMultiStepParserResult::TcpIpv6ExtsIpv6VlanEth(data_buffer)) => {
                        log_ethernet(&data_buffer, &mut output);
                        log_ipv6(&data_buffer, &mut output);
                        log_tcp(&data_buffer, &mut output);
                    }
                    Ok(EthernetMultiStepParserResult::UdpIpv6ExtsIpv6VlanEth(data_buffer)) => {
                        log_ethernet(&data_buffer, &mut output);
                        log_ipv6(&data_buffer, &mut output);
                        log_udp(&data_buffer, &mut output);
                    }
                    Ok(EthernetMultiStepParserResult::FragmentIpv6ExtsIpv6Eth(data_buffer)) => {
                        log_ethernet(&data_buffer, &mut output);
                        log_ipv6(&data_buffer, &mut output);
                        log_fragment(&mut output);
                    }
                    Ok(EthernetMultiStepParserResult::FragmentIpv6ExtsIpv6VlanEth(data_buffer)) => {
                        log_ethernet(&data_buffer, &mut output);
                        log_ipv6(&data_buffer, &mut output);
                        log_fragment(&mut output);
                    }
                    // Checksum errors are normal for outgoing packets if your system is using
                    // hardware offload.
                    Err(err) => eprintln!("{err}"),
                }
            }
            Err(err) => {
                eprintln!("{err}");
                return;
            }
        }
        if let Some(arp_op_code) = output.arp_op_code {
            writeln!(lock, "Arp opcode: {arp_op_code:?}").unwrap();
        }
        if let Some(arp_sender_prot_addr) = output.arp_sender_prot_addr {
            writeln!(lock, "Arp sender prot addr: {arp_sender_prot_addr:?}").unwrap();
        }
        if let Some(eth_ether_type) = output.eth_ether_type {
            writeln!(lock, "Ethertype {eth_ether_type:?}").unwrap();
        }
        if let Some(ipv4_prot) = output.ipv4_prot {
            writeln!(lock, "IPv4 prototocol: {ipv4_prot:?}").unwrap();
        }
        if let Some(ipv4_ihl) = output.ipv4_ihl {
            writeln!(lock, "IPv4 IHL: {ipv4_ihl:?}").unwrap();
        }
        if let Some(ipv4_src) = output.ipv4_src {
            writeln!(
                lock,
                "IPv4 SRC: {}.{}.{}.{}",
                ipv4_src[0], ipv4_src[1], ipv4_src[2], ipv4_src[3],
            )
            .unwrap();
        }
        if let Some(ipv4_dst) = output.ipv4_dst {
            writeln!(
                lock,
                "IPv4 DST: {}.{}.{}.{}",
                ipv4_dst[0], ipv4_dst[1], ipv4_dst[2], ipv4_dst[3],
            )
            .unwrap();
        }
        if let Some(ipv6_next_hdr) = output.ipv6_next_hdr {
            writeln!(lock, "IPv6 next header: {ipv6_next_hdr:?}").unwrap();
        }
        if let Some(ipv6_src) = output.ipv6_src {
            writeln!(lock, "IPv6 SRC {ipv6_src:X?}").unwrap();
        }
        if let Some(is_fragment) = output.fragment {
            writeln!(lock, "Is fragment: {is_fragment:?}").unwrap();
        }
        if let Some(tcp_source_port) = output.tcp_source_port {
            writeln!(lock, "TCP src port: {tcp_source_port:?}").unwrap();
        }
        if let Some(tcp_destination_port) = output.tcp_destination_port {
            writeln!(lock, "TCP dst port: {tcp_destination_port:?}").unwrap();
        }
        if let Some(udp_source_port) = output.udp_source_port {
            writeln!(lock, "UDP src port: {udp_source_port:?}").unwrap();
        }
        if let Some(udp_destination_port) = output.udp_destination_port {
            writeln!(lock, "UDP dst port: {udp_destination_port:?}").unwrap();
        }
        writeln!(lock, "Dropped packets {}", output.dropped_packets).unwrap();
        writeln!(lock, "------------------").unwrap();
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
    data.ipv4_ihl = Some(packet.ipv4_ihl());
    data.ipv4_src = Some(packet.ipv4_source());
    data.ipv4_dst = Some(packet.ipv4_destination());
}

fn log_fragment(data: &mut Data) {
    data.fragment = Some(true);
}

fn log_ipv6(packet: &impl Ipv6Methods, data: &mut Data) {
    data.ipv6_next_hdr = Some(packet.ipv6_typed_next_header().unwrap());
    data.ipv6_src = Some(packet.ipv6_source());
}

fn log_tcp(packet: &impl TcpMethods, data: &mut Data) {
    data.tcp_source_port = Some(packet.tcp_source_port());
    data.tcp_destination_port = Some(packet.tcp_destination_port());
}

fn log_udp(packet: &impl UdpMethods, data: &mut Data) {
    data.udp_source_port = Some(packet.udp_source_port());
    data.udp_destination_port = Some(packet.udp_destination_port());
}
