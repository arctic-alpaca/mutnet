/// Utils which might be required in multiple benchmarks.
use mutnet::arp::{Arp, ArpMethodsMut};
use mutnet::data_buffer::{BufferIntoInner, DataBuffer, PayloadMut};
use mutnet::ethernet::{Eth, EthernetMethodsMut};
use mutnet::ipv4::{Ipv4, Ipv4MethodsMut};
use mutnet::ipv6::{Ipv6, Ipv6MethodsMut};
use mutnet::no_previous_header::NoPreviousHeader;
use mutnet::tcp::{Tcp, TcpMethodsMut};
use mutnet::typed_protocol_headers::{
    Dscp, Ecn, EtherType, InternetProtocolNumber, Ipv6ExtensionType, OperationCode,
};
use mutnet::udp::{Udp, UdpMethodsMut};
use rand::{thread_rng, Rng};
use std::net::{Ipv4Addr, Ipv6Addr};

pub fn random_bytes<const SIZE: usize>() -> [u8; SIZE] {
    rand::random()
}

// ----------------------------------------------------------------
// ARP

// ARP for IPv4
#[rustfmt::skip]
pub const ARP_IPV4_REQUEST1: [u8;28] = [
    // Hardware type
    0x00, 0x01,
    // Protocol type
    0x08, 0x00,
    // Hardware address length
    0x06,
    // Protocol address length
    0x04,
    // Operation
    0x00, 0x01,
    // Sender hardware address (MAC address)
    0x1C, 0xED, 0xA4, 0xE1, 0xD2, 0xA2,
    // Sender protocol address (IPv4 address)
    0xC0, 0xA8, 0x0A, 0x01,
    // Target hardware address (MAC address)
    0x13, 0xE2, 0xAF, 0xE2, 0xD5, 0xA6,
    // Target protocol address (IPv4 address)
    0xC0, 0xA8, 0x7A, 0x0E,
];

pub fn random_valid_arp() -> [u8; 28] {
    let mut rng = thread_rng();

    let mut arp =
        DataBuffer::<_, Arp<NoPreviousHeader>>::parse_arp_alone(ARP_IPV4_REQUEST1, 0).unwrap();

    let operation_code = match rng.gen_range(0..2) {
        0_u8 => OperationCode::Reply,
        1.. => OperationCode::Request,
    };

    arp.set_arp_operation_code(operation_code);
    arp.set_arp_sender_hardware_address(&rng.gen());
    arp.set_arp_sender_protocol_address(&Ipv4Addr::from(rng.gen::<[u8; 4]>()));
    arp.set_arp_target_hardware_address(&rng.gen());
    arp.set_arp_target_protocol_address(&Ipv4Addr::from(rng.gen::<[u8; 4]>()));

    arp.buffer_into_inner()
}

// ----------------------------------------------------------------
// Ethernet

#[rustfmt::skip]
pub const ETHERNET: [u8; 64] = [
    // Dst
    0x0, 0x80, 0x41, 0xAE, 0xFD, 0x7E,
    // Src
    0x7E, 0xFD, 0xAE, 0x41, 0x80, 0x0,
    // Ether type
    0x88, 0x08,
    // Payload
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];

pub fn random_valid_ethernet() -> [u8; 64] {
    let mut ethernet = DataBuffer::<_, Eth>::parse_ethernet_layer(ETHERNET, 0).unwrap();
    ethernet.set_ethernet_destination(&rand::random());
    ethernet.set_ethernet_source(&rand::random());
    let ether_type = {
        let mut ether_type: u16 = rand::random();
        while EtherType::try_from(ether_type).is_err() {
            ether_type = rand::random();
        }
        EtherType::try_from(ether_type).unwrap()
    };
    ethernet.set_ethernet_ether_type(ether_type);
    ethernet
        .payload_mut()
        .iter_mut()
        .for_each(|byte| *byte = rand::random());
    ethernet.buffer_into_inner()
}

// ----------------------------------------------------------------
// IPv4

#[allow(clippy::unusual_byte_groupings)]
#[rustfmt::skip]
pub const IPV4: [u8; 92] = [
    // Version & IHL
    0x4F,
    // DSCP & ECN
    0b001010_00,
    // Total length
    0x00, 0x48,
    // Identification
    0x12, 0x34,
    // Flags & Fragment offset
    0x00, 0x00,
    // TTL
    0x01,
    // Protocol
    0x06,
    // Header Checksum
    0x9F, 0x52,
    // Source
    0x7f, 0x00, 0x00, 0x1,
    // Destination
    0x7f, 0x00, 0x00, 0x1,
    // Options
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    // Payload
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
];

pub fn random_ipv4() -> [u8; 92] {
    let mut rng = thread_rng();

    let mut ipv4 =
        DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(IPV4, 0, false).unwrap();
    ipv4.set_ipv4_ihl(rng.gen_range(0..11) + 5).unwrap();
    let dscp = {
        let mut dscp: u8 = rng.gen();
        while Dscp::try_from(dscp).is_err() {
            dscp = rng.gen();
        }
        Dscp::try_from(dscp).unwrap()
    };
    ipv4.set_ipv4_dscp(dscp);
    let ecn = {
        let mut ecn: u8 = rng.gen();
        while Ecn::try_from(ecn).is_err() {
            ecn = rng.gen();
        }
        Ecn::try_from(ecn).unwrap()
    };
    ipv4.set_ipv4_ecn(ecn);
    while ipv4.set_ipv4_total_length(rng.gen()).is_err() {}
    ipv4.set_ipv4_identification(rng.gen());
    ipv4.set_ipv4_flags(rng.gen());
    ipv4.set_ipv4_fragment_offset(rng.gen());
    ipv4.set_ipv4_time_to_live(rng.gen());
    ipv4.set_ipv4_protocol(rng.gen());
    ipv4.set_ipv4_header_checksum(rng.gen());
    ipv4.set_ipv4_source(Ipv4Addr::from(rng.gen::<[u8; 4]>()));
    ipv4.set_ipv4_destination(Ipv4Addr::from(rng.gen::<[u8; 4]>()));

    ipv4.ipv4_options_mut()
        .iter_mut()
        .for_each(|byte| *byte = rng.gen());
    ipv4.payload_mut()
        .iter_mut()
        .for_each(|byte| *byte = rng.gen());

    ipv4.buffer_into_inner()
}

// ----------------------------------------------------------------
// IPv6

#[rustfmt::skip]
pub const IPV6: [u8; 60] = [
    // Version, traffic class and flow label
    0x61, 0x23, 0xFF, 0xFF,
    // Payload Length
    0x00, 0x01,
    // Next header
    InternetProtocolNumber::Tcp as u8,
    // Hop limit
    0xFF,
    // Source
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    // Destination
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    // Payload
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];

pub fn random_ipv6() -> [u8; 60] {
    let mut ipv6 = DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(IPV6, 0).unwrap();
    ipv6.set_ipv6_traffic_class(rand::random());
    ipv6.set_ipv6_flow_label(rand::random());
    while ipv6.set_ipv6_payload_length(rand::random()).is_err() {}
    ipv6.set_ipv6_next_header(rand::random());
    ipv6.set_ipv6_hop_limit(rand::random());
    ipv6.set_ipv6_source(Ipv6Addr::from(rand::random::<[u8; 16]>()));
    ipv6.set_ipv6_destination(Ipv6Addr::from(rand::random::<[u8; 16]>()));
    ipv6.payload_mut()
        .iter_mut()
        .for_each(|byte| *byte = rand::random());

    ipv6.buffer_into_inner()
}

// ----------------------------------------------------------------
// IPv6 Extensions

pub const MEM_TO_FILL: usize = 64;
pub const MAX_EXTENSIONS: usize = 16;
/// MEM_TO_FILL needs to be at least 8 bytes.
pub fn random_valid_ipv6_extensions<const MEM_TO_FILL: usize>(
) -> ([u8; MEM_TO_FILL], Ipv6ExtensionType) {
    assert!(MEM_TO_FILL >= 8);

    let mut rng = thread_rng();
    let mut data_buffer = [0_u8; MEM_TO_FILL];
    let mut idx = 0;
    let mut next_header;
    let mut this_header;
    let mut first_extension = Ipv6ExtensionType::HopByHop as u8;
    let mut length = rng.gen_range(0..3);
    let mut remaining_space = MEM_TO_FILL;

    // Hop by hop
    if rng.gen::<bool>() {
        while MEM_TO_FILL < idx + (usize::from(length) + 1) * 8 {
            length -= 1;
        }

        remaining_space = remaining_space.saturating_sub((usize::from(length) + 1) * 8);
        next_header = match rng.gen_range(0..3) {
            0_u8 => Ipv6ExtensionType::Routing as u8,
            1 => Ipv6ExtensionType::Fragment as u8,
            2.. => Ipv6ExtensionType::DestinationOptions as u8,
        };

        data_buffer[idx] = next_header;
        idx += 1;
        data_buffer[idx] = length;
        idx += 1;

        for _ in 0..((usize::from(length) + 1) * 8 - 2) {
            data_buffer[idx] = rng.gen();
            idx += 1;
        }
        this_header = next_header;
    } else {
        first_extension = match rng.gen_range(0..3) {
            0_u8 => Ipv6ExtensionType::Routing as u8,
            1 => Ipv6ExtensionType::Fragment as u8,
            2.. => Ipv6ExtensionType::DestinationOptions as u8,
        };

        this_header = first_extension;

        next_header = if remaining_space >= 8 {
            match rng.gen_range(0..3) {
                0_u8 => Ipv6ExtensionType::Routing as u8,
                1 => Ipv6ExtensionType::Fragment as u8,
                2.. => Ipv6ExtensionType::DestinationOptions as u8,
            }
        } else {
            rng.gen_range(Ipv6ExtensionType::DestinationOptions as u8 + 1..u8::MAX)
        };
    }

    while Ipv6ExtensionType::try_from(next_header).is_ok() {
        if this_header == Ipv6ExtensionType::Fragment as u8 {
            length = 0;
        } else {
            length = rng.gen_range(0..3);
        }

        while MEM_TO_FILL < idx + (usize::from(length) + 1) * 8 {
            length -= 1;
        }

        remaining_space = remaining_space.saturating_sub((usize::from(length) + 1) * 8);

        next_header = if remaining_space >= 8 {
            match rng.gen_range(0..3) {
                0_u8 => Ipv6ExtensionType::Routing as u8,
                1 => Ipv6ExtensionType::Fragment as u8,
                2.. => Ipv6ExtensionType::DestinationOptions as u8,
            }
        } else {
            rng.gen_range(Ipv6ExtensionType::DestinationOptions as u8 + 1..u8::MAX)
        };

        data_buffer[idx] = next_header;
        idx += 1;
        data_buffer[idx] = length;
        idx += 1;
        this_header = next_header;

        for _ in 0..(((usize::from(length) + 1) * 8) - 2) {
            data_buffer[idx] = rng.gen();
            idx += 1;
        }
    }

    (
        data_buffer,
        Ipv6ExtensionType::try_from(first_extension).unwrap(),
    )
}

// ----------------------------------------------------------------
// UDP

#[rustfmt::skip]
pub const UDP: [u8; 14] = [
    // Source port
    0x12, 0x34,
    // Destination port
    0x0, 0x0,
    // Length
    0x00, 0x0C,
    // Checksum
    0xAB, 0xCD,
    // Payload
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];

pub fn random_udp() -> [u8; 14] {
    let mut rng = thread_rng();

    let mut udp = DataBuffer::<_, Udp<NoPreviousHeader>>::parse_udp_alone(UDP, 0).unwrap();
    udp.set_udp_destination_port(rand::random());
    udp.set_udp_source_port(rand::random());
    udp.set_udp_checksum(rand::random());
    udp.set_udp_length(rng.gen_range(8..14)).unwrap();
    udp.payload_mut()
        .iter_mut()
        .for_each(|byte| *byte = rand::random());

    udp.buffer_into_inner()
}

// ----------------------------------------------------------------
// TCP

#[allow(clippy::unusual_byte_groupings)]
#[rustfmt::skip]
pub const TCP: [u8;60] = [
    // Source port
    0x12, 0x34,
    // Destination port
    0x45, 0x67,
    // Sequence number
    0x12, 0x34, 0x56, 0x78,
    // Acknowledgment number
    0x09, 0x87, 0x65, 0x43,
    // Data offset, reserved bits, flags
    0xF0, 0b0101_0101,
    // Window
    0x12, 0x45,
    // Checksum
    0x12, 0x34,
    // Urgent pointer
    0x56, 0x78,
    // Options
    0xFF, 0xFF,
    0xFF, 0xFF,
    0xFF, 0xFF,
    0xFF, 0xFF,
    // Payload
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
];

pub fn random_tcp() -> [u8; 60] {
    let mut tcp = DataBuffer::<_, Tcp<NoPreviousHeader>>::parse_tcp_alone(TCP, 0).unwrap();
    tcp.set_tcp_source_port(rand::random());
    tcp.set_tcp_destination_port(rand::random());
    tcp.set_tcp_sequence_number(rand::random());
    tcp.set_tcp_acknowledgement_number(rand::random());
    tcp.set_tcp_reserved_bits(rand::random());
    tcp.set_tcp_flags(rand::random());
    tcp.set_tcp_window_size(rand::random());
    tcp.set_tcp_checksum(rand::random());
    tcp.set_tcp_urgent_pointer(rand::random());
    if let Some(options) = tcp.tcp_options_mut() {
        options.iter_mut().for_each(|byte| *byte = rand::random());
    }
    tcp.payload_mut()
        .iter_mut()
        .for_each(|byte| *byte = rand::random());

    let mut buffer = tcp.buffer_into_inner();
    buffer[13] = rand::random();
    buffer
}

// ----------------------------------------------------------------
// IPv4 TCP

#[allow(clippy::unusual_byte_groupings)]
#[rustfmt::skip]
pub const IPV4_TCP: [u8; 120] = [
    // Version & IHL
    0x4F,
    // DSCP & ECN
    0b001010_00,
    // Total length
    0x00, 0x78,
    // Identification
    0x12, 0x34,
    // Flags & Fragment offset
    0x00, 0x00,
    // TTL
    0x01,
    // Protocol
    0x06,
    // Header Checksum
    0x9F, 0x52,
    // Source
    0x7f, 0x00, 0x00, 0x1,
    // Destination
    0x7f, 0x00, 0x00, 0x1,
    // Options
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    // Payload
    // Source port
    0x12, 0x34,
    // Destination port
    0x45, 0x67,
    // Sequence number
    0x12, 0x34, 0x56, 0x78,
    // Acknowledgment number
    0x09, 0x87, 0x65, 0x43,
    // Data offset, reserved bits, flags
    0xF0, 0b0101_0101,
    // Window
    0x12, 0x45,
    // Checksum
    0x12, 0x34,
    // Urgent pointer
    0x56, 0x78,
    // Options
    0xFF, 0xFF,
    0xFF, 0xFF,
    0xFF, 0xFF,
    0xFF, 0xFF,
    // Payload
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
];

pub fn random_ipv4_tcp() -> [u8; 120] {
    let mut rng = thread_rng();

    let ipv4 =
        DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(IPV4_TCP, 0, false).unwrap();
    let mut ipv4_tcp = DataBuffer::<_, _>::parse_tcp_layer(ipv4, false).unwrap();
    ipv4_tcp.set_ipv4_ihl(rng.gen_range(0..11) + 5).unwrap();
    let dscp = {
        let mut dscp: u8 = rng.gen();
        while Dscp::try_from(dscp).is_err() {
            dscp = rng.gen();
        }
        Dscp::try_from(dscp).unwrap()
    };
    ipv4_tcp.set_ipv4_dscp(dscp);
    let ecn = {
        let mut ecn: u8 = rng.gen();
        while Ecn::try_from(ecn).is_err() {
            ecn = rng.gen();
        }
        Ecn::try_from(ecn).unwrap()
    };
    ipv4_tcp.set_ipv4_ecn(ecn);
    while ipv4_tcp.set_ipv4_total_length(rng.gen()).is_err() {}
    ipv4_tcp.set_ipv4_identification(rng.gen());
    ipv4_tcp.set_ipv4_flags(rng.gen());
    ipv4_tcp.set_ipv4_fragment_offset(rng.gen());
    ipv4_tcp.set_ipv4_time_to_live(rng.gen());
    ipv4_tcp.set_ipv4_protocol(rng.gen());
    ipv4_tcp.set_ipv4_header_checksum(rng.gen());
    ipv4_tcp.set_ipv4_source(Ipv4Addr::from(rng.gen::<[u8; 4]>()));
    ipv4_tcp.set_ipv4_destination(Ipv4Addr::from(rng.gen::<[u8; 4]>()));

    ipv4_tcp
        .ipv4_options_mut()
        .iter_mut()
        .for_each(|byte| *byte = rng.gen());

    ipv4_tcp.set_tcp_source_port(rand::random());
    ipv4_tcp.set_tcp_destination_port(rand::random());
    ipv4_tcp.set_tcp_sequence_number(rand::random());
    ipv4_tcp.set_tcp_acknowledgement_number(rand::random());
    ipv4_tcp.set_tcp_reserved_bits(rand::random());
    ipv4_tcp.set_tcp_flags(rand::random());
    ipv4_tcp.set_tcp_window_size(rand::random());
    ipv4_tcp.set_tcp_checksum(rand::random());
    ipv4_tcp.set_tcp_urgent_pointer(rand::random());
    if let Some(options) = ipv4_tcp.tcp_options_mut() {
        options.iter_mut().for_each(|byte| *byte = rand::random());
    }
    ipv4_tcp
        .payload_mut()
        .iter_mut()
        .for_each(|byte| *byte = rand::random());

    ipv4_tcp.buffer_into_inner()
}

// ----------------------------------------------------------------
// Ethernet IPv4 TCP
pub const ETH_IPV4_TCP: [u8; 64] = [
    0x00,
    0x80,
    0x41,
    0xAE,
    0xFD,
    0x7E, // Dst
    0x7E,
    0xFD,
    0xAE,
    0x41,
    0x80,
    0x00, // Src
    0x08,
    0x00, // Ether type
    // Version & IHL
    0x46,
    // DSCP & ECN
    0b0010_1000,
    // Total length
    0x00,
    0x32,
    // Identification
    0x12,
    0x34,
    // Flags & Fragment offset
    0b101_00000,
    0x03,
    // TTL
    0x01,
    // Protocol
    0x06,
    // Header Checksum
    0x06,
    0x61,
    // Source
    0x7f,
    0x00,
    0x00,
    0x1,
    // Destination
    0x7f,
    0x00,
    0x00,
    0x1,
    // Options
    0x02,
    0x04,
    0xFF,
    0xFF,
    // Payload
    // TCP
    // Source port
    0x12,
    0x34,
    // Destination port
    0x45,
    0x67,
    // Sequence number
    0x12,
    0x34,
    0x56,
    0x78,
    // Acknowledgment number
    0x09,
    0x87,
    0x65,
    0x43,
    // Data offset, reserved bits, flags
    0x50,
    0b0101_0101,
    // Window
    0x12,
    0x45,
    // Checksum
    0x19,
    0xB8,
    // Urgent pointer
    0x56,
    0x78,
    // payload
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
];
