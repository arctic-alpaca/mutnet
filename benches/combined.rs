use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use etherparse::{ReadError, SlicedPacket};
use mutnet::arp::{Arp, ParseArpError};
use mutnet::data_buffer::DataBuffer;
use mutnet::error::{Error, ParseNetworkDataError};
use mutnet::ethernet::Eth;
use mutnet::internet_protocol::InternetProtocolNumber;
use mutnet::ipv4::{Ipv4, ParseIpv4Error};
use mutnet::ipv6::{Ipv6, ParseIpv6Error};
use mutnet::multi_step_parser::{parse_network_data, EthernetMultiStepParserResult};
use mutnet::tcp::Tcp;

#[allow(clippy::unusual_byte_groupings)]
#[rustfmt::skip]
static ETHERNET_ARP: &[u8] = &[
    // Dst
    0x0, 0x80, 0x41, 0xAE, 0xFD, 0x7E,
    // Src
    0x7E, 0xFD, 0xAE, 0x41, 0x80, 0x0,
    // Ether type
    0x08, 0x06,
    // Hardware type
    0x00, 0x01,
    // Protocol type
    0x08, 0x00,
    // Hardware address length
    0x06,
    // Protocol address length
    0x04,
    // Operation
    0x00, 0x02,
    // Sender hardware address (MAC address)
    0x1C, 0xED, 0xA4, 0xE1, 0xD2, 0xA2,
    // Sender protocol address (IPv4 address)
    0xC0, 0xA8, 0x0A, 0x01,
    // Target hardware address (MAC address)
    0x13, 0xE2, 0xAF, 0xE2, 0xD5, 0xA6,
    // Target protocol address (IPv4 address)
    0xC0, 0xA8, 0x7A, 0xE,
];

#[allow(clippy::unusual_byte_groupings)]
#[rustfmt::skip]
static ETHERNET_IPV4_TCP: &[u8] = &[
    // Dst
    0x0, 0x80, 0x41, 0xAE, 0xFD, 0x7E,
    // Src
    0x7E, 0xFD, 0xAE, 0x41, 0x80, 0x0,
    // Ether type
    0x8, 0x0,
    // Version & IHL
    0x45,
    // DSCP & ECN
    0b001010_00,
    // Total length
    0x00, 0x2E,
    // Identification
    0x12, 0x34,
    // Flags & Fragment offset
    0x00, 0x00,
    // TTL
    0x01,
    // Protocol
    0x06,
    // Header Checksum
    0xA9, 0x6C,
    // Source
    0x7f, 0x00, 0x00, 0x1,
    // Destination
    0x7f, 0x00, 0x00, 0x1,
    // Payload
    // TCP
    // Source port
    0x12, 0x34,
    // Destination port
    0x45, 0x67,
    // Sequence number
    0x12, 0x34, 0x56, 0x78,
    // Acknowledgment number
    0x09, 0x87, 0x65, 0x43,
    // Data offset, reserved bits, flags
    0x50, 0b0101_0101,
    // Window
    0x12, 0x45,
    // Checksum
    0x19, 0xB8,
    // Urgent pointer
    0x56, 0x78,
    // payload
    0xFF, 0xFF,
    0xFF, 0xFF,
    0xFF, 0xFF,
];

#[allow(clippy::unusual_byte_groupings)]
#[rustfmt::skip]
static ETHERNET_IPV6_TCP: &[u8] = &[
    // Dst
    0x0, 0x80, 0x41, 0xAE, 0xFD, 0x7E,
    // Src
    0x7E, 0xFD, 0xAE, 0x41, 0x80, 0x0,
    // Ether type
    0x86, 0xDD,
    // Version, traffic class and flow label
    0x61,
    0x23,
    0xFF,
    0xFF,
    // Payload Length
    0x00,
    0x1A,
    // Next header
    InternetProtocolNumber::Tcp as u8,
    // Hop limit
    0xFF,
    // Source
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    // Destination
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    // Payload
    // TCP
    // Source port
    0x12, 0x34,
    // Destination port
    0x45, 0x67,
    // Sequence number
    0x12, 0x34, 0x56, 0x78,
    // Acknowledgment number
    0x09, 0x87, 0x65, 0x43,
    // Data offset, reserved bits, flags
    0x50, 0b0101_0101,
    // Window
    0x12, 0x45,
    // Checksum
    0x17, 0xBB,
    // Urgent pointer
    0x56, 0x78,
    // payload
    0xFF, 0xFF,
    0xFF, 0xFF,
    0xFF, 0xFF,
    ];

#[inline(always)]
pub fn parse_arp_combined(bytes: &[u8]) -> Result<DataBuffer<&[u8], Arp<Eth>>, ParseArpError> {
    let eth = DataBuffer::<_, Eth>::new(bytes, 0)?;
    DataBuffer::<_, Arp<Eth>>::new_from_lower(eth)
}

#[inline(always)]
pub fn parse_ipv4_combined(
    bytes: &[u8],
    check_ipv4_checksum: bool,
) -> Result<DataBuffer<&[u8], Ipv4<Eth>>, ParseIpv4Error> {
    let eth = DataBuffer::<_, Eth>::new(bytes, 0)?;
    DataBuffer::<_, Ipv4<Eth>>::new_from_lower(eth, check_ipv4_checksum)
}

#[inline(always)]
pub fn parse_ipv6_combined(bytes: &[u8]) -> Result<DataBuffer<&[u8], Ipv6<Eth>>, ParseIpv6Error> {
    let eth = DataBuffer::<_, Eth>::new(bytes, 0)?;
    DataBuffer::<_, Ipv6<Eth>>::new_from_lower(eth)
}

#[inline(always)]
pub fn parse_ipv4_tcp_combined(
    bytes: &[u8],
    check_ipv4_checksum: bool,
    check_tcp_checksum: bool,
) -> Result<DataBuffer<&[u8], Tcp<Ipv4<Eth>>>, Error> {
    let eth = DataBuffer::<_, Eth>::new(bytes, 0)?;
    let ipv4 = DataBuffer::<_, Ipv4<Eth>>::new_from_lower(eth, check_ipv4_checksum)?;
    Ok(DataBuffer::<_, Tcp<Ipv4<Eth>>>::new_from_lower(
        ipv4,
        check_tcp_checksum,
    )?)
}

#[inline(always)]
pub fn parse_ipv6_tcp_combined(
    bytes: &[u8],
    check_tcp_checksum: bool,
) -> Result<DataBuffer<&[u8], Tcp<Ipv6<Eth>>>, Error> {
    let eth = DataBuffer::<_, Eth>::new(bytes, 0)?;
    let ipv6 = DataBuffer::<_, Ipv6<Eth>>::new_from_lower(eth)?;
    Ok(DataBuffer::<_, Tcp<Ipv6<Eth>>>::new_from_lower(
        ipv6,
        check_tcp_checksum,
    )?)
}

#[inline(always)]
fn parse_multi(
    bytes: &[u8],
) -> Result<EthernetMultiStepParserResult<&[u8], 10>, ParseNetworkDataError> {
    parse_network_data(bytes, 0, true, true, true)
}

#[inline(always)]
fn etherparse_multi(bytes: &[u8]) -> Result<SlicedPacket, ReadError> {
    SlicedPacket::from_ethernet(bytes)
}

pub fn ether_arp(c: &mut Criterion) {
    let mut group = c.benchmark_group("combined");
    group.sample_size(1000);
    //group.measurement_time(Duration::from_secs(90));

    group.throughput(Throughput::Bytes(ETHERNET_ARP.len() as u64));

    group.bench_function("ethernet arp", |b| {
        b.iter(|| {
            let result = &parse_arp_combined(std::hint::black_box(ETHERNET_ARP));
            std::hint::black_box(result);
        })
    });

    group.bench_function("ethernet arp multi", |b| {
        b.iter(|| {
            let result = &parse_multi(std::hint::black_box(ETHERNET_ARP));

            std::hint::black_box(result);
        })
    });

    group.finish();
}

pub fn ether_ipv4(c: &mut Criterion) {
    let mut group = c.benchmark_group("combined");
    group.sample_size(1000);
    //group.measurement_time(Duration::from_secs(90));

    group.throughput(Throughput::Bytes(ETHERNET_IPV4_TCP.len() as u64));

    group.bench_function("ethernet ipv4", |b| {
        b.iter(|| {
            let result = &parse_ipv4_combined(std::hint::black_box(ETHERNET_IPV4_TCP), false);
            std::hint::black_box(result);
        })
    });

    group.bench_function("ethernet ipv4 checksum", |b| {
        b.iter(|| {
            let result = &parse_ipv4_combined(std::hint::black_box(ETHERNET_IPV4_TCP), true);
            std::hint::black_box(result);
        })
    });

    group.finish();
}

pub fn ether_ipv4_tcp(c: &mut Criterion) {
    let mut group = c.benchmark_group("combined");
    group.sample_size(1000);
    //group.measurement_time(Duration::from_secs(90));

    group.throughput(Throughput::Bytes(ETHERNET_IPV4_TCP.len() as u64));

    /*group.bench_function("ethernet ipv4 tcp", |b| {
        b.iter(|| {
            let result =
                &parse_ipv4_tcp_combined(std::hint::black_box(&ETHERNET_IPV4_TCP), false, false);
            std::hint::black_box(result);
        })
    });
    group.bench_function("ethernet ipv4 (checksum) tcp", |b| {
        b.iter(|| {
            let result =
                &parse_ipv4_tcp_combined(std::hint::black_box(&ETHERNET_IPV4_TCP), true, false);
            std::hint::black_box(result);
        })
    });
    group.bench_function("ethernet ipv4 (checksum) tcp (checksum)", |b| {
        b.iter(|| {
            let result =
                &parse_ipv4_tcp_combined(std::hint::black_box(&ETHERNET_IPV4_TCP), true, true);
            std::hint::black_box(result);
        })
    });*/
    group.bench_function("ethernet ipv4 tcp multi", |b| {
        b.iter(|| {
            let result = &parse_multi(std::hint::black_box(ETHERNET_IPV4_TCP));
            std::hint::black_box(result);
        })
    });

    group.bench_function("ethernet ipv4 tcp etherparse multi", |b| {
        b.iter(|| {
            let result = &etherparse_multi(std::hint::black_box(ETHERNET_IPV4_TCP));
            std::hint::black_box(result);
        })
    });

    group.finish();
}

pub fn ether_ipv6(c: &mut Criterion) {
    let mut group = c.benchmark_group("combined");
    group.sample_size(1000);
    //group.measurement_time(Duration::from_secs(90));

    group.throughput(Throughput::Bytes(ETHERNET_IPV6_TCP.len() as u64));

    group.bench_function("ethernet ipv6", |b| {
        b.iter(|| {
            let result = &parse_ipv6_combined(std::hint::black_box(ETHERNET_IPV6_TCP));
            std::hint::black_box(result);
        })
    });

    group.finish();
}

pub fn ether_ipv6_tcp(c: &mut Criterion) {
    let mut group = c.benchmark_group("combined");
    group.sample_size(1000);
    //group.measurement_time(Duration::from_secs(90));

    group.throughput(Throughput::Bytes(ETHERNET_IPV6_TCP.len() as u64));

    group.bench_function("ethernet ipv6 tcp", |b| {
        b.iter(|| {
            let result = &parse_ipv6_tcp_combined(std::hint::black_box(ETHERNET_IPV6_TCP), false);
            std::hint::black_box(result);
        })
    });
    group.bench_function("ethernet ipv6 tcp (checksum)", |b| {
        b.iter(|| {
            let result = &parse_ipv6_tcp_combined(std::hint::black_box(ETHERNET_IPV6_TCP), true);
            std::hint::black_box(result);
        })
    });

    group.bench_function("ethernet ipv6 tcp multi", |b| {
        b.iter(|| {
            let result = &parse_multi(std::hint::black_box(ETHERNET_IPV6_TCP));
            std::hint::black_box(result);
        })
    });

    group.bench_function("ethernet ipv6 tcp etherparse multi", |b| {
        b.iter(|| {
            let result = &etherparse_multi(std::hint::black_box(ETHERNET_IPV6_TCP));
            std::hint::black_box(result);
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    //ether_arp,
    //ether_ipv4,
    ether_ipv4_tcp,
    //ether_ipv6,
    //ether_ipv6_tcp
);

criterion_main!(benches);
