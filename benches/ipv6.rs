use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use mutnet::data_buffer::DataBuffer;
use mutnet::internet_protocol::InternetProtocolNumber;
use mutnet::ipv6::{Ipv6, ParseIpv6Error};
use mutnet::no_previous_header::NoPreviousHeaderInformation;

#[inline(always)]
pub fn parse_ipv6(
    bytes: &[u8],
) -> Result<DataBuffer<&[u8], Ipv6<NoPreviousHeaderInformation>>, ParseIpv6Error> {
    DataBuffer::<_, Ipv6<NoPreviousHeaderInformation>>::new(bytes, 0)
}

pub fn ipv6_no_extension(c: &mut Criterion) {
    let ipv6_packet_no_extensions = &mut [
        // Version, traffic class and flow label
        0x61,
        0x23,
        0xFF,
        0xFF,
        // Payload Length
        0x00,
        0x01,
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
        0xFF,
    ];

    let mut group = c.benchmark_group("ipv6");
    //group.measurement_time(Duration::from_secs(90));

    group.throughput(Throughput::Bytes(ipv6_packet_no_extensions.len() as u64));

    group.bench_function("ipv6 no extensions", |b| {
        b.iter(|| {
            let result = &parse_ipv6(std::hint::black_box(ipv6_packet_no_extensions));
            std::hint::black_box(result);
        })
    });

    group.finish();
}

pub fn ipv6_with_extensions(c: &mut Criterion) {
    let ipv6_packet_with_extensions = &mut [
        // Version, traffic class and flow label
        0x61,
        0x23,
        0xFF,
        0xFF,
        // Payload Length
        0x00,
        0x1A,
        // Next header
        InternetProtocolNumber::HopByHopOpt as u8,
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
        // Hop by hop extension
        InternetProtocolNumber::Ipv6Routing as u8,
        0x00,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        // Routing extension
        InternetProtocolNumber::Auth as u8,
        0x00,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        // Auth extension
        InternetProtocolNumber::Tcp as u8,
        0x00,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        // Payload
        0xFF,
        0xFF,
    ];

    let mut group = c.benchmark_group("ipv6");
    //group.measurement_time(Duration::from_secs(90));

    group.throughput(Throughput::Bytes(ipv6_packet_with_extensions.len() as u64));

    group.finish();
}

criterion_group!(benches, ipv6_no_extension, ipv6_with_extensions);

criterion_main!(benches);
