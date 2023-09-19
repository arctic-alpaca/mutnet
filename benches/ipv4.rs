use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use etherparse::{Ipv4HeaderSlice, ReadError};
use mutnet::checksum::internet_checksum;
use mutnet::data_buffer::DataBuffer;
use mutnet::internet_protocol::InternetProtocolNumber;
use mutnet::ipv4::{Ipv4, ParseIpv4Error};
use mutnet::no_previous_header::NoPreviousHeaderInformation;

pub fn random_ipv4<const SIZE: usize>() -> [u8; SIZE] {
    let protocol = [
        InternetProtocolNumber::Tcp as u8,
        InternetProtocolNumber::Udp as u8,
    ];
    let protocol = protocol[rand::random::<usize>() % 2];
    let mut result = [0xFF_u8; SIZE];
    result[0] = 0x4F;
    result[1] = 0b0010_1000;
    // total length
    result[2..4].copy_from_slice(&(SIZE as u16).to_be_bytes());
    // identification
    result[4..6].copy_from_slice(&rand::random::<[u8; 2]>());
    // flags & fragment offset
    result[4..6].copy_from_slice(&rand::random::<[u8; 2]>());
    // ttl
    result[6] = rand::random();
    // protocol
    result[7] = protocol;
    // checksum
    result[8..10].copy_from_slice(&[0, 0]);
    // source
    result[10..14].copy_from_slice(&rand::random::<[u8; 4]>());
    result[14..18].copy_from_slice(&rand::random::<[u8; 4]>());

    // checksum
    let checksum = &internet_checksum::<4>(0, &result[..18]).to_be_bytes();
    result[8..10].copy_from_slice(checksum);
    result
}

// IPv4 packet
#[allow(clippy::unusual_byte_groupings)]
#[rustfmt::skip]
static IP_V4: &[u8] = &[
    // Version & IHL
    0x45,
    // DSCP & ECN
    0b001010_00,
    // Total length
    0x00, 0x34,
    // Identification
    0x12, 0x34,
    // Flags & Fragment offset
    0x00, 0x00,
    // TTL
    0x01, 
    // Protocol
    0x06, 
    // Header Checksum
    0xA9, 0x66,
    // Source
    0x7f, 0x00, 0x00, 0x1,
    // Destination
    0x7f, 0x00, 0x00, 0x1,
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

#[allow(clippy::unusual_byte_groupings)]
#[rustfmt::skip]
static IP_V4_MAX_HEADER_LENGTH: &[u8] = &[
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

#[inline(always)]
pub fn parse_ipv4(
    bytes: &[u8],
) -> Result<DataBuffer<&[u8], Ipv4<NoPreviousHeaderInformation>>, ParseIpv4Error> {
    DataBuffer::<_, Ipv4<NoPreviousHeaderInformation>>::new(bytes, 0, false)
}

#[inline(always)]
fn parse_ipv4_etherparse(bytes: &[u8]) -> Result<Ipv4HeaderSlice, ReadError> {
    Ipv4HeaderSlice::from_slice(bytes)
}

pub fn ipv4(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipv4");
    //group.measurement_time(Duration::from_secs(20));

    group.throughput(Throughput::Bytes(IP_V4.len() as u64));

    group.bench_function("ipv4", |b| {
        b.iter(|| {
            let result = &parse_ipv4(std::hint::black_box(IP_V4));
            std::hint::black_box(result);
        })
    });

    group.bench_function("ipv4 rnd", |b| {
        b.iter_batched_ref(
            random_ipv4::<64>,
            |data| {
                let result = &parse_ipv4(std::hint::black_box(data));
                std::hint::black_box(result);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("ipv4 etherparse", |b| {
        b.iter(|| {
            let result = &parse_ipv4_etherparse(std::hint::black_box(IP_V4));
            std::hint::black_box(result);
        })
    });
    group.bench_function("ipv4 rnd etherparse", |b| {
        b.iter_batched_ref(
            random_ipv4::<64>,
            |data| {
                let result = &parse_ipv4_etherparse(std::hint::black_box(data));
                std::hint::black_box(result);
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

pub fn ipv4_max_header_length(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipv4");
    //group.measurement_time(Duration::from_secs(90));

    group.throughput(Throughput::Bytes(IP_V4_MAX_HEADER_LENGTH.len() as u64));

    group.bench_function("ipv4 max header length", |b| {
        b.iter(|| {
            let result = &parse_ipv4(std::hint::black_box(IP_V4_MAX_HEADER_LENGTH));
            std::hint::black_box(result);
        })
    });

    group.bench_function("ipv4 max header length etherparse", |b| {
        b.iter(|| {
            let result = &parse_ipv4_etherparse(std::hint::black_box(IP_V4_MAX_HEADER_LENGTH));
            std::hint::black_box(result);
        })
    });

    group.finish();
}

criterion_group!(benches, ipv4);

criterion_main!(benches);
