use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use mutnet::arp::{Arp, ParseArpError};
use mutnet::data_buffer::DataBuffer;
use mutnet::no_previous_header::NoPreviousHeaderInformation;

// ARP for IPv4
#[rustfmt::skip]
static ARP_IPV4_REQUEST: &[u8] = &[
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

// ARP for IPv4
#[rustfmt::skip]
static ARP_IPV4_REPLY: &[u8] = &[
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

#[inline(always)]
fn parse_arp(
    bytes: &mut [u8],
) -> Result<DataBuffer<&mut [u8], Arp<NoPreviousHeaderInformation>>, ParseArpError> {
    DataBuffer::<_, Arp<NoPreviousHeaderInformation>>::new(bytes, 0)
}

pub fn request(c: &mut Criterion) {
    let mut arp_request = Vec::from(ARP_IPV4_REQUEST);
    let arp_request_slice = arp_request.as_mut_slice();

    let mut group = c.benchmark_group("arp");
    //group.measurement_time(Duration::from_secs(90));

    group.throughput(Throughput::Bytes(arp_request_slice.len() as u64));

    group.bench_function("request", |b| {
        b.iter(|| {
            let result = &parse_arp(std::hint::black_box(arp_request_slice));
            std::hint::black_box(result);
        })
    });

    group.finish();
}

pub fn reply(c: &mut Criterion) {
    let mut arp_reply = Vec::from(ARP_IPV4_REPLY);
    let arp_reply_slice = arp_reply.as_mut_slice();

    let mut group = c.benchmark_group("arp");
    //group.measurement_time(Duration::from_secs(90));

    group.throughput(Throughput::Bytes(arp_reply_slice.len() as u64));

    group.bench_function("reply", |b| {
        b.iter(|| {
            let result = &parse_arp(std::hint::black_box(arp_reply_slice));
            std::hint::black_box(result);
        })
    });

    group.finish();
}

criterion_group!(benches, request, reply);

criterion_main!(benches);
