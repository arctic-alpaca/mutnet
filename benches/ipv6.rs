use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use etherparse::{Ipv6HeaderSlice, ReadError};
use mutnet::addresses::ipv6::Ipv6Addr;
use mutnet::data_buffer::{BufferIntoInner, DataBuffer, PayloadMut};
use mutnet::ipv6::{Ipv6, Ipv6Methods, Ipv6MethodsMut, ParseIpv6Error};
use mutnet::no_previous_header::NoPreviousHeaderInformation;
use mutnet::packet_data_enums::InternetProtocolNumber;

#[rustfmt::skip]
const IPV6: [u8; 60] = [
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
    let mut ipv6 = DataBuffer::<_, Ipv6<NoPreviousHeaderInformation>>::new(IPV6, 0).unwrap();
    ipv6.set_ipv6_traffic_class(rand::random());
    ipv6.set_ipv6_flow_label(rand::random());
    while ipv6.set_ipv6_payload_length(rand::random()).is_err() {}
    ipv6.set_ipv6_next_header(rand::random());
    ipv6.set_ipv6_hop_limit(rand::random());
    ipv6.set_ipv6_source(rand::random());
    ipv6.set_ipv6_destination(rand::random());
    ipv6.payload_mut()
        .iter_mut()
        .for_each(|byte| *byte = rand::random());

    ipv6.buffer_into_inner()
}

#[inline(always)]
pub fn mutnet_new(
    bytes: &[u8],
) -> Result<DataBuffer<&[u8], Ipv6<NoPreviousHeaderInformation>>, ParseIpv6Error> {
    DataBuffer::<_, Ipv6<NoPreviousHeaderInformation>>::new(bytes, 0)
}

#[inline(always)]
fn mutnet_get_functions_inlined(
    data_buffer: &impl Ipv6Methods,
) -> (u8, u8, u32, u16, u8, u8, Ipv6Addr, Ipv6Addr) {
    (
        data_buffer.ipv6_version(),
        data_buffer.ipv6_traffic_class(),
        data_buffer.ipv6_flow_label(),
        data_buffer.ipv6_payload_length(),
        data_buffer.ipv6_next_header(),
        data_buffer.ipv6_hop_limit(),
        data_buffer.ipv6_source(),
        data_buffer.ipv6_destination(),
    )
}

#[inline(never)]
fn mutnet_get_functions_not_inlined(
    data_buffer: &impl Ipv6Methods,
) -> (u8, u8, u32, u16, u8, u8, Ipv6Addr, Ipv6Addr) {
    (
        data_buffer.ipv6_version(),
        data_buffer.ipv6_traffic_class(),
        data_buffer.ipv6_flow_label(),
        data_buffer.ipv6_payload_length(),
        data_buffer.ipv6_next_header(),
        data_buffer.ipv6_hop_limit(),
        data_buffer.ipv6_source(),
        data_buffer.ipv6_destination(),
    )
}

#[inline(always)]
fn etherparse_new(bytes: &[u8]) -> Result<Ipv6HeaderSlice, ReadError> {
    Ipv6HeaderSlice::from_slice(bytes)
}

#[inline(always)]
fn etherparse_get_functions_inlined(
    data_buffer: &Ipv6HeaderSlice,
) -> (u8, u8, u32, u16, u8, u8, Ipv6Addr, Ipv6Addr) {
    (
        data_buffer.version(),
        data_buffer.traffic_class(),
        data_buffer.flow_label(),
        data_buffer.payload_length(),
        data_buffer.next_header(),
        data_buffer.hop_limit(),
        data_buffer.source(),
        data_buffer.destination(),
    )
}

#[inline(never)]
fn etherparse_get_functions_not_inlined(
    data_buffer: &Ipv6HeaderSlice,
) -> (u8, u8, u32, u16, u8, u8, Ipv6Addr, Ipv6Addr) {
    (
        data_buffer.version(),
        data_buffer.traffic_class(),
        data_buffer.flow_label(),
        data_buffer.payload_length(),
        data_buffer.next_header(),
        data_buffer.hop_limit(),
        data_buffer.source(),
        data_buffer.destination(),
    )
}

pub fn ipv6(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipv6");

    group.throughput(Throughput::Bytes(random_ipv6().len() as u64));

    group.bench_function("mutnet: new", |b| {
        b.iter_batched_ref(
            random_ipv6,
            |data| {
                let result = &mutnet_new(std::hint::black_box(data));
                std::hint::black_box(result);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("etherparse: new", |b| {
        b.iter_batched_ref(
            random_ipv6,
            |data| {
                let result = &etherparse_new(std::hint::black_box(data));
                std::hint::black_box(result);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("mutnet: new + get functions inlined", |b| {
        b.iter_batched_ref(
            random_ipv6,
            |data| {
                let buffer = DataBuffer::<_, Ipv6<NoPreviousHeaderInformation>>::new(
                    std::hint::black_box(data),
                    0,
                )
                .unwrap();
                let mut result = &mut mutnet_get_functions_inlined(&buffer);
                std::hint::black_box(&mut result);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("etherparse: new + get functions inlined", |b| {
        b.iter_batched_ref(
            random_ipv6,
            |data| {
                let ether_slice = Ipv6HeaderSlice::from_slice(std::hint::black_box(data)).unwrap();
                let mut result = &mut etherparse_get_functions_inlined(&ether_slice);
                std::hint::black_box(&mut result);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("mutnet: new + get functions not inlined", |b| {
        b.iter_batched_ref(
            random_ipv6,
            |data| {
                let buffer = DataBuffer::<_, Ipv6<NoPreviousHeaderInformation>>::new(
                    std::hint::black_box(data),
                    0,
                )
                .unwrap();
                let mut result = &mut mutnet_get_functions_not_inlined(&buffer);
                std::hint::black_box(&mut result);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("etherparse: new + get functions not inlined", |b| {
        b.iter_batched_ref(
            random_ipv6,
            |data| {
                let ether_slice = Ipv6HeaderSlice::from_slice(std::hint::black_box(data)).unwrap();
                let mut result = &mut etherparse_get_functions_not_inlined(&ether_slice);
                std::hint::black_box(&mut result);
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(benches, ipv6);

criterion_main!(benches);
