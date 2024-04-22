use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};

use mutnet::error::UnexpectedBufferEndError;
use mutnet::ethernet::EthernetMethods;

include!("utils.rs");

#[inline(always)]
fn mutnet_new(bytes: &[u8]) -> Result<DataBuffer<&[u8], Eth>, UnexpectedBufferEndError> {
    DataBuffer::<_, Eth>::parse_ethernet_layer(bytes, 0)
}

#[inline(always)]
fn mutnet_get_functions_inlined(data_buffer: &impl EthernetMethods) -> ([u8; 6], [u8; 6], u16) {
    (
        data_buffer.ethernet_destination(),
        data_buffer.ethernet_source(),
        data_buffer.ethernet_ether_type(),
    )
}

#[inline(never)]
fn mutnet_get_functions_not_inlined(data_buffer: &impl EthernetMethods) -> ([u8; 6], [u8; 6], u16) {
    (
        data_buffer.ethernet_destination(),
        data_buffer.ethernet_source(),
        data_buffer.ethernet_ether_type(),
    )
}

#[inline(always)]
fn etherparse_new(
    bytes: &[u8],
) -> Result<etherparse::Ethernet2HeaderSlice, etherparse::err::LenError> {
    etherparse::Ethernet2HeaderSlice::from_slice(bytes)
}

#[inline(always)]
fn etherparse_get_functions_inlined(
    ether_slice: &etherparse::Ethernet2HeaderSlice,
) -> ([u8; 6], [u8; 6], u16) {
    (
        ether_slice.destination(),
        ether_slice.source(),
        ether_slice.ether_type().0,
    )
}

#[inline(never)]
fn etherparse_get_functions_not_inlined(
    ether_slice: &etherparse::Ethernet2HeaderSlice,
) -> ([u8; 6], [u8; 6], u16) {
    (
        ether_slice.destination(),
        ether_slice.source(),
        ether_slice.ether_type().0,
    )
}

pub fn ethernet(c: &mut Criterion) {
    let mut group = c.benchmark_group("ethernet");

    group.throughput(Throughput::Bytes(random_valid_ethernet().len() as u64));

    group.bench_function("mutnet: new", |b| {
        b.iter_batched_ref(
            random_valid_ethernet,
            |data| {
                let mut result = &mut mutnet_new(std::hint::black_box(data));
                std::hint::black_box(&mut result);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("etherparse: new", |b| {
        b.iter_batched_ref(
            random_valid_ethernet,
            |data| {
                let mut result = &mut etherparse_new(std::hint::black_box(data));
                std::hint::black_box(&mut result);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("mutnet: new + get functions inlined", |b| {
        b.iter_batched_ref(
            random_valid_ethernet,
            |data| {
                let buffer =
                    DataBuffer::<_, Eth>::parse_ethernet_layer(std::hint::black_box(data), 0)
                        .unwrap();
                let mut result = &mut mutnet_get_functions_inlined(&buffer);
                std::hint::black_box(&mut result);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("etherparse: new + get functions inlined", |b| {
        b.iter_batched_ref(
            random_valid_ethernet,
            |data| {
                let ether_slice =
                    etherparse::Ethernet2HeaderSlice::from_slice(std::hint::black_box(data))
                        .unwrap();
                let mut result = &mut etherparse_get_functions_inlined(&ether_slice);
                std::hint::black_box(&mut result);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("mutnet: new + get functions not inlined", |b| {
        b.iter_batched_ref(
            random_valid_ethernet,
            |data| {
                let buffer =
                    DataBuffer::<_, Eth>::parse_ethernet_layer(std::hint::black_box(data), 0)
                        .unwrap();
                let mut result = &mut mutnet_get_functions_not_inlined(&buffer);
                std::hint::black_box(&mut result);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("etherparse: new + get functions not inlined", |b| {
        b.iter_batched_ref(
            random_valid_ethernet,
            |data| {
                let ether_slice =
                    etherparse::Ethernet2HeaderSlice::from_slice(std::hint::black_box(data))
                        .unwrap();
                let mut result = &mut etherparse_get_functions_not_inlined(&ether_slice);
                std::hint::black_box(&mut result);
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(benches, ethernet);

criterion_main!(benches);
