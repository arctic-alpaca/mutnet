use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use mutnet::data_buffer::{BufferIntoInner, DataBuffer, PayloadMut};
use mutnet::error::UnexpectedBufferEndError;
use mutnet::ethernet::{Eth, EthernetMethods, EthernetMethodsMut};
use mutnet::typed_protocol_headers::EtherType;

#[rustfmt::skip]
const ETHERNET: [u8; 64] = [
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

fn random_valid_ethernet() -> [u8; 64] {
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
fn etherparse_new(bytes: &[u8]) -> Result<etherparse::Ethernet2HeaderSlice, etherparse::ReadError> {
    etherparse::Ethernet2HeaderSlice::from_slice(bytes)
}

#[inline(always)]
fn etherparse_get_functions_inlined(
    ether_slice: &etherparse::Ethernet2HeaderSlice,
) -> ([u8; 6], [u8; 6], u16) {
    (
        ether_slice.destination(),
        ether_slice.source(),
        ether_slice.ether_type(),
    )
}

#[inline(never)]
fn etherparse_get_functions_not_inlined(
    ether_slice: &etherparse::Ethernet2HeaderSlice,
) -> ([u8; 6], [u8; 6], u16) {
    (
        ether_slice.destination(),
        ether_slice.source(),
        ether_slice.ether_type(),
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
