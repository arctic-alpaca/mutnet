use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use mutnet::udp::{ParseUdpError, UdpMethods};

include!("utils.rs");

#[inline(always)]
pub fn mutnet_new(bytes: &[u8]) -> Result<DataBuffer<&[u8], Udp<NoPreviousHeader>>, ParseUdpError> {
    DataBuffer::<_, Udp<NoPreviousHeader>>::parse_udp_alone(bytes, 0)
}

#[inline(always)]
fn mutnet_get_functions_inlined(data_buffer: &impl UdpMethods) -> (u16, u16, u16, u16) {
    (
        data_buffer.udp_source_port(),
        data_buffer.udp_destination_port(),
        data_buffer.udp_length(),
        data_buffer.udp_checksum(),
    )
}

#[inline(never)]
fn mutnet_get_functions_not_inlined(data_buffer: &impl UdpMethods) -> (u16, u16, u16, u16) {
    (
        data_buffer.udp_source_port(),
        data_buffer.udp_destination_port(),
        data_buffer.udp_length(),
        data_buffer.udp_checksum(),
    )
}

#[inline(always)]
fn etherparse_new(bytes: &[u8]) -> Result<etherparse::UdpHeaderSlice, etherparse::err::LenError> {
    etherparse::UdpHeaderSlice::from_slice(bytes)
}

#[inline(always)]
fn etherparse_get_functions_inlined(
    data_buffer: &etherparse::UdpHeaderSlice,
) -> (u16, u16, u16, u16) {
    (
        data_buffer.source_port(),
        data_buffer.destination_port(),
        data_buffer.length(),
        data_buffer.checksum(),
    )
}

#[inline(never)]
fn etherparse_get_functions_not_inlined(
    data_buffer: &etherparse::UdpHeaderSlice,
) -> (u16, u16, u16, u16) {
    (
        data_buffer.source_port(),
        data_buffer.destination_port(),
        data_buffer.length(),
        data_buffer.checksum(),
    )
}

pub fn tcp(c: &mut Criterion) {
    let mut group = c.benchmark_group("udp");

    group.throughput(Throughput::Bytes(40));

    group.bench_function("mutnet: new", |b| {
        b.iter_batched_ref(
            random_udp,
            |data| {
                let result = &mutnet_new(std::hint::black_box(data));
                std::hint::black_box(result);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("etherparse: new", |b| {
        b.iter_batched_ref(
            random_udp,
            |data| {
                let result = &etherparse_new(std::hint::black_box(data));
                std::hint::black_box(result);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("mutnet: new + get functions inlined", |b| {
        b.iter_batched_ref(
            random_udp,
            |data| {
                let buffer = DataBuffer::<_, Udp<NoPreviousHeader>>::parse_udp_alone(
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
            random_udp,
            |data| {
                let ether_slice =
                    etherparse::UdpHeaderSlice::from_slice(std::hint::black_box(data)).unwrap();
                let mut result = &mut etherparse_get_functions_inlined(&ether_slice);
                std::hint::black_box(&mut result);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("mutnet: new + get functions not inlined", |b| {
        b.iter_batched_ref(
            random_udp,
            |data| {
                let buffer = DataBuffer::<_, Udp<NoPreviousHeader>>::parse_udp_alone(
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
            random_udp,
            |data| {
                let ether_slice =
                    etherparse::UdpHeaderSlice::from_slice(std::hint::black_box(data)).unwrap();
                let mut result = &mut etherparse_get_functions_not_inlined(&ether_slice);
                std::hint::black_box(&mut result);
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(benches, tcp);

criterion_main!(benches);
