use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use mutnet::ipv4::{Ipv4Methods, ParseIpv4Error};

include!("utils.rs");

#[inline(always)]
pub fn parse_ipv4(
    bytes: &[u8],
) -> Result<DataBuffer<&[u8], Ipv4<NoPreviousHeader>>, ParseIpv4Error> {
    DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(bytes, 0, false)
}

#[allow(clippy::type_complexity)]
#[inline(always)]
fn mutnet_get_functions_inlined(
    data_buffer: &impl Ipv4Methods,
) -> (
    u8,
    u8,
    u8,
    u8,
    u16,
    u16,
    bool,
    bool,
    u16,
    u8,
    u8,
    u16,
    Ipv4Addr,
    Ipv4Addr,
    u16,
) {
    (
        data_buffer.ipv4_version(),
        data_buffer.ipv4_ihl(),
        data_buffer.ipv4_dscp(),
        data_buffer.ipv4_ecn(),
        data_buffer.ipv4_total_length(),
        data_buffer.ipv4_identification(),
        data_buffer.ipv4_dont_fragment_flag(),
        data_buffer.ipv4_more_fragments_flag(),
        data_buffer.ipv4_fragment_offset(),
        data_buffer.ipv4_time_to_live(),
        data_buffer.ipv4_protocol(),
        data_buffer.ipv4_header_checksum(),
        data_buffer.ipv4_source(),
        data_buffer.ipv4_destination(),
        data_buffer.ipv4_payload_length(),
    )
}

#[allow(clippy::type_complexity)]
#[inline(never)]
fn mutnet_get_functions_not_inlined(
    data_buffer: &impl Ipv4Methods,
) -> (
    u8,
    u8,
    u8,
    u8,
    u16,
    u16,
    bool,
    bool,
    u16,
    u8,
    u8,
    u16,
    Ipv4Addr,
    Ipv4Addr,
    u16,
) {
    (
        data_buffer.ipv4_version(),
        data_buffer.ipv4_ihl(),
        data_buffer.ipv4_dscp(),
        data_buffer.ipv4_ecn(),
        data_buffer.ipv4_total_length(),
        data_buffer.ipv4_identification(),
        data_buffer.ipv4_dont_fragment_flag(),
        data_buffer.ipv4_more_fragments_flag(),
        data_buffer.ipv4_fragment_offset(),
        data_buffer.ipv4_time_to_live(),
        data_buffer.ipv4_protocol(),
        data_buffer.ipv4_header_checksum(),
        data_buffer.ipv4_source(),
        data_buffer.ipv4_destination(),
        data_buffer.ipv4_payload_length(),
    )
}

#[inline(always)]
fn parse_ipv4_etherparse(
    bytes: &[u8],
) -> Result<etherparse::Ipv4HeaderSlice, etherparse::err::ipv4::HeaderSliceError> {
    etherparse::Ipv4HeaderSlice::from_slice(bytes)
}

#[allow(clippy::type_complexity)]
#[inline(always)]
fn etherparse_get_functions_inlined(
    data_buffer: &etherparse::Ipv4HeaderSlice,
) -> (
    u8,
    u8,
    u8,
    u8,
    u16,
    u16,
    bool,
    bool,
    u16,
    u8,
    u8,
    u16,
    [u8; 4],
    [u8; 4],
    u16,
) {
    (
        data_buffer.version(),
        data_buffer.ihl(),
        data_buffer.dcp().value(),
        data_buffer.ecn().value(),
        data_buffer.total_len(),
        data_buffer.identification(),
        data_buffer.dont_fragment(),
        data_buffer.more_fragments(),
        data_buffer.fragments_offset().value(),
        data_buffer.ttl(),
        data_buffer.protocol().0,
        data_buffer.header_checksum(),
        data_buffer.source(),
        data_buffer.destination(),
        data_buffer.payload_len().unwrap(),
    )
}

#[allow(clippy::type_complexity)]
#[inline(never)]
fn etherparse_get_functions_not_inlined(
    data_buffer: &etherparse::Ipv4HeaderSlice,
) -> (
    u8,
    u8,
    u8,
    u8,
    u16,
    u16,
    bool,
    bool,
    u16,
    u8,
    u8,
    u16,
    [u8; 4],
    [u8; 4],
    u16,
) {
    (
        data_buffer.version(),
        data_buffer.ihl(),
        data_buffer.dcp().value(),
        data_buffer.ecn().value(),
        data_buffer.total_len(),
        data_buffer.identification(),
        data_buffer.dont_fragment(),
        data_buffer.more_fragments(),
        data_buffer.fragments_offset().value(),
        data_buffer.ttl(),
        data_buffer.protocol().0,
        data_buffer.header_checksum(),
        data_buffer.source(),
        data_buffer.destination(),
        data_buffer.payload_len().unwrap(),
    )
}

pub fn ipv4(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipv4");

    group.throughput(Throughput::Bytes(random_ipv4().len() as u64));

    group.bench_function("mutnet: new", |b| {
        b.iter_batched_ref(
            random_ipv4,
            |data| {
                let result = &parse_ipv4(std::hint::black_box(data));
                std::hint::black_box(result);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("etherparse: new", |b| {
        b.iter_batched_ref(
            random_ipv4,
            |data| {
                let result = &parse_ipv4_etherparse(std::hint::black_box(data));
                std::hint::black_box(result);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("mutnet: new + get functions inlined", |b| {
        b.iter_batched_ref(
            random_ipv4,
            |data| {
                let buffer = DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(
                    std::hint::black_box(data),
                    0,
                    false,
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
            random_ipv4,
            |data| {
                let ether_slice =
                    etherparse::Ipv4HeaderSlice::from_slice(std::hint::black_box(data)).unwrap();
                let mut result = &mut etherparse_get_functions_inlined(&ether_slice);
                std::hint::black_box(&mut result);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("mutnet: new + get functions not inlined", |b| {
        b.iter_batched_ref(
            random_ipv4,
            |data| {
                let buffer = DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(
                    std::hint::black_box(data),
                    0,
                    false,
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
            random_ipv4,
            |data| {
                let ether_slice =
                    etherparse::Ipv4HeaderSlice::from_slice(std::hint::black_box(data)).unwrap();
                let mut result = &mut etherparse_get_functions_not_inlined(&ether_slice);
                std::hint::black_box(&mut result);
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(benches, ipv4);

criterion_main!(benches);
