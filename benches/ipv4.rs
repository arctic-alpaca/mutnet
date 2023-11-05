use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use etherparse::{Ipv4HeaderSlice, ReadError};
use mutnet::data_buffer::{BufferIntoInner, DataBuffer, PayloadMut};
use mutnet::ipv4::{Ipv4, Ipv4Methods, Ipv4MethodsMut, ParseIpv4Error};
use mutnet::no_previous_header::NoPreviousHeaderInformation;
use mutnet::typed_protocol_headers::{Dscp, Ecn};
use rand::{thread_rng, Rng};

#[allow(clippy::unusual_byte_groupings)]
#[rustfmt::skip]
const IPV4: [u8; 92] = [
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

    let mut ipv4 = DataBuffer::<_, Ipv4<NoPreviousHeaderInformation>>::new(IPV4, 0, false).unwrap();
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
    ipv4.set_ipv4_source(rng.gen());
    ipv4.set_ipv4_destination(rng.gen());

    ipv4.ipv4_options_mut()
        .iter_mut()
        .for_each(|byte| *byte = rng.gen());
    ipv4.payload_mut()
        .iter_mut()
        .for_each(|byte| *byte = rng.gen());

    ipv4.buffer_into_inner()
}

#[inline(always)]
pub fn parse_ipv4(
    bytes: &[u8],
) -> Result<DataBuffer<&[u8], Ipv4<NoPreviousHeaderInformation>>, ParseIpv4Error> {
    DataBuffer::<_, Ipv4<NoPreviousHeaderInformation>>::new(bytes, 0, false)
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
    [u8; 4],
    [u8; 4],
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
    [u8; 4],
    [u8; 4],
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
fn parse_ipv4_etherparse(bytes: &[u8]) -> Result<Ipv4HeaderSlice, ReadError> {
    Ipv4HeaderSlice::from_slice(bytes)
}

#[allow(clippy::type_complexity)]
#[inline(always)]
fn etherparse_get_functions_inlined(
    data_buffer: &Ipv4HeaderSlice,
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
        data_buffer.dcp(),
        data_buffer.ecn(),
        data_buffer.total_len(),
        data_buffer.identification(),
        data_buffer.dont_fragment(),
        data_buffer.more_fragments(),
        data_buffer.fragments_offset(),
        data_buffer.ttl(),
        data_buffer.protocol(),
        data_buffer.header_checksum(),
        data_buffer.source(),
        data_buffer.destination(),
        data_buffer.payload_len(),
    )
}

#[allow(clippy::type_complexity)]
#[inline(never)]
fn etherparse_get_functions_not_inlined(
    data_buffer: &Ipv4HeaderSlice,
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
        data_buffer.dcp(),
        data_buffer.ecn(),
        data_buffer.total_len(),
        data_buffer.identification(),
        data_buffer.dont_fragment(),
        data_buffer.more_fragments(),
        data_buffer.fragments_offset(),
        data_buffer.ttl(),
        data_buffer.protocol(),
        data_buffer.header_checksum(),
        data_buffer.source(),
        data_buffer.destination(),
        data_buffer.payload_len(),
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
                let buffer = DataBuffer::<_, Ipv4<NoPreviousHeaderInformation>>::new(
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
                let ether_slice = Ipv4HeaderSlice::from_slice(std::hint::black_box(data)).unwrap();
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
                let buffer = DataBuffer::<_, Ipv4<NoPreviousHeaderInformation>>::new(
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
                let ether_slice = Ipv4HeaderSlice::from_slice(std::hint::black_box(data)).unwrap();
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
