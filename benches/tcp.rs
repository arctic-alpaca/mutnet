use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use mutnet::data_buffer::{BufferIntoInner, DataBuffer, PayloadMut};
use mutnet::no_previous_header::NoPreviousHeader;
use mutnet::tcp::{ParseTcpError, Tcp, TcpMethods, TcpMethodsMut};

#[rustfmt::skip]
const TCP: [u8;60] = [
    // Source port
    0x12, 0x34,
    // Destination port
    0x45, 0x67,
    // Sequence number
    0x12, 0x34, 0x56, 0x78,
    // Acknowledgment number
    0x09, 0x87, 0x65, 0x43,
    // Data offset, reserved bits, flags
    0xF0, 0b0101_0101,
    // Window
    0x12, 0x45,
    // Checksum
    0x12, 0x34,
    // Urgent pointer
    0x56, 0x78,
    // Options
    0xFF, 0xFF,
    0xFF, 0xFF,
    0xFF, 0xFF,
    0xFF, 0xFF,
    // Payload
    0xFF, 0xFF,
    0xFF, 0xFF,
    0xFF, 0xFF,
    0xFF, 0xFF,
    0xFF, 0xFF,
    0xFF, 0xFF,
    0xFF, 0xFF,
    0xFF, 0xFF,0xFF, 0xFF,
    0xFF, 0xFF,
    0xFF, 0xFF,
    0xFF, 0xFF,0xFF, 0xFF,
    0xFF, 0xFF,
    0xFF, 0xFF,
    0xFF, 0xFF,
];

pub fn random_tcp() -> [u8; 60] {
    let mut tcp = DataBuffer::<_, Tcp<NoPreviousHeader>>::parse_tcp_alone(TCP, 0).unwrap();
    tcp.set_tcp_source_port(rand::random());
    tcp.set_tcp_destination_port(rand::random());
    tcp.set_tcp_sequence_number(rand::random());
    tcp.set_tcp_acknowledgement_number(rand::random());
    tcp.set_tcp_reserved_bits(rand::random());
    tcp.set_tcp_flags(rand::random());
    tcp.set_tcp_window_size(rand::random());
    tcp.set_tcp_checksum(rand::random());
    tcp.set_tcp_urgent_pointer(rand::random());
    if let Some(options) = tcp.tcp_options_mut() {
        options.iter_mut().for_each(|byte| *byte = rand::random());
    }
    tcp.payload_mut()
        .iter_mut()
        .for_each(|byte| *byte = rand::random());

    let mut buffer = tcp.buffer_into_inner();
    buffer[13] = rand::random();
    buffer
}

#[inline(always)]
pub fn mutnet_new(bytes: &[u8]) -> Result<DataBuffer<&[u8], Tcp<NoPreviousHeader>>, ParseTcpError> {
    DataBuffer::<_, Tcp<NoPreviousHeader>>::parse_tcp_alone(bytes, 0)
}

#[allow(clippy::type_complexity)]
#[inline(always)]
fn mutnet_get_functions_inlined(
    data_buffer: &impl TcpMethods,
) -> (
    u16,
    u16,
    u32,
    u32,
    u8,
    bool,
    bool,
    bool,
    bool,
    bool,
    bool,
    bool,
    bool,
    u16,
    u16,
    u16,
) {
    (
        data_buffer.tcp_source_port(),
        data_buffer.tcp_destination_port(),
        data_buffer.tcp_sequence_number(),
        data_buffer.tcp_acknowledgment_number(),
        data_buffer.tcp_data_offset(),
        data_buffer.tcp_congestion_window_reduced_flag(),
        data_buffer.tcp_ecn_echo_flag(),
        data_buffer.tcp_urgent_pointer_flag(),
        data_buffer.tcp_acknowledgement_flag(),
        data_buffer.tcp_push_flag(),
        data_buffer.tcp_reset_flag(),
        data_buffer.tcp_synchronize_flag(),
        data_buffer.tcp_fin_flag(),
        data_buffer.tcp_window_size(),
        data_buffer.tcp_checksum(),
        data_buffer.tcp_urgent_pointer(),
    )
}

#[allow(clippy::type_complexity)]
#[inline(never)]
fn mutnet_get_functions_not_inlined(
    data_buffer: &impl TcpMethods,
) -> (
    u16,
    u16,
    u32,
    u32,
    u8,
    bool,
    bool,
    bool,
    bool,
    bool,
    bool,
    bool,
    bool,
    u16,
    u16,
    u16,
) {
    (
        data_buffer.tcp_source_port(),
        data_buffer.tcp_destination_port(),
        data_buffer.tcp_sequence_number(),
        data_buffer.tcp_acknowledgment_number(),
        data_buffer.tcp_data_offset(),
        data_buffer.tcp_congestion_window_reduced_flag(),
        data_buffer.tcp_ecn_echo_flag(),
        data_buffer.tcp_urgent_pointer_flag(),
        data_buffer.tcp_acknowledgement_flag(),
        data_buffer.tcp_push_flag(),
        data_buffer.tcp_reset_flag(),
        data_buffer.tcp_synchronize_flag(),
        data_buffer.tcp_fin_flag(),
        data_buffer.tcp_window_size(),
        data_buffer.tcp_checksum(),
        data_buffer.tcp_urgent_pointer(),
    )
}

#[inline(always)]
fn etherparse_new(
    bytes: &[u8],
) -> Result<etherparse::TcpHeaderSlice, etherparse::err::tcp::HeaderSliceError> {
    etherparse::TcpHeaderSlice::from_slice(bytes)
}

#[allow(clippy::type_complexity)]
#[inline(always)]
fn etherparse_get_functions_inlined(
    data_buffer: &etherparse::TcpHeaderSlice,
) -> (
    u16,
    u16,
    u32,
    u32,
    u8,
    bool,
    bool,
    bool,
    bool,
    bool,
    bool,
    bool,
    bool,
    u16,
    u16,
    u16,
) {
    (
        data_buffer.source_port(),
        data_buffer.destination_port(),
        data_buffer.sequence_number(),
        data_buffer.acknowledgment_number(),
        data_buffer.data_offset(),
        data_buffer.cwr(),
        data_buffer.ece(),
        data_buffer.urg(),
        data_buffer.ack(),
        data_buffer.psh(),
        data_buffer.rst(),
        data_buffer.syn(),
        data_buffer.fin(),
        data_buffer.window_size(),
        data_buffer.checksum(),
        data_buffer.urgent_pointer(),
    )
}

#[allow(clippy::type_complexity)]
#[inline(never)]
fn etherparse_get_functions_not_inlined(
    data_buffer: &etherparse::TcpHeaderSlice,
) -> (
    u16,
    u16,
    u32,
    u32,
    u8,
    bool,
    bool,
    bool,
    bool,
    bool,
    bool,
    bool,
    bool,
    u16,
    u16,
    u16,
) {
    (
        data_buffer.source_port(),
        data_buffer.destination_port(),
        data_buffer.sequence_number(),
        data_buffer.acknowledgment_number(),
        data_buffer.data_offset(),
        data_buffer.cwr(),
        data_buffer.ece(),
        data_buffer.urg(),
        data_buffer.ack(),
        data_buffer.psh(),
        data_buffer.rst(),
        data_buffer.syn(),
        data_buffer.fin(),
        data_buffer.window_size(),
        data_buffer.checksum(),
        data_buffer.urgent_pointer(),
    )
}

pub fn tcp(c: &mut Criterion) {
    let mut group = c.benchmark_group("tcp");

    group.throughput(Throughput::Bytes(40));

    group.bench_function("mutnet: new", |b| {
        b.iter_batched_ref(
            random_tcp,
            |data| {
                let result = &mutnet_new(std::hint::black_box(data));
                std::hint::black_box(result);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("etherparse: new", |b| {
        b.iter_batched_ref(
            random_tcp,
            |data| {
                let result = &etherparse_new(std::hint::black_box(data));
                std::hint::black_box(result);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("mutnet: new + get functions inlined", |b| {
        b.iter_batched_ref(
            random_tcp,
            |data| {
                let buffer = DataBuffer::<_, Tcp<NoPreviousHeader>>::parse_tcp_alone(
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
            random_tcp,
            |data| {
                let ether_slice =
                    etherparse::TcpHeaderSlice::from_slice(std::hint::black_box(data)).unwrap();
                let mut result = &mut etherparse_get_functions_inlined(&ether_slice);
                std::hint::black_box(&mut result);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("mutnet: new + get functions not inlined", |b| {
        b.iter_batched_ref(
            random_tcp,
            |data| {
                let buffer = DataBuffer::<_, Tcp<NoPreviousHeader>>::parse_tcp_alone(
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
            random_tcp,
            |data| {
                let ether_slice =
                    etherparse::TcpHeaderSlice::from_slice(std::hint::black_box(data)).unwrap();
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
