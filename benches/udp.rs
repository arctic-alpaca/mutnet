use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use etherparse::{ReadError, UdpHeaderSlice};
use mutnet::data_buffer::{BufferIntoInner, DataBuffer, PayloadMut};
use mutnet::no_previous_header::NoPreviousHeader;
use mutnet::udp::{ParseUdpError, Udp, UdpMethods, UdpMethodsMut};
use rand::{thread_rng, Rng};

#[rustfmt::skip]
const UDP: [u8; 14] = [
    // Source port
    0x12, 0x34, 
    // Destination port
    0x0, 0x0, 
    // Length
    0x00, 0x0C, 
    // Checksum
    0xAB, 0xCD, 
    // Payload
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];

pub fn random_udp() -> [u8; 14] {
    let mut rng = thread_rng();

    let mut udp = DataBuffer::<_, Udp<NoPreviousHeader>>::new_without_checksum(UDP, 0).unwrap();
    udp.set_udp_destination_port(rand::random());
    udp.set_udp_source_port(rand::random());
    udp.set_udp_checksum(rand::random());
    udp.set_udp_length(rng.gen_range(8..14)).unwrap();
    udp.payload_mut()
        .iter_mut()
        .for_each(|byte| *byte = rand::random());

    udp.buffer_into_inner()
}

#[inline(always)]
pub fn mutnet_new(bytes: &[u8]) -> Result<DataBuffer<&[u8], Udp<NoPreviousHeader>>, ParseUdpError> {
    DataBuffer::<_, Udp<NoPreviousHeader>>::new_without_checksum(bytes, 0)
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
fn etherparse_new(bytes: &[u8]) -> Result<UdpHeaderSlice, ReadError> {
    UdpHeaderSlice::from_slice(bytes)
}

#[inline(always)]
fn etherparse_get_functions_inlined(data_buffer: &UdpHeaderSlice) -> (u16, u16, u16, u16) {
    (
        data_buffer.source_port(),
        data_buffer.destination_port(),
        data_buffer.length(),
        data_buffer.checksum(),
    )
}

#[inline(never)]
fn etherparse_get_functions_not_inlined(data_buffer: &UdpHeaderSlice) -> (u16, u16, u16, u16) {
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
                let buffer = DataBuffer::<_, Udp<NoPreviousHeader>>::new_without_checksum(
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
                let ether_slice = UdpHeaderSlice::from_slice(std::hint::black_box(data)).unwrap();
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
                let buffer = DataBuffer::<_, Udp<NoPreviousHeader>>::new_without_checksum(
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
                let ether_slice = UdpHeaderSlice::from_slice(std::hint::black_box(data)).unwrap();
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
