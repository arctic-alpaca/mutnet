use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};

use mutnet::addresses::mac::MacAddress;
use mutnet::arp::{ArpMethods, ParseArpError};

include!("utils.rs");

#[inline(always)]
fn mutnet_new(
    bytes: &mut [u8],
) -> Result<DataBuffer<&mut [u8], Arp<NoPreviousHeader>>, ParseArpError> {
    DataBuffer::<_, Arp<NoPreviousHeader>>::parse_arp_alone(bytes, 0)
}

#[inline(always)]
fn mutnet_get_functions_inlined(
    data_buffer: &impl ArpMethods,
) -> (
    u16,
    u16,
    u16,
    u8,
    u8,
    MacAddress,
    Ipv4Addr,
    MacAddress,
    Ipv4Addr,
) {
    (
        data_buffer.arp_hardware_type(),
        data_buffer.arp_protocol_type(),
        data_buffer.arp_operation_code(),
        data_buffer.arp_hardware_address_length(),
        data_buffer.arp_protocol_address_length(),
        data_buffer.arp_sender_hardware_address(),
        data_buffer.arp_sender_protocol_address(),
        data_buffer.arp_target_hardware_address(),
        data_buffer.arp_target_protocol_address(),
    )
}

#[inline(never)]
fn mutnet_get_functions_not_inlined(
    data_buffer: &impl ArpMethods,
) -> (
    u16,
    u16,
    u16,
    u8,
    u8,
    MacAddress,
    Ipv4Addr,
    MacAddress,
    Ipv4Addr,
) {
    (
        data_buffer.arp_hardware_type(),
        data_buffer.arp_protocol_type(),
        data_buffer.arp_operation_code(),
        data_buffer.arp_hardware_address_length(),
        data_buffer.arp_protocol_address_length(),
        data_buffer.arp_sender_hardware_address(),
        data_buffer.arp_sender_protocol_address(),
        data_buffer.arp_target_hardware_address(),
        data_buffer.arp_target_protocol_address(),
    )
}

pub fn arp(c: &mut Criterion) {
    let mut group = c.benchmark_group("arp");

    group.throughput(Throughput::Bytes(random_valid_arp().len() as u64));

    group.bench_function("mutnet: new", |b| {
        b.iter_batched_ref(
            random_valid_arp,
            |data| {
                let mut result = &mut mutnet_new(std::hint::black_box(data));
                std::hint::black_box(&mut result);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("mutnet: new + get functions inlined", |b| {
        b.iter_batched_ref(
            random_valid_arp,
            |data| {
                let buffer = DataBuffer::<_, Arp<NoPreviousHeader>>::parse_arp_alone(
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

    group.bench_function("mutnet: new + get functions not inlined", |b| {
        b.iter_batched_ref(
            random_valid_arp,
            |data| {
                let buffer = DataBuffer::<_, Arp<NoPreviousHeader>>::parse_arp_alone(
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

    group.finish();
}

criterion_group!(benches, arp);

criterion_main!(benches);
