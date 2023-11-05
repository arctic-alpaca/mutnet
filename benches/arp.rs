use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use mutnet::addresses::ipv4::Ipv4Address;
use mutnet::addresses::mac::MacAddress;
use mutnet::arp::{Arp, ArpMethods, ArpMethodsMut, ParseArpError};
use mutnet::data_buffer::{BufferIntoInner, DataBuffer};
use mutnet::no_previous_header::NoPreviousHeaderInformation;
use mutnet::typed_protocol_headers::OperationCode;
use rand::{thread_rng, Rng};

// ARP for IPv4
#[rustfmt::skip]
const ARP_IPV4_REQUEST1: [u8;28] = [
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

pub fn random_valid_arp() -> [u8; 28] {
    let mut rng = thread_rng();

    let mut arp =
        DataBuffer::<_, Arp<NoPreviousHeaderInformation>>::new(ARP_IPV4_REQUEST1, 0).unwrap();

    let operation_code = match rng.gen_range(0..2) {
        0_u8 => OperationCode::Reply,
        1.. => OperationCode::Request,
    };

    arp.set_arp_operation_code(operation_code);
    arp.set_arp_sender_hardware_address(&rng.gen());
    arp.set_arp_sender_protocol_address(&rng.gen());
    arp.set_arp_target_hardware_address(&rng.gen());
    arp.set_arp_target_protocol_address(&rng.gen());

    arp.buffer_into_inner()
}

#[inline(always)]
fn mutnet_new(
    bytes: &mut [u8],
) -> Result<DataBuffer<&mut [u8], Arp<NoPreviousHeaderInformation>>, ParseArpError> {
    DataBuffer::<_, Arp<NoPreviousHeaderInformation>>::new(bytes, 0)
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
    Ipv4Address,
    MacAddress,
    Ipv4Address,
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
    Ipv4Address,
    MacAddress,
    Ipv4Address,
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
                let buffer = DataBuffer::<_, Arp<NoPreviousHeaderInformation>>::new(
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
                let buffer = DataBuffer::<_, Arp<NoPreviousHeaderInformation>>::new(
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
