use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use etherparse::{ReadError, SlicedPacket};
use mutnet::addresses::mac::MacAddress;
use mutnet::data_buffer::DataBuffer;
use mutnet::error::{ParseNetworkDataError, UnexpectedBufferEndError};
use mutnet::ether_type::EtherType;
use mutnet::ethernet::{Eth, EthernetMethodsMut};
use mutnet::ieee802_1q_vlan::{Ieee802_1QVlan, ParseIeee802_1QError};
use mutnet::multi_step_parser::{parse_network_data, EthernetMultiStepParserResult};
use mutnet::vlan::Vlan;

fn random_ethernet<const SIZE: usize>(tag: Option<Vlan>) -> [u8; SIZE] {
    let ether_type = [
        EtherType::AppleTalk as u16,
        EtherType::EtherCat as u16,
        EtherType::EthernetFlowControl as u16,
    ];
    let ether_type = ether_type[rand::random::<usize>() % 3];
    let mut result = [0xFF_u8; SIZE];

    result[..6].copy_from_slice(&rand::random::<MacAddress>());
    result[6..12].copy_from_slice(&rand::random::<MacAddress>());
    match tag {
        Some(Vlan::SingleTagged) => {
            result[12..14].copy_from_slice(&(EtherType::CustomerTag as u16).to_be_bytes());
            result[14..16].copy_from_slice(&rand::random::<[u8; 2]>());
            result[16..18].copy_from_slice(&ether_type.to_be_bytes());
        }
        Some(Vlan::DoubleTagged) => {
            result[12..14].copy_from_slice(&(EtherType::ServiceTag as u16).to_be_bytes());
            result[14..16].copy_from_slice(&rand::random::<[u8; 2]>());
            result[16..18].copy_from_slice(&(EtherType::CustomerTag as u16).to_be_bytes());
            result[18..20].copy_from_slice(&rand::random::<[u8; 2]>());
            result[20..22].copy_from_slice(&ether_type.to_be_bytes());
        }
        None => {
            result[12..14].copy_from_slice(&ether_type.to_be_bytes());
        }
    }

    result
}

#[rustfmt::skip]
static ETHERNET_MIN_SIZE_UNTAGGED: [u8; 64] = [
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

#[rustfmt::skip]
static ETHERNET_MIN_SIZE_SINGLE_TAGGED: [u8; 64] = [
    // Dst
    0x0, 0x80, 0x41, 0xAE, 0xFD, 0x7E,
    // Src
    0x7E, 0xFD, 0xAE, 0x41, 0x80, 0x0,
    // VLAN tag
    0x81, 0x00,
    // VLAN parameter
    0xFF, 0xFF,
    // Ether type
    0x88, 0x08,
    // Payload
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
];

#[rustfmt::skip]
static ETHERNET_MIN_SIZE_DOUBLE_TAGGED: [u8; 64] = [
    // Dst
    0x0, 0x80, 0x41, 0xAE, 0xFD, 0x7E,
    // Src
    0x7E, 0xFD, 0xAE, 0x41, 0x80, 0x0,
    // 1. VLAN tag
    0x88, 0xA8,
    // 1. VLAN parameter
    0xFF, 0xFF,
    // 2. VLAN tag
    0x81, 0x00,
    // 2. VLAN parameter
    0xFF, 0xFF,
    // Ether type
    0x88, 0x08,
    // Payload
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF,
];

#[inline(always)]
fn parse_ether(bytes: &[u8]) -> Result<DataBuffer<&[u8], Eth>, UnexpectedBufferEndError> {
    DataBuffer::<_, Eth>::new(bytes, 0)
}

#[inline(always)]
fn parse_ether_vlan(
    bytes: &[u8],
) -> Result<DataBuffer<&[u8], Ieee802_1QVlan<Eth>>, ParseIeee802_1QError> {
    let ethernet = DataBuffer::<_, Eth>::new(bytes, 0)?;
    DataBuffer::<_, Ieee802_1QVlan<Eth>>::new_from_lower(ethernet, Vlan::SingleTagged)
}

#[inline(always)]
fn parse_ether_vlan_multi(
    bytes: &[u8],
) -> Result<EthernetMultiStepParserResult<&[u8], 10>, ParseNetworkDataError> {
    parse_network_data(bytes, 0, true, true)
}

#[inline(always)]
fn parse_ether_etherparse(
    bytes: &[u8],
) -> Result<etherparse::Ethernet2HeaderSlice, etherparse::ReadError> {
    etherparse::Ethernet2HeaderSlice::from_slice(bytes)
}

#[inline(always)]
fn parse_ether_etherparse_multi(bytes: &[u8]) -> Result<SlicedPacket, ReadError> {
    SlicedPacket::from_ethernet(bytes)
}

#[inline(always)]
fn parse_ether_then_set(bytes: &mut [u8]) -> DataBuffer<&mut [u8], Eth> {
    let mut result = DataBuffer::<_, Eth>::new(bytes, 0).unwrap();
    result.set_ethernet_destination(std::hint::black_box(&[0xFF; 6]));
    result
}

pub fn set(c: &mut Criterion) {
    let mut ether_min_size_untagged = Vec::from(ETHERNET_MIN_SIZE_UNTAGGED);
    let ether_min_size_untagged_slice = ether_min_size_untagged.as_mut_slice();

    let mut group = c.benchmark_group("ethernet 64 set");
    //group.measurement_time(Duration::from_secs(90));
    group.throughput(Throughput::Bytes(ether_min_size_untagged_slice.len() as u64));

    group.bench_function("set", |b| {
        b.iter(|| {
            parse_ether_then_set(std::hint::black_box(ether_min_size_untagged_slice));
        })
    });

    group.finish();
}

pub fn untagged(c: &mut Criterion) {
    let mut ether_min_size_untagged = Vec::from(ETHERNET_MIN_SIZE_UNTAGGED);
    let ether_min_size_untagged_slice = ether_min_size_untagged.as_mut_slice();

    let mut group = c.benchmark_group("ethernet 64 byte");
    //group.measurement_time(Duration::from_secs(90));
    group.throughput(Throughput::Bytes(ether_min_size_untagged_slice.len() as u64));
    group.sample_size(1000);

    group.bench_function("untagged", |b| {
        b.iter(|| {
            let result = &parse_ether(std::hint::black_box(ether_min_size_untagged_slice));
            std::hint::black_box(result);
        })
    });

    group.bench_function("untagged rnd", |b| {
        b.iter_batched_ref(
            || random_ethernet::<64>(None),
            |data| {
                let result = &parse_ether(std::hint::black_box(data));
                std::hint::black_box(result);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("untagged multi", |b| {
        b.iter(|| {
            let result =
                &parse_ether_vlan_multi(std::hint::black_box(ether_min_size_untagged_slice));
            std::hint::black_box(result);
        })
    });

    group.bench_function("untagged rnd multi", |b| {
        b.iter_batched_ref(
            || random_ethernet::<64>(None),
            |data| {
                let result = &parse_ether_vlan_multi(std::hint::black_box(data));
                std::hint::black_box(result);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("untagged etherparse", |b| {
        b.iter(|| {
            let result =
                &parse_ether_etherparse(std::hint::black_box(ether_min_size_untagged_slice));
            std::hint::black_box(result);
        })
    });

    group.bench_function("untagged rnd etherparse", |b| {
        b.iter_batched_ref(
            || random_ethernet::<64>(None),
            |data| {
                let result = &parse_ether_etherparse(std::hint::black_box(data));
                std::hint::black_box(result);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("untagged etherparse multi", |b| {
        b.iter(|| {
            let result =
                &parse_ether_etherparse_multi(std::hint::black_box(ether_min_size_untagged_slice));
            std::hint::black_box(result);
        })
    });

    group.bench_function("untagged rnd etherparse multi", |b| {
        b.iter_batched_ref(
            || random_ethernet::<64>(None),
            |data| {
                let result = &parse_ether_etherparse_multi(std::hint::black_box(data));
                std::hint::black_box(result);
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

pub fn single_tagged(c: &mut Criterion) {
    let mut ether_min_size_single_tagged_tagged = Vec::from(ETHERNET_MIN_SIZE_SINGLE_TAGGED);
    let ether_min_size_single_tagged_tagged_slice =
        ether_min_size_single_tagged_tagged.as_mut_slice();

    let mut group = c.benchmark_group("ethernet 64 byte");
    //group.measurement_time(Duration::from_secs(90));
    group.throughput(Throughput::Bytes(
        ether_min_size_single_tagged_tagged_slice.len() as u64,
    ));

    group.bench_function("single tagged", |b| {
        b.iter(|| {
            let result = &parse_ether_vlan(std::hint::black_box(
                ether_min_size_single_tagged_tagged_slice,
            ));
            std::hint::black_box(result);
        })
    });
    group.bench_function("single tagged rnd", |b| {
        b.iter_batched_ref(
            || random_ethernet::<64>(Some(Vlan::SingleTagged)),
            |data| {
                let result = &parse_ether_vlan(std::hint::black_box(data));
                std::hint::black_box(result);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("single tagged multi", |b| {
        b.iter(|| {
            let result = &parse_ether_vlan_multi(std::hint::black_box(
                ether_min_size_single_tagged_tagged_slice,
            ));
            std::hint::black_box(result);
        })
    });
    group.bench_function("single tagged rnd multi", |b| {
        b.iter_batched_ref(
            || random_ethernet::<64>(Some(Vlan::SingleTagged)),
            |data| {
                let result = &parse_ether_vlan_multi(std::hint::black_box(data));
                std::hint::black_box(result);
            },
            BatchSize::SmallInput,
        );
    });
    group.bench_function("single tagged etherparse multi", |b| {
        b.iter(|| {
            let result = &parse_ether_etherparse_multi(std::hint::black_box(
                ether_min_size_single_tagged_tagged_slice,
            ));
            std::hint::black_box(result);
        })
    });
    group.bench_function("single tagged rnd etherparse multi", |b| {
        b.iter_batched_ref(
            || random_ethernet::<64>(Some(Vlan::SingleTagged)),
            |data| {
                let result = &parse_ether_etherparse_multi(std::hint::black_box(data));
                std::hint::black_box(result);
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

pub fn double_tagged(c: &mut Criterion) {
    let mut ether_min_size_double_tagged_tagged = Vec::from(ETHERNET_MIN_SIZE_DOUBLE_TAGGED);
    let ether_min_size_double_tagged_tagged_slice =
        ether_min_size_double_tagged_tagged.as_mut_slice();

    let mut group = c.benchmark_group("ethernet 64 byte");
    //group.measurement_time(Duration::from_secs(90));
    group.throughput(Throughput::Bytes(
        ether_min_size_double_tagged_tagged_slice.len() as u64,
    ));

    group.bench_function("double tagged", |b| {
        b.iter(|| {
            let result = &parse_ether_vlan(std::hint::black_box(
                ether_min_size_double_tagged_tagged_slice,
            ));
            std::hint::black_box(result);
        })
    });
    group.bench_function("Double tagged rnd", |b| {
        b.iter_batched_ref(
            || random_ethernet::<64>(Some(Vlan::DoubleTagged)),
            |data| {
                let result = &parse_ether_vlan(std::hint::black_box(data));
                std::hint::black_box(result);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("double tagged multi", |b| {
        b.iter(|| {
            let result = &parse_ether_vlan_multi(std::hint::black_box(
                ether_min_size_double_tagged_tagged_slice,
            ));
            std::hint::black_box(result);
        })
    });
    group.bench_function("Double tagged rnd multi", |b| {
        b.iter_batched_ref(
            || random_ethernet::<64>(Some(Vlan::DoubleTagged)),
            |data| {
                let result = &parse_ether_vlan_multi(std::hint::black_box(data));
                std::hint::black_box(result);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("double tagged etherparse multi", |b| {
        b.iter(|| {
            let result = &parse_ether_etherparse_multi(std::hint::black_box(
                ether_min_size_double_tagged_tagged_slice,
            ));
            std::hint::black_box(result);
        })
    });
    group.bench_function("Double tagged rnd etherparse multi", |b| {
        b.iter_batched_ref(
            || random_ethernet::<64>(Some(Vlan::DoubleTagged)),
            |data| {
                let result = &parse_ether_etherparse_multi(std::hint::black_box(data));
                std::hint::black_box(result);
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(benches, untagged, single_tagged, double_tagged);

criterion_main!(benches);
