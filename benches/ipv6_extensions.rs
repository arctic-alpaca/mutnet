use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use etherparse::{Ipv6ExtensionsSlice, ReadError};
use mutnet::data_buffer::DataBuffer;
use mutnet::ipv6_extensions::{Ipv6Extensions, ParseIpv6ExtensionsError};
use mutnet::no_previous_header::NoPreviousHeader;
use mutnet::typed_protocol_headers::Ipv6ExtensionType;
use rand::{thread_rng, Rng};

const MEM_TO_FILL: usize = 64;
const MAX_EXTENSIONS: usize = 16;
/// MEM_TO_FILL needs to be at least 8 bytes.
pub fn random_valid_ipv6_extensions<const MEM_TO_FILL: usize>(
) -> ([u8; MEM_TO_FILL], Ipv6ExtensionType) {
    assert!(MEM_TO_FILL >= 8);

    let mut rng = thread_rng();
    let mut data_buffer = [0_u8; MEM_TO_FILL];
    let mut idx = 0;
    let mut next_header;
    let mut this_header;
    let mut first_extension = Ipv6ExtensionType::HopByHop as u8;
    let mut length = rng.gen_range(0..3);
    let mut remaining_space = MEM_TO_FILL;

    // Hop by hop
    if rng.gen::<bool>() {
        while MEM_TO_FILL < idx + (usize::from(length) + 1) * 8 {
            length -= 1;
        }

        remaining_space = remaining_space.saturating_sub((usize::from(length) + 1) * 8);
        next_header = match rng.gen_range(0..3) {
            0_u8 => Ipv6ExtensionType::Routing as u8,
            1 => Ipv6ExtensionType::Fragment as u8,
            2.. => Ipv6ExtensionType::DestinationOptions as u8,
        };

        data_buffer[idx] = next_header;
        idx += 1;
        data_buffer[idx] = length;
        idx += 1;

        for _ in 0..((usize::from(length) + 1) * 8 - 2) {
            data_buffer[idx] = rng.gen();
            idx += 1;
        }
        this_header = next_header;
    } else {
        first_extension = match rng.gen_range(0..3) {
            0_u8 => Ipv6ExtensionType::Routing as u8,
            1 => Ipv6ExtensionType::Fragment as u8,
            2.. => Ipv6ExtensionType::DestinationOptions as u8,
        };

        this_header = first_extension;

        next_header = if remaining_space >= 8 {
            match rng.gen_range(0..3) {
                0_u8 => Ipv6ExtensionType::Routing as u8,
                1 => Ipv6ExtensionType::Fragment as u8,
                2.. => Ipv6ExtensionType::DestinationOptions as u8,
            }
        } else {
            rng.gen_range(Ipv6ExtensionType::DestinationOptions as u8 + 1..u8::MAX)
        };
    }

    while Ipv6ExtensionType::try_from(next_header).is_ok() {
        if this_header == Ipv6ExtensionType::Fragment as u8 {
            length = 0;
        } else {
            length = rng.gen_range(0..3);
        }

        while MEM_TO_FILL < idx + (usize::from(length) + 1) * 8 {
            length -= 1;
        }

        remaining_space = remaining_space.saturating_sub((usize::from(length) + 1) * 8);

        next_header = if remaining_space >= 8 {
            match rng.gen_range(0..3) {
                0_u8 => Ipv6ExtensionType::Routing as u8,
                1 => Ipv6ExtensionType::Fragment as u8,
                2.. => Ipv6ExtensionType::DestinationOptions as u8,
            }
        } else {
            rng.gen_range(Ipv6ExtensionType::DestinationOptions as u8 + 1..u8::MAX)
        };

        data_buffer[idx] = next_header;
        idx += 1;
        data_buffer[idx] = length;
        idx += 1;
        this_header = next_header;

        for _ in 0..(((usize::from(length) + 1) * 8) - 2) {
            data_buffer[idx] = rng.gen();
            idx += 1;
        }
    }

    (
        data_buffer,
        Ipv6ExtensionType::try_from(first_extension).unwrap(),
    )
}

#[allow(clippy::type_complexity)]
#[inline(always)]
fn mutnet_new<const MAX_EXTENSIONS: usize>(
    bytes: &mut [u8],
    first_extension: Ipv6ExtensionType,
) -> Result<
    (
        DataBuffer<&mut [u8], Ipv6Extensions<NoPreviousHeader, MAX_EXTENSIONS>>,
        bool,
    ),
    ParseIpv6ExtensionsError,
> {
    DataBuffer::<_, Ipv6Extensions<NoPreviousHeader, MAX_EXTENSIONS>>::parse_ipv6_extensions_alone(
        bytes,
        0,
        first_extension,
    )
}

#[inline(always)]
fn etherparse_new(
    bytes: &[u8],
    first_extension: Ipv6ExtensionType,
) -> Result<(Ipv6ExtensionsSlice<'_>, u8, &[u8]), ReadError> {
    Ipv6ExtensionsSlice::from_slice(first_extension as u8, bytes)
}

pub fn ipv6_extension(c: &mut Criterion) {
    let mut group = c.benchmark_group("IPv6 extension");

    group.throughput(Throughput::Bytes(
        random_valid_ipv6_extensions::<MEM_TO_FILL>().0.len() as u64,
    ));

    group.bench_function("mutnet: new", |b| {
        b.iter_batched_ref(
            random_valid_ipv6_extensions::<MEM_TO_FILL>,
            |(data, first_extension)| {
                let mut result = &mut mutnet_new::<MAX_EXTENSIONS>(
                    std::hint::black_box(data),
                    std::hint::black_box(*first_extension),
                );
                std::hint::black_box(&mut result);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("etherparse: new", |b| {
        b.iter_batched_ref(
            random_valid_ipv6_extensions::<MEM_TO_FILL>,
            |(data, first_extension)| {
                let mut result = &mut etherparse_new(
                    std::hint::black_box(data),
                    std::hint::black_box(*first_extension),
                );
                std::hint::black_box(&mut result);
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(benches, ipv6_extension);

criterion_main!(benches);
