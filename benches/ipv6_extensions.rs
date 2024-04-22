use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use mutnet::ipv6_extensions::{Ipv6Extensions, ParseIpv6ExtensionsError};

include!("utils.rs");

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
    first_extension: etherparse::IpNumber,
) -> Result<
    (etherparse::Ipv6ExtensionsSlice, etherparse::IpNumber, &[u8]),
    etherparse::err::ipv6_exts::HeaderSliceError,
> {
    etherparse::Ipv6ExtensionsSlice::from_slice(first_extension, bytes)
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
                    std::hint::black_box(etherparse::IpNumber((*first_extension) as u8)),
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
