use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use mutnet::checksum::{internet_checksum, internet_checksum_up_to_64_bytes};

fn random_bytes<const SIZE: usize>() -> [u8; SIZE] {
    rand::random()
}

pub const VARIABLE_CHUNK: usize = 4;

pub fn bytes_20(c: &mut Criterion) {
    let mut group = c.benchmark_group("checksum");

    group.throughput(Throughput::Bytes(20));

    group.bench_function("20 byte ipv4 only rnd", |b| {
        b.iter_batched_ref(
            random_bytes::<20>,
            |data| {
                let result = &internet_checksum_up_to_64_bytes(std::hint::black_box(data));
                std::hint::black_box(result);
            },
            BatchSize::SmallInput,
        );
    });
    group.bench_function("20 byte variable chunks rnd", |b| {
        b.iter_batched_ref(
            random_bytes::<20>,
            |data| {
                let result = &internet_checksum::<VARIABLE_CHUNK>(0, std::hint::black_box(data));
                std::hint::black_box(result);
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

pub fn bytes_40(c: &mut Criterion) {
    let mut group = c.benchmark_group("checksum");

    group.throughput(Throughput::Bytes(40));

    group.bench_function("40 byte ipv4 only rnd", |b| {
        b.iter_batched_ref(
            random_bytes::<40>,
            |data| {
                let result = &internet_checksum_up_to_64_bytes(std::hint::black_box(data));
                std::hint::black_box(result);
            },
            BatchSize::SmallInput,
        );
    });
    group.bench_function("40 byte variable chunks rnd", |b| {
        b.iter_batched_ref(
            random_bytes::<40>,
            |data| {
                let result = &internet_checksum::<VARIABLE_CHUNK>(0, std::hint::black_box(data));
                std::hint::black_box(result);
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

pub fn bytes_60(c: &mut Criterion) {
    let mut group = c.benchmark_group("checksum");

    group.throughput(Throughput::Bytes(60));

    group.bench_function("60 byte ipv4 only rnd", |b| {
        b.iter_batched_ref(
            random_bytes::<60>,
            |data| {
                let result = &internet_checksum_up_to_64_bytes(std::hint::black_box(data));
                std::hint::black_box(result);
            },
            BatchSize::SmallInput,
        );
    });
    group.bench_function("60 byte variable chunks rnd", |b| {
        b.iter_batched_ref(
            random_bytes::<60>,
            |data| {
                let result = &internet_checksum::<VARIABLE_CHUNK>(0, std::hint::black_box(data));
                std::hint::black_box(result);
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

pub fn bytes_150(c: &mut Criterion) {
    let mut group = c.benchmark_group("checksum");

    group.throughput(Throughput::Bytes(150));

    group.bench_function("150 byte variable chunks rnd", |b| {
        b.iter_batched_ref(
            random_bytes::<150>,
            |data| {
                let result = &internet_checksum::<VARIABLE_CHUNK>(0, std::hint::black_box(data));
                std::hint::black_box(result);
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

pub fn bytes_300(c: &mut Criterion) {
    let mut group = c.benchmark_group("checksum");

    group.throughput(Throughput::Bytes(300));

    group.bench_function("300 byte variable chunks rnd", |b| {
        b.iter_batched_ref(
            random_bytes::<300>,
            |data| {
                let result = &internet_checksum::<VARIABLE_CHUNK>(0, std::hint::black_box(data));
                std::hint::black_box(result);
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

pub fn bytes_550(c: &mut Criterion) {
    let mut group = c.benchmark_group("checksum");

    group.throughput(Throughput::Bytes(550));

    group.bench_function("550 byte variable chunks rnd", |b| {
        b.iter_batched_ref(
            random_bytes::<550>,
            |data| {
                let result = &internet_checksum::<VARIABLE_CHUNK>(0, std::hint::black_box(data));
                std::hint::black_box(result);
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

pub fn bytes_1000(c: &mut Criterion) {
    let mut group = c.benchmark_group("checksum");

    group.throughput(Throughput::Bytes(1000));

    group.bench_function("1000 byte variable chunks rnd", |b| {
        b.iter_batched_ref(
            random_bytes::<1000>,
            |data| {
                let result = &internet_checksum::<VARIABLE_CHUNK>(0, std::hint::black_box(data));
                std::hint::black_box(result);
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

pub fn bytes_1500(c: &mut Criterion) {
    let mut group = c.benchmark_group("checksum");

    group.throughput(Throughput::Bytes(1500));

    group.bench_function("1500 byte variable chunks rnd", |b| {
        b.iter_batched_ref(
            random_bytes::<1500>,
            |data| {
                let result = &internet_checksum::<VARIABLE_CHUNK>(0, std::hint::black_box(data));
                std::hint::black_box(result);
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

pub fn bytes_5000(c: &mut Criterion) {
    let mut group = c.benchmark_group("checksum");

    group.throughput(Throughput::Bytes(5000));

    group.bench_function("5000 byte variable chunks rnd", |b| {
        b.iter_batched_ref(
            random_bytes::<5000>,
            |data| {
                let result = &internet_checksum::<VARIABLE_CHUNK>(0, std::hint::black_box(data));
                std::hint::black_box(result);
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

pub fn bytes_15000(c: &mut Criterion) {
    let mut group = c.benchmark_group("checksum");

    group.throughput(Throughput::Bytes(15000));

    group.bench_function("15000 byte variable chunks rnd", |b| {
        b.iter_batched_ref(
            random_bytes::<15000>,
            |data| {
                let result = &internet_checksum::<VARIABLE_CHUNK>(0, std::hint::black_box(data));
                std::hint::black_box(result);
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(
    benches,
    bytes_20,
    bytes_40,
    bytes_60,
    bytes_150,
    bytes_300,
    bytes_550,
    bytes_1000,
    bytes_1500,
    bytes_5000,
    bytes_15000,
);

criterion_main!(benches);
