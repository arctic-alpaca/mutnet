use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use mutnet::tcp::ParseTcpError;
use std::hint::black_box;

include!("utils.rs");

#[inline(always)]
pub fn parse_ipv4_tcp(
    ipv4: DataBuffer<&[u8; 120], Ipv4<NoPreviousHeader>>,
) -> Result<DataBuffer<&[u8; 120], Tcp<Ipv4<NoPreviousHeader>>>, ParseTcpError> {
    DataBuffer::<_, _>::parse_tcp_layer(ipv4, false)
}

pub fn ipv4_tcp(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipv4_tcp");

    group.throughput(Throughput::Bytes(random_ipv4_tcp().len() as u64));

    group.bench_function("ipv4_tcp", |b| {
        b.iter(|| {
            let data = DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(
                black_box(&IPV4_TCP),
                0,
                false,
            )
            .unwrap();
            let result = &DataBuffer::<_, _>::parse_tcp_layer(data, false).unwrap();
            black_box(&result);
        });
    });

    group.bench_function("eth_ipv4_tcp raw", |b| {
        b.iter(|| {
            let data =
                DataBuffer::<_, Eth>::parse_ethernet_layer(black_box(&ETH_IPV4_TCP), 0).unwrap();
            let data = DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(data, false).unwrap();
            let data = DataBuffer::<_, Tcp<Ipv4<Eth>>>::parse_tcp_layer(data, false).unwrap();
            black_box(&data);
        });
    });

    group.bench_function("eth_ipv4_tcp", |b| {
        b.iter(|| {
            let result = mutnet::multi_step_parser::parse_network_data::<_, 10>(
                black_box(&ETH_IPV4_TCP),
                0,
                false,
                false,
                false,
            )
            .unwrap();
            black_box(&result);
        });
    });

    group.bench_function("ether_eth_ipv4_tcp", |b| {
        b.iter(|| {
            let result = etherparse::SlicedPacket::from_ethernet(black_box(&ETH_IPV4_TCP)).unwrap();
            black_box(&result);
        });
    });

    group.finish();
}

criterion_group!(benches, ipv4_tcp);

criterion_main!(benches);
