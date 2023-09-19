use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use mutnet::data_buffer::DataBuffer;
use mutnet::error::ParseEthernetIpv4TcpError;
use mutnet::ethernet::Eth;
use mutnet::ipv4::Ipv4;
use mutnet::tcp::Tcp;

static PACKET: &[u8] = &[
    // Dst
    0x00,
    0x80,
    0x41,
    0xAE,
    0xFD,
    0x7E,
    // Src
    0x7E,
    0xFD,
    0xAE,
    0x41,
    0x80,
    0x00,
    // Ether type
    0x08,
    0x00,
    // Version & IHL
    0x45,
    // DSCP & ECN
    0b0010_1000,
    // Total length
    0x00,
    0x34,
    // Identification
    0x12,
    0x34,
    // Flags & Fragment offset
    0b101_00000,
    0x03,
    // TTL
    0x01,
    // Protocol
    0x06,
    // Header Checksum
    0x09,
    0x63,
    // Source
    0x7f,
    0x00,
    0x00,
    0x1,
    // Destination
    0x7f,
    0x00,
    0x00,
    0x1,
    // Source port
    0x12,
    0x34,
    // Destination port
    0x45,
    0x67,
    // Sequence number
    0x12,
    0x34,
    0x56,
    0x78,
    // Acknowledgment number
    0x09,
    0x87,
    0x65,
    0x43,
    // Data offset, reserved bits, flags
    0x70,
    0b0101_0101,
    // Window
    0x12,
    0x45,
    // Checksum
    0xF9,
    0xB1,
    // Urgent pointer
    0x56,
    0x78,
    // Options
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    // Payload
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    // extra bit of data
    0xFF,
];

#[inline(always)]
pub fn parse(bytes: &[u8]) -> Result<DataBuffer<&[u8], Tcp<Ipv4<Eth>>>, ParseEthernetIpv4TcpError> {
    let eth = DataBuffer::<_, Eth>::new(bytes, 0)?;
    let ipv4 = DataBuffer::<_, Ipv4<Eth>>::new_from_lower(eth, true)?;
    Ok(DataBuffer::<_, Tcp<Ipv4<Eth>>>::new_from_lower(ipv4, true)?)
}

#[inline(always)]
pub fn parse_mut(
    bytes: &mut [u8],
) -> Result<DataBuffer<&mut [u8], Tcp<Ipv4<Eth>>>, ParseEthernetIpv4TcpError> {
    let eth = DataBuffer::<_, Eth>::new(bytes, 0)?;
    let ipv4 = DataBuffer::<_, Ipv4<Eth>>::new_from_lower(eth, true)?;
    Ok(DataBuffer::<_, Tcp<Ipv4<Eth>>>::new_from_lower(ipv4, true)?)
}

pub fn tcp_combined(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipv4_tcp");
    let mut packet = PACKET.to_vec();
    let packet_ref = packet.as_mut_slice();
    //group.measurement_time(Duration::from_secs(90));

    group.throughput(Throughput::Bytes(PACKET.len() as u64));

    group.bench_function("ipv4_tcp mut", |b| {
        b.iter(|| {
            let result = &parse_mut(std::hint::black_box(packet_ref));
            std::hint::black_box(result);
        })
    });

    group.bench_function("ipv4_tcp", |b| {
        b.iter(|| {
            let result = &parse(std::hint::black_box(packet_ref));
            std::hint::black_box(result);
        })
    });
}

criterion_group!(benches, tcp_combined);

criterion_main!(benches);
