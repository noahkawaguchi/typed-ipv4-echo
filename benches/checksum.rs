use {
    criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main},
    std::hint::black_box,
    typenet::checksum,
};

/// Input sizes representative of real traffic through the server: a bare IPv4/TCP header, a
/// standard Ethernet MTU payload, and the largest possible IPv4 packet.
const SIZES: [(&str, usize); 4] =
    [("header_20B", 20), ("mtu_1500B", 1500), ("max_ipv4_65535B", 65_535), ("odd_1501B", 1501)];

fn bench_calculate(c: &mut Criterion) {
    let mut group = c.benchmark_group("checksum::calculate");

    for (label, size) in SIZES {
        let input = vec![0xABu8; size];

        group.throughput(Throughput::Bytes(size as u64)); // Report throughput in bytes/sec

        group.bench_with_input(BenchmarkId::from_parameter(label), &input, |b, data| {
            b.iter(|| checksum::calculate(black_box(data)));
        });
    }

    group.finish();
}

criterion_group!(benches, bench_calculate);
criterion_main!(benches);
