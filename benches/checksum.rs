use {
    criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main},
    std::hint::black_box,
    typenet::checksum,
};

/// A range of input sizes representative of real traffic: a bare IPv4/TCP header, a standard
/// Ethernet MTU payload, and the largest possible IPv4 packet.
const INPUT_SIZES: [usize; 3] = [20, 1500, 65_535];

type LabeledImplementation = (&'static str, fn(&[u8]) -> u16);

/// The set of checksum implementations to compare.
const IMPLEMENTATIONS: [LabeledImplementation; 3] = [
    ("production", checksum::calculate),
    ("always_folded", checksum::always_folded_checksum),
    ("overflowing", checksum::overflowing_checksum),
];

/// Compares the production checksum implementation against alternative implementations only exposed
/// for benchmarking purposes.
fn bench_checksum(c: &mut Criterion) {
    let mut group = c.benchmark_group("checksum");

    for size in INPUT_SIZES {
        let input = vec![0xABu8; size];

        group.throughput(Throughput::Bytes(size as u64)); // Report throughput in bytes/sec

        for (label, checksum_fn) in IMPLEMENTATIONS {
            group.bench_with_input(BenchmarkId::new(label, size), &input, |b, data| {
                b.iter(|| checksum_fn(black_box(data)));
            });
        }
    }

    group.finish();
}

criterion_group!(benches, bench_checksum);
criterion_main!(benches);
