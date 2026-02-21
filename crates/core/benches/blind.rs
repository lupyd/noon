use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use noon_core::{BlindSigner, create_blinded_message, unblind_signature};

fn benchmark_server_initialization(c: &mut Criterion) {
    c.bench_function("server_initialization", |b| {
        b.iter(|| {
            black_box(BlindSigner::generate());
        });
    });
}

fn benchmark_create_blinded_message(c: &mut Criterion) {
    let server = BlindSigner::generate();
    let public_key = server.public_key();
    let payload = b"I vote for freedom";

    c.bench_function("create_blinded_message", |b| {
        b.iter(|| {
            black_box(create_blinded_message(
                black_box(payload),
                black_box(&public_key),
            ));
        });
    });
}

fn benchmark_blind_sign(c: &mut Criterion) {
    let server = BlindSigner::generate();
    let public_key = server.public_key();
    let payload = b"I vote for freedom";
    let blinded_message = create_blinded_message(payload, &public_key);

    c.bench_function("blind_sign", |b| {
        b.iter(|| {
            black_box(
                server
                    .blind_sign(black_box(&blinded_message.blinded_message()))
                    .unwrap(),
            );
        });
    });
}

fn benchmark_unblind_signature(c: &mut Criterion) {
    let server = BlindSigner::generate();
    let public_key = server.public_key();
    let payload = b"I vote for freedom";
    let blinded_message = create_blinded_message(payload, &public_key);
    let blinded_signature = server
        .blind_sign(&blinded_message.blinded_message())
        .unwrap();

    c.bench_function("unblind_signature", |b| {
        b.iter(|| {
            black_box(unblind_signature(
                black_box(&blinded_message),
                black_box(&blinded_signature),
                black_box(&public_key),
            ));
        });
    });
}

fn benchmark_verify_signature(c: &mut Criterion) {
    let server = BlindSigner::generate();
    let public_key = server.public_key();
    let payload = b"I vote for freedom";
    let blinded_message = create_blinded_message(payload, &public_key);
    let blinded_signature = server
        .blind_sign(&blinded_message.blinded_message())
        .unwrap();
    let signature = unblind_signature(&blinded_message, &blinded_signature, &public_key);

    c.bench_function("verify_signature", |b| {
        b.iter(|| {
            black_box(server.verify(black_box(&blinded_message.message()), black_box(&signature)));
        });
    });
}

fn benchmark_full_blind_signature_flow(c: &mut Criterion) {
    c.bench_function("full_blind_signature_flow", |b| {
        b.iter(|| {
            let server = BlindSigner::generate();
            let public_key = server.public_key();
            let payload = b"I vote for freedom";

            let blinded_message = create_blinded_message(payload, &public_key);
            let blinded_signature = server
                .blind_sign(&blinded_message.blinded_message())
                .unwrap();
            let signature = unblind_signature(&blinded_message, &blinded_signature, &public_key);

            black_box(server.verify(&blinded_message.message(), &signature));
        });
    });
}

// Benchmarks based on payload size
fn benchmark_create_blinded_message_by_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("create_blinded_message_by_size");
    let server = BlindSigner::generate();
    let public_key = server.public_key();

    // Test with different payload sizes: 16B, 64B, 256B, 1KB, 4KB
    for size in [16, 64, 256, 1024, 4096].iter() {
        let payload = vec![0u8; *size];

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                black_box(create_blinded_message(
                    black_box(&payload),
                    black_box(&public_key),
                ));
            });
        });
    }
    group.finish();
}

fn benchmark_blind_sign_by_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("blind_sign_by_size");
    let server = BlindSigner::generate();
    let public_key = server.public_key();

    for size in [16, 64, 256, 1024, 4096].iter() {
        let payload = vec![0u8; *size];
        let blinded_message = create_blinded_message(&payload, &public_key);

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                black_box(
                    server
                        .blind_sign(black_box(&blinded_message.blinded_message()))
                        .unwrap(),
                );
            });
        });
    }
    group.finish();
}

fn benchmark_unblind_signature_by_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("unblind_signature_by_size");
    let server = BlindSigner::generate();
    let public_key = server.public_key();

    for size in [16, 64, 256, 1024, 4096].iter() {
        let payload = vec![0u8; *size];
        let blinded_message = create_blinded_message(&payload, &public_key);
        let blinded_signature = server
            .blind_sign(&blinded_message.blinded_message())
            .unwrap();

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                black_box(unblind_signature(
                    black_box(&blinded_message),
                    black_box(&blinded_signature),
                    black_box(&public_key),
                ));
            });
        });
    }
    group.finish();
}

fn benchmark_verify_signature_by_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify_signature_by_size");
    let server = BlindSigner::generate();
    let public_key = server.public_key();

    for size in [16, 64, 256, 1024, 4096].iter() {
        let payload = vec![0u8; *size];
        let blinded_message = create_blinded_message(&payload, &public_key);
        let blinded_signature = server
            .blind_sign(&blinded_message.blinded_message())
            .unwrap();
        let signature = unblind_signature(&blinded_message, &blinded_signature, &public_key);

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                black_box(
                    server.verify(black_box(&blinded_message.message()), black_box(&signature)),
                );
            });
        });
    }
    group.finish();
}

fn benchmark_full_flow_by_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("full_flow_by_size");

    for size in [16, 64, 256, 1024, 4096].iter() {
        let payload = vec![0u8; *size];

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                let server = BlindSigner::generate();
                let public_key = server.public_key();

                let blinded_message = create_blinded_message(&payload, &public_key);
                let blinded_signature = server
                    .blind_sign(&blinded_message.blinded_message())
                    .unwrap();
                let signature =
                    unblind_signature(&blinded_message, &blinded_signature, &public_key);

                black_box(server.verify(&blinded_message.message(), &signature));
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    benchmark_server_initialization,
    benchmark_create_blinded_message,
    benchmark_blind_sign,
    benchmark_unblind_signature,
    benchmark_verify_signature,
    benchmark_full_blind_signature_flow,
    benchmark_create_blinded_message_by_size,
    benchmark_blind_sign_by_size,
    benchmark_unblind_signature_by_size,
    benchmark_verify_signature_by_size,
    benchmark_full_flow_by_size
);
criterion_main!(benches);
