use criterion::{criterion_group, criterion_main, Criterion};

fn bench_sha256(c: &mut Criterion) {
    let data = [0u8; 1024];
    c.bench_function("sha256_1kb", |b| {
        b.iter(|| scannerbtc::crypto::sha256(&data));
    });
}

fn bench_ripemd160(c: &mut Criterion) {
    let data = [0u8; 32];
    c.bench_function("ripemd160_32b", |b| {
        b.iter(|| scannerbtc::crypto::ripemd160(&data));
    });
}

fn bench_hash160(c: &mut Criterion) {
    let data = [0u8; 32];
    c.bench_function("hash160_32b", |b| {
        b.iter(|| scannerbtc::crypto::hash160(&data));
    });
}

fn bench_hmac_sha512(c: &mut Criterion) {
    let key = [0u8; 32];
    let data = [0u8; 32];
    c.bench_function("hmac_sha512", |b| {
        b.iter(|| scannerbtc::crypto::hmac_sha512(&key, &data));
    });
}

fn bench_pbkdf2(c: &mut Criterion) {
    let password = b"password";
    let salt = b"mnemonic";
    c.bench_function("pbkdf2_2048", |b| {
        b.iter(|| scannerbtc::crypto::pbkdf2_hmac_sha512(password, salt, 2048));
    });
}

fn bench_siphash(c: &mut Criterion) {
    let data = [0u8; 32];
    c.bench_function("siphash13_double", |b| {
        b.iter(|| scannerbtc::siphash::siphash13_double(&data, 0, 0));
    });
}

fn bench_bip32_derivation(c: &mut Criterion) {
    let seed = [0x01u8; 32];
    let master = scannerbtc::bip32::derive_master_key(&seed).unwrap();
    c.bench_function("bip32_hardened_child", |b| {
        b.iter(|| scannerbtc::bip32::derive_child_key(&master, 0x80000000).unwrap());
    });
}

fn bench_mnemonic_to_seed(c: &mut Criterion) {
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    c.bench_function("mnemonic_to_seed", |b| {
        b.iter(|| scannerbtc::bip39::mnemonic_to_seed(phrase, ""));
    });
}

fn bench_address_generation(c: &mut Criterion) {
    let privkey = scannerbtc::crypto::generate_random_private_key();
    c.bench_function("fill_key_data", |b| {
        b.iter(|| scannerbtc::bitcoin::fill_key_data(&privkey));
    });
}

fn bench_base58check(c: &mut Criterion) {
    let payload = [0x80u8; 34];
    c.bench_function("base58check_encode", |b| {
        b.iter(|| scannerbtc::encoding::base58check_encode(&payload));
    });
}

fn bench_bech32(c: &mut Criterion) {
    let program = [0u8; 20];
    c.bench_function("encode_segwit_v0", |b| {
        b.iter(|| scannerbtc::encoding::encode_segwit(b"bc", 0, &program));
    });
}

criterion_group!(
    benches,
    bench_sha256,
    bench_ripemd160,
    bench_hash160,
    bench_hmac_sha512,
    bench_pbkdf2,
    bench_siphash,
    bench_bip32_derivation,
    bench_mnemonic_to_seed,
    bench_address_generation,
    bench_base58check,
    bench_bech32,
);
criterion_main!(benches);
