# AGENTS.md — Bitcoin Address Scanner

## Project

Single Rust binary `btc-scanner` with 3 subcommands: `build`, `scan`, `check`.

## Build & Test

```bash
cargo build --release         # single binary: target/release/btc-scanner
cargo test                    # 120 tests, all pass
cargo clippy --all-targets    # zero warnings
cargo fmt                     # format
cargo bench                   # run benchmarks
```

## Structure

| File | Purpose |
|------|---------|
| `src/main.rs` | CLI (clap derive) + all 3 subcommand implementations |
| `src/config.rs` | Configuration management with validation |
| `src/siphash.rs` | SipHash-1-3 double-output — bit-compatible with C++ version |
| `src/bloom.rs` | Bloom filter (v3 format), TSV index cache, line offsets |
| `src/crypto.rs` | SHA-256, RIPEMD-160, HMAC-SHA512, PBKDF2, secp256k1 |
| `src/encoding.rs` | Base58Check encode/decode, Bech32/Bech32m |
| `src/bitcoin.rs` | Address generation: P2PKH, P2SH-P2WPKH, P2WPKH, P2WSH, P2TR |
| `src/bip32.rs` | BIP-32 HD key derivation (Result-based error handling) |
| `src/bip39.rs` | BIP-39 mnemonic generation with NFKD normalization |
| `src/tsv.rs` | Memory-mapped TSV with parallel index, `.idx` cache |
| `tests/differential.rs` | Official BIP-32/BIP-39 test vectors |
| `benches/crypto_bench.rs` | Criterion benchmarks for crypto operations |

## Dependencies

sha2 0.11, ripemd 0.2, hmac 0.13, secp256k1 0.31, rand 0.9, pbkdf2 0.13, clap 4, zeroize 1, unicode-normalization 0.1, criterion 0.5.

## Key Design Decisions

- **Result-based errors**: `DerivationError`, `BloomError`, `MnemonicError`, `Base58Error`, `ConfigError`
- **Static secp256k1 context**: `LazyLock<Secp256k1<All>>` reused across all calls
- **NFKD normalization**: BIP-39 mnemonic and passphrase normalized before PBKDF2
- **Zeroize on drop**: `XKey` zeros key material when dropped
- **Randomized Bloom seeds**: k0/k1 generated randomly for security
- **Debug assertions**: Bloom filter indexing bounds checked in debug builds
- **TSV HashSet memory cap**: Hybrid mode caps `addr_set` at 20M entries (≈2GB); larger TSVs fall back to bloom‑only to prevent OOM
- **Thread‑panic handling**: Worker‑thread panics are logged via `eprintln!` instead of silently discarded
- **Secure temp files**: `ThreadWriter` uses `O_EXCL` + PID in temp file names to prevent TOCTOU symlink‑race attacks
- **Atomic console output**: HIT display uses single `print!` + `flush` instead of multiple `println!` to prevent output interleaving across threads

## Compatibility

- Bloom v3 format: `ver(1B) + k0(8B) + k1(8B) + k_num(4B) + bitmap_len(8B) + bitmap`
- Bitmap pow2-aligned for `& (bits-1)` fast modulo
- TSV `.idx` cache: `magic(8B) + tsv_size(8B) + mtime(8B) + data_start(8B) + n_lines(8B) + offsets`
