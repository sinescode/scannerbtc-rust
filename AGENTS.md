# AGENTS.md — Bitcoin Address Scanner (Rust)

## Project

Rust workspace with 3 binaries and a shared library. Single `Cargo.toml`, no workspace members.

## Build & Test

```bash
cargo build --release         # optimized binaries
cargo test                    # 74 tests, all pass
cargo clippy --all-targets    # zero warnings
cargo fmt                     # format
```

Binaries: `target/release/bloom_builder`, `scanner`, `bloom_checker`.

## Structure

| File | Purpose |
|------|---------|
| `src/siphash.rs` | SipHash-1-3 double-output — **must** be bit-compatible with C++ version for Bloom filter interop |
| `src/bloom.rs` | Bloom filter (v3 format), TSV index cache, line offset builder |
| `src/crypto.rs` | SHA-256, RIPEMD-160, HMAC-SHA512, PBKDF2, secp256k1 key ops |
| `src/encoding.rs` | Base58Check, Bech32/Bech32m (BIP-173/BIP-350) |
| `src/bitcoin.rs` | Address generation: P2PKH, P2SH-P2WPKH, P2WPKH, P2WSH, P2TR |
| `src/bip32.rs` | BIP-32 HD key derivation (hardened + unhardened) |
| `src/bip39.rs` | BIP-39 mnemonic generation, seed derivation |
| `src/tsv.rs` | Memory-mapped TSV with parallel index build, `.idx` cache |

## Dependencies

All latest stable versions (sha2 0.11, ripemd 0.2, hmac 0.13, secp256k1 0.31, rand 0.9, pbkdf2 0.13).

No C dependencies needed — pure Rust crypto via `secp256k1` crate (builds `libsecp256k1` from source automatically).

## Key Compatibility

- Bloom filter v3 binary format: `ver(1B) + k0(8B LE) + k1(8B LE) + k_num(4B LE) + bitmap_len(8B LE) + bitmap`
- Bitmap rounded to next power-of-2 bytes for fast `& (bits-1)` modulo
- TSV `.idx` cache format: `magic(8B) + tsv_size(8B) + tsv_mtime(8B) + data_start(8B) + n_lines(8B) + offsets(n×8B)`
- Address validation: 26–90 chars, first byte `1..z`

## Conventions

- No `unwrap()` in library code — use `Option`/`Result` propagation
- `#[inline]` on hot-path functions (bloom check, hash functions)
- `Arc<Mmap>` for shared mmap across threads (not raw pointers)
- Atomics for counters (`AtomicU64`), `Mutex<HitLogger>` for output
- Tests use `tempfile` crate for isolated I/O
