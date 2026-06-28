# AGENTS.md — Bitcoin Address Scanner

## Project

Single Rust binary `btc-scanner` with 3 subcommands: `build`, `scan`, `check`.

## Build & Test

```bash
cargo build --release         # single binary: target/release/btc-scanner
cargo test                    # 74 tests, all pass
cargo clippy --all-targets    # zero warnings
cargo fmt                     # format
```

## Structure

| File | Purpose |
|------|---------|
| `src/main.rs` | CLI (clap derive) + all 3 subcommand implementations |
| `src/siphash.rs` | SipHash-1-3 double-output — bit-compatible with C++ version |
| `src/bloom.rs` | Bloom filter (v3 format), TSV index cache, line offsets |
| `src/crypto.rs` | SHA-256, RIPEMD-160, HMAC-SHA512, PBKDF2, secp256k1 |
| `src/encoding.rs` | Base58Check, Bech32/Bech32m |
| `src/bitcoin.rs` | Address generation: P2PKH, P2SH-P2WPKH, P2WPKH, P2WSH, P2TR |
| `src/bip32.rs` | BIP-32 HD key derivation |
| `src/bip39.rs` | BIP-39 mnemonic generation |
| `src/tsv.rs` | Memory-mapped TSV with parallel index, `.idx` cache |

## Dependencies

sha2 0.11, ripemd 0.2, hmac 0.13, secp256k1 0.31, rand 0.9, pbkdf2 0.13, clap 4.

## Compatibility

- Bloom v3 format: `ver(1B) + k0(8B) + k1(8B) + k_num(4B) + bitmap_len(8B) + bitmap`
- Bitmap pow2-aligned for `& (bits-1)` fast modulo
- TSV `.idx` cache: `magic(8B) + tsv_size(8B) + mtime(8B) + data_start(8B) + n_lines(8B) + offsets`
