# Bitcoin Address Scanner

High-performance Bitcoin address scanner in Rust. Single binary with three subcommands.

## Install

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
git clone https://github.com/sinescode/scannerbtc-rust.git
cd scannerbtc-rust
cargo build --release
```

Binary: `target/release/btc-scanner`

## Usage

```bash
btc-scanner --help
btc-scanner build --help
btc-scanner scan --help
btc-scanner check --help
```

### `btc-scanner build` — Build Bloom filter

```bash
btc-scanner build addresses.tsv addresses.bloom
btc-scanner build addresses.tsv addresses.bloom --expected 50000000 --fpp 0.0001
```

| Flag | Default | Description |
|------|---------|-------------|
| `<input>` | required | Sorted TSV of Bitcoin addresses |
| `<output>` | required | Output Bloom filter file |
| `--expected` | `0` (auto) | Number of addresses |
| `--fpp` | `0.001` | False positive probability |

### `btc-scanner scan` — Scan for addresses

```bash
btc-scanner scan --bloom addresses.bloom --tsv addresses.tsv --output hits.tsv
btc-scanner scan --bloom addresses.bloom --mode mnemonic --words 24 --threads 16
```

| Flag | Default | Description |
|------|---------|-------------|
| `--bloom` | — | Bloom filter file |
| `--tsv` | — | Sorted TSV of target addresses |
| `--output` | stdout | Output TSV for hits |
| `--threads` | `nproc` | Worker threads |
| `--mode` | `random` | `random`, `mnemonic`, or `mix` |
| `--depth` | `5` | BIP-32 child keys per path |
| `--words` | `0` | Mnemonic words: `0` (random 12/24), `12`, or `24` |

Filter mode auto-detected: `--bloom --tsv` = HYBRID, `--bloom` only = BLOOM_ONLY, `--tsv` only = TSV_ONLY.

### `btc-scanner check` — Find missing addresses

```bash
btc-scanner check addresses.tsv addresses.bloom missing.tsv
```

## Performance

| Operation | Time | Throughput |
|-----------|------|------------|
| SHA-256 (1KB) | 597 ns | ~1.7 GB/s |
| RIPEMD-160 (32B) | 198 ns | ~162 MB/s |
| HASH160 (32B) | 267 ns | ~120 MB/s |
| HMAC-SHA512 | 969 ns | ~1.0M ops/s |
| PBKDF2 (2048 rounds) | 1.02 ms | ~981 ops/s |
| SipHash-1-3 | 549 ps | ~1.8B ops/s |
| BIP-32 hardened child | 1.01 µs | ~990K ops/s |
| Mnemonic → seed | 980 µs | ~1.0K ops/s |
| fill_key_data (all 5 addrs) | 76.9 µs | ~13K ops/s |
| Base58Check encode | 1.56 µs | ~641K ops/s |
| Bech32 encode (v0) | 342 ns | ~2.9M ops/s |

## Development

```bash
cargo test                    # 120 tests
cargo clippy --all-targets    # zero warnings
cargo fmt                     # format
cargo bench                   # run benchmarks
```

## Project Structure

```
src/
├── main.rs           # CLI + all 3 subcommands
├── lib.rs            # Module declarations
├── config.rs         # Configuration management
├── siphash.rs        # SipHash-1-3 (Bloom filter hash)
├── bloom.rs          # Bloom filter v3 + TSV index cache
├── crypto.rs         # SHA-256, RIPEMD-160, secp256k1
├── encoding.rs       # Base58Check, Bech32/Bech32m
├── bitcoin.rs        # P2PKH, P2SH, P2WPKH, P2WSH, P2TR
├── bip32.rs          # HD key derivation
├── bip39.rs          # Mnemonic generation
└── tsv.rs            # Memory-mapped TSV + .idx cache
benches/
└── crypto_bench.rs   # Criterion benchmarks
tests/
└── differential.rs   # Official BIP-32/BIP-39 test vectors
```

## Security

See [SECURITY.md](SECURITY.md) for threat model and security policy.

## License

MIT
