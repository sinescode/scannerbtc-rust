# Bitcoin Address Scanner (Rust)

High-performance Bitcoin address scanner written in Rust. Generates private keys, derives all 5 address types (P2PKH, P2SH-P2WPKH, P2WPKH, P2WSH, P2TR), and checks them against a target list using a hybrid Bloom filter + binary search pipeline.

## Quick Start

```bash
# Install Rust (if not installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build
cd scannerbtc-rust
cargo build --release

# Get a sorted address list (e.g. from Blockchair)
# https://gz.blockchair.com/bitcoin/addresses/

# 1. Build the Bloom filter
./target/release/bloom_builder addresses.tsv addresses.bloom

# 2. Run the scanner
./target/release/scanner --bloom addresses.bloom --tsv addresses.tsv --output hits.tsv
```

## Build

```bash
cargo build --release    # optimized, all 3 binaries
cargo build              # debug build
```

Binaries are in `target/release/`:
- `bloom_builder` — TSV → Bloom filter
- `scanner` — key generation + address checking
- `bloom_checker` — verify which addresses are missing from a Bloom filter

## Usage

### bloom_builder

```bash
./bloom_builder <input.tsv> <output.bloom> [expected_items] [fpp]
```

| Argument | Default | Description |
|----------|---------|-------------|
| `input.tsv` | required | Sorted TSV of Bitcoin addresses |
| `output.bloom` | required | Output Bloom filter file |
| `expected_items` | `0` (auto-count) | Number of addresses. `0` = count automatically |
| `fpp` | `0.001` | Target false-positive probability |

```bash
# Auto-count, 0.1% false positive rate
./bloom_builder addresses.tsv addresses.bloom

# Explicit count, tighter FPP
./bloom_builder addresses.tsv addresses.bloom 50000000 0.0001
```

### scanner

```bash
./scanner [options]
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--tsv <file>` | `-t` | — | Sorted TSV of target addresses |
| `--bloom <file>` | `-b` | — | Bloom filter file |
| `--output <file>` | `-o` | stdout | Output TSV for hits |
| `--threads <N>` | `-j` | `nproc` | Worker threads |
| `--mode <mode>` | — | `random` | `random`, `mnemonic`, or `mix` |
| `--depth <N>` | — | `5` | BIP-32 child keys per path |
| `--words <N>` | — | `0` | Mnemonic words: `0` (random 12/24), `12`, or `24` |

Filter mode is auto-detected:
- `--bloom --tsv` → **HYBRID** (bloom pre-filter + exact binary search)
- `--bloom` only → **BLOOM_ONLY** (fast, probabilistic)
- `--tsv` only → **TSV_ONLY** (exact, no pre-filter)

### bloom_checker

```bash
./bloom_checker <addresses.tsv> <addresses.bloom> <missing.tsv>
```

Finds addresses definitely NOT in the Bloom filter.

## Scanning Modes

### `random` (default)
Generates cryptographically random 256-bit private keys. Fastest mode.

```bash
./scanner --bloom addresses.bloom --mode random --threads 16
```

### `mnemonic`
Generates BIP-39 mnemonics (12 or 24 words) and derives HD wallet addresses.

```bash
./scanner --bloom addresses.bloom --mode mnemonic --words 24 --depth 10
```

### `mix`
50% random keys + 50% mnemonic-derived.

```bash
./scanner --bloom addresses.bloom --mode mix --threads 8
```

## Output Format

TSV output columns:

| Column | Description |
|--------|-------------|
| `timestamp` | ISO 8601 UTC |
| `address` | Matched Bitcoin address |
| `address_type` | P2PKH, P2SH-P2WPKH, P2WPKH, P2WSH, or P2TR |
| `private_key_wif` | WIF format |
| `private_key_hex` | Raw hex |
| `compressed_pubkey` | 33-byte compressed public key hex |
| `xonly_pubkey` | 32-byte x-only pubkey hex |
| `mnemonic` | BIP-39 phrase (mnemonic mode only) |
| `derivation_path` | BIP-32 path (mnemonic mode only) |

## Project Structure

```
scannerbtc-rust/
├── Cargo.toml
├── bip39_words.txt         # BIP-39 English word list
└── src/
    ├── lib.rs              # Module declarations
    ├── siphash.rs          # SipHash-1-3 (Bloom filter hash)
    ├── bloom.rs            # Bloom filter + TSV index
    ├── crypto.rs           # SHA-256, RIPEMD-160, secp256k1
    ├── encoding.rs         # Base58Check, Bech32/Bech32m
    ├── bitcoin.rs          # P2PKH, P2SH, P2WPKH, P2WSH, P2TR
    ├── bip32.rs            # HD key derivation
    ├── bip39.rs            # Mnemonic generation
    ├── tsv.rs              # Memory-mapped TSV + .idx cache
    └── bin/
        ├── bloom_builder.rs
        ├── scanner.rs
        └── bloom_checker.rs
```

## Development

```bash
cargo test                 # run all 74 tests
cargo clippy --all-targets # lint (zero warnings)
cargo fmt                  # format
```

## Performance

| Mode | Threads | Keys/sec |
|------|---------|----------|
| Random, HYBRID | 16 | ~4M |
| Random, BLOOM_ONLY | 16 | ~5M |
| Mnemonic (depth=5) | 16 | ~600K |
| Mix | 16 | ~2M |

Tips:
- Use `--mode random` for max throughput
- Build Bloom filter with low FPP (`0.0001`) for fewer false positives
- TSV index is cached to `.idx` file — second run is instant
