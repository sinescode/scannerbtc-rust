# Project Tree — scannerbtc-rust

> [github.com/sinescode/scannerbtc-rust](https://github.com/sinescode/scannerbtc-rust)

```
scannerbtc-rust/
├── Cargo.toml
├── Cargo.lock
├── README.md
├── AGENTS.md
├── SECURITY.md
├── PROJECT.md
├── bip39_words.txt
├── .gitignore
├── .github/
│   └── workflows/
│       └── ci.yml
├── src/
│   ├── main.rs
│   ├── lib.rs
│   ├── config.rs
│   ├── siphash.rs
│   ├── bloom.rs
│   ├── crypto.rs
│   ├── encoding.rs
│   ├── bitcoin.rs
│   ├── bip32.rs
│   ├── bip39.rs
│   ├── bip39_words.rs
│   └── tsv.rs
├── benches/
│   └── crypto_bench.rs
├── tests/
│   └── differential.rs
└── fuzz/
    └── fuzz_targets/
        └── fuzz_encoding.rs
```

## Files

| File | Lines | Purpose |
|------|-------|---------|
| [Cargo.toml](https://github.com/sinescode/scannerbtc-rust/blob/main/Cargo.toml) | 45 | Manifest: deps, profiles, binary definition |
| [README.md](https://github.com/sinescode/scannerbtc-rust/blob/main/README.md) | 115 | User docs: install, usage, benchmarks |
| [AGENTS.md](https://github.com/sinescode/scannerbtc-rust/blob/main/AGENTS.md) | 55 | Agent reference: build, structure, conventions |
| [SECURITY.md](https://github.com/sinescode/scannerbtc-rust/blob/main/SECURITY.md) | 68 | Threat model, security policy |
| [bip39_words.txt](https://github.com/sinescode/scannerbtc-rust/blob/main/bip39_words.txt) | 2048 | BIP-39 English wordlist |
| [src/main.rs](https://github.com/sinescode/scannerbtc-rust/blob/main/src/main.rs) | 1315 | CLI + `build` / `scan` / `check` subcommands |
| [src/lib.rs](https://github.com/sinescode/scannerbtc-rust/blob/main/src/lib.rs) | 9 | Module declarations |
| [src/config.rs](https://github.com/sinescode/scannerbtc-rust/blob/main/src/config.rs) | 188 | Configuration management with validation |
| [src/siphash.rs](https://github.com/sinescode/scannerbtc-rust/blob/main/src/siphash.rs) | 148 | SipHash-1-3 double-output (Bloom filter hash) |
| [src/bloom.rs](https://github.com/sinescode/scannerbtc-rust/blob/main/src/bloom.rs) | 431 | Bloom filter v3, TSV index cache, line offsets |
| [src/crypto.rs](https://github.com/sinescode/scannerbtc-rust/blob/main/src/crypto.rs) | 362 | SHA-256, RIPEMD-160, HMAC, PBKDF2, secp256k1 |
| [src/encoding.rs](https://github.com/sinescode/scannerbtc-rust/blob/main/src/encoding.rs) | 403 | Base58Check encode/decode, Bech32/Bech32m |
| [src/bitcoin.rs](https://github.com/sinescode/scannerbtc-rust/blob/main/src/bitcoin.rs) | 301 | P2PKH, P2SH-P2WPKH, P2WPKH, P2WSH, P2TR |
| [src/bip32.rs](https://github.com/sinescode/scannerbtc-rust/blob/main/src/bip32.rs) | 328 | BIP-32 HD key derivation |
| [src/bip39.rs](https://github.com/sinescode/scannerbtc-rust/blob/main/src/bip39.rs) | 400 | BIP-39 mnemonic generation with NFKD |
| [src/bip39_words.rs](https://github.com/sinescode/scannerbtc-rust/blob/main/src/bip39_words.rs) | 2050 | Generated wordlist const array |
| [src/tsv.rs](https://github.com/sinescode/scannerbtc-rust/blob/main/src/tsv.rs) | 262 | Memory-mapped TSV with `.idx` cache |
| [benches/crypto_bench.rs](https://github.com/sinescode/scannerbtc-rust/blob/main/benches/crypto_bench.rs) | 97 | Criterion benchmarks |
| [tests/differential.rs](https://github.com/sinescode/scannerbtc-rust/blob/main/tests/differential.rs) | 128 | Official BIP-32/BIP-39 test vectors |
| [.github/workflows/ci.yml](https://github.com/sinescode/scannerbtc-rust/blob/main/.github/workflows/ci.yml) | 65 | CI: test, build, audit |

## Raw Links

```
https://raw.githubusercontent.com/sinescode/scannerbtc-rust/main/Cargo.toml
https://raw.githubusercontent.com/sinescode/scannerbtc-rust/main/README.md
https://raw.githubusercontent.com/sinescode/scannerbtc-rust/main/AGENTS.md
https://raw.githubusercontent.com/sinescode/scannerbtc-rust/main/SECURITY.md
https://raw.githubusercontent.com/sinescode/scannerbtc-rust/main/bip39_words.txt
https://raw.githubusercontent.com/sinescode/scannerbtc-rust/main/src/main.rs
https://raw.githubusercontent.com/sinescode/scannerbtc-rust/main/src/lib.rs
https://raw.githubusercontent.com/sinescode/scannerbtc-rust/main/src/config.rs
https://raw.githubusercontent.com/sinescode/scannerbtc-rust/main/src/siphash.rs
https://raw.githubusercontent.com/sinescode/scannerbtc-rust/main/src/bloom.rs
https://raw.githubusercontent.com/sinescode/scannerbtc-rust/main/src/crypto.rs
https://raw.githubusercontent.com/sinescode/scannerbtc-rust/main/src/encoding.rs
https://raw.githubusercontent.com/sinescode/scannerbtc-rust/main/src/bitcoin.rs
https://raw.githubusercontent.com/sinescode/scannerbtc-rust/main/src/bip32.rs
https://raw.githubusercontent.com/sinescode/scannerbtc-rust/main/src/bip39.rs
https://raw.githubusercontent.com/sinescode/scannerbtc-rust/main/src/bip39_words.rs
https://raw.githubusercontent.com/sinescode/scannerbtc-rust/main/src/tsv.rs
https://raw.githubusercontent.com/sinescode/scannerbtc-rust/main/benches/crypto_bench.rs
https://raw.githubusercontent.com/sinescode/scannerbtc-rust/main/tests/differential.rs
https://raw.githubusercontent.com/sinescode/scannerbtc-rust/main/.github/workflows/ci.yml
```
