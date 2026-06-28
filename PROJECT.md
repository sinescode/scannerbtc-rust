# Project Tree — scannerbtc-rust

> [github.com/sinescode/scannerbtc-rust](https://github.com/sinescode/scannerbtc-rust)

```
scannerbtc-rust/
├── Cargo.toml
├── Cargo.lock
├── README.md
├── AGENTS.md
├── PROJECT.md
├── bip39_words.txt
├── .gitignore
└── src/
    ├── main.rs
    ├── lib.rs
    ├── siphash.rs
    ├── bloom.rs
    ├── crypto.rs
    ├── encoding.rs
    ├── bitcoin.rs
    ├── bip32.rs
    ├── bip39.rs
    ├── bip39_words.rs
    └── tsv.rs
```

## Files

| File | Lines | Purpose |
|------|-------|---------|
| [Cargo.toml](https://github.com/sinescode/scannerbtc-rust/blob/main/Cargo.toml) | 38 | Manifest: deps, profiles, binary definition |
| [README.md](https://github.com/sinescode/scannerbtc-rust/blob/main/README.md) | 90 | User docs: install, usage, examples |
| [AGENTS.md](https://github.com/sinescode/scannerbtc-rust/blob/main/AGENTS.md) | 40 | Agent reference: build, structure, conventions |
| [bip39_words.txt](https://github.com/sinescode/scannerbtc-rust/blob/main/bip39_words.txt) | 2048 | BIP-39 English wordlist |
| [src/main.rs](https://github.com/sinescode/scannerbtc-rust/blob/main/src/main.rs) | 850 | CLI + `build` / `scan` / `check` subcommands |
| [src/lib.rs](https://github.com/sinescode/scannerbtc-rust/blob/main/src/lib.rs) | 11 | Module declarations |
| [src/siphash.rs](https://github.com/sinescode/scannerbtc-rust/blob/main/src/siphash.rs) | 115 | SipHash-1-3 double-output (Bloom filter hash) |
| [src/bloom.rs](https://github.com/sinescode/scannerbtc-rust/blob/main/src/bloom.rs) | 260 | Bloom filter v3, TSV index cache, line offsets |
| [src/crypto.rs](https://github.com/sinescode/scannerbtc-rust/blob/main/src/crypto.rs) | 165 | SHA-256, RIPEMD-160, HMAC, PBKDF2, secp256k1 |
| [src/encoding.rs](https://github.com/sinescode/scannerbtc-rust/blob/main/src/encoding.rs) | 135 | Base58Check, Bech32/Bech32m |
| [src/bitcoin.rs](https://github.com/sinescode/scannerbtc-rust/blob/main/src/bitcoin.rs) | 277 | P2PKH, P2SH-P2WPKH, P2WPKH, P2WSH, P2TR |
| [src/bip32.rs](https://github.com/sinescode/scannerbtc-rust/blob/main/src/bip32.rs) | 175 | BIP-32 HD key derivation |
| [src/bip39.rs](https://github.com/sinescode/scannerbtc-rust/blob/main/src/bip39.rs) | 155 | BIP-39 mnemonic generation |
| [src/bip39_words.rs](https://github.com/sinescode/scannerbtc-rust/blob/main/src/bip39_words.rs) | 2050 | Generated wordlist const array |
| [src/tsv.rs](https://github.com/sinescode/scannerbtc-rust/blob/main/src/tsv.rs) | 155 | Memory-mapped TSV with `.idx` cache |

## Raw Links

```
https://raw.githubusercontent.com/sinescode/scannerbtc-rust/main/Cargo.toml
https://raw.githubusercontent.com/sinescode/scannerbtc-rust/main/README.md
https://raw.githubusercontent.com/sinescode/scannerbtc-rust/main/AGENTS.md
https://raw.githubusercontent.com/sinescode/scannerbtc-rust/main/bip39_words.txt
https://raw.githubusercontent.com/sinescode/scannerbtc-rust/main/src/main.rs
https://raw.githubusercontent.com/sinescode/scannerbtc-rust/main/src/lib.rs
https://raw.githubusercontent.com/sinescode/scannerbtc-rust/main/src/siphash.rs
https://raw.githubusercontent.com/sinescode/scannerbtc-rust/main/src/bloom.rs
https://raw.githubusercontent.com/sinescode/scannerbtc-rust/main/src/crypto.rs
https://raw.githubusercontent.com/sinescode/scannerbtc-rust/main/src/encoding.rs
https://raw.githubusercontent.com/sinescode/scannerbtc-rust/main/src/bitcoin.rs
https://raw.githubusercontent.com/sinescode/scannerbtc-rust/main/src/bip32.rs
https://raw.githubusercontent.com/sinescode/scannerbtc-rust/main/src/bip39.rs
https://raw.githubusercontent.com/sinescode/scannerbtc-rust/main/src/bip39_words.rs
https://raw.githubusercontent.com/sinescode/scannerbtc-rust/main/src/tsv.rs
```
