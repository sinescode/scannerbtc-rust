use crate::bip32::{derive_child_key, derive_master_key, DerivationError};
use crate::bitcoin::fill_key_data;
use crate::crypto::{pbkdf2_hmac_sha512, random_bytes, sha256};

mod words {
    include!("bip39_words.rs");
}

pub use words::BIP39_WORDS;

pub const BIP39_WORD_COUNT: usize = 2048;

/// Errors in mnemonic/seed operations.
#[derive(Debug)]
pub enum MnemonicError {
    Derivation(DerivationError),
}

impl std::fmt::Display for MnemonicError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MnemonicError::Derivation(e) => write!(f, "key derivation: {}", e),
        }
    }
}

impl std::error::Error for MnemonicError {}

impl From<DerivationError> for MnemonicError {
    fn from(e: DerivationError) -> Self {
        MnemonicError::Derivation(e)
    }
}

pub fn generate_mnemonic(word_count: usize) -> String {
    let entropy_bytes = if word_count == 24 { 32 } else { 16 };

    let mut entropy = [0u8; 32];
    random_bytes(&mut entropy[..entropy_bytes]);

    let h = sha256(&entropy[..entropy_bytes]);

    let mut bits: Vec<u8> = Vec::with_capacity(entropy_bytes + 1);
    bits.extend_from_slice(&entropy[..entropy_bytes]);
    bits.push(h[0]);

    let mut result = String::new();
    for i in 0..word_count {
        let bit_offset = i * 11;
        let byte_offset = bit_offset / 8;
        let bit_in_byte = bit_offset % 8;

        let mut word_bits: u32 = 0;
        for b in 0..3 {
            let idx = byte_offset + b;
            word_bits = (word_bits << 8)
                | if idx < bits.len() {
                    bits[idx] as u32
                } else {
                    0
                };
        }

        let shift = 24 - bit_in_byte - 11;
        let idx = ((word_bits >> shift) & 0x7ff) % BIP39_WORD_COUNT as u32;

        if i > 0 {
            result.push(' ');
        }
        result.push_str(BIP39_WORDS[idx as usize]);
    }
    result
}

pub fn mnemonic_to_seed(phrase: &str) -> [u8; 64] {
    pbkdf2_hmac_sha512(phrase.as_bytes(), b"mnemonic", 2048)
}

#[derive(Clone)]
pub struct MnemonicRecord {
    pub addr_type: String,
    pub address: String,
    pub wif: String,
    pub priv_hex: String,
    pub compressed_pub_hex: String,
    pub xonly_pub_hex: String,
    pub derivation_path: String,
    pub mnemonic: String,
}

pub fn generate_mnemonic_addresses(
    phrase: &str,
    depth: usize,
) -> Result<Vec<MnemonicRecord>, MnemonicError> {
    let seed = mnemonic_to_seed(phrase);
    let master = derive_master_key(&seed)?;

    struct PurposeInfo {
        purpose: u32,
        addr_type: &'static str,
        also_wsh: bool,
    }

    let purposes = [
        PurposeInfo {
            purpose: 44,
            addr_type: "P2PKH",
            also_wsh: false,
        },
        PurposeInfo {
            purpose: 49,
            addr_type: "P2SH-P2WPKH",
            also_wsh: false,
        },
        PurposeInfo {
            purpose: 84,
            addr_type: "P2WPKH",
            also_wsh: true,
        },
        PurposeInfo {
            purpose: 86,
            addr_type: "P2TR",
            also_wsh: false,
        },
    ];

    let mut records = Vec::new();

    for pi in &purposes {
        let k = match derive_child_key(
            &derive_child_key(
                &derive_child_key(
                    &derive_child_key(&master, pi.purpose | 0x80000000)?,
                    0x80000000,
                )?,
                0x80000000,
            )?,
            0,
        ) {
            Ok(k) => k,
            Err(_) => continue,
        };

        for i in 0..depth {
            let ck = match derive_child_key(&k, i as u32) {
                Ok(ck) => ck,
                Err(_) => continue,
            };
            let kd = match fill_key_data(&ck.key) {
                Some(kd) => kd,
                None => continue,
            };

            let path = format!("m/{}'/0'/0'/0/{}", pi.purpose, i);

            let push = |addr_type: &str, address: String| -> MnemonicRecord {
                MnemonicRecord {
                    addr_type: addr_type.to_string(),
                    address,
                    wif: kd.wif.clone(),
                    priv_hex: kd.priv_hex.clone(),
                    compressed_pub_hex: kd.compressed_pub_hex.clone(),
                    xonly_pub_hex: kd.xonly_pub_hex.clone(),
                    derivation_path: path.clone(),
                    mnemonic: phrase.to_string(),
                }
            };

            match pi.addr_type {
                "P2PKH" => records.push(push("P2PKH", kd.p2pkh)),
                "P2SH-P2WPKH" => records.push(push("P2SH-P2WPKH", kd.p2sh_p2wpkh)),
                "P2WPKH" => {
                    records.push(push("P2WPKH", kd.p2wpkh));
                    if pi.also_wsh {
                        records.push(push("P2WSH", kd.p2wsh));
                    }
                }
                "P2TR" => records.push(push("P2TR", kd.p2tr)),
                _ => {}
            }
        }
    }

    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wordlist_length() {
        assert_eq!(BIP39_WORDS.len(), 2048);
    }

    #[test]
    fn test_wordlist_first_word() {
        assert_eq!(BIP39_WORDS[0], "abandon");
    }

    #[test]
    fn test_wordlist_last_word() {
        assert_eq!(BIP39_WORDS[2047], "zoo");
    }

    #[test]
    fn test_generate_mnemonic_12_words() {
        let mnemonic = generate_mnemonic(12);
        let words: Vec<&str> = mnemonic.split(' ').collect();
        assert_eq!(words.len(), 12);
        for w in &words {
            assert!(BIP39_WORDS.contains(w));
        }
    }

    #[test]
    fn test_generate_mnemonic_24_words() {
        let mnemonic = generate_mnemonic(24);
        let words: Vec<&str> = mnemonic.split(' ').collect();
        assert_eq!(words.len(), 24);
        for w in &words {
            assert!(BIP39_WORDS.contains(w));
        }
    }

    #[test]
    fn test_generate_mnemonic_deterministic() {
        let m1 = generate_mnemonic(12);
        let m2 = generate_mnemonic(12);
        assert_ne!(m1, m2);
    }

    #[test]
    fn test_mnemonic_to_seed_deterministic() {
        let phrase = "test test test test test test test test test test test test";
        let s1 = mnemonic_to_seed(phrase);
        let s2 = mnemonic_to_seed(phrase);
        assert_eq!(s1, s2);
    }

    // Official BIP-39 test vector: "abandon" x11 + "about"
    // PBKDF2-HMAC-SHA512 with empty password and "mnemonic" salt
    #[test]
    fn test_bip39_official_vector_abandon() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let seed = mnemonic_to_seed(phrase);
        let seed_hex = hex::encode(seed);
        assert_eq!(
            seed_hex,
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
        );
    }

    #[test]
    fn test_generate_mnemonic_addresses() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let records = generate_mnemonic_addresses(phrase, 1).unwrap();
        assert!(!records.is_empty());
        for r in &records {
            assert!(!r.address.is_empty());
            assert!(!r.wif.is_empty());
            assert_eq!(r.mnemonic, phrase);
        }
    }

    #[test]
    fn test_generate_mnemonic_addresses_depth() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let r1 = generate_mnemonic_addresses(phrase, 1).unwrap();
        let r2 = generate_mnemonic_addresses(phrase, 2).unwrap();
        assert!(r2.len() > r1.len());
    }
}
