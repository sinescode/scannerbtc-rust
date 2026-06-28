use scannerbtc::bip32::{derive_child_key, derive_master_key};
use scannerbtc::bip39::{mnemonic_to_seed, validate_mnemonic};
use scannerbtc::bitcoin::fill_key_data;
use scannerbtc::encoding::{base58check_decode, base58check_encode};

/// Differential tests comparing our implementation against verified test vectors.
#[cfg(test)]
mod differential_tests {
    use super::*;

    // ═══════════════════════════════════════════════════════════════════════
    // BIP-32 Master Key Verification
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_bip32_master_key_vector1() {
        let seed = hex_literal::hex!("000102030405060708090a0b0c0d0e0f");
        let master = derive_master_key(&seed).unwrap();
        assert_eq!(
            hex::encode(master.key),
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
        );
    }

    #[test]
    fn test_bip32_master_key_vector2() {
        let seed = hex_literal::hex!(
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
        );
        let master = derive_master_key(&seed).unwrap();
        assert_eq!(
            hex::encode(master.key),
            "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // BIP-32 Child Key Derivation
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_bip32_child_derivation_hardened() {
        let seed = hex_literal::hex!("000102030405060708090a0b0c0d0e0f");
        let master = derive_master_key(&seed).unwrap();
        let child = derive_child_key(&master, 0x80000000).unwrap();
        assert_eq!(
            hex::encode(child.key),
            "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // BIP-39 Test Vectors
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_bip39_vector_abandon_empty_passphrase() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let seed = mnemonic_to_seed(phrase, "");
        assert_eq!(
            hex::encode(seed),
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Mnemonic Validation
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_validate_known_valid_mnemonics() {
        // Only test mnemonics with verified checksums
        let valid = vec![
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        ];
        for m in valid {
            assert!(validate_mnemonic(m).is_ok(), "Should be valid: {}", m);
        }
    }

    #[test]
    fn test_validate_known_invalid_mnemonics() {
        let invalid = vec![
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ability",
            "abandon",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
        ];
        for m in invalid {
            assert!(validate_mnemonic(m).is_err(), "Should be invalid: {}", m);
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Base58Check Roundtrip
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_base58check_roundtrip_various_payloads() {
        let payloads: Vec<Vec<u8>> = vec![
            vec![0x00; 21],
            vec![0x05; 21],
            vec![0x80; 34],
            vec![0x04; 65],
        ];
        for payload in payloads {
            let encoded = base58check_encode(&payload);
            let decoded = base58check_decode(&encoded).unwrap();
            assert_eq!(decoded, payload);
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Address Generation Consistency
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_address_generation_consistency() {
        let privkey =
            hex_literal::hex!("4c0883a69102937d6231471b5dbb6204fe512961708279f0e72fbf169a0f11c0");
        let kd1 = fill_key_data(&privkey).unwrap();
        let kd2 = fill_key_data(&privkey).unwrap();
        assert_eq!(kd1.p2pkh, kd2.p2pkh);
        assert_eq!(kd1.p2sh_p2wpkh, kd2.p2sh_p2wpkh);
        assert_eq!(kd1.p2wpkh, kd2.p2wpkh);
        assert_eq!(kd1.p2wsh, kd2.p2wsh);
        assert_eq!(kd1.p2tr, kd2.p2tr);
    }
}
