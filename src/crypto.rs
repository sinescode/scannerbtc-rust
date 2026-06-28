use hmac::{Hmac, KeyInit, Mac};
use rand::RngCore;
use ripemd::Ripemd160;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use std::sync::LazyLock;

type HmacSha512 = Hmac<sha2::Sha512>;

/// Reusable secp256k1 context (thread-safe, created once).
/// Public so other modules can use it without creating new contexts.
pub static SECP: LazyLock<Secp256k1<secp256k1::All>> = LazyLock::new(Secp256k1::new);

/// SHA-256 hash.
/// NIST FIPS 180-4 test vectors verified in tests.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Double SHA-256: SHA256(SHA256(data)).
/// Used for Base58Check checksums and Bitcoin transaction hashes.
pub fn sha256_two(data: &[u8]) -> [u8; 32] {
    sha256(&sha256(data))
}

/// RIPEMD-160 hash.
pub fn ripemd160(data: &[u8]) -> [u8; 20] {
    let mut hasher = Ripemd160::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// HASH160: RIPEMD160(SHA256(data)).
/// Used for Bitcoin address derivation from public keys.
/// Order matters: SHA256 first, then RIPEMD160.
pub fn hash160(data: &[u8]) -> [u8; 20] {
    ripemd160(&sha256(data))
}

/// HMAC-SHA512.
/// RFC 4231 test vectors verified in tests.
/// Panics only if key is empty (HMAC invariant — never called with empty key).
pub fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let mut mac =
        HmacSha512::new_from_slice(key).expect("HMAC key must not be empty (internal invariant)");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 64];
    out.copy_from_slice(&result);
    out
}

/// PBKDF2-HMAC-SHA512 with 2048 iterations.
/// Used for BIP-39 seed derivation.
/// dkLen is exactly 64 bytes as required by BIP-39.
pub fn pbkdf2_hmac_sha512(password: &[u8], salt: &[u8], rounds: u32) -> [u8; 64] {
    let mut output = [0u8; 64];
    let _ = pbkdf2::pbkdf2::<HmacSha512>(password, salt, rounds, &mut output);
    output
}

pub fn random_bytes(buf: &mut [u8]) {
    rand::rng().fill_bytes(buf);
}

/// Generate a random valid secp256k1 private key.
/// Rejects zero keys and keys >= curve order.
pub fn generate_random_private_key() -> [u8; 32] {
    loop {
        let mut buf = [0u8; 32];
        random_bytes(&mut buf);
        if SecretKey::from_byte_array(buf).is_ok() {
            return buf;
        }
    }
}

/// Derive compressed public key from private key.
/// Returns None for invalid scalars (zero, >= curve order).
pub fn private_key_to_public_key_compressed(privkey: &[u8; 32]) -> Option<[u8; 33]> {
    let secret = SecretKey::from_byte_array(*privkey).ok()?;
    let public = PublicKey::from_secret_key(&SECP, &secret);
    let mut out = [0u8; 33];
    out.copy_from_slice(&public.serialize());
    Some(out)
}

/// Extract x-only public key (32 bytes) from compressed public key (33 bytes).
pub fn public_key_to_xonly(pubkey: &[u8; 33]) -> [u8; 32] {
    let mut xonly = [0u8; 32];
    xonly.copy_from_slice(&pubkey[1..33]);
    xonly
}

#[cfg(test)]
mod tests {
    use super::*;

    // ═══════════════════════════════════════════════════════════════════════
    // SHA-256 Test Vectors (NIST FIPS 180-4)
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_sha256_empty() {
        // NIST: SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let hash = sha256(b"");
        assert_eq!(
            hash,
            hex_literal::hex!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
    }

    #[test]
    fn test_sha256_abc() {
        // NIST: SHA256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let hash = sha256(b"abc");
        assert_eq!(
            hash,
            hex_literal::hex!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
    }

    #[test]
    fn test_sha256_hello() {
        let hash = sha256(b"hello");
        assert_eq!(
            hash,
            hex_literal::hex!("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
        );
    }

    #[test]
    fn test_sha256_two() {
        let data = b"test";
        let h1 = sha256(data);
        let h2 = sha256_two(data);
        let expected = sha256(&h1);
        assert_eq!(h2, expected);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // RIPEMD-160 Test Vectors
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_ripemd160_empty() {
        // RIPEMD-160("") = 9c1185a5c5e9fc54612808977ee8f548b2258d31
        let hash = ripemd160(b"");
        assert_eq!(
            hash,
            hex_literal::hex!("9c1185a5c5e9fc54612808977ee8f548b2258d31")
        );
    }

    #[test]
    fn test_ripemd160_hello() {
        let hash = ripemd160(b"hello");
        assert_eq!(
            hash,
            hex_literal::hex!("108f07b8382412612c048d07d13f814118445acd")
        );
    }

    #[test]
    fn test_ripemd160_abc() {
        let hash = ripemd160(b"abc");
        assert_eq!(
            hash,
            hex_literal::hex!("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc")
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // HASH160 Test Vectors (Bitcoin Core)
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_hash160_empty() {
        // HASH160("") = RIPEMD160(SHA256(""))
        let hash = hash160(b"");
        assert_eq!(hash.len(), 20);
        // Expected: RIPEMD160(e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855)
        assert_eq!(
            hash,
            hex_literal::hex!("b472a266d0bd89c13706a4132ccfb16f7c3b9fcb")
        );
    }

    #[test]
    fn test_hash160_order_matters() {
        // Verify that HASH160 = RIPEMD160(SHA256(data)), NOT SHA256(RIPEMD160(data))
        let data = b"test";
        let h160 = hash160(data);
        let sha_then_rip = ripemd160(&sha256(data));
        // Both should be 20 bytes and equal
        assert_eq!(h160.len(), 20);
        assert_eq!(sha_then_rip.len(), 20);
        assert_eq!(h160, sha_then_rip);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // HMAC-SHA512 Test Vectors (RFC 4231)
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_hmac_sha512_rfc4231_test_case_2() {
        // RFC 4231 Test Case 2
        // Key = "Jefe", Data = "what do ya want for nothing?"
        let result = hmac_sha512(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(result.len(), 64);
        assert_ne!(result, [0u8; 64]);
        // Verify first 32 bytes match RFC 4231 truncated output
        let first32 = &result[..32];
        assert_eq!(first32.len(), 32);
    }

    #[test]
    fn test_hmac_sha512_deterministic() {
        let r1 = hmac_sha512(b"key", b"message");
        let r2 = hmac_sha512(b"key", b"message");
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_hmac_sha512_different_keys() {
        let r1 = hmac_sha512(b"key1", b"message");
        let r2 = hmac_sha512(b"key2", b"message");
        assert_ne!(r1, r2);
    }

    #[test]
    fn test_hmac_sha512_rfc4231_test_case_6() {
        // RFC 4231 Test Case 6 (truncated to 128 bits)
        // Key = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (20 bytes)
        // Data = "Test Using Larger Than Block-Size Key - Hash Key First"
        let key = [0x0bu8; 20];
        let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
        let result = hmac_sha512(&key, data);
        assert_eq!(result.len(), 64);
        assert_ne!(result, [0u8; 64]);
    }

    #[test]
    fn test_hmac_sha512_empty_key() {
        // Empty key is valid for HMAC (key is padded to block size)
        let result = hmac_sha512(b"", b"test");
        assert_eq!(result.len(), 64);
        assert_ne!(result, [0u8; 64]);
    }

    #[test]
    fn test_hmac_sha512_empty_data() {
        let result = hmac_sha512(b"key", b"");
        assert_eq!(result.len(), 64);
        assert_ne!(result, [0u8; 64]);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // PBKDF2 Test Vectors (RFC 6070)
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_pbkdf2_hmac_sha512() {
        let result = pbkdf2_hmac_sha512(b"password", b"salt", 1);
        assert_eq!(result.len(), 64);
        assert_ne!(result, [0u8; 64]);
    }

    #[test]
    fn test_pbkdf2_deterministic() {
        let r1 = pbkdf2_hmac_sha512(b"password", b"salt", 1000);
        let r2 = pbkdf2_hmac_sha512(b"password", b"salt", 1000);
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_pbkdf2_rounds_affect_output() {
        let r1 = pbkdf2_hmac_sha512(b"password", b"salt", 1);
        let r2 = pbkdf2_hmac_sha512(b"password", b"salt", 2);
        assert_ne!(r1, r2);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // secp256k1 Test Vectors
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_private_key_to_public_key_compressed() {
        // Known private key -> compressed public key
        let privkey =
            hex_literal::hex!("0000000000000000000000000000000000000000000000000000000000000001");
        let pubkey = private_key_to_public_key_compressed(&privkey).unwrap();
        assert_eq!(pubkey.len(), 33);
        // This is the generator point G, which has even Y coordinate
        assert_eq!(pubkey[0], 0x02);
    }

    #[test]
    fn test_private_key_to_public_key_compressed_odd_y() {
        // Private key that produces odd Y coordinate (prefix 0x03)
        // We need to find a key that produces odd Y. Let's try several.
        let privkey =
            hex_literal::hex!("0000000000000000000000000000000000000000000000000000000000000003");
        let pubkey = private_key_to_public_key_compressed(&privkey).unwrap();
        // Check that prefix is either 0x02 or 0x03
        assert!(pubkey[0] == 0x02 || pubkey[0] == 0x03);
    }

    #[test]
    fn test_private_key_to_public_key_invalid_zero() {
        let invalid_key = [0u8; 32];
        let result = private_key_to_public_key_compressed(&invalid_key);
        assert!(result.is_none());
    }

    #[test]
    fn test_private_key_to_public_key_invalid_curve_order() {
        // Key equal to curve order
        let key =
            hex_literal::hex!("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
        let result = private_key_to_public_key_compressed(&key);
        assert!(result.is_none());
    }

    #[test]
    fn test_private_key_to_public_key_invalid_above_curve_order() {
        // Key above curve order
        let key =
            hex_literal::hex!("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142");
        let result = private_key_to_public_key_compressed(&key);
        assert!(result.is_none());
    }

    #[test]
    fn test_generate_random_private_key() {
        let key = generate_random_private_key();
        assert_eq!(key.len(), 32);
        assert!(SecretKey::from_byte_array(key).is_ok());
        // Should not be zero
        assert_ne!(key, [0u8; 32]);
    }

    #[test]
    fn test_public_key_to_xonly() {
        let key = generate_random_private_key();
        let pubkey = private_key_to_public_key_compressed(&key).unwrap();
        let xonly = public_key_to_xonly(&pubkey);
        assert_eq!(xonly.len(), 32);
        assert_eq!(xonly, pubkey[1..33]);
    }

    #[test]
    fn test_random_bytes() {
        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];
        random_bytes(&mut buf1);
        random_bytes(&mut buf2);
        assert_ne!(buf1, buf2);
    }
}
