use hmac::{Hmac, KeyInit, Mac};
use rand::RngCore;
use ripemd::Ripemd160;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

type HmacSha512 = Hmac<sha2::Sha512>;

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn sha256_two(data: &[u8]) -> [u8; 32] {
    sha256(&sha256(data))
}

pub fn ripemd160(data: &[u8]) -> [u8; 20] {
    let mut hasher = Ripemd160::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn hash160(data: &[u8]) -> [u8; 20] {
    ripemd160(&sha256(data))
}

pub fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let mut mac = HmacSha512::new_from_slice(key).expect("HMAC key error");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 64];
    out.copy_from_slice(&result);
    out
}

pub fn pbkdf2_hmac_sha512(password: &[u8], salt: &[u8], rounds: u32) -> [u8; 64] {
    let mut output = [0u8; 64];
    let _ = pbkdf2::pbkdf2::<HmacSha512>(password, salt, rounds, &mut output);
    output
}

pub fn random_bytes(buf: &mut [u8]) {
    rand::rng().fill_bytes(buf);
}

pub fn generate_random_private_key() -> [u8; 32] {
    loop {
        let mut buf = [0u8; 32];
        random_bytes(&mut buf);
        if SecretKey::from_byte_array(buf).is_ok() {
            return buf;
        }
    }
}

pub fn private_key_to_public_key_compressed(privkey: &[u8; 32]) -> Option<[u8; 33]> {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_byte_array(*privkey).ok()?;
    let public = PublicKey::from_secret_key(&secp, &secret);
    let mut out = [0u8; 33];
    out.copy_from_slice(&public.serialize());
    Some(out)
}

pub fn public_key_to_xonly(pubkey: &[u8; 33]) -> [u8; 32] {
    let mut xonly = [0u8; 32];
    xonly.copy_from_slice(&pubkey[1..33]);
    xonly
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_empty() {
        let hash = sha256(b"");
        assert_eq!(
            hash,
            hex_literal::hex!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
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

    #[test]
    fn test_ripemd160_empty() {
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
    fn test_hash160() {
        let hash = hash160(b"test");
        assert_eq!(hash.len(), 20);
    }

    #[test]
    fn test_hmac_sha512() {
        let result = hmac_sha512(b"key", b"message");
        assert_eq!(result.len(), 64);
        assert_ne!(result, [0u8; 64]);
    }

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
    fn test_random_bytes() {
        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];
        random_bytes(&mut buf1);
        random_bytes(&mut buf2);
        assert_ne!(buf1, buf2);
    }

    #[test]
    fn test_generate_random_private_key() {
        let key = generate_random_private_key();
        assert_eq!(key.len(), 32);
        assert!(SecretKey::from_byte_array(key).is_ok());
    }

    #[test]
    fn test_private_key_to_public_key_compressed() {
        let key = generate_random_private_key();
        let pubkey = private_key_to_public_key_compressed(&key);
        assert!(pubkey.is_some());
        let pubkey = pubkey.unwrap();
        assert_eq!(pubkey.len(), 33);
        assert!(pubkey[0] == 0x02 || pubkey[0] == 0x03);
    }

    #[test]
    fn test_private_key_to_public_key_invalid() {
        let invalid_key = [0u8; 32];
        let result = private_key_to_public_key_compressed(&invalid_key);
        assert!(result.is_none());
    }

    #[test]
    fn test_public_key_to_xonly() {
        let key = generate_random_private_key();
        let pubkey = private_key_to_public_key_compressed(&key).unwrap();
        let xonly = public_key_to_xonly(&pubkey);
        assert_eq!(xonly.len(), 32);
        assert_eq!(xonly, pubkey[1..33]);
    }
}
