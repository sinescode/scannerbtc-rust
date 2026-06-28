use crate::crypto::{hmac_sha512, private_key_to_public_key_compressed};
use zeroize::Zeroize;

/// BIP-32 secp256k1 curve order n.
const CURVE_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// Errors that can occur during BIP-32 key derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerivationError {
    /// The IL value >= curve order, making this child index invalid.
    /// Per BIP-32, the caller should try the next index.
    InvalidChildIndex,
    /// The derived key is zero, making this child index invalid.
    ZeroChildKey,
    /// The parent key is invalid (not a valid secp256k1 scalar).
    InvalidParentKey,
}

impl std::fmt::Display for DerivationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DerivationError::InvalidChildIndex => {
                write!(f, "IL >= curve order (invalid child index)")
            }
            DerivationError::ZeroChildKey => write!(f, "derived key is zero"),
            DerivationError::InvalidParentKey => write!(f, "invalid parent key"),
        }
    }
}

impl std::error::Error for DerivationError {}

/// A BIP-32 extended key (private + chain code).
///
/// Implements `Zeroize` to ensure sensitive material is cleared on drop.
/// The `zeroize` crate securely wipes memory when `Drop` runs, preventing
/// secret key material from lingering in freed memory.
#[derive(Clone)]
pub struct XKey {
    pub key: [u8; 32],
    pub chain: [u8; 32],
}

impl Drop for XKey {
    fn drop(&mut self) {
        // Zeroize sensitive key material on drop
        self.key.zeroize();
        self.chain.zeroize();
    }
}

/// Compare two 32-byte values as big-endian unsigned integers.
/// Returns true if a >= b.
fn ge_be(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for i in 0..32 {
        if a[i] < b[i] {
            return false;
        }
        if a[i] > b[i] {
            return true;
        }
    }
    true // equal
}

/// Add two 32-byte scalars mod curve order.
/// Returns None if result is zero or if IL >= curve order.
///
/// # Why manual arithmetic?
///
/// The secp256k1 crate does not expose scalar addition (only point tweaking).
/// BIP-32 requires: child_key = (IL + parent_key) mod n, where n is the curve order.
/// This is a scalar-level operation, not a point operation.
///
/// Safety: All operations are on fixed-size 32-byte arrays with well-defined
/// big-endian arithmetic. No heap allocation, no pointer arithmetic, no UB.
/// The implementation has been verified against official BIP-32 test vectors.
fn scalar_add_mod_n(a: &[u8; 32], b: &[u8; 32]) -> Option<[u8; 32]> {
    // Check if b >= n (IL >= curve order means invalid)
    if ge_be(b, &CURVE_ORDER) {
        return None;
    }

    // a + b mod n
    let mut result = [0u8; 32];
    let mut carry = 0u16;
    for i in (0..32).rev() {
        let sum = a[i] as u16 + b[i] as u16 + carry;
        result[i] = (sum & 0xff) as u8;
        carry = sum >> 8;
    }

    // If overflow or result >= n, subtract n
    let needs_sub = carry != 0 || ge_be(&result, &CURVE_ORDER);
    if needs_sub {
        let mut borrow = 0i32;
        for i in (0..32).rev() {
            let diff = result[i] as i32 - CURVE_ORDER[i] as i32 - borrow;
            if diff < 0 {
                result[i] = (diff + 256) as u8;
                borrow = 1;
            } else {
                result[i] = diff as u8;
                borrow = 0;
            }
        }
    }

    // BIP-32: if result is zero, this is an invalid child
    if result.iter().all(|&b| b == 0) {
        return None;
    }

    Some(result)
}

/// Derive the master key from a seed (BIP-32).
///
/// The seed is validated: the left 32 bytes of HMAC-SHA512("Bitcoin seed", seed)
/// must be a valid secp256k1 secret scalar (non-zero, less than curve order).
pub fn derive_master_key(seed: &[u8]) -> Result<XKey, DerivationError> {
    let out = hmac_sha512(b"Bitcoin seed", seed);
    let mut key = [0u8; 32];
    let mut chain = [0u8; 32];
    key.copy_from_slice(&out[..32]);
    chain.copy_from_slice(&out[32..64]);

    // BIP-32: master key must be valid scalar
    if key.iter().all(|&b| b == 0) {
        return Err(DerivationError::InvalidParentKey);
    }
    if ge_be(&key, &CURVE_ORDER) {
        return Err(DerivationError::InvalidParentKey);
    }

    Ok(XKey { key, chain })
}

/// Derive a child key from a parent (BIP-32).
///
/// Returns `Err(DerivationError::InvalidChildIndex)` if IL >= curve order
/// or the derived key is zero. Per BIP-32, the caller should skip this index.
pub fn derive_child_key(parent: &XKey, index: u32) -> Result<XKey, DerivationError> {
    let hardened = index >= 0x80000000;
    let mut data = [0u8; 37];

    if hardened {
        data[0] = 0x00;
        data[1..33].copy_from_slice(&parent.key);
    } else {
        let pubkey = private_key_to_public_key_compressed(&parent.key)
            .ok_or(DerivationError::InvalidParentKey)?;
        data[..33].copy_from_slice(&pubkey);
    }

    data[33] = (index >> 24) as u8;
    data[34] = (index >> 16) as u8;
    data[35] = (index >> 8) as u8;
    data[36] = index as u8;

    let out = hmac_sha512(&parent.chain, &data);
    let il = {
        let mut tmp = [0u8; 32];
        tmp.copy_from_slice(&out[..32]);
        tmp
    };

    // BIP-32: child_key = (IL + parent_key) mod n
    let child_key = scalar_add_mod_n(&parent.key, &il).ok_or(DerivationError::InvalidChildIndex)?;

    let mut chain = [0u8; 32];
    chain.copy_from_slice(&out[32..64]);

    Ok(XKey {
        key: child_key,
        chain,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_master_key() {
        let seed = [0x01u8; 32];
        let master = derive_master_key(&seed).unwrap();
        assert_ne!(master.key, [0u8; 32]);
        assert_ne!(master.chain, [0u8; 32]);
    }

    #[test]
    fn test_derive_master_key_deterministic() {
        let seed = [0x01u8; 32];
        let m1 = derive_master_key(&seed).unwrap();
        let m2 = derive_master_key(&seed).unwrap();
        assert_eq!(m1.key, m2.key);
        assert_eq!(m1.chain, m2.chain);
    }

    #[test]
    fn test_derive_child_hardened() {
        let seed = [0u8; 32];
        let master = derive_master_key(&seed).unwrap();
        let child = derive_child_key(&master, 0x80000000).unwrap();
        assert_ne!(child.key, master.key);
        assert_ne!(child.chain, master.chain);
    }

    #[test]
    fn test_derive_child_unhardened() {
        let seed = [0u8; 32];
        let master = derive_master_key(&seed).unwrap();
        let child = derive_child_key(&master, 0).unwrap();
        assert_ne!(child.key, master.key);
    }

    #[test]
    fn test_derive_child_deterministic() {
        let seed = [0x02u8; 32];
        let master = derive_master_key(&seed).unwrap();
        let c1 = derive_child_key(&master, 44 | 0x80000000).unwrap();
        let c2 = derive_child_key(&master, 44 | 0x80000000).unwrap();
        assert_eq!(c1.key, c2.key);
        assert_eq!(c1.chain, c2.chain);
    }

    #[test]
    fn test_derive_different_indices() {
        let seed = [0x03u8; 32];
        let master = derive_master_key(&seed).unwrap();
        let c1 = derive_child_key(&master, 0).unwrap();
        let c2 = derive_child_key(&master, 1).unwrap();
        assert_ne!(c1.key, c2.key);
    }

    #[test]
    fn test_derivation_path_m44h() {
        let seed = hex_literal::hex!("000102030405060708090a0b0c0d0e0f");
        let master = derive_master_key(&seed).unwrap();
        let child = derive_child_key(&master, 44 | 0x80000000).unwrap();
        assert_ne!(child.key, [0u8; 32]);
    }

    #[test]
    fn test_invalid_key_returns_error() {
        let invalid = XKey {
            key: [0u8; 32],
            chain: [0u8; 32],
        };
        let result = derive_child_key(&invalid, 0);
        assert!(result.is_err());
    }

    // Official BIP-32 test vector 1 (master key from known seed)
    #[test]
    fn test_bip32_vector1_master() {
        let seed = hex_literal::hex!("000102030405060708090a0b0c0d0e0f");
        let master = derive_master_key(&seed).unwrap();
        let expected_key =
            hex_literal::hex!("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35");
        let expected_chain =
            hex_literal::hex!("873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508");
        assert_eq!(master.key, expected_key);
        assert_eq!(master.chain, expected_chain);
    }

    // Official BIP-32 test vector 1 (m/0')
    #[test]
    fn test_bip32_vector1_child_0h() {
        let seed = hex_literal::hex!("000102030405060708090a0b0c0d0e0f");
        let master = derive_master_key(&seed).unwrap();
        let child = derive_child_key(&master, 0x80000000).unwrap();

        // Child key verified against Bitcoin Core
        let expected_key =
            hex_literal::hex!("edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea");
        assert_eq!(child.key, expected_key, "child key mismatch");

        // Chain code verified against our Python reference implementation
        // Both produce the same result, confirming correctness
        let expected_chain =
            hex_literal::hex!("47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141");
        assert_eq!(child.chain, expected_chain, "child chain code mismatch");
    }

    // Test scalar_add_mod_n edge cases
    #[test]
    fn test_scalar_add_mod_n_basic() {
        let a = [0x01u8; 32];
        let b = [0x02u8; 32];
        let result = scalar_add_mod_n(&a, &b).unwrap();
        assert_eq!(result[31], 0x03);
    }

    #[test]
    fn test_scalar_add_mod_n_overflow() {
        // Add something that causes carry
        let a = [0xffu8; 32];
        let b = [0x01u8; 32];
        let result = scalar_add_mod_n(&a, &b);
        assert!(result.is_some());
    }

    #[test]
    fn test_scalar_add_mod_n_zero_result() {
        // a + (-a) mod n = 0 → should return None
        let a = [0x01u8; 32];
        // Compute n - a (negate)
        let mut neg_a = [0u8; 32];
        let mut borrow = 0i32;
        for i in (0..32).rev() {
            let diff = CURVE_ORDER[i] as i32 - a[i] as i32 - borrow;
            if diff < 0 {
                neg_a[i] = (diff + 256) as u8;
                borrow = 1;
            } else {
                neg_a[i] = diff as u8;
                borrow = 0;
            }
        }
        let result = scalar_add_mod_n(&a, &neg_a);
        assert!(result.is_none());
    }
}
