use crate::crypto::{hmac_sha512, private_key_to_public_key_compressed};

#[derive(Clone)]
pub struct XKey {
    pub key: [u8; 32],
    pub chain: [u8; 32],
}

pub fn derive_master_key(seed: &[u8]) -> XKey {
    let out = hmac_sha512(b"Bitcoin seed", seed);
    let mut key = [0u8; 32];
    let mut chain = [0u8; 32];
    key.copy_from_slice(&out[..32]);
    chain.copy_from_slice(&out[32..64]);
    XKey { key, chain }
}

pub fn derive_child_key(parent: &XKey, index: u32) -> XKey {
    let hardened = index >= 0x80000000;
    let mut data = [0u8; 37];

    if hardened {
        data[0] = 0x00;
        data[1..33].copy_from_slice(&parent.key);
    } else {
        if let Some(pubkey) = private_key_to_public_key_compressed(&parent.key) {
            data[..33].copy_from_slice(&pubkey);
        } else {
            return parent.clone();
        }
    }

    data[33] = (index >> 24) as u8;
    data[34] = (index >> 16) as u8;
    data[35] = (index >> 8) as u8;
    data[36] = index as u8;

    let out = hmac_sha512(&parent.chain, &data);

    let order = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
        0x41, 0x41,
    ];

    let mut child_key = parent.key;
    let mut carry = 0u16;
    for i in (0..32).rev() {
        let sum = child_key[i] as u16 + out[i] as u16 + carry;
        child_key[i] = (sum & 0xff) as u8;
        carry = sum >> 8;
    }

    let ge = carry != 0 || {
        let mut result = true;
        for i in 0..32 {
            if child_key[i] < order[i] {
                result = false;
                break;
            }
            if child_key[i] > order[i] {
                break;
            }
        }
        result
    };
    if ge {
        let mut borrow = 0i32;
        for i in (0..32).rev() {
            let diff = child_key[i] as i32 - order[i] as i32 - borrow;
            if diff < 0 {
                child_key[i] = (diff + 256) as u8;
                borrow = 1;
            } else {
                child_key[i] = diff as u8;
                borrow = 0;
            }
        }
    }

    let all_zero = child_key.iter().all(|&b| b == 0);
    if all_zero {
        return parent.clone();
    }

    let mut chain = [0u8; 32];
    chain.copy_from_slice(&out[32..64]);

    XKey {
        key: child_key,
        chain,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_master_key() {
        let seed = [0u8; 32];
        let master = derive_master_key(&seed);
        assert_ne!(master.key, [0u8; 32]);
        assert_ne!(master.chain, [0u8; 32]);
    }

    #[test]
    fn test_derive_master_key_deterministic() {
        let seed = [0x01u8; 32];
        let m1 = derive_master_key(&seed);
        let m2 = derive_master_key(&seed);
        assert_eq!(m1.key, m2.key);
        assert_eq!(m1.chain, m2.chain);
    }

    #[test]
    fn test_derive_child_hardened() {
        let seed = [0u8; 32];
        let master = derive_master_key(&seed);
        let child = derive_child_key(&master, 0x80000000);
        assert_ne!(child.key, master.key);
        assert_ne!(child.chain, master.chain);
    }

    #[test]
    fn test_derive_child_unhardened() {
        let seed = [0u8; 32];
        let master = derive_master_key(&seed);
        let child = derive_child_key(&master, 0);
        assert_ne!(child.key, master.key);
    }

    #[test]
    fn test_derive_child_deterministic() {
        let seed = [0x02u8; 32];
        let master = derive_master_key(&seed);
        let c1 = derive_child_key(&master, 44 | 0x80000000);
        let c2 = derive_child_key(&master, 44 | 0x80000000);
        assert_eq!(c1.key, c2.key);
        assert_eq!(c1.chain, c2.chain);
    }

    #[test]
    fn test_derive_different_indices() {
        let seed = [0x03u8; 32];
        let master = derive_master_key(&seed);
        let c1 = derive_child_key(&master, 0);
        let c2 = derive_child_key(&master, 1);
        assert_ne!(c1.key, c2.key);
    }

    #[test]
    fn test_derivation_path_m44h() {
        let seed = hex_literal::hex!("000102030405060708090a0b0c0d0e0f");
        let master = derive_master_key(&seed);
        let child = derive_child_key(&master, 44 | 0x80000000);
        assert_ne!(child.key, [0u8; 32]);
    }

    #[test]
    fn test_invalid_key_fallback() {
        let invalid = XKey {
            key: [0u8; 32],
            chain: [0u8; 32],
        };
        let child = derive_child_key(&invalid, 0);
        assert_eq!(child.key, invalid.key);
    }

    // Official BIP-32 test vector 1 (master key from known seed)
    #[test]
    fn test_bip32_vector1_master() {
        let seed = hex_literal::hex!("000102030405060708090a0b0c0d0e0f");
        let master = derive_master_key(&seed);
        // Master key (m):
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
        let master = derive_master_key(&seed);
        let child = derive_child_key(&master, 0x80000000);
        let expected_key =
            hex_literal::hex!("edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea");
        assert_eq!(child.key, expected_key);
    }
}
