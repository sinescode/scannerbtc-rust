use crate::crypto::{hash160, private_key_to_public_key_compressed, public_key_to_xonly, sha256};
use crate::encoding::{base58check_encode, encode_segwit};

#[derive(Clone)]
pub struct KeyData {
    pub priv_key: [u8; 32],
    pub compressed_pub: [u8; 33],
    pub xonly_pub: [u8; 32],
    pub wif: String,
    pub priv_hex: String,
    pub compressed_pub_hex: String,
    pub xonly_pub_hex: String,
    pub p2pkh: String,
    pub p2sh_p2wpkh: String,
    pub p2wpkh: String,
    pub p2wsh: String,
    pub p2tr: String,
}

pub fn pubkey_to_p2pkh(pubkey: &[u8; 33]) -> String {
    let h = hash160(pubkey);
    let mut buf = [0u8; 21];
    buf[0] = 0x00;
    buf[1..21].copy_from_slice(&h);
    base58check_encode(&buf)
}

pub fn pubkey_to_p2sh_p2wpkh(pubkey: &[u8; 33]) -> String {
    let h = hash160(pubkey);
    let mut script = [0u8; 22];
    script[0] = 0x00;
    script[1] = 0x14;
    script[2..22].copy_from_slice(&h);
    let sh = hash160(&script);
    let mut buf = [0u8; 21];
    buf[0] = 0x05;
    buf[1..21].copy_from_slice(&sh);
    base58check_encode(&buf)
}

pub fn pubkey_to_p2wpkh(pubkey: &[u8; 33]) -> String {
    let h = hash160(pubkey);
    encode_segwit(b"bc", 0, &h)
}

pub fn pubkey_to_p2wsh(pubkey: &[u8; 33]) -> String {
    let mut script = Vec::with_capacity(35);
    script.push(0x21);
    script.extend_from_slice(pubkey);
    script.push(0xac);
    let h = sha256(&script);
    encode_segwit(b"bc", 0, &h)
}

fn privkey_to_wif(privkey: &[u8; 32]) -> String {
    let mut buf = [0u8; 34];
    buf[0] = 0x80;
    buf[1..33].copy_from_slice(privkey);
    buf[33] = 0x01;
    base58check_encode(&buf)
}

pub fn privkey_to_p2tr(privkey: &[u8; 32], xonly_out: &mut [u8; 32]) -> String {
    let secp = secp256k1::Secp256k1::new();
    let secret = match secp256k1::SecretKey::from_byte_array(*privkey) {
        Ok(s) => s,
        Err(_) => return String::new(),
    };
    let public = secp256k1::PublicKey::from_secret_key(&secp, &secret);
    let pub33 = public.serialize();

    let mut xonly_internal = [0u8; 32];
    xonly_internal.copy_from_slice(&pub33[1..33]);

    let mut priv_even = *privkey;
    if pub33[0] == 0x03 {
        #[allow(clippy::unnecessary_cast)]
        let order: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
            0xd0, 0x36, 0x41, 0x41,
        ];
        let mut borrow = 0i32;
        for i in (0..32).rev() {
            let diff = order[i] as i32 - priv_even[i] as i32 - borrow;
            if diff < 0 {
                priv_even[i] = (diff + 256) as u8;
                borrow = 1;
            } else {
                priv_even[i] = diff as u8;
                borrow = 0;
            }
        }
        if let Ok(sk) = secp256k1::SecretKey::from_byte_array(priv_even) {
            let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);
            let p = pk.serialize();
            xonly_internal.copy_from_slice(&p[1..33]);
        }
    }

    let tag_hash = sha256(b"TapTweak");
    let mut tweak_input = Vec::with_capacity(64);
    tweak_input.extend_from_slice(&tag_hash);
    tweak_input.extend_from_slice(&tag_hash);
    tweak_input.extend_from_slice(&xonly_internal);
    let tweak = sha256(&tweak_input);

    let mut tweaked_priv = priv_even;
    let mut carry = 0u16;
    for i in (0..32).rev() {
        let sum = tweaked_priv[i] as u16 + tweak[i] as u16 + carry;
        tweaked_priv[i] = (sum & 0xff) as u8;
        carry = sum >> 8;
    }

    let order = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
        0x41, 0x41,
    ];
    let ge = carry != 0 || {
        let mut result = true;
        for i in 0..32 {
            if tweaked_priv[i] < order[i] {
                result = false;
                break;
            }
            if tweaked_priv[i] > order[i] {
                break;
            }
        }
        result
    };
    if ge {
        let mut borrow = 0i32;
        for i in (0..32).rev() {
            let diff = tweaked_priv[i] as i32 - order[i] as i32 - borrow;
            if diff < 0 {
                tweaked_priv[i] = (diff + 256) as u8;
                borrow = 1;
            } else {
                tweaked_priv[i] = diff as u8;
                borrow = 0;
            }
        }
    }

    let all_zero = tweaked_priv.iter().all(|&b| b == 0);
    if all_zero {
        return String::new();
    }

    if let Ok(sk) = secp256k1::SecretKey::from_byte_array(tweaked_priv) {
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);
        let p = pk.serialize();
        xonly_out.copy_from_slice(&p[1..33]);
        encode_segwit(b"bc", 1, &p[1..33])
    } else {
        String::new()
    }
}

pub fn fill_key_data(privkey: &[u8; 32]) -> Option<KeyData> {
    let compressed_pub = private_key_to_public_key_compressed(privkey)?;
    let xonly_pub = public_key_to_xonly(&compressed_pub);

    let mut xonly_tweaked = [0u8; 32];
    let p2tr = privkey_to_p2tr(privkey, &mut xonly_tweaked);

    Some(KeyData {
        priv_key: *privkey,
        compressed_pub,
        xonly_pub,
        wif: privkey_to_wif(privkey),
        priv_hex: hex::encode(privkey),
        compressed_pub_hex: hex::encode(compressed_pub),
        xonly_pub_hex: hex::encode(xonly_pub),
        p2pkh: pubkey_to_p2pkh(&compressed_pub),
        p2sh_p2wpkh: pubkey_to_p2sh_p2wpkh(&compressed_pub),
        p2wpkh: pubkey_to_p2wpkh(&compressed_pub),
        p2wsh: pubkey_to_p2wsh(&compressed_pub),
        p2tr,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_privkey() -> [u8; 32] {
        hex_literal::hex!("4c0883a69102937d6231471b5dbb6204fe512961708279f0e72fbf169a0f11c0")
    }

    #[test]
    fn test_pubkey_to_p2pkh() {
        let key = test_privkey();
        let pubkey = private_key_to_public_key_compressed(&key).unwrap();
        let addr = pubkey_to_p2pkh(&pubkey);
        assert!(addr.starts_with('1'));
        assert!((25..=34).contains(&addr.len()));
    }

    #[test]
    fn test_pubkey_to_p2sh_p2wpkh() {
        let key = test_privkey();
        let pubkey = private_key_to_public_key_compressed(&key).unwrap();
        let addr = pubkey_to_p2sh_p2wpkh(&pubkey);
        assert!(addr.starts_with('3'));
        assert_eq!(addr.len(), 34);
    }

    #[test]
    fn test_pubkey_to_p2wpkh() {
        let key = test_privkey();
        let pubkey = private_key_to_public_key_compressed(&key).unwrap();
        let addr = pubkey_to_p2wpkh(&pubkey);
        assert!(addr.starts_with("bc1q"));
        assert_eq!(addr.len(), 42);
    }

    #[test]
    fn test_pubkey_to_p2wsh() {
        let key = test_privkey();
        let pubkey = private_key_to_public_key_compressed(&key).unwrap();
        let addr = pubkey_to_p2wsh(&pubkey);
        assert!(addr.starts_with("bc1q"));
        assert_eq!(addr.len(), 62);
    }

    #[test]
    fn test_privkey_to_wif() {
        let key = test_privkey();
        let wif = privkey_to_wif(&key);
        assert!(wif.starts_with('K') || wif.starts_with('L'));
    }

    #[test]
    fn test_privkey_to_p2tr() {
        let key = test_privkey();
        let mut xonly = [0u8; 32];
        let addr = privkey_to_p2tr(&key, &mut xonly);
        assert!(addr.starts_with("bc1p"));
        assert_eq!(addr.len(), 62);
        assert_ne!(xonly, [0u8; 32]);
    }

    #[test]
    fn test_fill_key_data() {
        let key = test_privkey();
        let kd = fill_key_data(&key);
        assert!(kd.is_some());
        let kd = kd.unwrap();
        assert_eq!(kd.priv_key, key);
        assert!(kd.wif.starts_with('K') || kd.wif.starts_with('L'));
        assert!(kd.p2pkh.starts_with('1'));
        assert!(kd.p2sh_p2wpkh.starts_with('3'));
        assert!(kd.p2wpkh.starts_with("bc1q"));
        assert!(kd.p2wsh.starts_with("bc1q"));
        assert!(kd.p2tr.starts_with("bc1p"));
    }

    #[test]
    fn test_fill_key_data_invalid() {
        let key = [0u8; 32];
        let result = fill_key_data(&key);
        assert!(result.is_none());
    }

    #[test]
    fn test_known_p2pkh_address() {
        let privkey =
            hex_literal::hex!("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35");
        let kd = fill_key_data(&privkey).unwrap();
        assert_eq!(kd.p2pkh, "15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma");
    }

    // Known private key → address vectors
    #[test]
    fn test_known_private_key_vector() {
        let privkey =
            hex_literal::hex!("18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c20354248a276fc3653");
        let kd = fill_key_data(&privkey).unwrap();
        assert_eq!(kd.p2pkh, "12PJseie1jCENoAij3Qw5crtBa4cBtagEU");
        assert!(kd.p2wpkh.starts_with("bc1q"));
        assert!(kd.p2tr.starts_with("bc1p"));
    }

    #[test]
    fn test_all_address_types_different() {
        let key = test_privkey();
        let kd = fill_key_data(&key).unwrap();
        // All 5 address types should be different
        let addrs = [&kd.p2pkh, &kd.p2sh_p2wpkh, &kd.p2wpkh, &kd.p2wsh, &kd.p2tr];
        for i in 0..addrs.len() {
            for j in (i + 1)..addrs.len() {
                assert_ne!(addrs[i], addrs[j]);
            }
        }
    }
}
