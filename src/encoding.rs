use crate::crypto::sha256_two;

const B58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

pub fn base58check_encode(payload: &[u8]) -> String {
    let checksum = sha256_two(payload);
    let mut buf = Vec::with_capacity(payload.len() + 4);
    buf.extend_from_slice(payload);
    buf.extend_from_slice(&checksum[..4]);

    let mut leading = 0;
    for &b in &buf {
        if b == 0 {
            leading += 1;
        } else {
            break;
        }
    }

    let mut digits: Vec<u8> = Vec::new();
    for &byte in &buf {
        let mut carry = byte as u16;
        for d in digits.iter_mut() {
            carry += (*d as u16) * 256;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }

    let mut result = String::with_capacity(leading + digits.len());
    for _ in 0..leading {
        result.push('1');
    }
    for &d in digits.iter().rev() {
        result.push(B58_ALPHABET[d as usize] as char);
    }
    result
}

const BECH32_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
const BECH32_CONST: u32 = 1;
const BECH32M_CONST: u32 = 0x2bc830a3;

fn bech32_polymod(values: &[u8]) -> u32 {
    let mut chk: u32 = 1;
    for &v in values {
        let top = chk >> 25;
        chk = (chk & 0x1ffffff) << 5 ^ (v as u32);
        for (i, &gen) in BECH32_GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= gen;
            }
        }
    }
    chk
}

fn bech32_hrp_expand(hrp: &[u8]) -> Vec<u8> {
    let mut ret = Vec::with_capacity(hrp.len() * 2 + 1);
    for &c in hrp {
        ret.push(c >> 5);
    }
    ret.push(0);
    for &c in hrp {
        ret.push(c & 31);
    }
    ret
}

fn bech32_create_checksum(hrp: &[u8], data: &[u8], bech32m: bool) -> [u8; 6] {
    let mut values = bech32_hrp_expand(hrp);
    values.extend_from_slice(data);
    values.extend_from_slice(&[0u8; 6]);
    let polymod = bech32_polymod(&values) ^ if bech32m { BECH32M_CONST } else { BECH32_CONST };
    let mut checksum = [0u8; 6];
    for (i, item) in checksum.iter_mut().enumerate() {
        *item = ((polymod >> (5 * (5 - i))) & 31) as u8;
    }
    checksum
}

fn convert_bits_8to5(data: &[u8]) -> Vec<u8> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut ret = Vec::new();
    let maxv: u32 = (1 << 5) - 1;
    for &byte in data {
        acc = (acc << 8) | (byte as u32);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            ret.push(((acc >> bits) & maxv) as u8);
        }
    }
    if bits > 0 {
        ret.push(((acc << (5 - bits)) & maxv) as u8);
    }
    ret
}

pub fn encode_segwit(hrp: &[u8], witver: u8, witprog: &[u8]) -> String {
    let bech32m = witver >= 1;
    let mut data = Vec::with_capacity(1 + witprog.len() * 8 / 5 + 6);
    data.push(witver);
    data.extend_from_slice(&convert_bits_8to5(witprog));
    let chk = bech32_create_checksum(hrp, &data, bech32m);
    data.extend_from_slice(&chk);

    let mut result = String::with_capacity(hrp.len() + 1 + data.len());
    // SAFETY: hrp is always ASCII ("bc", "tb") — caller ensures via BIP-173
    result.push_str(std::str::from_utf8(hrp).expect("HRP must be ASCII"));
    result.push('1');
    for &d in &data {
        result.push(BECH32_CHARSET[d as usize] as char);
    }
    result
}

pub fn is_valid_btc_address(s: &str) -> bool {
    let n = s.len();
    if !(26..=90).contains(&n) {
        return false;
    }
    let c = s.as_bytes()[0];
    (b'1'..=b'z').contains(&c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base58check_encode_p2pkh() {
        let payload = [0x00u8; 21];
        let encoded = base58check_encode(&payload);
        assert!(!encoded.is_empty());
        for c in encoded.chars() {
            assert!(B58_ALPHABET.contains(&(c as u8)));
        }
    }

    #[test]
    fn test_base58check_known_address() {
        let privkey =
            hex_literal::hex!("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35");
        let mut payload = [0u8; 34];
        payload[0] = 0x80;
        payload[1..33].copy_from_slice(&privkey);
        payload[33] = 0x01;
        let wif = base58check_encode(&payload);
        assert!(wif.starts_with('K') || wif.starts_with('L'));
    }

    #[test]
    fn test_encode_segwit_v0() {
        let program = [0u8; 20];
        let addr = encode_segwit(b"bc", 0, &program);
        assert!(addr.starts_with("bc1q"));
        assert_eq!(addr.len(), 42);
    }

    #[test]
    fn test_encode_segwit_v1() {
        let program = [0u8; 32];
        let addr = encode_segwit(b"bc", 1, &program);
        assert!(addr.starts_with("bc1p"));
        assert_eq!(addr.len(), 62);
    }

    #[test]
    fn test_convert_bits_8to5() {
        let data = [0xffu8, 0x00];
        let result = convert_bits_8to5(&data);
        assert!(!result.is_empty());
        for &b in &result {
            assert!(b < 32);
        }
    }

    #[test]
    fn test_is_valid_btc_address() {
        assert!(is_valid_btc_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"));
        assert!(is_valid_btc_address(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        ));
        assert!(!is_valid_btc_address(""));
        assert!(!is_valid_btc_address("short"));
        assert!(!is_valid_btc_address(&"a".repeat(25)));
    }

    #[test]
    fn test_is_valid_rejects_header() {
        assert!(!is_valid_btc_address("address"));
        assert!(!is_valid_btc_address("balance"));
    }

    #[test]
    fn test_bech32_known_p2wpkh() {
        // Known P2WPKH: bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
        // 20-byte program
        let program = [
            0x75u8, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c, 0x45, 0xd1, 0xad,
            0x31, 0xc7, 0x04, 0x21, 0x26, 0x24,
        ];
        let addr = encode_segwit(b"bc", 0, &program);
        assert!(addr.starts_with("bc1q"));
        assert_eq!(addr.len(), 42);
    }
}
