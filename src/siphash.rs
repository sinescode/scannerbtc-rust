#[derive(Clone, Copy)]
pub struct SipPair {
    pub h1: u64,
    pub h2: u64,
}

#[inline]
fn rotl64(x: u64, b: i32) -> u64 {
    x.rotate_left(b as u32)
}

macro_rules! sip_round {
    ($v0:expr, $v1:expr, $v2:expr, $v3:expr) => {
        $v0 = $v0.wrapping_add($v1);
        $v1 = rotl64($v1, 13);
        $v1 ^= $v0;
        $v0 = rotl64($v0, 32);
        $v2 = $v2.wrapping_add($v3);
        $v3 = rotl64($v3, 16);
        $v3 ^= $v2;
        $v0 = $v0.wrapping_add($v3);
        $v3 = rotl64($v3, 21);
        $v3 ^= $v0;
        $v2 = $v2.wrapping_add($v1);
        $v1 = rotl64($v1, 17);
        $v1 ^= $v2;
        $v2 = rotl64($v2, 32);
    };
}

pub fn siphash13_double(data: &[u8], k0: u64, k1: u64) -> SipPair {
    let len = data.len();
    let mut v0 = k0 ^ 0x736f6d6570736575;
    let mut v1 = k1 ^ 0x646f72616e646f6d;
    let mut v2 = k0 ^ 0x6c7967656e657261;
    let mut v3 = k1 ^ 0x7465646279746573;

    let end = (len / 8) * 8;
    let mut i = 0;
    while i < end {
        let m = u64::from_le_bytes([
            data[i],
            data[i + 1],
            data[i + 2],
            data[i + 3],
            data[i + 4],
            data[i + 5],
            data[i + 6],
            data[i + 7],
        ]);
        v3 ^= m;
        sip_round!(v0, v1, v2, v3);
        v0 ^= m;
        i += 8;
    }

    let mut last = (len as u64 & 0xff) << 56;
    let mut j = 0;
    while j < (len & 7) {
        last |= (data[end + j] as u64) << (j * 8);
        j += 1;
    }

    v3 ^= last;
    sip_round!(v0, v1, v2, v3);
    v0 ^= last;
    v2 ^= 0xff;

    sip_round!(v0, v1, v2, v3);
    sip_round!(v0, v1, v2, v3);
    sip_round!(v0, v1, v2, v3);

    let h1 = v0 ^ v1 ^ v2 ^ v3;
    v1 ^= 0xee;

    sip_round!(v0, v1, v2, v3);
    sip_round!(v0, v1, v2, v3);
    sip_round!(v0, v1, v2, v3);

    SipPair {
        h1,
        h2: v0 ^ v1 ^ v2 ^ v3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_siphash_empty() {
        let result = siphash13_double(b"", 0, 0);
        assert_ne!(result.h1, 0);
        assert_ne!(result.h2, 0);
    }

    #[test]
    fn test_siphash_deterministic() {
        let r1 = siphash13_double(b"test", 123, 456);
        let r2 = siphash13_double(b"test", 123, 456);
        assert_eq!(r1.h1, r2.h1);
        assert_eq!(r1.h2, r2.h2);
    }

    #[test]
    fn test_siphash_different_data() {
        let r1 = siphash13_double(b"hello", 0, 0);
        let r2 = siphash13_double(b"world", 0, 0);
        assert_ne!(r1.h1, r2.h1);
    }

    #[test]
    fn test_siphash_different_keys() {
        let r1 = siphash13_double(b"test", 0, 0);
        let r2 = siphash13_double(b"test", 1, 0);
        assert_ne!(r1.h1, r2.h1);
    }

    #[test]
    fn test_siphash_8byte_aligned() {
        let data = [0x01u8; 16];
        let result = siphash13_double(&data, 0, 0);
        assert_ne!(result.h1, 0);
        assert_ne!(result.h2, 0);
    }

    #[test]
    fn test_siphash_unaligned() {
        let data = [0x01u8; 13];
        let result = siphash13_double(&data, 0, 0);
        assert_ne!(result.h1, 0);
        assert_ne!(result.h2, 0);
    }

    #[test]
    fn test_siphash_single_byte() {
        let result = siphash13_double(&[0x42], 0, 0);
        assert_ne!(result.h1, 0);
        assert_ne!(result.h2, 0);
    }

    #[test]
    fn test_siphash_zero_key() {
        let r1 = siphash13_double(b"test", 0, 0);
        let r2 = siphash13_double(b"test", 0, 0);
        assert_eq!(r1.h1, r2.h1);
    }
}
