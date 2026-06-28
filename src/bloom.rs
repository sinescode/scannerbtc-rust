use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};

use crate::encoding::is_valid_btc_address;
use crate::siphash::{siphash13_double, SipPair};

const IDX_MAGIC: u64 = 0x5458564944585801;

pub struct BloomFilter {
    pub bitmap: Vec<u8>,
    pub bitmap_bits: u64,
    pub mask: u64,
    pub pow2: bool,
    pub k_num: i32,
    pub k0: u64,
    pub k1: u64,
}

impl BloomFilter {
    pub fn load(path: &str) -> Option<Self> {
        let mut f = File::open(path).ok()?;
        let mut ver_buf = [0u8; 1];
        f.read_exact(&mut ver_buf).ok()?;
        let ver = ver_buf[0];

        let mut k0: u64 = 0;
        let mut k1: u64 = 0;
        let mut k_num: i32 = 0;
        let mut k_stored = false;

        if ver == 3 {
            let mut buf = [0u8; 8];
            f.read_exact(&mut buf).ok()?;
            k0 = u64::from_le_bytes(buf);
            f.read_exact(&mut buf).ok()?;
            k1 = u64::from_le_bytes(buf);
            let mut k32 = [0u8; 4];
            f.read_exact(&mut k32).ok()?;
            k_num = u32::from_le_bytes(k32) as i32;
            k_stored = true;
        } else if ver == 2 {
            let mut buf = [0u8; 8];
            f.read_exact(&mut buf).ok()?;
            k0 = u64::from_le_bytes(buf);
            f.read_exact(&mut buf).ok()?;
            k1 = u64::from_le_bytes(buf);
        } else if ver != 1 {
            return None;
        }

        let mut blen_buf = [0u8; 8];
        f.read_exact(&mut blen_buf).ok()?;
        let blen = u64::from_le_bytes(blen_buf);

        let mut bitmap = vec![0u8; blen as usize];
        f.read_exact(&mut bitmap).ok()?;

        let bitmap_bits = blen * 8;
        let b2 = blen.next_power_of_two();
        let pow2 = b2 == blen;
        let mask = if pow2 { bitmap_bits - 1 } else { 0 };

        if !k_stored {
            k_num = 0;
        }

        Some(BloomFilter {
            bitmap,
            bitmap_bits,
            mask,
            pow2,
            k_num,
            k0,
            k1,
        })
    }

    pub fn set_k_from_valid_count(&mut self, n_valid: u64) {
        if self.k_num > 0 {
            return;
        }
        if n_valid == 0 || self.bitmap_bits == 0 {
            self.k_num = 10;
            return;
        }
        let k = (self.bitmap_bits as f64 / n_valid as f64) * core::f64::consts::LN_2;
        self.k_num = k.floor().max(1.0) as i32;
    }

    #[inline]
    pub fn contains(&self, addr: &str) -> bool {
        if self.bitmap.is_empty() {
            return false;
        }
        let SipPair { h1, h2 } = siphash13_double(addr.as_bytes(), self.k0, self.k1);
        if self.pow2 {
            for i in 0..self.k_num {
                let bit = h1.wrapping_add((i as u64).wrapping_mul(h2)) & self.mask;
                let byte_idx = (bit >> 3) as usize;
                let bmask = 1u8 << (bit & 7);
                if self.bitmap[byte_idx] & bmask == 0 {
                    return false;
                }
            }
        } else {
            for i in 0..self.k_num {
                let bit = (h1.wrapping_add((i as u64).wrapping_mul(h2))) % self.bitmap_bits;
                let byte_idx = (bit >> 3) as usize;
                let bmask = 1u8 << (bit & 7);
                if self.bitmap[byte_idx] & bmask == 0 {
                    return false;
                }
            }
        }
        true
    }
}

pub fn next_pow2(n: u64) -> u64 {
    if n == 0 {
        return 1;
    }
    let mut n = n - 1;
    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;
    n |= n >> 32;
    n + 1
}

pub fn count_valid_addresses(data: &[u8], offsets: &[usize], from: usize, to: usize) -> u64 {
    let mut n = 0u64;
    for li in from..to {
        let s = offsets[li];
        let e = if li + 1 < offsets.len() {
            offsets[li + 1]
        } else {
            data.len()
        };
        let line = &data[s..e];
        let line = std::str::from_utf8(line).unwrap_or("");
        let line = line.trim_end_matches('\n').trim_end_matches('\r');
        let addr = if let Some(tab) = line.find('\t') {
            &line[..tab]
        } else {
            line
        };
        if is_valid_btc_address(addr) {
            n += 1;
        }
    }
    n
}

pub fn build_offsets(data: &[u8]) -> Vec<usize> {
    let mut v = Vec::with_capacity(data.len() / 38 + 1);
    v.push(0);
    for i in 0..data.len() {
        if data[i] == b'\n' && i + 1 < data.len() {
            v.push(i + 1);
        }
    }
    v
}

pub fn load_idx(
    path: &str,
    expected_size: u64,
    expected_mtime: u64,
) -> Option<(Vec<usize>, usize)> {
    let f = File::open(path).ok()?;
    let mut reader = BufReader::new(f);

    let mut buf = [0u8; 8];
    reader.read_exact(&mut buf).ok()?;
    let magic = u64::from_le_bytes(buf);
    if magic != IDX_MAGIC {
        return None;
    }

    reader.read_exact(&mut buf).ok()?;
    let sz = u64::from_le_bytes(buf);
    if sz != expected_size {
        return None;
    }

    reader.read_exact(&mut buf).ok()?;
    let mt = u64::from_le_bytes(buf);
    if mt != expected_mtime {
        return None;
    }

    reader.read_exact(&mut buf).ok()?;
    let ds = u64::from_le_bytes(buf) as usize;

    reader.read_exact(&mut buf).ok()?;
    let n = u64::from_le_bytes(buf) as usize;

    let mut offsets = vec![0u64; n];
    // SAFETY: We read `n * 8` bytes from a file into a properly allocated Vec<u64>.
    // The vec is allocated with n elements, and we read exactly n*8 bytes as raw u8.
    // On little-endian platforms (x86_64, aarch64), this is equivalent to reading
    // n u64 values directly. On big-endian, the values would be byte-swapped —
    // but this code only runs on little-endian targets (Linux x86_64/aarch64, macOS ARM64).
    let offsets_u8 =
        unsafe { std::slice::from_raw_parts_mut(offsets.as_mut_ptr() as *mut u8, n * 8) };
    reader.read_exact(offsets_u8).ok()?;

    Some((offsets.iter().map(|&x| x as usize).collect(), ds))
}

pub fn save_idx(path: &str, tsv_size: u64, tsv_mtime: u64, data_start: usize, offsets: &[usize]) {
    if let Ok(f) = File::create(path) {
        let mut writer = BufWriter::new(f);
        writer.write_all(&IDX_MAGIC.to_le_bytes()).ok();
        writer.write_all(&tsv_size.to_le_bytes()).ok();
        writer.write_all(&tsv_mtime.to_le_bytes()).ok();
        writer.write_all(&(data_start as u64).to_le_bytes()).ok();
        writer.write_all(&(offsets.len() as u64).to_le_bytes()).ok();
        for &o in offsets {
            writer.write_all(&(o as u64).to_le_bytes()).ok();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_next_pow2() {
        assert_eq!(next_pow2(0), 1);
        assert_eq!(next_pow2(1), 1);
        assert_eq!(next_pow2(2), 2);
        assert_eq!(next_pow2(3), 4);
        assert_eq!(next_pow2(4), 4);
        assert_eq!(next_pow2(5), 8);
        assert_eq!(next_pow2(100), 128);
        assert_eq!(next_pow2(1024), 1024);
        assert_eq!(next_pow2(1025), 2048);
    }

    #[test]
    fn test_build_offsets_simple() {
        let data = b"line1\nline2\nline3\n";
        let offsets = build_offsets(data);
        assert_eq!(offsets, vec![0, 6, 12]);
    }

    #[test]
    fn test_build_offsets_empty() {
        let data = b"";
        let offsets = build_offsets(data);
        assert_eq!(offsets, vec![0]);
    }

    #[test]
    fn test_count_valid_addresses() {
        let data = b"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n1invalid\n";
        let offsets = build_offsets(data);
        let count = count_valid_addresses(data, &offsets, 0, offsets.len());
        assert_eq!(count, 1);
    }

    #[test]
    fn test_count_valid_skips_headers() {
        let data = b"address\tbalance\n1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n";
        let offsets = build_offsets(data);
        let count = count_valid_addresses(data, &offsets, 0, offsets.len());
        assert_eq!(count, 1);
    }

    #[test]
    fn test_save_load_idx() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.idx");
        let offsets = vec![0, 10, 20, 30];
        save_idx(path.to_str().unwrap(), 100, 12345, 5, &offsets);

        let result = load_idx(path.to_str().unwrap(), 100, 12345);
        assert!(result.is_some());
        let (loaded, ds) = result.unwrap();
        assert_eq!(loaded, offsets);
        assert_eq!(ds, 5);
    }

    #[test]
    fn test_load_idx_wrong_magic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.idx");
        let mut f = File::create(&path).unwrap();
        f.write_all(&0u64.to_le_bytes()).unwrap();
        f.flush().unwrap();

        let result = load_idx(path.to_str().unwrap(), 0, 0);
        assert!(result.is_none());
    }

    #[test]
    fn test_load_idx_wrong_size() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.idx");
        let offsets = vec![0usize; 4];
        save_idx(path.to_str().unwrap(), 100, 12345, 0, &offsets);

        let result = load_idx(path.to_str().unwrap(), 999, 12345);
        assert!(result.is_none());
    }

    #[test]
    fn test_load_idx_wrong_mtime() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.idx");
        let offsets = vec![0usize; 4];
        save_idx(path.to_str().unwrap(), 100, 12345, 0, &offsets);

        let result = load_idx(path.to_str().unwrap(), 100, 99999);
        assert!(result.is_none());
    }
}
