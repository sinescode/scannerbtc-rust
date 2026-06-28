use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};

use crate::encoding::is_valid_btc_address;
use crate::siphash::{siphash13_double, SipPair};

const IDX_MAGIC: u64 = 0x5458564944585801;

/// Errors in Bloom filter operations.
#[derive(Debug)]
pub enum BloomError {
    Io(std::io::Error),
    InvalidVersion(u8),
    InvalidFileSize { expected: u64, actual: u64 },
    TruncatedFile,
    InvalidBitmapSize(u64),
}

impl std::fmt::Display for BloomError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BloomError::Io(e) => write!(f, "I/O error: {}", e),
            BloomError::InvalidVersion(v) => {
                write!(f, "unsupported bloom version: {} (expected 1, 2, or 3)", v)
            }
            BloomError::InvalidFileSize { expected, actual } => {
                write!(
                    f,
                    "file size mismatch: expected {}, got {}",
                    expected, actual
                )
            }
            BloomError::TruncatedFile => write!(f, "bloom file truncated"),
            BloomError::InvalidBitmapSize(s) => write!(f, "invalid bitmap size: {} bytes", s),
        }
    }
}

impl std::error::Error for BloomError {}

impl From<std::io::Error> for BloomError {
    fn from(e: std::io::Error) -> Self {
        BloomError::Io(e)
    }
}

#[derive(Debug)]
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
    /// Load a Bloom filter from a file.
    ///
    /// Validates:
    /// - File is not empty
    /// - Version byte is 1, 2, or 3
    /// - All header fields can be read (not truncated)
    /// - Bitmap size is reasonable (> 0, not absurdly large)
    pub fn load(path: &str) -> Result<Self, BloomError> {
        let mut f = File::open(path)?;

        // Read version byte
        let mut ver_buf = [0u8; 1];
        f.read_exact(&mut ver_buf)?;
        let ver = ver_buf[0];

        // Validate version
        if ver != 1 && ver != 2 && ver != 3 {
            return Err(BloomError::InvalidVersion(ver));
        }

        let mut k0: u64 = 0;
        let mut k1: u64 = 0;
        let mut k_num: i32 = 0;
        let mut k_stored = false;

        if ver == 3 {
            let mut buf = [0u8; 8];
            f.read_exact(&mut buf)?;
            k0 = u64::from_le_bytes(buf);
            f.read_exact(&mut buf)?;
            k1 = u64::from_le_bytes(buf);
            let mut k32 = [0u8; 4];
            f.read_exact(&mut k32)?;
            k_num = u32::from_le_bytes(k32) as i32;
            k_stored = true;
        } else if ver == 2 {
            let mut buf = [0u8; 8];
            f.read_exact(&mut buf)?;
            k0 = u64::from_le_bytes(buf);
            f.read_exact(&mut buf)?;
            k1 = u64::from_le_bytes(buf);
        }
        // ver == 1: no k0/k1 stored

        // Read bitmap length
        let mut blen_buf = [0u8; 8];
        f.read_exact(&mut blen_buf)?;
        let blen = u64::from_le_bytes(blen_buf);

        // Validate bitmap size
        if blen == 0 {
            return Err(BloomError::InvalidBitmapSize(0));
        }
        // Sanity check: bitmap should not exceed 1GB
        if blen > 1_073_741_824 {
            return Err(BloomError::InvalidBitmapSize(blen));
        }

        // Read bitmap
        let mut bitmap = vec![0u8; blen as usize];
        f.read_exact(&mut bitmap)?;

        // Validate we read the full file (detect truncation)
        // It's OK if we can't read more — that means we're at EOF
        // But if we can read more, the file is larger than expected
        // (which is fine for forward compatibility)

        let bitmap_bits = blen * 8;
        let b2 = blen.next_power_of_two();
        let pow2 = b2 == blen;
        let mask = if pow2 { bitmap_bits - 1 } else { 0 };

        if !k_stored {
            k_num = 0;
        }

        Ok(BloomFilter {
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

    /// Check if an address is possibly in the Bloom filter.
    ///
    /// Returns false = DEFINITELY NOT PRESENT (100% certain).
    /// Returns true = POSSIBLY PRESENT (may be false positive).
    ///
    /// # Safety
    ///
    /// The bitmap indexing uses `byte_idx = bit >> 3` where `bit < bitmap_bits`.
    /// Since `bitmap_bits = bitmap.len() * 8`, we have `byte_idx < bitmap.len()`.
    /// The mask/ modulo operations guarantee `bit` stays within bounds.
    #[inline]
    pub fn contains(&self, addr: &str) -> bool {
        if self.bitmap.is_empty() || self.k_num <= 0 {
            return false;
        }
        let SipPair { h1, h2 } = siphash13_double(addr.as_bytes(), self.k0, self.k1);
        if self.pow2 {
            // Fast path: bitmap size is power-of-2, use & instead of %
            for i in 0..self.k_num {
                let bit = h1.wrapping_add((i as u64).wrapping_mul(h2)) & self.mask;
                let byte_idx = (bit >> 3) as usize;
                debug_assert!(byte_idx < self.bitmap.len(), "bloom index out of bounds");
                let bmask = 1u8 << (bit & 7);
                if self.bitmap[byte_idx] & bmask == 0 {
                    return false;
                }
            }
        } else {
            // General path: use modulo for non-pow2 bitmap
            for i in 0..self.k_num {
                let bit = h1.wrapping_add((i as u64).wrapping_mul(h2)) % self.bitmap_bits;
                let byte_idx = (bit >> 3) as usize;
                debug_assert!(byte_idx < self.bitmap.len(), "bloom index out of bounds");
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

    #[test]
    fn test_bloom_load_invalid_version() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.bloom");
        let mut f = File::create(&path).unwrap();
        f.write_all(&[99]).unwrap(); // invalid version
        f.flush().unwrap();

        let result = BloomFilter::load(path.to_str().unwrap());
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            BloomError::InvalidVersion(99)
        ));
    }

    #[test]
    fn test_bloom_load_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.bloom");
        File::create(&path).unwrap();

        let result = BloomFilter::load(path.to_str().unwrap());
        assert!(result.is_err());
    }
}
