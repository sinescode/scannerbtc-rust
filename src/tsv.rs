use std::fs::File;
use std::sync::Arc;

use crate::bloom::{build_offsets, load_idx, save_idx};
use crate::encoding::is_valid_btc_address;
use memmap2::Mmap;

pub struct TSVFile {
    pub mmap: Arc<Mmap>,
    pub data_start: usize,
    pub offsets: Vec<usize>,
    pub total_lines: usize,
    pub fsize: u64,
    pub mtime: u64,
}

fn get_mtime(path: &str) -> u64 {
    // SAFETY: We call libc::stat on a valid C string path.
    // The path comes from File::open which already validated it exists.
    // stat() fills a valid stat struct — no memory safety issues.
    unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        let c_path = std::ffi::CString::new(path).expect("path contains null byte");
        libc::stat(c_path.as_ptr(), &mut st);
        st.st_mtime as u64
    }
}

impl TSVFile {
    pub fn open(path: &str) -> Option<Self> {
        let file = File::open(path).ok()?;
        let fsize = file.metadata().ok()?.len();
        if fsize == 0 {
            return None;
        }

        let mmap = unsafe { Mmap::map(&file).ok()? };
        let mmap = Arc::new(mmap);

        // SAFETY: madvise is a pure advisory call — it hints to the kernel about
        // access patterns. MADV_SEQUENTIAL tells the kernel to prefetch pages linearly.
        // The pointer and length are valid (from Mmap which checks bounds).
        unsafe {
            libc::madvise(
                mmap.as_ptr() as *mut libc::c_void,
                mmap.len(),
                libc::MADV_SEQUENTIAL,
            );
        }

        let mut data_start = 0;
        if let Some(nl_pos) = mmap.iter().position(|&b| b == b'\n') {
            let first_line = std::str::from_utf8(&mmap[..nl_pos]).unwrap_or("");
            if !is_valid_btc_address(first_line) {
                data_start = nl_pos + 1;
            }
        }

        let mtime = get_mtime(path);
        let idx_path = format!("{}.idx", path);

        if let Some((idx_offsets, idx_ds)) = load_idx(&idx_path, fsize, mtime) {
            let total_lines = idx_offsets.len();
            // SAFETY: MADV_RANDOM tells kernel to use random access pattern.
            // Same validity guarantees as above.
            unsafe {
                libc::madvise(
                    mmap.as_ptr() as *mut libc::c_void,
                    mmap.len(),
                    libc::MADV_RANDOM,
                );
            }
            return Some(TSVFile {
                mmap,
                data_start: idx_ds,
                offsets: idx_offsets,
                total_lines,
                fsize,
                mtime,
            });
        }

        let offsets = build_offsets(&mmap);
        let total_lines = offsets.len();

        // SAFETY: Same as above — advisory madvise hint.
        unsafe {
            libc::madvise(
                mmap.as_ptr() as *mut libc::c_void,
                mmap.len(),
                libc::MADV_RANDOM,
            );
        }

        save_idx(&idx_path, fsize, mtime, data_start, &offsets);

        Some(TSVFile {
            mmap,
            data_start,
            offsets,
            total_lines,
            fsize,
            mtime,
        })
    }

    pub fn get_line(&self, idx: usize) -> Option<(&str, &str)> {
        if idx >= self.total_lines {
            return None;
        }
        let s = self.offsets[idx];
        let e = if idx + 1 < self.total_lines {
            self.offsets[idx + 1]
        } else {
            self.mmap.len()
        };
        let line = std::str::from_utf8(&self.mmap[s..e]).ok()?;
        let line = line.trim_end_matches('\n').trim_end_matches('\r');
        let addr = if let Some(tab) = line.find('\t') {
            &line[..tab]
        } else {
            line
        };
        Some((line, addr))
    }

    pub fn count_valid(&self, ncpu: usize) -> u64 {
        let chunk = self.total_lines.div_ceil(ncpu);
        let mut total = 0u64;
        let mut handles = Vec::new();

        for t in 0..ncpu {
            let from = t * chunk;
            let to = std::cmp::min(from + chunk, self.total_lines);
            if from >= self.total_lines {
                break;
            }
            let offsets = self.offsets.clone();
            let mmap = self.mmap.clone();
            handles.push(std::thread::spawn(move || {
                let mut n = 0u64;
                for li in from..to {
                    let s = offsets[li];
                    let e = if li + 1 < offsets.len() {
                        offsets[li + 1]
                    } else {
                        mmap.len()
                    };
                    let line = std::str::from_utf8(&mmap[s..e]).unwrap_or("");
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
            }));
        }

        for h in handles {
            total += h.join().unwrap_or(0);
        }
        total
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn create_tsv(content: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn test_tsv_open_simple() {
        let f = create_tsv("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n");
        let tsv = TSVFile::open(f.path().to_str().unwrap()).unwrap();
        assert_eq!(tsv.total_lines, 1);
        assert!(tsv.data_start <= tsv.mmap.len());
    }

    #[test]
    fn test_tsv_open_with_header() {
        let f = create_tsv("address\tbalance\n1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n");
        let tsv = TSVFile::open(f.path().to_str().unwrap()).unwrap();
        assert!(tsv.data_start > 0);
    }

    #[test]
    fn test_tsv_open_empty() {
        let f = create_tsv("");
        let result = TSVFile::open(f.path().to_str().unwrap());
        assert!(result.is_none());
    }

    #[test]
    fn test_tsv_get_line() {
        let f = create_tsv("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n");
        let tsv = TSVFile::open(f.path().to_str().unwrap()).unwrap();
        let result = tsv.get_line(0);
        assert!(result.is_some());
        let (_line, addr) = result.unwrap();
        assert_eq!(addr, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
    }

    #[test]
    fn test_tsv_get_line_out_of_bounds() {
        let f = create_tsv("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n");
        let tsv = TSVFile::open(f.path().to_str().unwrap()).unwrap();
        assert!(tsv.get_line(1).is_none());
    }

    #[test]
    fn test_tsv_get_line_with_tab() {
        let f = create_tsv("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\t100\n");
        let tsv = TSVFile::open(f.path().to_str().unwrap()).unwrap();
        let (_, addr) = tsv.get_line(0).unwrap();
        assert_eq!(addr, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
    }

    #[test]
    fn test_tsv_count_valid() {
        let f = create_tsv("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n1invalid\n");
        let tsv = TSVFile::open(f.path().to_str().unwrap()).unwrap();
        let count = tsv.count_valid(1);
        assert_eq!(count, 1);
    }

    #[test]
    fn test_tsv_multiple_lines() {
        let content = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n1BvBMSEYstWetqTFn5Au4m4SVgH1Mvsw4t\n";
        let f = create_tsv(content);
        let tsv = TSVFile::open(f.path().to_str().unwrap()).unwrap();
        assert_eq!(tsv.total_lines, 2);
        assert!(tsv.get_line(0).is_some());
        assert!(tsv.get_line(1).is_some());
        assert!(tsv.get_line(2).is_none());
    }

    #[test]
    fn test_tsv_idx_cache() {
        let content = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n1BvBMSEYstWetqTFn5Au4m4SVgH1Mvsw4t\n";
        let f = create_tsv(content);
        let path = f.path().to_str().unwrap().to_string();
        let idx_path = format!("{}.idx", path);

        let tsv1 = TSVFile::open(&path).unwrap();
        assert!(std::path::Path::new(&idx_path).exists());

        let tsv2 = TSVFile::open(&path).unwrap();
        assert_eq!(tsv1.total_lines, tsv2.total_lines);
    }
}
