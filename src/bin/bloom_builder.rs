#![allow(clippy::print_literal)]

use std::fs::File;
use std::io::{BufWriter, Write};
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;

use scannerbtc::bloom::{build_offsets, count_valid_addresses, next_pow2};
use scannerbtc::encoding::is_valid_btc_address;
use scannerbtc::siphash::{siphash13_double, SipPair};

const ANSI_RESET: &str = "\x1b[0m";
const ANSI_BOLD: &str = "\x1b[1m";
const ANSI_DIM: &str = "\x1b[2m";
const ANSI_RED: &str = "\x1b[91m";
const ANSI_GREEN: &str = "\x1b[92m";
const ANSI_YELLOW: &str = "\x1b[93m";
const ANSI_CYAN: &str = "\x1b[96m";

fn fmt_num(n: u64) -> String {
    let s = n.to_string();
    let m = s.len() % 3;
    let mut r = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (i - m) % 3 == 0 {
            r.push(',');
        }
        r.push(c);
    }
    r
}

fn fmt_bytes(n: u64) -> String {
    let units = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < 4 {
        v /= 1024.0;
        i += 1;
    }
    format!("{:.2} {}", v, units[i])
}

struct BloomFilterBuilder {
    bitmap: Vec<AtomicU8>,
    bitmap_bytes: u64,
    bitmap_bits: u64,
    mask: u64,
    k_num: i32,
    k0: u64,
    k1: u64,
}

impl BloomFilterBuilder {
    fn init(expected_items: u64, fpp: f64) -> Self {
        let ln2 = core::f64::consts::LN_2;
        let m_f = -(expected_items as f64) * fpp.ln() / (ln2 * ln2);
        let m = (m_f.ceil() as u64).max(1);
        let bytes_raw = m.div_ceil(8);
        let bitmap_bytes = next_pow2(bytes_raw);
        let bitmap_bits = bitmap_bytes * 8;
        let mask = bitmap_bits - 1;
        let k_f = (bitmap_bits as f64 / expected_items as f64) * ln2;
        let k_num = (k_f.floor().max(1.0)) as i32;

        let bitmap = (0..bitmap_bytes).map(|_| AtomicU8::new(0)).collect();

        BloomFilterBuilder {
            bitmap,
            bitmap_bytes,
            bitmap_bits,
            mask,
            k_num,
            k0: 0,
            k1: 0,
        }
    }

    #[inline]
    fn add(&self, item: &[u8]) {
        let SipPair { h1, h2 } = siphash13_double(item, self.k0, self.k1);
        for i in 0..self.k_num {
            let bit = h1.wrapping_add((i as u64).wrapping_mul(h2)) & self.mask;
            let byte_idx = (bit >> 3) as usize;
            let bmask = 1u8 << (bit & 7);
            self.bitmap[byte_idx].fetch_or(bmask, Ordering::Relaxed);
        }
    }

    fn save(&self, path: &str) {
        let f = File::create(path).expect("Cannot open output");
        let mut writer = BufWriter::new(f);
        writer.write_all(&[3]).unwrap(); // version 3
        writer.write_all(&self.k0.to_le_bytes()).unwrap();
        writer.write_all(&self.k1.to_le_bytes()).unwrap();
        writer
            .write_all(&(self.k_num as u32).to_le_bytes())
            .unwrap();
        writer.write_all(&self.bitmap_bytes.to_le_bytes()).unwrap();
        for i in 0..self.bitmap_bytes as usize {
            let v = self.bitmap[i].load(Ordering::Relaxed);
            writer.write_all(&[v]).unwrap();
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!(
            "Usage: {} <input.tsv> <output.bloom> [expected=0] [fpp=0.001]",
            args[0]
        );
        std::process::exit(1);
    }

    let tsv_path = &args[1];
    let bloom_path = &args[2];
    let expected: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(0);
    let fpp: f64 = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(0.001);

    let ncpu = num_cpus::get();

    println!();
    println!(
        "{}  ╔═══════════════════════════════════════════════════════╗",
        ANSI_CYAN
    );
    println!("  ║   Bitcoin Bloom Builder  v3  ·  Rust Edition          ║");
    println!(
        "  ╚═══════════════════════════════════════════════════════╝{}",
        ANSI_RESET
    );
    println!();
    println!("{}  Input:   {}{}", ANSI_BOLD, tsv_path, ANSI_RESET);
    println!("{}  Output:  {}{}", ANSI_BOLD, bloom_path, ANSI_RESET);
    println!("{}  FPP:     {}{}", ANSI_BOLD, fpp, ANSI_RESET);
    println!("{}  Threads: {}{}", ANSI_BOLD, ncpu, ANSI_RESET);
    println!();

    // Memory-map
    println!("{}  ⟳{}  Mapping {}...", ANSI_YELLOW, ANSI_RESET, tsv_path);
    let mmap = Arc::new(unsafe {
        let file = std::fs::File::open(tsv_path).expect("Cannot open TSV");
        memmap2::Mmap::map(&file).expect("Cannot mmap TSV")
    });
    println!(
        "{}  ✔{}  {}",
        ANSI_GREEN,
        ANSI_RESET,
        fmt_bytes(mmap.len() as u64)
    );
    println!();

    // Build line index
    println!("{}  ⟳{}  Building line index...", ANSI_YELLOW, ANSI_RESET);
    let t0 = std::time::Instant::now();
    let offsets = build_offsets(&mmap);
    let idx_s = t0.elapsed().as_secs_f64();

    // Detect header
    let mut has_header = false;
    let mut start_idx = 0;
    if !offsets.is_empty() {
        let e0 = if offsets.len() > 1 {
            offsets[1]
        } else {
            mmap.len()
        };
        let first_line = std::str::from_utf8(&mmap[..e0]).unwrap_or("");
        let first_line = first_line.trim_end_matches('\n').trim_end_matches('\r');
        let tok = if let Some(tab) = first_line.find('\t') {
            &first_line[..tab]
        } else {
            first_line
        };
        if !is_valid_btc_address(tok) {
            has_header = true;
            start_idx = 1;
        }
    }
    let header_str = if has_header { " (header skipped)" } else { "" };
    println!(
        "{}  ✔{}  {} lines{} in {:.2}s",
        ANSI_GREEN,
        ANSI_RESET,
        fmt_num(offsets.len() as u64),
        header_str,
        idx_s
    );
    println!();

    // Count valid addresses
    let mut expected = expected;
    if expected == 0 {
        println!(
            "{}  ⟳{}  Counting valid addresses ({} threads)...",
            ANSI_YELLOW, ANSI_RESET, ncpu
        );
        let tc0 = std::time::Instant::now();
        let total_work = offsets.len() - start_idx;
        let chunk = total_work.div_ceil(ncpu);
        let mut handles = Vec::new();

        for i in 0..ncpu {
            let from = start_idx + i * chunk;
            let to = std::cmp::min(from + chunk, offsets.len());
            if from >= offsets.len() {
                break;
            }
            let offsets_clone = offsets.clone();
            let mmap_clone = mmap.clone();
            handles.push(std::thread::spawn(move || {
                count_valid_addresses(&mmap_clone, &offsets_clone, from, to)
            }));
        }

        for h in handles {
            expected += h.join().unwrap_or(0);
        }
        let tc_s = tc0.elapsed().as_secs_f64();
        println!(
            "{}  ✔{}  {} valid addresses in {:.2}s",
            ANSI_GREEN,
            ANSI_RESET,
            fmt_num(expected),
            tc_s
        );
        println!();
    }

    if expected == 0 {
        eprintln!("No valid addresses found");
        std::process::exit(1);
    }

    // Allocate bloom filter
    let bloom = BloomFilterBuilder::init(expected, fpp);
    println!("{}  Bloom filter:{}", ANSI_BOLD, ANSI_RESET);
    println!("    k_num:      {}{}{}", ANSI_CYAN, bloom.k_num, ANSI_RESET);
    println!(
        "    bits:       {}{} (power-of-2 → fast modulo-free lookup){}",
        ANSI_CYAN,
        fmt_num(bloom.bitmap_bits),
        ANSI_RESET
    );
    println!(
        "    size:       {}{}{}",
        ANSI_CYAN,
        fmt_bytes(bloom.bitmap_bytes),
        ANSI_RESET
    );
    println!("    seeds:      {}k0=0 k1=0{}", ANSI_CYAN, ANSI_RESET);
    println!();

    // Parallel insertion
    println!(
        "{}  ⟳{}  Inserting {} addresses ({} threads)...",
        ANSI_YELLOW,
        ANSI_RESET,
        fmt_num(expected),
        ncpu
    );

    let total_work = offsets.len() - start_idx;
    let chunk = total_work.div_ceil(ncpu);
    let inserted = Arc::new(AtomicU64::new(0));
    let ti0 = std::time::Instant::now();

    let bloom = Arc::new(bloom);

    let mut handles = Vec::new();
    for i in 0..ncpu {
        let from = start_idx + i * chunk;
        let to = std::cmp::min(from + chunk, offsets.len());
        if from >= offsets.len() {
            break;
        }
        let offsets_clone = offsets.clone();
        let mmap_clone = mmap.clone();
        let inserted_clone = inserted.clone();
        let bloom_clone = bloom.clone();

        handles.push(std::thread::spawn(move || {
            let mut local = 0u64;
            for li in from..to {
                let s = offsets_clone[li];
                let e = if li + 1 < offsets_clone.len() {
                    offsets_clone[li + 1]
                } else {
                    mmap_clone.len()
                };
                let line = std::str::from_utf8(&mmap_clone[s..e]).unwrap_or("");
                let line = line.trim_end_matches('\n').trim_end_matches('\r');
                let addr = if let Some(tab) = line.find('\t') {
                    &line[..tab]
                } else {
                    line
                };
                if is_valid_btc_address(addr) {
                    bloom_clone.add(addr.as_bytes());
                    local += 1;
                    if local % 1_000_000 == 0 {
                        inserted_clone.fetch_add(local, Ordering::Relaxed);
                        local = 0;
                    }
                }
            }
            inserted_clone.fetch_add(local, Ordering::Relaxed);
        }));
    }

    // Progress thread
    let inserted_clone = inserted.clone();
    let progress = std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_millis(250));
        let ins = inserted_clone.load(Ordering::Relaxed);
        let el = ti0.elapsed().as_secs_f64();
        let rate = if el > 0.0 { ins as f64 / el / 1e6 } else { 0.0 };
        let pct = if expected > 0 {
            100.0 * ins as f64 / expected as f64
        } else {
            0.0
        };
        let bar_len = (pct * 0.4) as usize;
        let bar: String = "#".repeat(bar_len) + &".".repeat(40 - bar_len);
        print!(
            "\r  [{}{}{}{} ] {}{:.1}% {} {}/{} {} {:.2}M/s{}     ",
            ANSI_GREEN,
            bar,
            ANSI_RESET,
            "",
            ANSI_RESET,
            pct,
            ANSI_CYAN,
            fmt_num(ins),
            fmt_num(expected),
            ANSI_YELLOW,
            rate,
            ANSI_RESET
        );
        std::io::stdout().flush().ok();
        if ins as f64 >= expected as f64 * 0.9999 {
            break;
        }
    });

    for h in handles {
        h.join().ok();
    }
    progress.join().ok();

    let final_ins = inserted.load(Ordering::Relaxed);
    let ti_s = ti0.elapsed().as_secs_f64();
    println!(
        "\r  {}✔{}  {} inserted in {:.2}s ({:.2} M/s)",
        ANSI_GREEN,
        ANSI_RESET,
        fmt_num(final_ins),
        ti_s,
        final_ins as f64 / ti_s / 1e6
    );
    println!();

    // Save
    println!("{}  ⟳{}  Saving...", ANSI_YELLOW, ANSI_RESET);
    bloom.save(bloom_path);
    let file_size = std::fs::metadata(bloom_path).map(|m| m.len()).unwrap_or(0);
    println!(
        "{}  ✔{}  {}  ({})  {}v3 format — k_num stored{}",
        ANSI_GREEN,
        ANSI_RESET,
        bloom_path,
        fmt_bytes(file_size),
        ANSI_DIM,
        ANSI_RESET
    );
    println!();

    // Self-test
    println!("{}  ⟳{}  Self-test...", ANSI_YELLOW, ANSI_RESET);
    let mut checked_st = 0;
    let mut ok = true;
    for li in start_idx..offsets.len() {
        if checked_st >= 10 {
            break;
        }
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
        if !is_valid_btc_address(addr) {
            continue;
        }
        let SipPair { h1, h2 } = siphash13_double(addr.as_bytes(), bloom.k0, bloom.k1);
        let mut present = true;
        for i in 0..bloom.k_num {
            let bit = h1.wrapping_add((i as u64).wrapping_mul(h2)) & bloom.mask;
            if bloom.bitmap[(bit >> 3) as usize].load(Ordering::Relaxed) & (1u8 << (bit & 7)) == 0 {
                present = false;
                break;
            }
        }
        let mark = if present {
            format!("{}✔{}", ANSI_GREEN, ANSI_RESET)
        } else {
            format!("{}✘{}", ANSI_RED, ANSI_RESET)
        };
        println!("    {}  {}", mark, addr);
        if !present {
            ok = false;
        }
        checked_st += 1;
    }
    println!();
    if ok && checked_st > 0 {
        println!("{}  ✔ All self-checks passed{}", ANSI_GREEN, ANSI_RESET);
    } else {
        println!("{}  ✘ SELF-TEST FAILED{}", ANSI_RED, ANSI_RESET);
    }

    // Summary
    println!();
    println!("{}", "=".repeat(60));
    println!("{}  Summary{}", ANSI_BOLD, ANSI_RESET);
    println!(
        "  Addresses: {}{}{}",
        ANSI_CYAN,
        fmt_num(final_ins),
        ANSI_RESET
    );
    println!(
        "  Bloom:     {}{}{}  (k={}, fpp≈{})",
        ANSI_CYAN,
        fmt_bytes(bloom.bitmap_bytes),
        ANSI_RESET,
        bloom.k_num,
        fpp
    );
    println!("  Format:    v3 (k_num stored — no guesswork needed)");
    println!(
        "  Speed:     {}{:.2}M addr/s{}",
        ANSI_YELLOW,
        final_ins as f64 / ti_s / 1e6,
        ANSI_RESET
    );
    println!("{}", "=".repeat(60));
    println!();

    std::process::exit(if ok { 0 } else { 1 });
}
