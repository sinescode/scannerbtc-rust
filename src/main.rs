use clap::{Parser, Subcommand};
use rand::Rng;
use rand::RngCore;
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use scannerbtc::bip39::{generate_mnemonic, generate_mnemonic_addresses};
use scannerbtc::bitcoin::fill_key_data;
use scannerbtc::bloom::{build_offsets, count_valid_addresses, next_pow2, BloomFilter};
use scannerbtc::crypto::generate_random_private_key;
use scannerbtc::encoding::is_valid_btc_address;
use scannerbtc::siphash::{siphash13_double, SipPair};
use scannerbtc::tsv::TSVFile;

const ANSI_RESET: &str = "\x1b[0m";
const ANSI_BOLD: &str = "\x1b[1m";
const ANSI_DIM: &str = "\x1b[2m";
const ANSI_RED: &str = "\x1b[91m";
const ANSI_GREEN: &str = "\x1b[92m";
const ANSI_YELLOW: &str = "\x1b[93m";
const ANSI_BLUE: &str = "\x1b[94m";
const ANSI_CYAN: &str = "\x1b[96m";
const ANSI_MAGENTA: &str = "\x1b[95m";

// ─── Formatting helpers ──────────────────────────────────────────────────────

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

fn fmt_rate(r: f64) -> String {
    if r >= 1e6 {
        format!("{:.2}M/s", r / 1e6)
    } else if r >= 1e3 {
        format!("{:.1}k/s", r / 1e3)
    } else {
        format!("{}/s", r as u64)
    }
}

/// Format Unix timestamp as ISO 8601 UTC string (YYYY-MM-DDTHH:MM:SS).
fn format_timestamp(secs: u64) -> String {
    // Simple calendar math for UTC
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Days since epoch to year/month/day
    // Using a simple algorithm that handles leap years
    let mut y = 1970u32;
    let mut remaining = days;
    loop {
        let days_in_year = if is_leap_year(y) { 366 } else { 365 };
        if remaining < days_in_year as u64 {
            break;
        }
        remaining -= days_in_year as u64;
        y += 1;
    }

    let month_days = [
        31,
        if is_leap_year(y) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut m = 1u32;
    for &md in &month_days {
        if remaining < md as u64 {
            break;
        }
        remaining -= md as u64;
        m += 1;
    }
    let d = remaining + 1;

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        y, m, d, hours, minutes, seconds
    )
}

fn is_leap_year(y: u32) -> bool {
    (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)
}

// ─── CLI ─────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "btc-scanner",
    version,
    about = "Bitcoin Address Scanner — Rust"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Build a Bloom filter from a sorted TSV of Bitcoin addresses
    Build {
        /// Input TSV file (sorted, one address per line)
        input: String,
        /// Output Bloom filter file
        output: String,
        /// Expected number of items (0 = auto-count)
        #[arg(short, long, default_value_t = 0)]
        expected: u64,
        /// False positive probability (e.g. 0.001 = 0.1%)
        #[arg(short, long, default_value_t = 0.001)]
        fpp: f64,
    },

    /// Scan for matching Bitcoin addresses
    Scan {
        /// Sorted TSV of target addresses
        #[arg(short, long)]
        tsv: Option<String>,
        /// Bloom filter file
        #[arg(short, long)]
        bloom: Option<String>,
        /// Output TSV file for hits
        #[arg(short, long)]
        output: Option<String>,
        /// Worker threads
        #[arg(short, long, default_value_t = num_cpus::get())]
        threads: usize,
        /// Key generation mode: random, mnemonic, mix
        #[arg(long, default_value = "random")]
        mode: String,
        /// BIP-32 derivation depth per path
        #[arg(long, default_value_t = 5)]
        depth: usize,
        /// Mnemonic word count: 0 (random 12/24), 12, or 24
        #[arg(long, default_value_t = 0)]
        words: usize,
    },

    /// Check which addresses from a TSV are missing from a Bloom filter
    Check {
        /// Sorted TSV of addresses
        tsv: String,
        /// Bloom filter file
        bloom: String,
        /// Output file for missing addresses
        output: String,
    },
}

// ─── Build subcommand ────────────────────────────────────────────────────────

struct BloomFilterBuilder {
    bitmap: Vec<std::sync::atomic::AtomicU8>,
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

        let bitmap = (0..bitmap_bytes)
            .map(|_| std::sync::atomic::AtomicU8::new(0))
            .collect();

        // Randomize k0/k1 for security (prevents preimage attacks on Bloom filter)
        let mut k0_bytes = [0u8; 8];
        let mut k1_bytes = [0u8; 8];
        rand::rng().fill_bytes(&mut k0_bytes);
        rand::rng().fill_bytes(&mut k1_bytes);

        BloomFilterBuilder {
            bitmap,
            bitmap_bytes,
            bitmap_bits,
            mask,
            k_num,
            k0: u64::from_le_bytes(k0_bytes),
            k1: u64::from_le_bytes(k1_bytes),
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

    fn save(&self, path: &str) -> std::io::Result<()> {
        let f = File::create(path)?;
        let mut writer = BufWriter::new(f);
        writer.write_all(&[3])?;
        writer.write_all(&self.k0.to_le_bytes())?;
        writer.write_all(&self.k1.to_le_bytes())?;
        writer.write_all(&(self.k_num as u32).to_le_bytes())?;
        writer.write_all(&self.bitmap_bytes.to_le_bytes())?;
        let mut buf = Vec::with_capacity(self.bitmap_bytes as usize);
        for i in 0..self.bitmap_bytes as usize {
            buf.push(self.bitmap[i].load(Ordering::Relaxed));
        }
        writer.write_all(&buf)?;
        Ok(())
    }
}

#[allow(clippy::print_literal)]
fn cmd_build(input: &str, output: &str, expected: u64, fpp: f64) {
    // Validate inputs
    if input.is_empty() {
        eprintln!("Error: input file path is empty");
        std::process::exit(1);
    }
    if output.is_empty() {
        eprintln!("Error: output file path is empty");
        std::process::exit(1);
    }
    if !std::path::Path::new(input).exists() {
        eprintln!("Error: input file does not exist: {}", input);
        std::process::exit(1);
    }
    if fpp <= 0.0 || fpp >= 1.0 {
        eprintln!("Error: --fpp must be between 0 and 1 (exclusive)");
        std::process::exit(1);
    }

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
    println!("{}  Input:   {}{}", ANSI_BOLD, input, ANSI_RESET);
    println!("{}  Output:  {}{}", ANSI_BOLD, output, ANSI_RESET);
    println!("{}  FPP:     {}{}", ANSI_BOLD, fpp, ANSI_RESET);
    println!("{}  Threads: {}{}", ANSI_BOLD, ncpu, ANSI_RESET);
    println!();

    println!("{}  ⟳{}  Mapping {}...", ANSI_YELLOW, ANSI_RESET, input);
    let mmap = Arc::new({
        let file = File::open(input).unwrap_or_else(|e| {
            eprintln!("Cannot open TSV: {}", e);
            std::process::exit(1);
        });
        unsafe {
            memmap2::Mmap::map(&file).unwrap_or_else(|e| {
                eprintln!("Cannot mmap TSV: {}", e);
                std::process::exit(1);
            })
        }
    });
    println!(
        "{}  ✔{}  {}",
        ANSI_GREEN,
        ANSI_RESET,
        fmt_bytes(mmap.len() as u64)
    );
    println!();

    println!("{}  ⟳{}  Building line index...", ANSI_YELLOW, ANSI_RESET);
    let t0 = std::time::Instant::now();
    let offsets = build_offsets(&mmap);
    let idx_s = t0.elapsed().as_secs_f64();

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

    let bloom = BloomFilterBuilder::init(expected, fpp);
    println!("{}  Bloom filter:{}", ANSI_BOLD, ANSI_RESET);
    println!("    k_num:      {}{}{}", ANSI_CYAN, bloom.k_num, ANSI_RESET);
    println!(
        "    bits:       {}{} (power-of-2){}",
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
    println!(
        "    seeds:      {}k0={} k1={}{}",
        ANSI_CYAN, bloom.k0, bloom.k1, ANSI_RESET
    );
    println!();

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
            "\r  [{}{}{}] {}{:.1}% {} {}/{} {} {:.2}M/s{}     ",
            ANSI_GREEN,
            bar,
            ANSI_RESET,
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
        if ins >= expected.saturating_mul(9999) / 10000 {
            break;
        }
    });

    for h in handles {
        if h.join().is_err() {
            eprintln!("Warning: build thread panicked");
        }
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

    println!("{}  ⟳{}  Saving...", ANSI_YELLOW, ANSI_RESET);
    if let Err(e) = bloom.save(output) {
        eprintln!("Failed to save bloom filter: {}", e);
        std::process::exit(1);
    }
    let file_size = std::fs::metadata(output).map(|m| m.len()).unwrap_or(0);
    println!(
        "{}  ✔{}  {}  ({})  {}v3 format — k_num stored{}",
        ANSI_GREEN,
        ANSI_RESET,
        output,
        fmt_bytes(file_size),
        ANSI_DIM,
        ANSI_RESET
    );
    println!();

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
    println!("  Format:    v3 (k_num stored)");
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

// ─── Scan subcommand ─────────────────────────────────────────────────────────

struct HitLogger {
    file: Option<BufWriter<File>>,
}

impl HitLogger {
    fn open(path: &str) -> Option<Self> {
        let is_new = !std::path::Path::new(path).exists();
        let f = File::options().append(true).create(true).mode(0o600).open(path).ok()?;
        let mut writer = BufWriter::new(f);
        if is_new {
            writeln!(
                writer,
                "timestamp\taddress\taddress_type\tprivate_key_wif\tprivate_key_hex\tcompressed_pubkey\txonly_pubkey\tmnemonic\tderivation_path"
            )
            .ok();
        }
        Some(HitLogger {
            file: Some(writer),
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn log(
        &mut self,
        addr: &str,
        addr_type: &str,
        wif: &str,
        priv_hex: &str,
        compressed_pub: &str,
        xonly_pub: &str,
        mnemonic: &str,
        path: &str,
    ) {
        if let Some(ref mut f) = self.file {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let ts = format_timestamp(now);
            writeln!(
                f,
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                ts, addr, addr_type, wif, priv_hex, compressed_pub, xonly_pub, mnemonic, path
            )
            .ok();
        }
    }
}

#[allow(clippy::print_literal)]
fn print_banner() {
    println!(
        "{}{}",
        ANSI_CYAN,
        r#"  ██████╗ ████████╗ ██████╗     ███████╗ ██████╗ █████╗ ███╗  ██╗
  ██╔══██╗╚══██╔══╝██╔════╝     ██╔════╝██╔════╝██╔══██╗████╗ ██║
  ██████╔╝   ██║   ██║          ███████╗██║     ███████║██╔██╗██║
  ██╔══██╗   ██║   ██║          ╚════██║██║     ██╔══██║██║╚████║
  ██████╔╝   ██║   ╚██████╗     ███████║╚██████╗██║  ██║██║ ╚███║
  ╚═════╝    ╚═╝    ╚═════╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚══╝"#
    );
    println!(
        "{}  Bitcoin Address Scanner · Rust · Multi-Thread · Fast\n{}",
        ANSI_DIM, ANSI_RESET
    );
}

struct WorkerConfig {
    mode: i32,
    depth: usize,
    words: usize,
    bloom: Arc<BloomFilter>,
    addr_set: Option<Arc<HashSet<String>>>,
    logger: Option<Arc<Mutex<HitLogger>>>,
    scanned: Arc<AtomicU64>,
    hits: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
}

const MODE_RANDOM: i32 = 0;
const MODE_MNEMONIC: i32 = 1;
const MODE_MIX: i32 = 2;

/// Confirm a Bloom positive with a hash set lookup.
/// Returns true only if the address is found in the TSV (exact match).
fn confirm_with_set(addr_set: &HashSet<String>, addr: &str) -> bool {
    addr_set.contains(addr)
}

fn worker_func(cfg: WorkerConfig) {
    let mut rng = rand::rng();

    while !cfg.stop.load(Ordering::Acquire) {
        let do_mnemonic = match cfg.mode {
            MODE_RANDOM => false,
            MODE_MNEMONIC => true,
            MODE_MIX => rng.random_bool(0.5),
            _ => false,
        };

        if !do_mnemonic {
            let priv_key = generate_random_private_key();
            let kd = match fill_key_data(&priv_key) {
                Some(kd) => kd,
                None => continue,
            };

            let addrs = [
                ("P2PKH", &kd.p2pkh),
                ("P2SH-P2WPKH", &kd.p2sh_p2wpkh),
                ("P2WPKH", &kd.p2wpkh),
                ("P2WSH", &kd.p2wsh),
                ("P2TR", &kd.p2tr),
            ];

            for (addr_type, addr) in &addrs {
                // In hybrid mode: bloom pre-filter → hash set confirm
                // In bloom-only mode: just bloom check (probabilistic)
                let hit = if let Some(ref addr_set) = cfg.addr_set {
                    cfg.bloom.contains(addr) && confirm_with_set(addr_set, addr)
                } else {
                    cfg.bloom.contains(addr)
                };
                if hit {
                    cfg.hits.fetch_add(1, Ordering::Relaxed);
                    if let Some(ref logger) = cfg.logger {
                        if let Ok(mut log) = logger.lock() {
                            log.log(
                                addr,
                                addr_type,
                                &kd.wif,
                                &kd.priv_hex,
                                &kd.compressed_pub_hex,
                                &kd.xonly_pub_hex,
                                "",
                                "random",
                            );
                        }
                    }
                    print!(
                        "\n{}{}🎯 HIT! {} {}{}\n  WIF:  {}\n  HEX:  {}{}",
                        ANSI_GREEN, ANSI_BOLD, addr_type, addr, ANSI_RESET,
                        kd.wif, kd.priv_hex, ANSI_RESET
                    );
                    std::io::stdout().flush().ok();
                }
            }
            cfg.scanned.fetch_add(5, Ordering::Relaxed);
        } else {
            let wc = if cfg.words == 0 {
                if rng.random_bool(0.5) {
                    24
                } else {
                    12
                }
            } else {
                cfg.words
            };
            let mnemonic_str = generate_mnemonic(wc);
            let records = match generate_mnemonic_addresses(&mnemonic_str, cfg.depth) {
                Ok(r) => r,
                Err(_) => continue,
            };
            let count = records.len() as u64;

            for r in &records {
                // In hybrid mode: bloom pre-filter → hash set confirm
                // In bloom-only mode: just bloom check (probabilistic)
                let hit = if let Some(ref addr_set) = cfg.addr_set {
                    cfg.bloom.contains(&r.address) && confirm_with_set(addr_set, &r.address)
                } else {
                    cfg.bloom.contains(&r.address)
                };
                if hit {
                    cfg.hits.fetch_add(1, Ordering::Relaxed);
                    if let Some(ref logger) = cfg.logger {
                        if let Ok(mut log) = logger.lock() {
                            log.log(
                                &r.address,
                                &r.addr_type,
                                &r.wif,
                                &r.priv_hex,
                                &r.compressed_pub_hex,
                                &r.xonly_pub_hex,
                                &r.mnemonic,
                                &r.derivation_path,
                            );
                        }
                    }
                    print!(
                        "\n{}{}🎯 HIT! {} {}{}\n  WIF:  {}\n  PATH: {}\n  MNEM: {}{}",
                        ANSI_GREEN, ANSI_BOLD, r.addr_type, r.address, ANSI_RESET,
                        r.wif, r.derivation_path, r.mnemonic, ANSI_RESET
                    );
                    std::io::stdout().flush().ok();
                }
            }
            cfg.scanned.fetch_add(count, Ordering::Relaxed);
        }
    }
}

fn cmd_scan(
    tsv_path: &Option<String>,
    bloom_path: &Option<String>,
    output_path: &Option<String>,
    nthreads: usize,
    mode: &str,
    depth: usize,
    words: usize,
) {
    let bloom_path = bloom_path.as_deref().unwrap_or("");
    let tsv_path = tsv_path.as_deref().unwrap_or("");
    let output_tsv = output_path.as_deref().unwrap_or("");

    // Validate inputs
    if !bloom_path.is_empty() && !std::path::Path::new(bloom_path).exists() {
        eprintln!("Error: bloom file does not exist: {}", bloom_path);
        std::process::exit(1);
    }
    if !tsv_path.is_empty() && !std::path::Path::new(tsv_path).exists() {
        eprintln!("Error: TSV file does not exist: {}", tsv_path);
        std::process::exit(1);
    }
    if nthreads == 0 {
        eprintln!("Error: --threads must be > 0");
        std::process::exit(1);
    }
    if depth == 0 {
        eprintln!("Error: --depth must be > 0");
        std::process::exit(1);
    }

    let mode_val = match mode {
        "mnemonic" => MODE_MNEMONIC,
        "mix" => MODE_MIX,
        _ => MODE_RANDOM,
    };

    if words != 0 && words != 12 && words != 24 {
        eprintln!("Error: --words must be 0, 12, or 24.");
        std::process::exit(1);
    }

    print_banner();
    let mode_str = match mode_val {
        MODE_RANDOM => "RANDOM",
        MODE_MNEMONIC => "MNEMONIC",
        MODE_MIX => "MIX",
        _ => "UNKNOWN",
    };

    println!("{}  Mode:    {}{}", ANSI_BOLD, mode_str, ANSI_RESET);
    println!("{}  Threads: {}{}", ANSI_BOLD, nthreads, ANSI_RESET);
    if mode_val != MODE_RANDOM {
        let words_str = if words == 0 {
            "random (12 or 24)".to_string()
        } else {
            format!("{}-word mnemonics", words)
        };
        println!("{}  Words:   {}{}", ANSI_BOLD, words_str, ANSI_RESET);
        println!(
            "{}  Depth:   {}{} addresses per BIP path",
            ANSI_BOLD, depth, ANSI_RESET
        );
    }
    if !tsv_path.is_empty() {
        println!("{}  TSV:     {}{}", ANSI_BOLD, tsv_path, ANSI_RESET);
    }
    if !bloom_path.is_empty() {
        println!("{}  Bloom:   {}{}", ANSI_BOLD, bloom_path, ANSI_RESET);
    }

    let filter_mode_str = if !bloom_path.is_empty() && !tsv_path.is_empty() {
        "HYBRID (bloom + exact TSV)"
    } else if !bloom_path.is_empty() {
        "BLOOM ONLY (probabilistic)"
    } else {
        "TSV ONLY (exact, no bloom)"
    };
    println!("{}  Filter:  {}{}", ANSI_BOLD, filter_mode_str, ANSI_RESET);
    if !output_tsv.is_empty() {
        println!("{}  Output:  {}{}", ANSI_BOLD, output_tsv, ANSI_RESET);
    }

    let bloom = match BloomFilter::load(bloom_path) {
        Ok(b) => Arc::new(b),
        Err(e) => {
            eprintln!("Failed to load bloom filter: {}", e);
            std::process::exit(1);
        }
    };

    let addr_set = if !tsv_path.is_empty() {
        match TSVFile::open(tsv_path) {
            Some(t) => {
                const MAX_TSV_LINES: usize = 20_000_000;
                if t.total_lines > MAX_TSV_LINES {
                    eprintln!(
                        "{}  TSV has {} lines — too large for HashSet (max {}). Falling back to bloom-only.{}",
                        ANSI_YELLOW, t.total_lines, MAX_TSV_LINES, ANSI_RESET
                    );
                    None
                } else {
                    let mut set = HashSet::with_capacity(t.total_lines);
                    for i in 0..t.total_lines {
                        if let Some((_, addr)) = t.get_line(i) {
                            if is_valid_btc_address(addr) {
                                set.insert(addr.to_string());
                            }
                        }
                    }
                    Some(Arc::new(set))
                }
            }
            None => {
                eprintln!("Failed to load TSV file.");
                std::process::exit(1);
            }
        }
    } else {
        None
    };

    println!();

    let logger = if !output_tsv.is_empty() {
        HitLogger::open(output_tsv).map(|l| Arc::new(Mutex::new(l)))
    } else {
        None
    };

    let scanned = Arc::new(AtomicU64::new(0));
    let hits = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));

    // Set up Ctrl+C handler for graceful shutdown
    let stop_signal = stop.clone();
    ctrlc::set_handler(move || {
        stop_signal.store(true, Ordering::Release);
    })
    .expect("Error setting Ctrl+C handler");

    let mut handles = Vec::new();
    for _ in 0..nthreads {
        let cfg = WorkerConfig {
            mode: mode_val,
            depth,
            words,
            bloom: bloom.clone(),
            addr_set: addr_set.clone(),
            logger: logger.clone(),
            scanned: scanned.clone(),
            hits: hits.clone(),
            stop: stop.clone(),
        };
        handles.push(std::thread::spawn(move || worker_func(cfg)));
    }

    let scanned2 = scanned.clone();
    let hits2 = hits.clone();
    let stop2 = stop.clone();
    let filter_mode_str2 = filter_mode_str.to_string();

    let stats_thread = std::thread::spawn(move || {
        let t_start = std::time::Instant::now();
        let mut prev_scanned = 0u64;

        while !stop2.load(Ordering::Acquire) {
            std::thread::sleep(std::time::Duration::from_secs(1));
            let s = scanned2.load(Ordering::Relaxed);
            let h = hits2.load(Ordering::Relaxed);
            let elapsed = t_start.elapsed().as_secs_f64();
            let delta = s - prev_scanned;
            prev_scanned = s;
            let rate = delta as f64;
            let progress_pct = ((s % 10000) * 30 / 10000) as usize;
            let bar: String = "|".repeat(progress_pct) + &".".repeat(30 - progress_pct);
            let speed_str = fmt_rate(rate);

            print!(
                "\r{}[{}]{}  Scanned: {}{}{}  Hits: {}{}{}  Speed: {}{}{}  Time: {}{}{}s  Filter: {}{}{}  Thr: {}     ",
                ANSI_CYAN, bar, ANSI_RESET,
                ANSI_CYAN, s, ANSI_RESET,
                ANSI_GREEN, h, ANSI_RESET,
                ANSI_YELLOW, speed_str, ANSI_RESET,
                ANSI_BLUE, elapsed as u64, ANSI_RESET,
                ANSI_DIM, filter_mode_str2, ANSI_RESET,
                nthreads
            );
            std::io::stdout().flush().ok();
        }
    });

    println!("{}  Press CTRL+C to stop.{}", ANSI_DIM, ANSI_RESET);

    for h in handles {
        if h.join().is_err() {
            eprintln!("{}  Worker thread panicked{}", ANSI_YELLOW, ANSI_RESET);
        }
    }

    stop.store(true, Ordering::Release);
    if stats_thread.join().is_err() {
        eprintln!("{}  Stats thread panicked{}", ANSI_YELLOW, ANSI_RESET);
    }

    // Flush stdout before exit
    std::io::stdout().flush().ok();

    let total = scanned.load(Ordering::Relaxed);
    let total_hits = hits.load(Ordering::Relaxed);

    println!("\n\n{}", "=".repeat(60));
    println!("{}  Session Complete{}", ANSI_BOLD, ANSI_RESET);
    println!("  Total Scanned: {}{}{}", ANSI_CYAN, total, ANSI_RESET);
    println!(
        "  Total Hits:    {}{}{}",
        ANSI_GREEN, total_hits, ANSI_RESET
    );
    println!("{}", "=".repeat(60));
}

// ─── Check subcommand ────────────────────────────────────────────────────────

struct ThreadWriter {
    tmp_path: String,
    writer: BufWriter<File>,
    count: u64,
}

impl ThreadWriter {
    fn open(base: &str, thread_id: usize) -> Option<Self> {
        let tmp_path = format!("{}.tmp{}", base, thread_id);
        let f = File::options()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path).ok()?;
        Some(ThreadWriter {
            tmp_path,
            writer: BufWriter::new(f),
            count: 0,
        })
    }

    fn write_line(&mut self, line: &str) {
        writeln!(self.writer, "{}", line).ok();
        self.count += 1;
        if self.count % 500_000 == 0 {
            self.writer.flush().ok();
        }
    }

    fn close(&mut self) {
        self.writer.flush().ok();
    }
}

fn merge_outputs(final_path: &str, writers: &mut [ThreadWriter]) {
    let f = File::create(final_path).unwrap_or_else(|e| {
        eprintln!("Cannot create output: {}", e);
        std::process::exit(1);
    });
    let mut out = BufWriter::new(f);
    writeln!(out, "address\trest").ok();

    for w in writers.iter_mut() {
        w.close();
        let f = File::open(&w.tmp_path).ok();
        if let Some(f) = f {
            let mut reader = BufReader::new(f);
            let mut buf = [0u8; 65536];
            loop {
                let n = reader.read(&mut buf).unwrap_or(0);
                if n == 0 {
                    break;
                }
                out.write_all(&buf[..n]).ok();
            }
        }
        std::fs::remove_file(&w.tmp_path).ok();
    }
    out.flush().ok();
}

#[allow(clippy::print_literal)]
fn cmd_check(tsv_path: &str, bloom_path: &str, out_path: &str) {
    // Validate inputs
    if !std::path::Path::new(tsv_path).exists() {
        eprintln!("Error: TSV file does not exist: {}", tsv_path);
        std::process::exit(1);
    }
    if !std::path::Path::new(bloom_path).exists() {
        eprintln!("Error: bloom file does not exist: {}", bloom_path);
        std::process::exit(1);
    }
    if out_path.is_empty() {
        eprintln!("Error: output file path is empty");
        std::process::exit(1);
    }

    let ncpu = num_cpus::get();

    println!();
    println!(
        "{}  ╔══════════════════════════════════════════════════════╗",
        ANSI_CYAN
    );
    println!("  ║   Bitcoin Bloom Checker  v3  ·  Rust Edition         ║");
    println!(
        "  ╚══════════════════════════════════════════════════════╝{}",
        ANSI_RESET
    );
    println!();
    println!("{}  TSV:     {}{}", ANSI_BOLD, tsv_path, ANSI_RESET);
    println!("{}  Bloom:   {}{}", ANSI_BOLD, bloom_path, ANSI_RESET);
    println!("{}  Output:  {}{}", ANSI_BOLD, out_path, ANSI_RESET);
    println!("{}  Threads: {}{}", ANSI_BOLD, ncpu, ANSI_RESET);
    println!();

    let mut bloom = match BloomFilter::load(bloom_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Cannot load bloom filter: {}", e);
            std::process::exit(1);
        }
    };

    let tsv = match TSVFile::open(tsv_path) {
        Some(t) => t,
        None => {
            eprintln!("Cannot open TSV file.");
            std::process::exit(1);
        }
    };
    println!();

    if bloom.k_num == 0 {
        println!(
            "{}  ⟳{}  Counting valid addresses for k recovery...",
            ANSI_YELLOW, ANSI_RESET
        );
        let n_valid = tsv.count_valid(ncpu);
        bloom.set_k_from_valid_count(n_valid);
    }
    if bloom.k_num <= 0 {
        eprintln!("Cannot determine k_num. Rebuild bloom with new bloom_builder.");
        std::process::exit(1);
    }
    println!();

    let mut writers: Vec<Option<ThreadWriter>> = Vec::new();
    for t in 0..ncpu {
        match ThreadWriter::open(out_path, t) {
            Some(w) => writers.push(Some(w)),
            None => {
                eprintln!("Cannot open temp output for thread {}", t);
                std::process::exit(1);
            }
        }
    }
    let writers = Arc::new(Mutex::new(writers));

    let total_lines = tsv.total_lines;
    let chunk = total_lines.div_ceil(ncpu);

    let g_checked = Arc::new(AtomicU64::new(0));
    let g_missing = Arc::new(AtomicU64::new(0));
    let g_skipped = Arc::new(AtomicU64::new(0));

    let t_start = std::time::Instant::now();
    println!(
        "{}  ⟳ Checking {} lines...{}",
        ANSI_YELLOW,
        fmt_num(total_lines as u64),
        ANSI_RESET
    );

    let bloom_arc = Arc::new(bloom);
    let tsv_arc = Arc::new(tsv);

    let mut handles = Vec::new();
    for t in 0..ncpu {
        let from = t * chunk;
        let to = std::cmp::min(from + chunk, total_lines);
        if from >= total_lines {
            break;
        }

        let bloom_clone = bloom_arc.clone();
        let tsv_clone = tsv_arc.clone();
        let g_checked_clone = g_checked.clone();
        let g_missing_clone = g_missing.clone();
        let g_skipped_clone = g_skipped.clone();
        let writers_clone = writers.clone();

        handles.push(std::thread::spawn(move || {
            let mut local_checked = 0u64;
            let mut local_missing = 0u64;
            let mut local_skipped = 0u64;
            let flush_interval = 65536u64;

            for i in from..to {
                if let Some((line, addr)) = tsv_clone.get_line(i) {
                    if !is_valid_btc_address(addr) {
                        local_skipped += 1;
                    } else {
                        local_checked += 1;
                        if !bloom_clone.contains(addr) {
                            local_missing += 1;
                            if let Ok(mut writers_guard) = writers_clone.lock() {
                                if let Some(Some(writer)) = writers_guard.get_mut(t) {
                                    writer.write_line(line);
                                }
                            }
                        }
                    }
                    if (local_checked + local_skipped) % flush_interval == 0 {
                        g_checked_clone.fetch_add(local_checked, Ordering::Relaxed);
                        g_missing_clone.fetch_add(local_missing, Ordering::Relaxed);
                        g_skipped_clone.fetch_add(local_skipped, Ordering::Relaxed);
                        local_checked = 0;
                        local_missing = 0;
                        local_skipped = 0;
                    }
                }
            }

            g_checked_clone.fetch_add(local_checked, Ordering::Relaxed);
            g_missing_clone.fetch_add(local_missing, Ordering::Relaxed);
            g_skipped_clone.fetch_add(local_skipped, Ordering::Relaxed);
        }));
    }

    let g_checked_clone = g_checked.clone();
    let g_missing_clone = g_missing.clone();
    let t_start_clone = t_start;

    let progress = std::thread::spawn(move || {
        let mut prev = 0u64;
        let mut prev_t = t_start_clone;

        loop {
            std::thread::sleep(std::time::Duration::from_millis(400));
            let chk = g_checked_clone.load(Ordering::Relaxed);
            let mis = g_missing_clone.load(Ordering::Relaxed);
            let now = std::time::Instant::now();
            let elapsed = t_start_clone.elapsed().as_secs_f64();
            let window = prev_t.elapsed().as_secs_f64();
            let rate = if elapsed > 0.0 {
                chk as f64 / elapsed
            } else {
                0.0
            };
            let instant = if window > 0.0 {
                (chk - prev) as f64 / window
            } else {
                rate
            };
            let pct = if total_lines > 0 {
                100.0 * chk as f64 / total_lines as f64
            } else {
                0.0
            };
            let miss_pct = if chk > 0 {
                100.0 * mis as f64 / chk as f64
            } else {
                0.0
            };
            let remaining = if total_lines > chk as usize {
                (total_lines - chk as usize) as f64
            } else {
                0.0
            };
            let eta = if instant > 0.0 && remaining > 0.0 {
                let secs = remaining / instant;
                if secs < 60.0 {
                    format!("{}s", secs as u64)
                } else if secs < 3600.0 {
                    format!("{}m{}s", secs as u64 / 60, secs as u64 % 60)
                } else {
                    format!("{}h{}m", secs as u64 / 3600, secs as u64 % 3600 / 60)
                }
            } else {
                "--".to_string()
            };

            let bar_len = (pct * 0.35) as usize;
            let bar: String = "#".repeat(bar_len) + &".".repeat(35 - bar_len);

            print!(
                "\r  [{}{}{}] {}{:.1}%  {}{}{} checked  {}{}{} missing({:.1}%)  {}{}{}  ETA:{}{}{}     ",
                ANSI_GREEN, bar, ANSI_RESET,
                ANSI_RESET, pct,
                ANSI_CYAN, fmt_num(chk), ANSI_RESET,
                ANSI_RED, fmt_num(mis), ANSI_RESET,
                miss_pct,
                ANSI_YELLOW, fmt_rate(instant), ANSI_RESET,
                ANSI_MAGENTA, eta, ANSI_RESET
            );
            std::io::stdout().flush().ok();

            prev = chk;
            prev_t = now;

            if chk >= (total_lines as u64).saturating_mul(9999) / 10000 {
                break;
            }
        }
    });

    for h in handles {
        h.join().ok();
    }
    progress.join().ok();

    println!(
        "\n\n{}  ⟳{}  Merging {} output shards...",
        ANSI_YELLOW, ANSI_RESET, ncpu
    );

    let _total_missing = g_missing.load(Ordering::Relaxed);
    let mut writers_guard = writers.lock().unwrap_or_else(|poison| poison.into_inner());
    let mut writers_vec: Vec<ThreadWriter> = writers_guard.drain(..).flatten().collect();
    drop(writers_guard);
    merge_outputs(out_path, &mut writers_vec);

    println!("{}  ✔{}  Merged → {}", ANSI_GREEN, ANSI_RESET, out_path);
    println!();

    let elapsed = t_start.elapsed().as_secs_f64();
    let checked = g_checked.load(Ordering::Relaxed);
    let missing = g_missing.load(Ordering::Relaxed);
    let skipped = g_skipped.load(Ordering::Relaxed);
    let miss_pct = if checked > 0 {
        100.0 * missing as f64 / checked as f64
    } else {
        0.0
    };
    let speed = if elapsed > 0.0 {
        checked as f64 / elapsed / 1e6
    } else {
        0.0
    };

    println!("{}", "=".repeat(58));
    println!("{}  Results{}", ANSI_BOLD, ANSI_RESET);
    println!(
        "  Checked:  {}{}{}",
        ANSI_CYAN,
        fmt_num(checked),
        ANSI_RESET
    );
    println!(
        "  Missing:  {}{}{}  ({:.2}% — DEFINITELY absent)",
        ANSI_RED,
        fmt_num(missing),
        ANSI_RESET,
        miss_pct
    );
    println!(
        "  Skipped:  {}{}{} (non-address lines)",
        ANSI_DIM,
        fmt_num(skipped),
        ANSI_RESET
    );
    println!(
        "  Speed:    {}{:.2}M addr/s{}",
        ANSI_YELLOW, speed, ANSI_RESET
    );
    println!("  Time:     {:.2}s", elapsed);
    println!(
        "  Est.FPR:  {}{:.4}%{}  (should ≈ bloom's fpp)",
        ANSI_MAGENTA, miss_pct, ANSI_RESET
    );
    println!("  Output:   {}{}{}", ANSI_GREEN, out_path, ANSI_RESET);
    println!(
        "  k_num:    {}{}",
        bloom_arc.k_num,
        if bloom_arc.pow2 {
            "  [fast pow2 lookup]"
        } else {
            "  [standard modulo]"
        }
    );
    println!("{}", "=".repeat(58));
    println!();
}

// ─── Main ────────────────────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Build {
            input,
            output,
            expected,
            fpp,
        } => cmd_build(&input, &output, expected, fpp),
        Commands::Scan {
            tsv,
            bloom,
            output,
            threads,
            mode,
            depth,
            words,
        } => cmd_scan(&tsv, &bloom, &output, threads, &mode, depth, words),
        Commands::Check { tsv, bloom, output } => cmd_check(&tsv, &bloom, &output),
    }
}
