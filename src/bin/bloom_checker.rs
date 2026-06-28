#![allow(clippy::print_literal)]

use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use scannerbtc::bloom::BloomFilter;
use scannerbtc::encoding::is_valid_btc_address;
use scannerbtc::tsv::TSVFile;

const ANSI_RESET: &str = "\x1b[0m";
const ANSI_BOLD: &str = "\x1b[1m";
const ANSI_DIM: &str = "\x1b[2m";
const ANSI_RED: &str = "\x1b[91m";
const ANSI_GREEN: &str = "\x1b[92m";
const ANSI_YELLOW: &str = "\x1b[93m";
const ANSI_CYAN: &str = "\x1b[96m";
const ANSI_MAGENTA: &str = "\x1b[95m";

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

fn _fmt_bytes(n: u64) -> String {
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

struct ThreadWriter {
    tmp_path: String,
    writer: BufWriter<File>,
    count: u64,
}

impl ThreadWriter {
    fn open(base: &str, thread_id: usize) -> Option<Self> {
        let tmp_path = format!("{}.tmp{}", base, thread_id);
        let f = File::create(&tmp_path).ok()?;
        Some(ThreadWriter {
            tmp_path,
            writer: BufWriter::new(f),
            count: 0,
        })
    }

    fn write(&mut self, line: &str) {
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
    let f = File::create(final_path).expect("Cannot create output");
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

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!(
            "\nUsage: {} <addresses.tsv> <addresses.bloom> <missing.tsv>\n",
            args[0]
        );
        eprintln!("  Finds addresses DEFINITELY NOT in the bloom filter.");
        eprintln!("  Uses .idx cache for instant startup on large files.\n");
        std::process::exit(1);
    }

    let tsv_path = &args[1];
    let bloom_path = &args[2];
    let out_path = &args[3];
    let ncpu = num_cpus::get();

    // Banner
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

    // Load bloom
    let mut bloom = match BloomFilter::load(bloom_path) {
        Some(b) => b,
        None => {
            eprintln!("Cannot load bloom filter.");
            std::process::exit(1);
        }
    };

    // Open TSV
    let tsv = match TSVFile::open(tsv_path) {
        Some(t) => t,
        None => {
            eprintln!("Cannot open TSV file.");
            std::process::exit(1);
        }
    };
    println!();

    // For v1/v2: count valid addresses accurately for k computation
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

    // Setup per-thread writers
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

    // Parallel check
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
                                    writer.write(line);
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

    // Progress thread
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
                "\r  [{}{}{}] {} {:.1}%  {}{}{} checked  {}{}{} missing({:.1}%)  {}{}{}  ETA:{}{}{}     ",
                ANSI_GREEN, bar, ANSI_RESET,
                "",
                pct,
                ANSI_CYAN, fmt_num(chk), ANSI_RESET,
                ANSI_RED, fmt_num(mis), ANSI_RESET,
                miss_pct,
                ANSI_YELLOW, fmt_rate(instant), ANSI_RESET,
                ANSI_MAGENTA, eta, ANSI_RESET
            );
            std::io::stdout().flush().ok();

            prev = chk;
            prev_t = now;

            if chk as f64 >= total_lines as f64 * 0.9999 {
                break;
            }
        }
    });

    for h in handles {
        h.join().ok();
    }
    progress.join().ok();

    // Merge outputs
    println!(
        "\n\n{}  ⟳{}  Merging {} output shards...",
        ANSI_YELLOW, ANSI_RESET, ncpu
    );

    let _total_missing = g_missing.load(Ordering::Relaxed);
    let mut writers_guard = writers.lock().unwrap();
    let mut writers_vec: Vec<ThreadWriter> = writers_guard.drain(..).flatten().collect();
    drop(writers_guard);
    merge_outputs(out_path, &mut writers_vec);

    println!("{}  ✔{}  Merged → {}", ANSI_GREEN, ANSI_RESET, out_path);
    println!();

    // Final statistics
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
        "  Est.FPR:  {}{:.4}%{}  (should ≈ bloom's fpp when set matches)",
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
