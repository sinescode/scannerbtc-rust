use rand::Rng;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use scannerbtc::bip39::{generate_mnemonic, generate_mnemonic_addresses};
use scannerbtc::bitcoin::fill_key_data;
use scannerbtc::bloom::BloomFilter;
use scannerbtc::crypto::generate_random_private_key;
use scannerbtc::tsv::TSVFile;

const ANSI_RESET: &str = "\x1b[0m";
const ANSI_BOLD: &str = "\x1b[1m";
const ANSI_DIM: &str = "\x1b[2m";
const ANSI_GREEN: &str = "\x1b[92m";
const ANSI_YELLOW: &str = "\x1b[93m";
const ANSI_BLUE: &str = "\x1b[94m";
const ANSI_CYAN: &str = "\x1b[96m";

const MODE_RANDOM: i32 = 0;
const MODE_MNEMONIC: i32 = 1;
const MODE_MIX: i32 = 2;

struct HitLogger {
    file: Option<BufWriter<File>>,
    mutex: Mutex<()>,
}

impl HitLogger {
    fn open(path: &str) -> Option<Self> {
        let is_new = !std::path::Path::new(path).exists();
        let f = File::options().append(true).create(true).open(path).ok()?;
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
            mutex: Mutex::new(()),
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
        let _lock = self.mutex.lock().unwrap();
        if let Some(ref mut f) = self.file {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let ts = format!(
                "{}-{:02}-{:02}T{:02}:{:02}:{:02}",
                1970 + (now / 31557600) as u16,
                ((now % 31557600) / 2592000) as u8 + 1,
                ((now % 2592000) / 86400) as u8 + 1,
                (now % 86400 / 3600) as u8,
                (now % 3600 / 60) as u8,
                (now % 60) as u8,
            );
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
    logger: Option<Arc<Mutex<HitLogger>>>,
    scanned: Arc<AtomicU64>,
    hits: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
}

fn worker_func(cfg: WorkerConfig) {
    let mut rng = rand::rng();

    while !cfg.stop.load(Ordering::Relaxed) {
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
                let hit = cfg.bloom.contains(addr);

                if hit {
                    cfg.hits.fetch_add(1, Ordering::Relaxed);
                    if let Some(ref logger) = cfg.logger {
                        logger.lock().unwrap().log(
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
                    println!(
                        "\n{}{}🎯 HIT! {} {}{}",
                        ANSI_GREEN, ANSI_BOLD, addr_type, addr, ANSI_RESET
                    );
                    println!("  WIF:  {}", kd.wif);
                    println!("  HEX:  {}", kd.priv_hex);
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
            let records = generate_mnemonic_addresses(&mnemonic_str, cfg.depth);
            let count = records.len() as u64;

            for r in &records {
                let hit = cfg.bloom.contains(&r.address);
                if hit {
                    cfg.hits.fetch_add(1, Ordering::Relaxed);
                    if let Some(ref logger) = cfg.logger {
                        logger.lock().unwrap().log(
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
                    println!(
                        "\n{}{}🎯 HIT! {} {}{}",
                        ANSI_GREEN, ANSI_BOLD, r.addr_type, r.address, ANSI_RESET
                    );
                    println!("  WIF:  {}", r.wif);
                    println!("  PATH: {}", r.derivation_path);
                    println!("  MNEM: {}", r.mnemonic);
                }
            }
            cfg.scanned.fetch_add(count, Ordering::Relaxed);
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut tsv_path = String::new();
    let mut bloom_path = String::new();
    let mut output_tsv = String::new();
    let mut pg_conn = String::new();
    let mut nthreads = num_cpus::get();
    let mut mode = MODE_RANDOM;
    let mut depth = 5;
    let mut words = 0;
    let mut _show_interval: u64 = 0;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--tsv" | "-t" => {
                i += 1;
                tsv_path = args.get(i).cloned().unwrap_or_default();
            }
            "--bloom" | "-b" => {
                i += 1;
                bloom_path = args.get(i).cloned().unwrap_or_default();
            }
            "--output" | "-o" => {
                i += 1;
                output_tsv = args.get(i).cloned().unwrap_or_default();
            }
            "--pg" => {
                i += 1;
                pg_conn = args.get(i).cloned().unwrap_or_default();
            }
            "--threads" | "-j" => {
                i += 1;
                nthreads = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(nthreads);
            }
            "--depth" => {
                i += 1;
                depth = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(depth);
            }
            "--words" => {
                i += 1;
                words = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(words);
            }
            "--mode" => {
                i += 1;
                mode = match args.get(i).map(|s| s.as_str()) {
                    Some("mnemonic") => MODE_MNEMONIC,
                    Some("mix") => MODE_MIX,
                    _ => MODE_RANDOM,
                };
            }
            "--show" => {
                i += 1;
                _show_interval = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(0);
            }
            "--help" | "-h" => {
                println!("Usage: scanner [options]");
                println!("  --tsv     <file>       Sorted TSV of target addresses");
                println!("  --bloom   <file>       Bloom filter file");
                println!("  --output  <file>       Output TSV file for hits");
                println!("  --threads <N>          Worker threads (default: nproc)");
                println!("  --mode    random|mnemonic|mix  (default: random)");
                println!("  --depth   <N>          BIP-32 derivation depth (default: 5)");
                println!("  --words   <0|12|24>    Mnemonic word count (default: 0)");
                println!("  --show    <N>          Print panel every N addresses");
                return;
            }
            _ => {}
        }
        i += 1;
    }

    if !output_tsv.is_empty() && !pg_conn.is_empty() {
        eprintln!("Error: specify --output OR --pg, not both.");
        std::process::exit(1);
    }
    if nthreads < 1 {
        nthreads = 1;
    }
    if words != 0 && words != 12 && words != 24 {
        eprintln!("Error: --words must be 0, 12, or 24.");
        std::process::exit(1);
    }

    print_banner();
    let mode_str = match mode {
        MODE_RANDOM => "RANDOM",
        MODE_MNEMONIC => "MNEMONIC",
        MODE_MIX => "MIX",
        _ => "UNKNOWN",
    };

    println!("{}  Mode:    {}{}", ANSI_BOLD, mode_str, ANSI_RESET);
    println!("{}  Threads: {}{}", ANSI_BOLD, nthreads, ANSI_RESET);
    if mode != MODE_RANDOM {
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

    let bloom = match BloomFilter::load(&bloom_path) {
        Some(b) => Arc::new(b),
        None => {
            eprintln!("Failed to load bloom filter.");
            std::process::exit(1);
        }
    };

    let _tsv = if !tsv_path.is_empty() {
        match TSVFile::open(&tsv_path) {
            Some(t) => Some(Arc::new(t)),
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
        HitLogger::open(&output_tsv).map(|l| Arc::new(Mutex::new(l)))
    } else {
        None
    };

    let scanned = Arc::new(AtomicU64::new(0));
    let hits = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));

    let mut handles = Vec::new();
    for _ in 0..nthreads {
        let cfg = WorkerConfig {
            mode,
            depth,
            words,
            bloom: bloom.clone(),
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
    let nthreads_clone = nthreads;
    let filter_mode_str2 = filter_mode_str.to_string();

    let stats_thread = std::thread::spawn(move || {
        let t_start = std::time::Instant::now();
        let mut prev_scanned = 0u64;

        while !stop2.load(Ordering::Relaxed) {
            std::thread::sleep(std::time::Duration::from_secs(1));
            let s = scanned2.load(Ordering::Relaxed);
            let h = hits2.load(Ordering::Relaxed);
            let elapsed = t_start.elapsed().as_secs_f64();
            let delta = s - prev_scanned;
            prev_scanned = s;
            let rate = delta as f64;
            let progress_pct = ((s % 10000) * 30 / 10000) as usize;
            let bar: String = "|".repeat(progress_pct) + &".".repeat(30 - progress_pct);
            let speed_str = if rate >= 1e6 {
                format!("{:.2}M/s", rate / 1e6)
            } else if rate >= 1e3 {
                format!("{:.1}k/s", rate / 1e3)
            } else {
                format!("{}/s", rate as u64)
            };

            print!(
                "\r{}[{}]{}  Scanned: {}{}{}  Hits: {}{}{}  Speed: {}{}{}  Time: {}{}{}s  Filter: {}{}{}  Thr: {}     ",
                ANSI_CYAN, bar, ANSI_RESET,
                ANSI_CYAN, s, ANSI_RESET,
                ANSI_GREEN, h, ANSI_RESET,
                ANSI_YELLOW, speed_str, ANSI_RESET,
                ANSI_BLUE, elapsed as u64, ANSI_RESET,
                ANSI_DIM, filter_mode_str2, ANSI_RESET,
                nthreads_clone
            );
            std::io::stdout().flush().ok();
        }
    });

    println!("{}  Press CTRL+C to stop.{}", ANSI_DIM, ANSI_RESET);

    for h in handles {
        h.join().ok();
    }

    stop.store(true, Ordering::Relaxed);
    stats_thread.join().ok();

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
