use std::path::PathBuf;

/// Configuration for the Bitcoin Address Scanner.
///
/// This struct centralizes all configuration options, making it easier to:
/// - Validate configuration before starting
/// - Pass configuration between components
/// - Support configuration files in the future
/// - Test with different configurations
#[derive(Clone, Debug)]
pub struct Config {
    /// Bloom filter file path (optional)
    pub bloom_path: Option<PathBuf>,
    /// TSV file path (optional)
    pub tsv_path: Option<PathBuf>,
    /// Output TSV file path (optional)
    pub output_path: Option<PathBuf>,
    /// PostgreSQL connection string (optional)
    pub pg_conn: Option<String>,
    /// Number of worker threads
    pub threads: usize,
    /// Key generation mode
    pub mode: ScanMode,
    /// BIP-32 derivation depth per path
    pub depth: usize,
    /// Mnemonic word count: 0 (random 12/24), 12, or 24
    pub words: usize,
    /// Show full key panel every N addresses (0 = disabled)
    pub show_interval: u64,
}

/// Key generation mode for the scanner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanMode {
    /// Pure random private keys (fastest)
    Random,
    /// BIP-39 mnemonic only
    Mnemonic,
    /// 50% random + 50% mnemonic
    Mix,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bloom_path: None,
            tsv_path: None,
            output_path: None,
            pg_conn: None,
            threads: num_cpus::get(),
            mode: ScanMode::Random,
            depth: 5,
            words: 0,
            show_interval: 0,
        }
    }
}

impl Config {
    /// Validate the configuration and return errors if invalid.
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Must have at least one filter
        if self.bloom_path.is_none() && self.tsv_path.is_none() {
            return Err(ConfigError::NoFilter);
        }

        // output and pg are mutually exclusive
        if self.output_path.is_some() && self.pg_conn.is_some() {
            return Err(ConfigError::OutputAndPgMutuallyExclusive);
        }

        // Validate words
        if self.words != 0 && self.words != 12 && self.words != 24 {
            return Err(ConfigError::InvalidWordCount(self.words));
        }

        // Validate threads
        if self.threads == 0 {
            return Err(ConfigError::InvalidThreadCount);
        }

        Ok(())
    }

    /// Check if output is configured.
    pub fn has_output(&self) -> bool {
        self.output_path.is_some() || self.pg_conn.is_some()
    }

    /// Get the filter mode description.
    pub fn filter_mode_str(&self) -> &'static str {
        match (self.bloom_path.is_some(), self.tsv_path.is_some()) {
            (true, true) => "HYBRID (bloom + exact TSV)",
            (true, false) => "BLOOM ONLY (probabilistic)",
            (false, true) => "TSV ONLY (exact, no bloom)",
            (false, false) => unreachable!("validated earlier"),
        }
    }
}

/// Configuration errors.
#[derive(Debug)]
pub enum ConfigError {
    NoFilter,
    OutputAndPgMutuallyExclusive,
    InvalidWordCount(usize),
    InvalidThreadCount,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::NoFilter => write!(f, "must provide at least --bloom or --tsv"),
            ConfigError::OutputAndPgMutuallyExclusive => {
                write!(f, "specify --output OR --pg, not both")
            }
            ConfigError::InvalidWordCount(n) => {
                write!(f, "--words must be 0, 12, or 24 (got {})", n)
            }
            ConfigError::InvalidThreadCount => write!(f, "thread count must be > 0"),
        }
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert!(config.validate().is_err()); // No filter
    }

    #[test]
    fn test_valid_config() {
        let config = Config {
            bloom_path: Some(PathBuf::from("test.bloom")),
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_no_filter_error() {
        let config = Config::default();
        assert!(matches!(config.validate(), Err(ConfigError::NoFilter)));
    }

    #[test]
    fn test_output_pg_mutually_exclusive() {
        let config = Config {
            bloom_path: Some(PathBuf::from("test.bloom")),
            output_path: Some(PathBuf::from("hits.tsv")),
            pg_conn: Some("postgresql://localhost/test".to_string()),
            ..Default::default()
        };
        assert!(matches!(
            config.validate(),
            Err(ConfigError::OutputAndPgMutuallyExclusive)
        ));
    }

    #[test]
    fn test_invalid_word_count() {
        let config = Config {
            bloom_path: Some(PathBuf::from("test.bloom")),
            words: 15,
            ..Default::default()
        };
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidWordCount(15))
        ));
    }

    #[test]
    fn test_filter_mode_str() {
        let config = Config {
            bloom_path: Some(PathBuf::from("test.bloom")),
            tsv_path: Some(PathBuf::from("test.tsv")),
            ..Default::default()
        };
        assert_eq!(config.filter_mode_str(), "HYBRID (bloom + exact TSV)");
    }
}
