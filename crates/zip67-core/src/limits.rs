//! Safety limits against malicious archives (zip bombs, memory exhaustion).

use serde::{Deserialize, Serialize};

/// Limits applied while reading archives. The defaults are generous enough
/// for real archives but stop decompression bombs and absurd headers.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Limits {
    /// Maximum number of entries in one archive.
    pub max_entries: u64,
    /// Maximum total size that extraction may write (bytes).
    pub max_total_size: u64,
    /// Maximum allowed ratio of extracted bytes to archive bytes. Only
    /// enforced once more than `ratio_grace` bytes were produced.
    pub max_ratio: u64,
    pub ratio_grace: u64,
    /// Maximum memory a single decoder may allocate (dictionary, model, ...).
    pub max_decoder_memory: u64,
    /// Maximum size of metadata structures (headers, directories, names).
    pub max_header_size: u64,
    /// Maximum path length of an entry in bytes.
    pub max_path_len: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_entries: 10_000_000,
            max_total_size: 1 << 44, // 16 TiB
            max_ratio: 20_000,
            ratio_grace: 1 << 30, // 1 GiB
            max_decoder_memory: 3 << 30, // 3 GiB
            max_header_size: 1 << 30,
            max_path_len: 16 * 1024,
        }
    }
}

impl Limits {
    /// Limits without the ratio check (for trusted, self-made archives).
    pub fn relaxed() -> Self {
        Limits { max_ratio: u64::MAX, ..Default::default() }
    }
}
