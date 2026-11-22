//! Shared fuzzing harness: open bytes as an archive and test every entry
//! with tight limits. Any panic, hang or runaway allocation is a bug.

use std::io::Cursor;

use zip67_core::archive::open_reader;
use zip67_core::extract::{test, Selection};
use zip67_core::{ArchiveType, Limits, OpenOptions, Password, Progress};

pub fn run(data: &[u8], format: Option<ArchiveType>, name: &str) {
    let limits = Limits {
        max_entries: 50_000,
        max_total_size: 64 << 20,
        max_ratio: u64::MAX,
        ratio_grace: 0,
        max_decoder_memory: 128 << 20,
        max_header_size: 8 << 20,
        max_path_len: 4096,
    };
    // Alternate between the single- and multi-threaded decoders.
    let threads = if data.len() % 2 == 0 { 1 } else { 2 };
    let opts = OpenOptions { password: Some(Password::new("fuzz")), limits, threads, format, ..Default::default() };
    if let Ok(mut r) = open_reader(Box::new(Cursor::new(data.to_vec())), data.len() as u64, name, &opts) {
        let _ = r.info();
        let _ = test(r.as_mut(), &Selection::All, &Progress::new());
    }
}
