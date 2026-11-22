//! Built-in benchmark: compression and decompression speed per method.

use std::io::{Read, Write};
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::codecs::{self, BoxWrite};
use crate::detect::Compression;
use crate::error::Result;
use crate::limits::Limits;
use crate::progress::Progress;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BenchResult {
    pub method: String,
    pub threads: usize,
    /// MB/s of input processed.
    pub compress_mbps: f64,
    /// MB/s of output produced.
    pub decompress_mbps: f64,
    /// Compressed size / original size, in percent.
    pub ratio: f64,
}

/// Compressible pseudo-text: words, numbers and some noise.
pub fn sample_data(size: usize, seed: u64) -> Vec<u8> {
    const WORDS: [&str; 32] = [
        "archive", "file", "the", "data", "compress", "folder", "and", "of", "67zip", "linux",
        "speed", "secure", "rust", "block", "stream", "header", "entry", "name", "size", "time",
        "value", "table", "index", "from", "into", "with", "level", "method", "test", "open",
        "save", "close",
    ];
    let mut x = seed | 1;
    let mut next = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let mut out = Vec::with_capacity(size + 64);
    while out.len() < size {
        let r = next();
        match r % 16 {
            0 => out.extend_from_slice(format!("{} ", r % 100_000).as_bytes()),
            1 => {
                for _ in 0..(r >> 8) % 12 {
                    out.push((next() >> 16) as u8);
                }
            }
            2 => out.push(b'\n'),
            _ => {
                out.extend_from_slice(WORDS[((r >> 8) % 32) as usize].as_bytes());
                out.push(b' ');
            }
        }
    }
    out.truncate(size);
    out
}

fn measure(
    c: Compression,
    level: u32,
    threads: usize,
    data: &[u8],
    progress: &Progress,
) -> Result<BenchResult> {
    progress.check()?;
    let t = Instant::now();
    let mut packed = Vec::new();
    {
        let sink: BoxWrite<'_> = Box::new(&mut packed);
        let mut enc = codecs::encoder(c, sink, level, threads, None, 0)?;
        enc.write_all(data)?;
        enc.finish_box()?;
    }
    let ct = t.elapsed().as_secs_f64().max(1e-6);
    progress.check()?;
    let t = Instant::now();
    let mut dec = codecs::decoder(c, Box::new(&packed[..]), &Limits::default())?;
    let mut n = 0u64;
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let k = dec.read(&mut buf)?;
        if k == 0 {
            break;
        }
        n += k as u64;
    }
    let dt = t.elapsed().as_secs_f64().max(1e-6);
    progress.add_done(1);
    Ok(BenchResult {
        method: format!(
            "{}{}",
            c.display(),
            if c == Compression::Xz { " (LZMA2)" } else { "" }
        ),
        threads,
        compress_mbps: data.len() as f64 / 1e6 / ct,
        decompress_mbps: n as f64 / 1e6 / dt,
        ratio: 100.0 * packed.len() as f64 / data.len() as f64,
    })
}

/// Runs the benchmark on `size` bytes of sample data.
pub fn run(size: usize, threads: usize, progress: &Progress) -> Result<Vec<BenchResult>> {
    let data = sample_data(size, 67);
    let threads = threads.max(1);
    progress.set_total(8);
    let mut out = Vec::new();
    out.push(measure(Compression::Xz, 5, threads, &data, progress)?);
    if threads > 1 {
        out.push(measure(Compression::Xz, 5, 1, &data, progress)?);
    }
    out.push(measure(Compression::Gzip, 5, 1, &data, progress)?);
    out.push(measure(Compression::Bzip2, 5, threads, &data, progress)?);
    out.push(measure(Compression::Zstd, 5, threads, &data, progress)?);
    Ok(out)
}
