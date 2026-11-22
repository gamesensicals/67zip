//! Compression streams: one place that knows how to build a decoder or an
//! encoder for every stream compression 67zip supports.

pub mod bz2;
pub mod deflate;
pub mod gzip;
pub mod lzma2;
pub mod parallel;
pub mod zstd;

use std::io::{self, BufRead, BufReader, Read, Write};
use std::num::NonZeroU64;
use std::sync::Arc;

use crate::detect::Compression;
use crate::error::{Error, Result};
use crate::limits::Limits;

pub type BoxRead<'a> = Box<dyn Read + Send + 'a>;
pub type BoxWrite<'a> = Box<dyn Write + Send + 'a>;

/// A compressing writer that must be finished explicitly.
pub trait FinishWrite: Write + Send {
    fn finish_box(self: Box<Self>) -> Result<()>;
}

/// 7-Zip style level (0..=9) to LZMA/xz preset. Level 5 maps to preset 7,
/// which uses the same 16 MiB dictionary as 7-Zip's default.
pub fn lzma_preset(level: u32) -> u32 {
    [0, 1, 2, 3, 4, 7, 7, 8, 9, 9][level.min(9) as usize]
}

/// LZMA settings matching 7-Zip's levels: 5 = 16 MiB dictionary with 32
/// fast bytes (BT4), 7 = 32 MiB / 64, 9 = 64 MiB / 64.
pub fn lzma_options(level: u32) -> lzma_rust2::LzmaOptions {
    let mut o = lzma_rust2::LzmaOptions::with_preset(lzma_preset(level));
    if (4..=6).contains(&level) {
        o.nice_len = 32;
    }
    o
}

/// 7-Zip style level to zlib/deflate level.
pub fn deflate_level(level: u32) -> u32 {
    [0, 1, 2, 4, 5, 6, 7, 8, 9, 9][level.min(9) as usize]
}

/// 7-Zip style level to bzip2 block size (100k units).
pub fn bzip2_level(level: u32) -> u32 {
    [1, 1, 3, 5, 7, 9, 9, 9, 9, 9][level.min(9) as usize]
}

fn mem_limit_kb(limits: &Limits) -> u32 {
    (limits.max_decoder_memory / 1024).min(u32::MAX as u64) as u32
}

/// Builds a decoder for a whole compressed stream.
pub fn decoder<'a>(c: Compression, inner: BoxRead<'a>, limits: &Limits) -> Result<BoxRead<'a>> {
    let buffered = BufReader::with_capacity(128 * 1024, inner);
    Ok(match c {
        Compression::None => Box::new(buffered),
        Compression::Gzip => Box::new(gzip::GzipReader::new(buffered)),
        Compression::Bzip2 => Box::new(bz2::BzDecoder::new(buffered, crate::util::default_threads())),
        Compression::Xz => Box::new(lzma_rust2::XzReader::new_mem_limit(buffered, true, mem_limit_kb(limits))),
        Compression::Zstd => Box::new(zstd::ZstdReader::new(buffered, limits.max_decoder_memory)),
        Compression::Lzma => Box::new(
            lzma_rust2::LzmaReader::new_mem_limit(buffered, mem_limit_kb(limits), None)
                .map_err(|e| Error::corrupt(format!("lzma: {e}")))?,
        ),
        Compression::Lzip => Box::new(lzma_rust2::LzipReader::new(buffered)),
    })
}

/// Reads up to `n` bytes from the start of a decoded stream (for detection).
pub fn peek_decoded(c: Compression, inner: BoxRead<'_>, n: usize, limits: &Limits) -> Result<Vec<u8>> {
    let mut d = decoder(c, inner, limits)?;
    let mut buf = vec![0u8; n];
    let got = crate::io::read_full(&mut d, &mut buf).map_err(Error::from)?;
    buf.truncate(got);
    Ok(buf)
}

macro_rules! finish_wrapper {
    ($name:ident, $ty:ty, |$s:ident| $finish:expr) => {
        struct $name<'a>($ty);
        impl Write for $name<'_> {
            fn write(&mut self, b: &[u8]) -> io::Result<usize> {
                self.0.write(b)
            }
            fn flush(&mut self) -> io::Result<()> {
                self.0.flush()
            }
        }
        impl FinishWrite for $name<'_> {
            fn finish_box(self: Box<Self>) -> Result<()> {
                let $s = self.0;
                let mut w = $finish;
                w.flush()?;
                Ok(())
            }
        }
    };
}

finish_wrapper!(PlainW, BoxWrite<'a>, |w| w);
finish_wrapper!(GzW, gzip::GzipWriter<BoxWrite<'a>>, |w| w.finish()?);
finish_wrapper!(BzW, bzip2::write::BzEncoder<BoxWrite<'a>>, |w| w.finish()?);
finish_wrapper!(XzW, lzma_rust2::XzWriter<BoxWrite<'a>>, |w| w.finish()?);
finish_wrapper!(XzMtW, lzma_rust2::XzWriterMt<BoxWrite<'a>>, |w| w.finish()?);
finish_wrapper!(LzipW, lzma_rust2::LzipWriter<BoxWrite<'a>>, |w| w.finish()?);
finish_wrapper!(LzipMtW, lzma_rust2::LzipWriterMt<BoxWrite<'a>>, |w| w.finish()?);
finish_wrapper!(LzmaW, lzma_rust2::LzmaWriter<BoxWrite<'a>>, |w| w.finish()?);
finish_wrapper!(ParW, parallel::ParallelWriter<BoxWrite<'a>>, |w| w.finish()?);

/// Builds an encoder for a stream compression.
///
/// `level` is a 7-Zip style level 0..=9, `name`/`mtime` are stored in gzip
/// headers, `threads` > 1 enables multi-threaded compression.
pub fn encoder<'a>(
    c: Compression,
    inner: BoxWrite<'a>,
    level: u32,
    threads: usize,
    name: Option<&str>,
    mtime: u32,
) -> Result<Box<dyn FinishWrite + 'a>> {
    encoder_sized(c, inner, level, threads, name, mtime, None)
}

/// Block size for multi-threaded LZMA/LZMA2: split the known total evenly
/// over the threads, but keep blocks between 2x and 4x the dictionary
/// (7-Zip uses 4x), so ratio stays good and memory stays bounded.
pub fn mt_block_size(dict: u32, threads: usize, size_hint: Option<u64>) -> u64 {
    let dict = u64::from(dict).max(1 << 20);
    match size_hint {
        Some(total) if threads > 1 => {
            let even = total.div_ceil(threads as u64);
            even.clamp(dict * 2, dict * 4).next_multiple_of(1 << 20)
        }
        _ => dict * 2,
    }
}

/// Like [`encoder`], with the expected input size as a hint.
pub fn encoder_sized<'a>(
    c: Compression,
    inner: BoxWrite<'a>,
    level: u32,
    threads: usize,
    name: Option<&str>,
    mtime: u32,
    size_hint: Option<u64>,
) -> Result<Box<dyn FinishWrite + 'a>> {
    let level = level.min(9);
    Ok(match c {
        Compression::None => Box::new(PlainW(inner)),
        Compression::Gzip => {
            let lvl = deflate_level(level);
            if threads > 1 {
                let f = Arc::new(move |d: &[u8]| gzip::gzip_member(d, lvl));
                Box::new(ParW(parallel::ParallelWriter::new(inner, 4 << 20, threads, f)))
            } else {
                Box::new(GzW(gzip::GzipWriter::new(inner, lvl, name, mtime)?))
            }
        }
        Compression::Bzip2 => {
            let lvl = bzip2_level(level);
            if threads > 1 {
                let f = Arc::new(move |d: &[u8]| {
                    let mut e = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::new(lvl));
                    e.write_all(d)?;
                    Ok(e.finish()?)
                });
                // Slightly under one bzip2 block so each chunk is one block.
                let chunk = lvl as usize * 100_000 - 10_000;
                Box::new(ParW(parallel::ParallelWriter::new(inner, chunk, threads, f)))
            } else {
                Box::new(BzW(bzip2::write::BzEncoder::new(inner, bzip2::Compression::new(lvl))))
            }
        }
        Compression::Xz => {
            let mut opts = lzma_rust2::XzOptions::with_preset(lzma_preset(level));
            opts.lzma_options = lzma_options(level);
            if threads > 1 {
                let block = mt_block_size(opts.lzma_options.dict_size, threads, size_hint);
                opts.set_block_size(NonZeroU64::new(block));
                Box::new(XzMtW(lzma_rust2::XzWriterMt::new(inner, opts, threads as u32)?))
            } else {
                Box::new(XzW(lzma_rust2::XzWriter::new(inner, opts)?))
            }
        }
        Compression::Lzip => {
            let mut opts = lzma_rust2::LzipOptions::with_preset(lzma_preset(level));
            opts.lzma_options.nice_len = lzma_options(level).nice_len;
            if threads > 1 {
                let block = mt_block_size(opts.lzma_options.dict_size, threads, size_hint);
                opts.set_member_size(NonZeroU64::new(block));
                Box::new(LzipMtW(lzma_rust2::LzipWriterMt::new(inner, opts, threads as u32)?))
            } else {
                Box::new(LzipW(lzma_rust2::LzipWriter::new(inner, opts)))
            }
        }
        Compression::Lzma => {
            let opts = lzma_options(level);
            Box::new(LzmaW(lzma_rust2::LzmaWriter::new_use_header(inner, &opts, None)?))
        }
        Compression::Zstd => {
            // The pure-Rust zstd encoder implements its fastest level only.
            let lvl = if level == 0 {
                ruzstd::encoding::CompressionLevel::Uncompressed
            } else {
                ruzstd::encoding::CompressionLevel::Fastest
            };
            let f = Arc::new(move |d: &[u8]| Ok(ruzstd::encoding::compress_to_vec(d, lvl)));
            Box::new(ParW(parallel::ParallelWriter::new(inner, 8 << 20, threads.max(1), f)))
        }
    })
}

/// Wraps a reader in a `BufRead` if needed.
pub fn buffered<'a, R: Read + Send + 'a>(r: R) -> impl BufRead + Send + 'a {
    BufReader::with_capacity(128 * 1024, r)
}
