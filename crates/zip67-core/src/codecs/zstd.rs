//! Zstandard: multi-frame decoding with a window-size limit.

use std::io::{self, BufRead, Read};

use ruzstd::decoding::{FrameDecoder, StreamingDecoder};

use crate::error::Error;

pub struct ZstdReader<R: BufRead> {
    source: Option<R>,
    dec: Option<StreamingDecoder<R, FrameDecoder>>,
    max_window: u64,
}

impl<R: BufRead> ZstdReader<R> {
    pub fn new(inner: R, max_window: u64) -> Self {
        ZstdReader {
            source: Some(inner),
            dec: None,
            max_window,
        }
    }
}

const ZSTD_MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];

impl<R: BufRead> Read for ZstdReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if let Some(dec) = self.dec.as_mut() {
                let n = dec.read(buf)?;
                if n > 0 {
                    return Ok(n);
                }
                let dec = self.dec.take().expect("decoder present");
                self.source = Some(dec.into_inner());
            }
            let Some(mut src) = self.source.take() else {
                return Ok(0);
            };
            // Skip skippable frames (magic 0x184D2A5?) and stop at anything else.
            loop {
                let head = src.fill_buf()?;
                if head.len() >= 8 && head[0] & 0xf0 == 0x50 && head[1..4] == [0x2a, 0x4d, 0x18] {
                    let len = u32::from_le_bytes([head[4], head[5], head[6], head[7]]) as u64;
                    src.consume(8);
                    io::copy(&mut (&mut src).take(len), &mut io::sink())?;
                    continue;
                }
                break;
            }
            let head = src.fill_buf()?;
            if head.len() < 4 || head[..4] != ZSTD_MAGIC {
                return Ok(0);
            }
            let dec = StreamingDecoder::new_with_max_window_size(src, self.max_window)
                .map_err(|e| io::Error::from(Error::corrupt(format!("zstd: {e}"))))?;
            self.dec = Some(dec);
        }
    }
}
