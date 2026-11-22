//! Streaming raw-deflate decoder on top of the safe `miniz_oxide` inflater.

use std::io::{self, BufRead, Read};

use miniz_oxide::inflate::stream::{InflateState, inflate};
use miniz_oxide::{DataFormat, MZError, MZFlush, MZStatus};

use crate::error::Error;

/// Decodes a raw deflate stream. Bytes after the end of the deflate stream
/// stay unread in the inner `BufRead` (gzip needs them for its trailer).
pub struct InflateReader<R> {
    inner: R,
    state: Box<InflateState>,
    done: bool,
}

impl<R: BufRead> InflateReader<R> {
    pub fn new(inner: R) -> Self {
        InflateReader {
            inner,
            state: InflateState::new_boxed(DataFormat::Raw),
            done: false,
        }
    }
    pub fn is_done(&self) -> bool {
        self.done
    }
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }
    pub fn into_inner(self) -> R {
        self.inner
    }
    /// Starts decoding a new, independent stream (next gzip member).
    pub fn reset(&mut self) {
        self.state.reset(DataFormat::Raw);
        self.done = false;
    }
}

impl<R: BufRead> Read for InflateReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.done || out.is_empty() {
            return Ok(0);
        }
        loop {
            let input = self.inner.fill_buf()?;
            let eof = input.is_empty();
            let res = inflate(&mut self.state, input, out, MZFlush::None);
            self.inner.consume(res.bytes_consumed);
            match res.status {
                Ok(MZStatus::StreamEnd) => {
                    self.done = true;
                    return Ok(res.bytes_written);
                }
                Ok(_) => {
                    if res.bytes_written > 0 {
                        return Ok(res.bytes_written);
                    }
                    if eof {
                        return Err(Error::corrupt("deflate stream ends too early").into());
                    }
                }
                Err(MZError::Buf) => {
                    if res.bytes_written > 0 {
                        return Ok(res.bytes_written);
                    }
                    if eof {
                        return Err(Error::corrupt("deflate stream ends too early").into());
                    }
                }
                Err(_) => return Err(Error::corrupt("invalid deflate data").into()),
            }
        }
    }
}
