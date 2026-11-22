//! Buffered input for the RAR decoders: most-significant-bit-first bit
//! reading (Huffman codes, extra bits) and byte reading (PPMd range coder)
//! from the same stream.
//!
//! Reading past the end yields zero bits and is recorded, so a damaged
//! stream can never index outside the buffer; decoders check
//! [`Input::overrun`] to stop.

use std::io::{self, Read};

const CHUNK: usize = 256 * 1024;
/// Zero bytes kept after the data, so peeks never need bounds handling.
const PAD: usize = 16;

pub struct Input {
    buf: Vec<u8>,
    /// Valid bytes in `buf` (the rest is zero padding).
    len: usize,
    pos: usize,
    bit: u32,
    /// Stream offset of `buf[0]`.
    base: u64,
    src: Box<dyn Read + Send>,
    eof: bool,
    err: Option<io::Error>,
}

impl Default for Input {
    fn default() -> Self {
        Input::new(Box::new(io::empty()))
    }
}

impl Input {
    pub fn new(src: Box<dyn Read + Send>) -> Self {
        Input { buf: Vec::new(), len: 0, pos: 0, bit: 0, base: 0, src, eof: false, err: None }
    }

    /// Input over bytes already in memory.
    pub fn from_vec(mut data: Vec<u8>) -> Self {
        let len = data.len();
        data.resize(len + PAD, 0);
        Input { buf: data, len, pos: 0, bit: 0, base: 0, src: Box::new(io::empty()), eof: true, err: None }
    }

    /// Makes sure at least `need` bytes after the read position are
    /// buffered, unless the stream ends first.
    #[inline(always)]
    pub fn ensure(&mut self, need: usize) {
        if self.pos + need > self.len && !self.eof {
            self.refill(need);
        }
    }

    #[cold]
    fn refill(&mut self, need: usize) {
        let keep = self.len.saturating_sub(self.pos);
        if self.pos > 0 {
            let start = self.pos.min(self.len);
            self.buf.copy_within(start..self.len, 0);
            self.base += start as u64;
            self.pos -= start;
            self.len = keep;
        }
        let want = (keep + CHUNK).max(need + CHUNK / 4);
        if self.buf.len() < want + PAD {
            self.buf.resize(want + PAD, 0);
        }
        while self.len < want && !self.eof {
            match self.src.read(&mut self.buf[self.len..want]) {
                Ok(0) => self.eof = true,
                Ok(n) => self.len += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => {
                    self.err = Some(e);
                    self.eof = true;
                }
            }
        }
        self.buf[self.len..].fill(0);
    }

    /// The next 32 bits, most significant first (zeros past the end).
    #[inline(always)]
    pub fn peek32(&self) -> u32 {
        match self.buf.get(self.pos..self.pos + 8) {
            Some(b) => {
                let v = u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
                ((v << self.bit) >> 32) as u32
            }
            None => self.peek32_slow(),
        }
    }

    #[cold]
    fn peek32_slow(&self) -> u32 {
        let mut v = 0u64;
        for i in 0..8 {
            let b = if self.pos + i < self.len { self.buf[self.pos + i] } else { 0 };
            v = (v << 8) | u64::from(b);
        }
        ((v << self.bit) >> 32) as u32
    }

    /// The next 16 bits, most significant first.
    #[inline(always)]
    pub fn peek16(&self) -> u32 {
        self.peek32() >> 16
    }

    #[inline(always)]
    pub fn skip(&mut self, n: u32) {
        let t = self.bit + n;
        self.pos += (t >> 3) as usize;
        self.bit = t & 7;
    }

    /// Reads `n` (0..=16) bits.
    #[inline(always)]
    pub fn bits(&mut self, n: u32) -> u32 {
        if n == 0 {
            return 0;
        }
        let v = self.peek32() >> (32 - n);
        self.skip(n);
        v
    }

    /// Skips to the next byte boundary.
    #[inline]
    pub fn align(&mut self) {
        if self.bit != 0 {
            self.bit = 0;
            self.pos += 1;
        }
    }

    /// Reads one byte at a byte boundary (range coder input).
    #[inline(always)]
    pub fn byte(&mut self) -> u8 {
        if self.pos + 1 > self.len && !self.eof {
            self.refill(1);
        }
        let b = if self.pos < self.len { self.buf[self.pos] } else { 0 };
        self.pos += 1;
        b
    }

    /// Absolute position in bits from the start of the stream.
    #[inline(always)]
    pub fn bit_pos(&self) -> u64 {
        (self.base + self.pos as u64) * 8 + u64::from(self.bit)
    }

    /// True once more bits were consumed than the stream holds.
    #[inline(always)]
    pub fn overrun(&self) -> bool {
        self.eof && (self.pos > self.len || (self.pos == self.len && self.bit > 0))
    }

    /// An I/O error from the underlying reader, if one happened.
    pub fn take_error(&mut self) -> Option<io::Error> {
        self.err.take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bits_and_bytes() {
        let mut i = Input::new(Box::new(io::Cursor::new(vec![0b1010_0000, 0xff, 0x12, 0x34])));
        i.ensure(4);
        assert_eq!(i.bits(3), 0b101);
        assert_eq!(i.bits(5), 0);
        assert_eq!(i.peek16(), 0xff12);
        assert_eq!(i.byte(), 0xff);
        assert_eq!(i.bits(4), 1);
        i.align();
        assert_eq!(i.byte(), 0x34);
        assert!(!i.overrun());
        assert_eq!(i.bits(1), 0);
        assert!(i.overrun());
    }
}
