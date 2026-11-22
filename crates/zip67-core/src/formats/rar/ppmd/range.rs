//! The carryless range decoder of PPMd var.H (Dmitry Subbotin's design),
//! as RAR 2.9 uses it.

use super::{ByteSource, Error, PPMD_BIN_SCALE};

const K_TOP_VALUE: u32 = 1 << 24;
const K_BOT_VALUE: u32 = 1 << 15;

pub(crate) trait Ppmd7RangeDecoder {
    fn range(&self) -> u32;
    fn code(&self) -> u32;
    fn get_threshold(&mut self, total: u32) -> Result<u32, std::io::Error>;
    fn decode_bit_0(&mut self, src: &mut dyn ByteSource, size: u32) -> Result<(), std::io::Error>;
    fn decode_bit_1(&mut self, size: u32);
    fn decode(&mut self, start: u32, size: u32);
    fn decode_final(&mut self, src: &mut dyn ByteSource, start: u32, freq: u32) -> Result<(), std::io::Error>;
    fn normalize_remote(&mut self, src: &mut dyn ByteSource) -> Result<(), std::io::Error>;
}

fn damaged() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, "damaged PPMd data")
}

pub(crate) struct RangeDecoder7a {
    range: u32,
    code: u32,
    low: u32,
}

impl RangeDecoder7a {
    pub(crate) fn new(src: &mut dyn ByteSource) -> Result<Self, Error> {
        let mut code = 0u32;
        for _ in 0..4 {
            code = code << 8 | u32::from(src.next_byte());
        }
        if code == 0xFFFF_FFFF {
            return Err(Error::RangeDecoderInitialization);
        }
        Ok(Self { range: 0xFFFF_FFFF, code, low: 0 })
    }

    #[inline(always)]
    fn normalize(&mut self, src: &mut dyn ByteSource) -> Result<(), std::io::Error> {
        while self.low ^ self.low.wrapping_add(self.range) < K_TOP_VALUE
            || self.range < K_BOT_VALUE && {
                self.range = 0u32.wrapping_sub(self.low) & (K_BOT_VALUE - 1);
                true
            }
        {
            // 67zip: a zero range would never leave this loop.
            if self.range == 0 {
                return Err(damaged());
            }
            self.code = self.code << 8 | u32::from(src.next_byte());
            self.range <<= 8;
            self.low <<= 8;
        }
        Ok(())
    }
}

impl Ppmd7RangeDecoder for RangeDecoder7a {
    #[inline(always)]
    fn range(&self) -> u32 {
        self.range
    }

    #[inline(always)]
    fn code(&self) -> u32 {
        self.code
    }

    #[inline(always)]
    fn get_threshold(&mut self, total: u32) -> Result<u32, std::io::Error> {
        // 67zip: only damaged data gets here with a zero total or a range
        // below it; fail instead of dividing by zero.
        if total == 0 || self.range < total {
            return Err(damaged());
        }
        self.range /= total;
        Ok(self.code / self.range)
    }

    #[inline(always)]
    fn decode_bit_0(&mut self, src: &mut dyn ByteSource, size: u32) -> Result<(), std::io::Error> {
        self.range = size;
        self.normalize(src)
    }

    #[inline(always)]
    fn decode_bit_1(&mut self, size: u32) {
        self.low = self.low.wrapping_add(size);
        self.code = self.code.wrapping_sub(size);
        self.range = (self.range & !(PPMD_BIN_SCALE - 1)).wrapping_sub(size);
    }

    #[inline(always)]
    fn decode(&mut self, start: u32, size: u32) {
        let start = start.wrapping_mul(self.range);
        self.low = self.low.wrapping_add(start);
        self.code = self.code.wrapping_sub(start);
        self.range = self.range.wrapping_mul(size);
    }

    #[inline(always)]
    fn decode_final(&mut self, src: &mut dyn ByteSource, start: u32, freq: u32) -> Result<(), std::io::Error> {
        Ppmd7RangeDecoder::decode(self, start, freq);
        self.normalize(src)
    }

    #[inline(always)]
    fn normalize_remote(&mut self, src: &mut dyn ByteSource) -> Result<(), std::io::Error> {
        self.normalize(src)
    }
}
