//! Canonical Huffman decoding as used by every RAR version since 2.0:
//! code lengths up to 15 bits, read most significant bit first. The
//! decoding rules for incomplete or over-full tables match the reference
//! decoder, so damaged data decodes the same way (and never out of bounds).

use super::bits::Input;

/// Largest alphabet (RAR5 main table).
const MAX_SYMBOLS: usize = 306;

pub struct Huffman {
    quick_bits: u32,
    decode_len: [u32; 16],
    decode_pos: [u32; 16],
    decode_num: [u16; MAX_SYMBOLS],
    quick_len: [u8; 1 << 10],
    quick_num: [u16; 1 << 10],
    max_num: u32,
}

impl Huffman {
    pub fn empty() -> Box<Self> {
        Box::new(Huffman {
            quick_bits: 7,
            decode_len: [0; 16],
            decode_pos: [0; 16],
            decode_num: [0; MAX_SYMBOLS],
            quick_len: [0; 1 << 10],
            quick_num: [0; 1 << 10],
            max_num: 0,
        })
    }

    /// Builds the decoder for `lengths` (one 0..=15 bit length per symbol).
    pub fn build(&mut self, lengths: &[u8]) {
        let size = lengths.len().min(MAX_SYMBOLS);
        let lengths = &lengths[..size];
        self.max_num = size as u32;
        let mut count = [0u32; 16];
        for &l in lengths {
            count[usize::from(l & 15)] += 1;
        }
        count[0] = 0;
        self.decode_num[..size].fill(0);
        self.decode_pos[0] = 0;
        self.decode_len[0] = 0;
        let mut upper = 0u32;
        for i in 1..16 {
            upper += count[i];
            self.decode_len[i] = upper << (16 - i);
            upper *= 2;
            self.decode_pos[i] = self.decode_pos[i - 1] + count[i - 1];
        }
        let mut next = self.decode_pos;
        for (sym, &l) in lengths.iter().enumerate() {
            let l = usize::from(l & 15);
            if l != 0 {
                let p = next[l] as usize;
                if p < size {
                    self.decode_num[p] = sym as u16;
                }
                next[l] += 1;
            }
        }
        self.quick_bits = if size >= 290 { 10 } else { 7 };
        let mut cur = 1usize;
        for code in 0..(1u32 << self.quick_bits) {
            let field = code << (16 - self.quick_bits);
            while cur < 16 && field >= self.decode_len[cur] {
                cur += 1;
            }
            self.quick_len[code as usize] = cur as u8;
            let dist = field.wrapping_sub(self.decode_len[cur - 1]) >> (16 - cur.min(16));
            let num = if cur < 16 {
                let p = self.decode_pos[cur].wrapping_add(dist);
                if (p as usize) < size { self.decode_num[p as usize] } else { 0 }
            } else {
                0
            };
            self.quick_num[code as usize] = num;
        }
    }

    #[inline(always)]
    pub fn decode(&self, inp: &mut Input) -> u32 {
        let field = inp.peek16() & 0xfffe;
        if field < self.decode_len[self.quick_bits as usize] {
            let code = (field >> (16 - self.quick_bits)) as usize;
            inp.skip(u32::from(self.quick_len[code]));
            return u32::from(self.quick_num[code]);
        }
        self.decode_slow(inp, field)
    }

    #[inline(never)]
    fn decode_slow(&self, inp: &mut Input, field: u32) -> u32 {
        let mut bits = 15usize;
        for i in (self.quick_bits as usize + 1)..15 {
            if field < self.decode_len[i] {
                bits = i;
                break;
            }
        }
        inp.skip(bits as u32);
        let dist = field.wrapping_sub(self.decode_len[bits - 1]) >> (16 - bits);
        let mut pos = self.decode_pos[bits].wrapping_add(dist);
        if pos >= self.max_num {
            pos = 0;
        }
        u32::from(self.decode_num[pos as usize])
    }
}

/// Reads the 20 bit lengths of the table that codes the other tables
/// (shared by RAR 2.9 and RAR5): 4 bits each, 15 followed by a zero-run.
pub fn read_bit_lengths(inp: &mut Input) -> [u8; 20] {
    let mut bl = [0u8; 20];
    let mut i = 0;
    while i < 20 {
        let len = inp.bits(4) as u8;
        if len == 15 {
            let zeros = inp.bits(4) as usize;
            if zeros == 0 {
                bl[i] = 15;
            } else {
                for _ in 0..zeros + 2 {
                    if i >= 20 {
                        break;
                    }
                    bl[i] = 0;
                    i += 1;
                }
                continue;
            }
        } else {
            bl[i] = len;
        }
        i += 1;
    }
    bl
}

/// Reads code lengths for `out.len()` symbols with the bit-length table
/// (codes 16/17 repeat the previous length, 18/19 write zeros). `old`
/// is added modulo 16 for RAR 2.9 delta tables. Returns false on a
/// repeat code at the start, which only damaged data has.
pub fn read_lengths(inp: &mut Input, bd: &Huffman, out: &mut [u8], old: Option<&[u8]>) -> bool {
    let n = out.len();
    let mut i = 0;
    while i < n {
        inp.ensure(8);
        if inp.overrun() {
            return false;
        }
        let num = bd.decode(inp);
        if num < 16 {
            out[i] = match old {
                Some(o) => ((num as u8) + o[i]) & 15,
                None => num as u8,
            };
            i += 1;
        } else if num < 18 {
            let count = if num == 16 { inp.bits(3) + 3 } else { inp.bits(7) + 11 };
            if i == 0 {
                return false;
            }
            for _ in 0..count {
                if i >= n {
                    break;
                }
                out[i] = out[i - 1];
                i += 1;
            }
        } else {
            let count = if num == 18 { inp.bits(3) + 3 } else { inp.bits(7) + 11 };
            for _ in 0..count {
                if i >= n {
                    break;
                }
                out[i] = 0;
                i += 1;
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_codes() {
        // Lengths 1,2,3,3 -> codes 0, 10, 110, 111.
        let mut h = Huffman::empty();
        h.build(&[1, 2, 3, 3]);
        let mut inp = Input::from_vec(vec![0b0101_1011, 0b1000_0000]);
        let got: Vec<u32> = (0..5).map(|_| h.decode(&mut inp)).collect();
        assert_eq!(got, vec![0, 1, 2, 3, 0]);
    }
}
