//! The RAR5 compression algorithm (WinRAR 5.0 and later): blocks with
//! their own Huffman tables, LZ matches with four repeat distances, and
//! delta / x86 / ARM filters.

use super::bits::Input;
use super::huffman::{Huffman, read_bit_lengths, read_lengths};
use super::window::{Filter, FilterOp, Window};
use crate::error::{Error, Result};

const NC: usize = 306;
const DC: usize = 64;
const LDC: usize = 16;
const RC: usize = 44;
const MAX_FILTER_BLOCK: u32 = 0x40_0000;

struct Tables {
    ld: Box<Huffman>,
    dd: Box<Huffman>,
    ldd: Box<Huffman>,
    rd: Box<Huffman>,
}

pub struct Unpack5 {
    tables: Option<Tables>,
    old_dist: [u64; 4],
    last_len: usize,
    /// Bit position where the current block ends.
    block_end: u64,
    last_block: bool,
    started: bool,
    pub finished: bool,
}

fn bad(msg: &str) -> Error {
    Error::corrupt(format!("RAR5 data: {msg}"))
}

impl Unpack5 {
    pub fn new() -> Self {
        Unpack5 {
            tables: None,
            old_dist: [u64::MAX; 4],
            last_len: 0,
            block_end: 0,
            last_block: false,
            started: false,
            finished: false,
        }
    }

    /// Prepares for the next file; a non-solid file forgets all state.
    pub fn start_file(&mut self, solid: bool) {
        if !solid {
            self.tables = None;
            self.old_dist = [u64::MAX; 4];
            self.last_len = 0;
        }
        self.started = false;
        self.finished = false;
        self.last_block = false;
    }

    fn read_block_header(&mut self, inp: &mut Input) -> Result<bool> {
        inp.align();
        inp.ensure(8);
        let flags = inp.bits(8);
        let checksum = inp.bits(8);
        let size_bytes = ((flags >> 3) & 3) + 1;
        if size_bytes == 4 {
            return Err(bad("bad block header"));
        }
        let mut size = 0u32;
        for i in 0..size_bytes {
            size |= inp.bits(8) << (i * 8);
        }
        let check = (0x5a ^ flags ^ size ^ (size >> 8) ^ (size >> 16)) & 0xff;
        if check != checksum || inp.overrun() {
            return Err(bad("block header checksum mismatch"));
        }
        let bit_size = u64::from((flags & 7) + 1);
        let start = inp.bit_pos();
        self.block_end = (start + u64::from(size) * 8).saturating_sub(8 - bit_size);
        self.last_block = flags & 0x40 != 0;
        Ok(flags & 0x80 != 0)
    }

    fn read_tables(&mut self, inp: &mut Input) -> Result<()> {
        inp.ensure(64);
        let bl = read_bit_lengths(inp);
        let mut bd = Huffman::empty();
        bd.build(&bl);
        let mut lens = [0u8; NC + DC + LDC + RC];
        if !read_lengths(inp, &bd, &mut lens, None) || inp.overrun() {
            return Err(bad("bad Huffman tables"));
        }
        let t = self.tables.get_or_insert_with(|| Tables {
            ld: Huffman::empty(),
            dd: Huffman::empty(),
            ldd: Huffman::empty(),
            rd: Huffman::empty(),
        });
        t.ld.build(&lens[..NC]);
        t.dd.build(&lens[NC..NC + DC]);
        t.ldd.build(&lens[NC + DC..NC + DC + LDC]);
        t.rd.build(&lens[NC + DC + LDC..]);
        Ok(())
    }

    fn next_block(&mut self, inp: &mut Input) -> Result<()> {
        if self.read_block_header(inp)? {
            self.read_tables(inp)?;
        }
        if self.tables.is_none() {
            return Err(bad("block without Huffman tables"));
        }
        Ok(())
    }

    #[inline(always)]
    fn slot_to_length(inp: &mut Input, slot: u32) -> usize {
        let (lbits, mut len) = if slot < 8 {
            (0, 2 + slot)
        } else {
            let b = slot / 4 - 1;
            (b, 2 + ((4 | (slot & 3)) << b))
        };
        if lbits > 0 {
            len += inp.bits(lbits);
        }
        len as usize
    }

    fn read_filter_data(inp: &mut Input) -> u32 {
        let n = inp.bits(2) + 1;
        let mut v = 0u32;
        for i in 0..n {
            v |= inp.bits(8) << (i * 8);
        }
        v
    }

    fn read_filter(inp: &mut Input, win: &mut Window) -> Result<()> {
        inp.ensure(16);
        let start = u64::from(Self::read_filter_data(inp));
        let mut len = Self::read_filter_data(inp);
        if len > MAX_FILTER_BLOCK {
            len = 0;
        }
        let op = match inp.bits(3) {
            0 => FilterOp::Delta5 {
                channels: inp.bits(5) + 1,
            },
            1 => FilterOp::E85 { e9: false },
            2 => FilterOp::E85 { e9: true },
            3 => FilterOp::Arm5,
            _ => return Err(bad("unknown filter")),
        };
        win.add_filter(Filter {
            start: win.pos + start,
            len,
            op,
        })
    }

    /// Decodes until the window has no more room, `budget` bytes were
    /// produced, or the file's data ends.
    pub fn decode(&mut self, inp: &mut Input, win: &mut Window, budget: u64) -> Result<()> {
        if self.finished {
            return Ok(());
        }
        if !self.started {
            self.started = true;
            self.next_block(inp)?;
        }
        let stop = win.pos + budget.min(win.space());
        let Some(_) = self.tables.as_ref() else {
            return Err(bad("no tables"));
        };
        while win.pos < stop {
            inp.ensure(32);
            while inp.bit_pos() >= self.block_end {
                if self.last_block {
                    self.finished = true;
                    return Ok(());
                }
                self.next_block(inp)?;
                inp.ensure(32);
            }
            if inp.overrun() {
                return Err(bad("compressed data ends too early"));
            }
            let t = self.tables.as_ref().ok_or_else(|| bad("no tables"))?;
            let main = t.ld.decode(inp);
            if main < 256 {
                win.put(main as u8);
                continue;
            }
            if main >= 262 {
                let mut len = Self::slot_to_length(inp, main - 262);
                let slot = t.dd.decode(inp);
                let mut dist: u64 = 1;
                let dbits;
                if slot < 4 {
                    dbits = 0;
                    dist += u64::from(slot);
                } else {
                    dbits = slot / 2 - 1;
                    dist += u64::from(2 | (slot & 1)) << dbits;
                }
                if dbits > 0 {
                    if dbits >= 4 {
                        if dbits > 4 {
                            let hi = u64::from(inp.peek32() >> (36 - dbits));
                            inp.skip(dbits - 4);
                            dist += hi << 4;
                        }
                        dist += u64::from(t.ldd.decode(inp));
                    } else {
                        dist += u64::from(inp.bits(dbits));
                    }
                }
                if dist > 0x100 {
                    len += 1;
                    if dist > 0x2000 {
                        len += 1;
                        if dist > 0x40000 {
                            len += 1;
                        }
                    }
                }
                self.old_dist = [dist, self.old_dist[0], self.old_dist[1], self.old_dist[2]];
                self.last_len = len;
                win.copy(dist, len);
                continue;
            }
            match main {
                256 => Self::read_filter(inp, win)?,
                257 => {
                    if self.last_len != 0 {
                        win.copy(self.old_dist[0], self.last_len);
                    }
                }
                _ => {
                    let n = (main - 258) as usize;
                    let dist = self.old_dist[n];
                    for i in (1..=n).rev() {
                        self.old_dist[i] = self.old_dist[i - 1];
                    }
                    self.old_dist[0] = dist;
                    let slot = t.rd.decode(inp);
                    let len = Self::slot_to_length(inp, slot);
                    self.last_len = len;
                    win.copy(dist, len);
                }
            }
        }
        Ok(())
    }
}
