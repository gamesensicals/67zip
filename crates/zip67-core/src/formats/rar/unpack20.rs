//! The RAR 2.0 compression algorithm (WinRAR 2.x archives): LZ with three
//! Huffman tables, or an adaptive multi-channel audio predictor. Files have
//! no end marker; decoding stops at the stored size.

use super::bits::Input;
use super::huffman::Huffman;
use super::window::Window;
use crate::error::{Error, Result};

const NC: usize = 298;
const DC: usize = 48;
const RC: usize = 28;
const BC: usize = 19;
const MC: usize = 257;

const LDECODE: [u8; 28] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224];
const LBITS: [u8; 28] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5];
const DDECODE: [u32; 48] = [
    0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536, 2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768, 49152, 65536, 98304, 131072,
    196608, 262144, 327680, 393216, 458752, 524288, 589824, 655360, 720896, 786432, 851968, 917504, 983040,
];
const DBITS: [u8; 48] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13, 14, 14, 15, 15, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
];
const SDDECODE: [u8; 8] = [0, 4, 8, 16, 32, 64, 128, 192];
const SDBITS: [u8; 8] = [2, 2, 3, 4, 5, 6, 6, 6];

#[derive(Clone, Copy, Default)]
struct Audio {
    k: [i32; 5],
    d: [i32; 4],
    last_delta: i32,
    dif: [u32; 11],
    byte_count: u32,
    last_char: i32,
}

pub struct Unpack20 {
    ld: Box<Huffman>,
    dd: Box<Huffman>,
    rd: Box<Huffman>,
    md: [Box<Huffman>; 4],
    tables_read: bool,
    audio: bool,
    channels: usize,
    cur_channel: usize,
    channel_delta: i32,
    aud: [Audio; 4],
    old_table: [u8; MC * 4],
    old_dist: [u64; 4],
    old_ptr: usize,
    last_dist: u64,
    last_len: usize,
    /// Bytes still to produce for the current file (None: unknown size).
    left: Option<u64>,
    started: bool,
    pub finished: bool,
}

fn bad(msg: &str) -> Error {
    Error::corrupt(format!("RAR 2.0 data: {msg}"))
}

impl Unpack20 {
    pub fn new() -> Self {
        Unpack20 {
            ld: Huffman::empty(),
            dd: Huffman::empty(),
            rd: Huffman::empty(),
            md: [Huffman::empty(), Huffman::empty(), Huffman::empty(), Huffman::empty()],
            tables_read: false,
            audio: false,
            channels: 1,
            cur_channel: 0,
            channel_delta: 0,
            aud: [Audio::default(); 4],
            old_table: [0; MC * 4],
            old_dist: [u64::MAX; 4],
            old_ptr: 0,
            last_dist: u64::MAX,
            last_len: 0,
            left: None,
            started: false,
            finished: false,
        }
    }

    pub fn start_file(&mut self, solid: bool, size: Option<u64>) {
        if !solid {
            self.tables_read = false;
            self.audio = false;
            self.channel_delta = 0;
            self.cur_channel = 0;
            self.channels = 1;
            self.aud = [Audio::default(); 4];
            self.old_table = [0; MC * 4];
            self.old_dist = [u64::MAX; 4];
            self.old_ptr = 0;
            self.last_dist = u64::MAX;
            self.last_len = 0;
        }
        self.left = size;
        self.started = false;
        self.finished = false;
    }

    fn read_tables(&mut self, inp: &mut Input) -> Result<()> {
        inp.ensure(64);
        let field = inp.peek16();
        self.audio = field & 0x8000 != 0;
        if field & 0x4000 == 0 {
            self.old_table = [0; MC * 4];
        }
        inp.skip(2);
        let size = if self.audio {
            self.channels = (((field >> 12) & 3) + 1) as usize;
            if self.cur_channel >= self.channels {
                self.cur_channel = 0;
            }
            inp.skip(2);
            MC * self.channels
        } else {
            NC + DC + RC
        };
        let mut bl = [0u8; BC];
        for b in bl.iter_mut() {
            *b = inp.bits(4) as u8;
        }
        let mut bd = Huffman::empty();
        bd.build(&bl);
        let mut table = [0u8; MC * 4];
        let mut i = 0;
        while i < size {
            inp.ensure(8);
            if inp.overrun() {
                return Err(bad("tables run past the end of the data"));
            }
            let num = bd.decode(inp);
            if num < 16 {
                table[i] = (num as u8 + self.old_table[i]) & 15;
                i += 1;
            } else if num == 16 {
                let n = inp.bits(2) + 3;
                if i == 0 {
                    return Err(bad("bad Huffman tables"));
                }
                for _ in 0..n {
                    if i >= size {
                        break;
                    }
                    table[i] = table[i - 1];
                    i += 1;
                }
            } else {
                let n = if num == 17 { inp.bits(3) + 3 } else { inp.bits(7) + 11 };
                for _ in 0..n {
                    if i >= size {
                        break;
                    }
                    table[i] = 0;
                    i += 1;
                }
            }
        }
        if inp.overrun() {
            return Err(bad("tables run past the end of the data"));
        }
        self.tables_read = true;
        if self.audio {
            for c in 0..self.channels {
                self.md[c].build(&table[c * MC..(c + 1) * MC]);
            }
        } else {
            self.ld.build(&table[..NC]);
            self.dd.build(&table[NC..NC + DC]);
            self.rd.build(&table[NC + DC..NC + DC + RC]);
        }
        self.old_table[..size].copy_from_slice(&table[..size]);
        Ok(())
    }

    fn decode_audio(&mut self, delta: i32) -> u8 {
        let cd = self.channel_delta;
        let v = &mut self.aud[self.cur_channel];
        v.byte_count = v.byte_count.wrapping_add(1);
        v.d[3] = v.d[2];
        v.d[2] = v.d[1];
        v.d[1] = v.last_delta.wrapping_sub(v.d[0]);
        v.d[0] = v.last_delta;
        let pch = 8i32
            .wrapping_mul(v.last_char)
            .wrapping_add(v.k[0].wrapping_mul(v.d[0]))
            .wrapping_add(v.k[1].wrapping_mul(v.d[1]))
            .wrapping_add(v.k[2].wrapping_mul(v.d[2]))
            .wrapping_add(v.k[3].wrapping_mul(v.d[3]))
            .wrapping_add(v.k[4].wrapping_mul(cd));
        let pch = (pch >> 3) & 0xff;
        let ch = pch.wrapping_sub(delta);
        let d = i32::from(delta as u8 as i8).wrapping_shl(3);
        let terms = [0, v.d[0], v.d[0], v.d[1], v.d[1], v.d[2], v.d[2], v.d[3], v.d[3], cd, cd];
        for (j, t) in terms.iter().enumerate() {
            let x = if j == 0 { d } else if j % 2 == 1 { d.wrapping_sub(*t) } else { d.wrapping_add(*t) };
            v.dif[j] = v.dif[j].wrapping_add(x.unsigned_abs());
        }
        let nd = i32::from(ch.wrapping_sub(v.last_char) as u8 as i8);
        v.last_delta = nd;
        v.last_char = ch;
        if v.byte_count & 0x1f == 0 {
            let mut min = v.dif[0];
            let mut num = 0;
            v.dif[0] = 0;
            for j in 1..11 {
                if v.dif[j] < min {
                    min = v.dif[j];
                    num = j;
                }
                v.dif[j] = 0;
            }
            if num > 0 {
                let k = (num - 1) / 2;
                if num % 2 == 1 {
                    if v.k[k] >= -16 {
                        v.k[k] -= 1;
                    }
                } else if v.k[k] < 16 {
                    v.k[k] += 1;
                }
            }
        }
        self.channel_delta = nd;
        ch as u8
    }

    #[inline(always)]
    fn copy(&mut self, win: &mut Window, len: usize, dist: u64) {
        self.last_dist = dist;
        self.old_dist[self.old_ptr & 3] = dist;
        self.old_ptr = self.old_ptr.wrapping_add(1);
        self.last_len = len;
        win.copy(dist, len);
        self.produced(len as u64);
    }

    #[inline(always)]
    fn produced(&mut self, n: u64) {
        if let Some(l) = self.left.as_mut() {
            *l = l.saturating_sub(n);
        }
    }

    /// At the end of a file, a table switch for the next file of a solid
    /// archive may follow.
    fn read_last_tables(&mut self, inp: &mut Input) -> Result<()> {
        inp.ensure(8);
        if inp.available() >= 5 {
            if self.audio {
                if self.md[self.cur_channel].decode(inp) == 256 {
                    self.read_tables(inp)?;
                }
            } else if self.ld.decode(inp) == 269 {
                self.read_tables(inp)?;
            }
        }
        Ok(())
    }

    pub fn decode(&mut self, inp: &mut Input, win: &mut Window, budget: u64) -> Result<()> {
        if self.finished {
            return Ok(());
        }
        if !self.started {
            self.started = true;
            if !self.tables_read {
                self.read_tables(inp)?;
            }
        }
        let stop = win.pos + budget.min(win.space());
        while win.pos < stop {
            if self.left == Some(0) {
                self.finished = true;
                return self.read_last_tables(inp);
            }
            inp.ensure(32);
            if inp.overrun() {
                self.finished = true;
                return Ok(());
            }
            if self.audio {
                let num = self.md[self.cur_channel].decode(inp);
                if num == 256 {
                    self.read_tables(inp)?;
                    continue;
                }
                let b = self.decode_audio(num as i32);
                win.put(b);
                self.cur_channel += 1;
                if self.cur_channel == self.channels {
                    self.cur_channel = 0;
                }
                self.produced(1);
                continue;
            }
            let num = self.ld.decode(inp) as usize;
            if num < 256 {
                win.put(num as u8);
                self.produced(1);
                continue;
            }
            if num > 269 {
                let n = num - 270;
                if n >= LDECODE.len() {
                    return Err(bad("bad length code"));
                }
                let mut len = usize::from(LDECODE[n]) + 3 + inp.bits(u32::from(LBITS[n])) as usize;
                let dn = self.dd.decode(inp) as usize;
                if dn >= DDECODE.len() {
                    return Err(bad("bad distance code"));
                }
                let dist = u64::from(DDECODE[dn]) + 1 + u64::from(inp.bits(u32::from(DBITS[dn])));
                if dist >= 0x2000 {
                    len += 1;
                    if dist >= 0x40000 {
                        len += 1;
                    }
                }
                self.copy(win, len, dist);
                continue;
            }
            match num {
                269 => self.read_tables(inp)?,
                256 => {
                    let (len, dist) = (self.last_len, self.last_dist);
                    self.copy(win, len, dist);
                }
                257..=260 => {
                    let dist = self.old_dist[self.old_ptr.wrapping_sub(num - 256) & 3];
                    let ln = self.rd.decode(inp) as usize;
                    if ln >= LDECODE.len() {
                        return Err(bad("bad length code"));
                    }
                    let mut len = usize::from(LDECODE[ln]) + 2 + inp.bits(u32::from(LBITS[ln])) as usize;
                    if dist >= 0x101 {
                        len += 1;
                        if dist >= 0x2000 {
                            len += 1;
                            if dist >= 0x40000 {
                                len += 1;
                            }
                        }
                    }
                    self.copy(win, len, dist);
                }
                _ => {
                    let n = num - 261;
                    let dist = u64::from(SDDECODE[n]) + 1 + u64::from(inp.bits(u32::from(SDBITS[n])));
                    self.copy(win, 2, dist);
                }
            }
        }
        Ok(())
    }
}
