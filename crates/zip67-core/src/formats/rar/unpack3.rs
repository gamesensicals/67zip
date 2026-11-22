//! The RAR 2.9 compression algorithm (RAR 3.x and 4.x archives): LZ blocks
//! with delta-coded Huffman tables, PPMd blocks, and filters written as
//! programs for RAR's virtual machine. WinRAR only ever wrote six standard
//! programs; they are recognised by checksum and run natively here, and
//! nothing else is executed.

use super::bits::Input;
use super::huffman::{Huffman, read_bit_lengths, read_lengths};
use super::ppmd::{ByteSource, PPMD7_MAX_ORDER, PPMD7_MIN_ORDER, PPMd7, RangeDecoder7a};
use super::window::{Filter, FilterOp, VmKind, Window};
use crate::error::{Error, Result};

const NC: usize = 299;
const DC: usize = 60;
const LDC: usize = 17;
const RC: usize = 28;
const TABLE: usize = NC + DC + LDC + RC;
const VM_MEMSIZE: u32 = 0x40000;

const LDECODE: [u8; 28] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128,
    160, 192, 224,
];
const LBITS: [u8; 28] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5,
];
const DDECODE: [u32; 60] = [
    0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536,
    2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768, 49152, 65536, 98304, 131072, 196608,
    262144, 327680, 393216, 458752, 524288, 589824, 655360, 720896, 786432, 851968, 917504, 983040,
    1048576, 1310720, 1572864, 1835008, 2097152, 2359296, 2621440, 2883584, 3145728, 3407872,
    3670016, 3932160,
];
const DBITS: [u8; 60] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13, 14, 14, 15, 15, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 18, 18, 18, 18, 18,
    18, 18, 18, 18, 18, 18, 18,
];
const SDDECODE: [u8; 8] = [0, 4, 8, 16, 32, 64, 128, 192];
const SDBITS: [u8; 8] = [2, 2, 3, 4, 5, 6, 6, 6];

/// (code length, CRC-32) of the standard VM programs.
const STANDARD_FILTERS: [(usize, u32, VmKind); 6] = [
    (53, 0xad57_6887, VmKind::E8),
    (57, 0x3cd7_e57e, VmKind::E8E9),
    (120, 0x3769_893f, VmKind::Itanium),
    (29, 0x0e06_077d, VmKind::Delta),
    (149, 0x1c2c_5dc8, VmKind::Rgb),
    (216, 0xbc85_e701, VmKind::Audio),
];

impl ByteSource for Input {
    #[inline(always)]
    fn next_byte(&mut self) -> u8 {
        self.byte()
    }
}

pub struct Unpack3 {
    ld: Box<Huffman>,
    dd: Box<Huffman>,
    ldd: Box<Huffman>,
    rd: Box<Huffman>,
    tables_read: bool,
    old_table: [u8; TABLE],
    old_dist: [u64; 4],
    last_len: usize,
    prev_low_dist: u32,
    low_dist_rep: u32,
    ppm_mode: bool,
    ppm: Option<Box<PPMd7<RangeDecoder7a>>>,
    ppm_esc: u32,
    max_ppm_memory: u64,
    /// Filter programs seen so far, and the last block length of each.
    programs: Vec<VmKind>,
    old_lengths: Vec<u32>,
    last_filter: usize,
    started: bool,
    pub finished: bool,
}

fn bad(msg: &str) -> Error {
    Error::corrupt(format!("RAR data: {msg}"))
}

/// The variable-length numbers of VM filter headers.
fn vm_number(inp: &mut Input) -> u32 {
    let d = inp.peek16();
    match d & 0xc000 {
        0 => {
            inp.skip(6);
            (d >> 10) & 0xf
        }
        0x4000 => {
            if d & 0x3c00 == 0 {
                inp.skip(14);
                0xffff_ff00 | ((d >> 2) & 0xff)
            } else {
                inp.skip(10);
                (d >> 6) & 0xff
            }
        }
        0x8000 => {
            inp.skip(2);
            inp.bits(16)
        }
        _ => {
            inp.skip(2);
            let hi = inp.bits(16);
            (hi << 16) | inp.bits(16)
        }
    }
}

fn identify_program(code: &[u8]) -> VmKind {
    let Some((&first, rest)) = code.split_first() else {
        return VmKind::None;
    };
    if rest.iter().fold(0u8, |a, &b| a ^ b) != first {
        return VmKind::None;
    }
    let crc = crate::crc::crc32(code);
    STANDARD_FILTERS
        .iter()
        .find(|(len, c, _)| *len == code.len() && *c == crc)
        .map_or(VmKind::None, |f| f.2)
}

impl Unpack3 {
    pub fn new(max_ppm_memory: u64) -> Self {
        Unpack3 {
            ld: Huffman::empty(),
            dd: Huffman::empty(),
            ldd: Huffman::empty(),
            rd: Huffman::empty(),
            tables_read: false,
            old_table: [0; TABLE],
            old_dist: [u64::MAX; 4],
            last_len: 0,
            prev_low_dist: 0,
            low_dist_rep: 0,
            ppm_mode: false,
            ppm: None,
            ppm_esc: 2,
            max_ppm_memory,
            programs: Vec::new(),
            old_lengths: Vec::new(),
            last_filter: 0,
            started: false,
            finished: false,
        }
    }

    pub fn start_file(&mut self, solid: bool) {
        if !solid {
            self.tables_read = false;
            self.old_table = [0; TABLE];
            self.old_dist = [u64::MAX; 4];
            self.last_len = 0;
            self.ppm_esc = 2;
            self.ppm_mode = false;
            self.ppm = None;
            self.programs.clear();
            self.old_lengths.clear();
            self.last_filter = 0;
        }
        self.started = false;
        self.finished = false;
    }

    fn read_tables(&mut self, inp: &mut Input) -> Result<()> {
        inp.align();
        inp.ensure(64);
        let field = inp.peek16();
        if field & 0x8000 != 0 {
            self.ppm_mode = true;
            return self.ppm_init(inp);
        }
        self.ppm_mode = false;
        self.prev_low_dist = 0;
        self.low_dist_rep = 0;
        if field & 0x4000 == 0 {
            self.old_table = [0; TABLE];
        }
        inp.skip(2);
        let bl = read_bit_lengths(inp);
        let mut bd = Huffman::empty();
        bd.build(&bl);
        let mut table = [0u8; TABLE];
        if !read_lengths(inp, &bd, &mut table, Some(&self.old_table)) || inp.overrun() {
            return Err(bad("bad Huffman tables"));
        }
        self.tables_read = true;
        self.ld.build(&table[..NC]);
        self.dd.build(&table[NC..NC + DC]);
        self.ldd.build(&table[NC + DC..NC + DC + LDC]);
        self.rd.build(&table[NC + DC + LDC..]);
        self.old_table = table;
        Ok(())
    }

    fn ppm_init(&mut self, inp: &mut Input) -> Result<()> {
        let flags = u32::from(inp.byte());
        let reset = flags & 0x20 != 0;
        let max_mb = if reset { u32::from(inp.byte()) } else { 0 };
        if !reset && self.ppm.is_none() {
            return Err(bad("PPMd block continues a model that does not exist"));
        }
        if flags & 0x40 != 0 {
            self.ppm_esc = u32::from(inp.byte());
        }
        if reset {
            self.ppm = None;
            let mut order = (flags & 0x1f) + 1;
            if order > 16 {
                order = 16 + (order - 16) * 3;
            }
            if !(PPMD7_MIN_ORDER..=PPMD7_MAX_ORDER).contains(&order) {
                return Err(bad("bad PPMd order"));
            }
            let mem = (max_mb + 1) << 20;
            if u64::from(mem) > self.max_ppm_memory {
                return Err(Error::limit("PPMd model needs more memory than allowed"));
            }
            let model = PPMd7::new_decoder_7a(inp, order, mem)
                .map_err(|_| bad("cannot start PPMd model"))?;
            self.ppm = Some(Box::new(model));
        } else if let Some(m) = self.ppm.as_mut() {
            m.restart_range_decoder(inp)
                .map_err(|_| bad("bad PPMd block"))?;
        }
        Ok(())
    }

    #[inline(always)]
    fn ppm_char(ppm: &mut Option<Box<PPMd7<RangeDecoder7a>>>, inp: &mut Input) -> Result<u32> {
        let m = ppm.as_mut().ok_or_else(|| bad("no PPMd model"))?;
        match m.decode_symbol(inp) {
            Ok(c) if c >= 0 => Ok(c as u32),
            _ => Err(bad("PPMd data is damaged")),
        }
    }

    fn add_vm_code(&mut self, first: u32, code: Vec<u8>, win: &mut Window) -> Result<()> {
        let size = code.len();
        let mut r = Input::from_vec(code);
        let pos = if first & 0x80 != 0 {
            match vm_number(&mut r) {
                0 => {
                    self.programs.clear();
                    self.old_lengths.clear();
                    self.last_filter = 0;
                    win.clear_filters();
                    0
                }
                p => (p - 1) as usize,
            }
        } else {
            self.last_filter
        };
        if pos > self.programs.len() || pos > self.old_lengths.len() {
            return Err(bad("bad filter number"));
        }
        self.last_filter = pos;
        let new = pos == self.programs.len();
        if new {
            if pos > 1024 {
                return Err(bad("too many filters"));
            }
            self.programs.push(VmKind::None);
            self.old_lengths.push(0);
        }
        let mut start = vm_number(&mut r);
        if first & 0x40 != 0 {
            start = start.wrapping_add(258);
        }
        let len = if first & 0x20 != 0 {
            let l = vm_number(&mut r);
            self.old_lengths[pos] = l;
            l
        } else {
            self.old_lengths.get(pos).copied().unwrap_or(0)
        };
        let mut regs = [0u32; 7];
        regs[4] = len;
        if first & 0x10 != 0 {
            let mask = r.bits(7);
            for (i, reg) in regs.iter_mut().enumerate() {
                if mask & (1 << i) != 0 {
                    *reg = vm_number(&mut r);
                }
            }
        }
        if new {
            let n = vm_number(&mut r) as usize;
            if n >= 0x10000 || n == 0 || (r.bit_pos() / 8) as usize + n > size {
                return Err(bad("bad filter program"));
            }
            let prog: Vec<u8> = (0..n).map(|_| r.bits(8) as u8).collect();
            self.programs[pos] = identify_program(&prog);
        }
        let kind = self.programs[pos];
        if kind == VmKind::None {
            return Err(Error::unsupported(
                "a RAR filter program that is not one of the standard ones",
            ));
        }
        if len > VM_MEMSIZE {
            return Err(bad("filter block too large"));
        }
        win.add_filter(Filter {
            start: win.pos + u64::from(start),
            len,
            op: FilterOp::Vm { kind, r: regs },
        })
    }

    fn read_vm_code(&mut self, inp: &mut Input, win: &mut Window) -> Result<()> {
        inp.ensure(8);
        let first = inp.bits(8);
        let mut len = (first & 7) + 1;
        if len == 7 {
            len = inp.bits(8) + 7;
        } else if len == 8 {
            len = inp.bits(16);
        }
        if len == 0 {
            return Err(bad("empty filter"));
        }
        inp.ensure(len as usize + 8);
        let code: Vec<u8> = (0..len).map(|_| inp.bits(8) as u8).collect();
        if inp.overrun() {
            return Err(bad("filter runs past the end of the data"));
        }
        self.add_vm_code(first, code, win)
    }

    fn read_vm_code_ppm(&mut self, inp: &mut Input, win: &mut Window) -> Result<()> {
        let first = Self::ppm_char(&mut self.ppm, inp)?;
        let mut len = (first & 7) + 1;
        if len == 7 {
            len = Self::ppm_char(&mut self.ppm, inp)? + 7;
        } else if len == 8 {
            let hi = Self::ppm_char(&mut self.ppm, inp)?;
            len = hi * 256 + Self::ppm_char(&mut self.ppm, inp)?;
        }
        if len == 0 {
            return Err(bad("empty filter"));
        }
        let mut code = Vec::with_capacity(len as usize);
        for _ in 0..len {
            code.push(Self::ppm_char(&mut self.ppm, inp)? as u8);
        }
        self.add_vm_code(first, code, win)
    }

    #[inline(always)]
    fn insert_dist(&mut self, d: u64) {
        self.old_dist = [d, self.old_dist[0], self.old_dist[1], self.old_dist[2]];
    }

    /// Decodes until the window has no more room, `budget` bytes were
    /// produced, or the file's data ends.
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
            inp.ensure(32);
            if inp.overrun() {
                // Ran out of data without an end marker: the caller checks
                // the size.
                self.finished = true;
                return Ok(());
            }
            if self.ppm_mode {
                let ch = Self::ppm_char(&mut self.ppm, inp)?;
                if ch == self.ppm_esc {
                    match Self::ppm_char(&mut self.ppm, inp)? {
                        0 => {
                            self.read_tables(inp)?;
                            continue;
                        }
                        2 => {
                            self.finished = true;
                            return Ok(());
                        }
                        3 => {
                            self.read_vm_code_ppm(inp, win)?;
                            continue;
                        }
                        4 => {
                            let mut dist = 0u32;
                            for _ in 0..3 {
                                dist = (dist << 8) | Self::ppm_char(&mut self.ppm, inp)?;
                            }
                            let len = Self::ppm_char(&mut self.ppm, inp)?;
                            win.copy(u64::from(dist) + 2, len as usize + 32);
                            continue;
                        }
                        5 => {
                            let len = Self::ppm_char(&mut self.ppm, inp)?;
                            win.copy(1, len as usize + 4);
                            continue;
                        }
                        _ => {}
                    }
                }
                win.put(ch as u8);
                continue;
            }

            let num = self.ld.decode(inp) as usize;
            if num < 256 {
                win.put(num as u8);
                continue;
            }
            if num >= 271 {
                let n = num - 271;
                if n >= LDECODE.len() {
                    return Err(bad("bad length code"));
                }
                let mut len = usize::from(LDECODE[n]) + 3 + inp.bits(u32::from(LBITS[n])) as usize;
                let dn = self.dd.decode(inp) as usize;
                if dn >= DDECODE.len() {
                    return Err(bad("bad distance code"));
                }
                let mut dist = u64::from(DDECODE[dn]) + 1;
                let bits = u32::from(DBITS[dn]);
                if bits > 0 {
                    if dn > 9 {
                        if bits > 4 {
                            dist += u64::from(inp.bits(bits - 4)) << 4;
                        }
                        if self.low_dist_rep > 0 {
                            self.low_dist_rep -= 1;
                            dist += u64::from(self.prev_low_dist);
                        } else {
                            let low = self.ldd.decode(inp);
                            if low == 16 {
                                self.low_dist_rep = 15;
                                dist += u64::from(self.prev_low_dist);
                            } else {
                                dist += u64::from(low);
                                self.prev_low_dist = low;
                            }
                        }
                    } else {
                        dist += u64::from(inp.bits(bits));
                    }
                }
                if dist >= 0x2000 {
                    len += 1;
                    if dist >= 0x40000 {
                        len += 1;
                    }
                }
                self.insert_dist(dist);
                self.last_len = len;
                win.copy(dist, len);
                continue;
            }
            match num {
                256 => {
                    // End of block: "1" new tables follow; "0x" end of file,
                    // with x telling whether the next file starts with tables.
                    let field = inp.peek16();
                    if field & 0x8000 != 0 {
                        inp.skip(1);
                        self.tables_read = false;
                        self.read_tables(inp)?;
                    } else {
                        inp.skip(2);
                        self.tables_read = field & 0x4000 == 0;
                        self.finished = true;
                        return Ok(());
                    }
                }
                257 => self.read_vm_code(inp, win)?,
                258 => {
                    if self.last_len != 0 {
                        win.copy(self.old_dist[0], self.last_len);
                    }
                }
                259..=262 => {
                    let n = num - 259;
                    let dist = self.old_dist[n];
                    for i in (1..=n).rev() {
                        self.old_dist[i] = self.old_dist[i - 1];
                    }
                    self.old_dist[0] = dist;
                    let ln = self.rd.decode(inp) as usize;
                    if ln >= LDECODE.len() {
                        return Err(bad("bad length code"));
                    }
                    let len =
                        usize::from(LDECODE[ln]) + 2 + inp.bits(u32::from(LBITS[ln])) as usize;
                    self.last_len = len;
                    win.copy(dist, len);
                }
                _ => {
                    let n = num - 263;
                    if n >= SDDECODE.len() {
                        return Err(bad("bad short distance code"));
                    }
                    let dist =
                        u64::from(SDDECODE[n]) + 1 + u64::from(inp.bits(u32::from(SDBITS[n])));
                    self.insert_dist(dist);
                    self.last_len = 2;
                    win.copy(dist, 2);
                }
            }
        }
        Ok(())
    }
}
