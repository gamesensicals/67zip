//! The sliding dictionary shared by the RAR decoders, with the output side:
//! decoded bytes are handed out in order, and blocks that a filter covers
//! (x86 call addresses, ARM branches, delta, RGB and audio prediction) are
//! transformed once complete. Positions are absolute stream offsets, so
//! wrap-around never changes the meaning of a position.

use std::collections::VecDeque;

use crate::error::{Error, Result};

/// Room kept free for the longest single match of any RAR version.
pub const MARGIN: u64 = 0x2000;
const MAX_FILTERS: usize = 8192;
const VM_MEMSIZE: usize = 0x40000;
const VM_MEMMASK: u32 = (VM_MEMSIZE - 1) as u32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmKind {
    None,
    E8,
    E8E9,
    Itanium,
    Delta,
    Rgb,
    Audio,
}

#[derive(Clone, Debug)]
pub enum FilterOp {
    /// RAR5 filters.
    Delta5 {
        channels: u32,
    },
    E85 {
        e9: bool,
    },
    Arm5,
    /// RAR 2.9 virtual machine programs (recognised standard ones only).
    Vm {
        kind: VmKind,
        r: [u32; 7],
    },
}

#[derive(Clone, Debug)]
pub struct Filter {
    pub start: u64,
    pub len: u32,
    pub op: FilterOp,
}

pub struct Window {
    buf: Vec<u8>,
    mask: usize,
    /// Absolute position of the next decoded byte.
    pub pos: u64,
    /// Absolute position of the next byte to hand out.
    wr: u64,
    /// First position that holds data of the current (solid) stream.
    stream_start: u64,
    filters: VecDeque<Filter>,
    staged: Vec<u8>,
    staged_at: usize,
    /// Bytes handed out for the current file (filter address offsets).
    file_written: u64,
    vm_mem: Vec<u8>,
}

impl Window {
    /// `size` is rounded up to a power of two.
    pub fn new(size: usize) -> Result<Self> {
        let size = size.max(1 << 16).checked_next_power_of_two().ok_or_else(|| Error::limit("RAR dictionary too large"))?;
        let mut buf = Vec::new();
        buf.try_reserve_exact(size).map_err(|_| Error::limit("not enough memory for the RAR dictionary"))?;
        buf.resize(size, 0);
        Ok(Window {
            buf,
            mask: size - 1,
            pos: 0,
            wr: 0,
            stream_start: 0,
            filters: VecDeque::new(),
            staged: Vec::new(),
            staged_at: 0,
            file_written: 0,
            vm_mem: Vec::new(),
        })
    }

    pub fn size(&self) -> usize {
        self.buf.len()
    }

    /// Enlarges the dictionary, keeping its content (solid archives whose
    /// later files use a larger dictionary).
    pub fn grow(&mut self, size: usize) -> Result<()> {
        let size = size.checked_next_power_of_two().ok_or_else(|| Error::limit("RAR dictionary too large"))?;
        if size <= self.buf.len() {
            return Ok(());
        }
        let mut nb = Vec::new();
        nb.try_reserve_exact(size).map_err(|_| Error::limit("not enough memory for the RAR dictionary"))?;
        nb.resize(size, 0);
        let keep = (self.pos - self.stream_start).min(self.buf.len() as u64);
        let nmask = size - 1;
        for p in self.pos - keep..self.pos {
            nb[p as usize & nmask] = self.buf[p as usize & self.mask];
        }
        self.buf = nb;
        self.mask = nmask;
        Ok(())
    }

    /// Starts the next file. `solid` keeps the dictionary content.
    pub fn start_file(&mut self, solid: bool) {
        self.wr = self.pos;
        if !solid {
            self.stream_start = self.pos;
        }
        self.filters.clear();
        self.staged.clear();
        self.staged_at = 0;
        self.file_written = 0;
    }

    /// How many more bytes may be decoded before undelivered data would be
    /// overwritten.
    #[inline(always)]
    pub fn space(&self) -> u64 {
        (self.wr + self.buf.len() as u64).saturating_sub(MARGIN).saturating_sub(self.pos)
    }

    #[inline(always)]
    pub fn put(&mut self, b: u8) {
        let i = self.pos as usize & self.mask;
        self.buf[i] = b;
        self.pos += 1;
    }

    /// Copies `len` bytes from `dist` bytes back. Distances reaching before
    /// the stream start (or beyond the dictionary) produce zeros, so data of
    /// an unrelated earlier file can never leak into this one.
    #[inline(always)]
    pub fn copy(&mut self, dist: u64, len: usize) {
        if dist == 0 || dist > self.pos - self.stream_start || dist > self.buf.len() as u64 {
            for _ in 0..len {
                self.put(0);
            }
            return;
        }
        let size = self.buf.len();
        let mut src = (self.pos - dist) as usize & self.mask;
        let mut dst = self.pos as usize & self.mask;
        if dist as usize >= len && src + len <= size && dst + len <= size {
            self.buf.copy_within(src..src + len, dst);
        } else {
            for _ in 0..len {
                self.buf[dst] = self.buf[src];
                src = (src + 1) & self.mask;
                dst = (dst + 1) & self.mask;
            }
        }
        self.pos += len as u64;
    }

    pub fn add_filter(&mut self, f: Filter) -> Result<()> {
        if self.filters.len() >= MAX_FILTERS {
            return Err(Error::corrupt("too many RAR filters"));
        }
        self.filters.push_back(f);
        Ok(())
    }

    pub fn clear_filters(&mut self) {
        self.filters.clear();
    }

    /// A filter covers data beyond the decoded end (damaged archive).
    pub fn has_unfinished_filter(&self) -> bool {
        self.filters.iter().any(|f| f.start < self.pos && f.len > 0)
    }

    fn copy_out(&self, from: u64, out: &mut [u8]) {
        let mut at = from as usize & self.mask;
        let mut done = 0;
        while done < out.len() {
            let n = (out.len() - done).min(self.buf.len() - at);
            out[done..done + n].copy_from_slice(&self.buf[at..at + n]);
            done += n;
            at = (at + n) & self.mask;
        }
    }

    /// Hands out decoded bytes in order. Returns 0 when more decoding is
    /// needed (or everything has been delivered).
    pub fn deliver(&mut self, out: &mut [u8]) -> usize {
        if out.is_empty() {
            return 0;
        }
        loop {
            if self.staged_at < self.staged.len() {
                let n = out.len().min(self.staged.len() - self.staged_at);
                out[..n].copy_from_slice(&self.staged[self.staged_at..self.staged_at + n]);
                self.staged_at += n;
                return n;
            }
            while self.filters.front().is_some_and(|f| f.start < self.wr) {
                self.filters.pop_front();
            }
            let limit = self.filters.front().map_or(self.pos, |f| f.start.min(self.pos));
            if self.wr < limit {
                let n = out.len().min((limit - self.wr) as usize);
                self.copy_out(self.wr, &mut out[..n]);
                self.wr += n as u64;
                self.file_written += n as u64;
                return n;
            }
            let Some(f) = self.filters.front() else { return 0 };
            if f.start != self.wr || self.pos < f.start + u64::from(f.len) {
                return 0;
            }
            let Some(f) = self.filters.pop_front() else { return 0 };
            let end = f.start + u64::from(f.len);
            if f.len > 0 {
                let mut block = vec![0u8; f.len as usize];
                self.copy_out(f.start, &mut block);
                let data = self.apply(&f, block);
                self.file_written += data.len() as u64;
                self.staged = data;
                self.staged_at = 0;
            }
            self.wr = end;
        }
    }

    fn apply(&mut self, f: &Filter, mut data: Vec<u8>) -> Vec<u8> {
        let offset = self.file_written;
        match f.op {
            FilterOp::E85 { e9 } => {
                e8_filter(&mut data, offset as u32, e9, true);
                data
            }
            FilterOp::Arm5 => {
                let base = offset as u32;
                let mut p = 0usize;
                while p + 3 < data.len() {
                    if data[p + 3] == 0xeb {
                        let mut v = u32::from(data[p]) | u32::from(data[p + 1]) << 8 | u32::from(data[p + 2]) << 16;
                        v = v.wrapping_sub(base.wrapping_add(p as u32) / 4);
                        data[p] = v as u8;
                        data[p + 1] = (v >> 8) as u8;
                        data[p + 2] = (v >> 16) as u8;
                    }
                    p += 4;
                }
                data
            }
            FilterOp::Delta5 { channels } => {
                let mut out = vec![0u8; data.len()];
                let mut src = 0usize;
                for ch in 0..channels as usize {
                    let mut prev = 0u8;
                    let mut d = ch;
                    while d < out.len() {
                        prev = prev.wrapping_sub(data[src]);
                        out[d] = prev;
                        src += 1;
                        d += channels as usize;
                    }
                }
                out
            }
            FilterOp::Vm { kind, r } => {
                let mut out = self.run_vm(kind, r, &data, offset);
                // Several filters may be stacked on the same block.
                while let Some(next) = self.filters.front() {
                    let FilterOp::Vm { kind: k2, r: r2 } = next.op else { break };
                    if next.start != f.start || next.len as usize != out.len() {
                        break;
                    }
                    self.filters.pop_front();
                    out = self.run_vm(k2, r2, &out, offset);
                }
                out
            }
        }
    }

    /// Runs a standard RAR 2.9 filter the way the reference virtual machine
    /// does: the block is placed at the start of the VM memory and the
    /// result is read from there (or right after the input).
    fn run_vm(&mut self, kind: VmKind, mut r: [u32; 7], data: &[u8], offset: u64) -> Vec<u8> {
        if self.vm_mem.is_empty() {
            self.vm_mem = vec![0u8; VM_MEMSIZE + 4];
        }
        r[6] = offset as u32;
        let n = data.len().min(VM_MEMSIZE);
        self.vm_mem[..n].copy_from_slice(&data[..n]);
        let size = (r[4] & VM_MEMMASK) as usize;
        let ok = vm_filter(&mut self.vm_mem, kind, &r);
        let at = match kind {
            VmKind::Delta | VmKind::Rgb | VmKind::Audio if ok && 2 * size <= VM_MEMSIZE => size,
            _ => 0,
        };
        self.vm_mem[at..at + size].to_vec()
    }
}

/// x86 CALL/JMP address conversion (RAR5 and the RAR 2.9 standard filter).
fn e8_filter(data: &mut [u8], file_offset: u32, e9: bool, modulo: bool) {
    const FILE_SIZE: u32 = 0x100_0000;
    let mut p = 0usize;
    while p + 4 < data.len() {
        let b = data[p];
        p += 1;
        if b == 0xe8 || (e9 && b == 0xe9) {
            let mut offset = (p as u32).wrapping_add(file_offset);
            if modulo {
                offset %= FILE_SIZE;
            }
            let addr = u32::from_le_bytes([data[p], data[p + 1], data[p + 2], data[p + 3]]);
            let new = if addr & 0x8000_0000 != 0 {
                (addr.wrapping_add(offset) & 0x8000_0000 == 0).then(|| addr.wrapping_add(FILE_SIZE))
            } else {
                (addr.wrapping_sub(FILE_SIZE) & 0x8000_0000 != 0).then(|| addr.wrapping_sub(offset))
            };
            if let Some(v) = new {
                data[p..p + 4].copy_from_slice(&v.to_le_bytes());
            }
            p += 4;
        }
    }
}

fn itanium_get(d: &[u8], bit: usize, count: u32) -> u32 {
    let a = bit / 8;
    let v = u32::from_le_bytes([d[a], d[a + 1], d[a + 2], d[a + 3]]) >> (bit & 7);
    v & (u32::MAX >> (32 - count))
}

fn itanium_set(d: &mut [u8], value: u32, bit: usize, count: u32) {
    let a = bit / 8;
    let sh = (bit & 7) as u32;
    let mut and = !((u32::MAX >> (32 - count)) << sh);
    let mut v = value << sh;
    for i in 0..4 {
        d[a + i] &= and as u8;
        d[a + i] |= v as u8;
        and = (and >> 8) | 0xff00_0000;
        v >>= 8;
    }
}

/// The six standard filters of RAR 2.9. `mem` is the VM memory; returns
/// false where the reference VM rejects the parameters.
fn vm_filter(mem: &mut [u8], kind: VmKind, r: &[u32; 7]) -> bool {
    let size = r[4] as usize;
    match kind {
        VmKind::None => false,
        VmKind::E8 | VmKind::E8E9 => {
            if !(4..=VM_MEMSIZE).contains(&size) {
                return false;
            }
            e8_filter(&mut mem[..size], r[6], kind == VmKind::E8E9, false);
            true
        }
        VmKind::Itanium => {
            if !(21..=VM_MEMSIZE).contains(&size) {
                return false;
            }
            const MASKS: [u8; 16] = [4, 4, 6, 6, 0, 0, 7, 7, 4, 4, 0, 0, 4, 4, 0, 0];
            let mut file_offset = r[6] >> 4;
            let mut cur = 0usize;
            while cur < size - 21 {
                let d = &mut mem[cur..];
                let b = i32::from(d[0] & 0x1f) - 0x10;
                if b >= 0 {
                    let cmd = MASKS[b as usize];
                    if cmd != 0 {
                        for i in 0..3 {
                            if cmd & (1 << i) != 0 {
                                let start = i * 41 + 5;
                                if itanium_get(d, start + 37, 4) == 5 {
                                    let off = itanium_get(d, start + 13, 20);
                                    itanium_set(d, off.wrapping_sub(file_offset) & 0xfffff, start + 13, 20);
                                }
                            }
                        }
                    }
                }
                cur += 16;
                file_offset = file_offset.wrapping_add(1);
            }
            true
        }
        VmKind::Delta => {
            let channels = r[0] as usize;
            if size > VM_MEMSIZE / 2 || channels > 1024 || channels == 0 {
                return false;
            }
            let mut src = 0usize;
            for ch in 0..channels {
                let mut prev = 0u8;
                let mut d = size + ch;
                while d < 2 * size {
                    prev = prev.wrapping_sub(mem[src]);
                    mem[d] = prev;
                    src += 1;
                    d += channels;
                }
            }
            true
        }
        VmKind::Rgb => {
            let width = r[0].wrapping_sub(3) as usize;
            let pos_r = r[1] as usize;
            if !(3..=VM_MEMSIZE / 2).contains(&size) || width > size || pos_r > 2 {
                return false;
            }
            let mut src = 0usize;
            for ch in 0..3 {
                let mut prev: u32 = 0;
                let mut i = ch;
                while i < size {
                    let predicted = if i >= width + 3 {
                        let upper = u32::from(mem[size + i - width]);
                        let upper_left = u32::from(mem[size + i - width - 3]);
                        let p = prev.wrapping_add(upper).wrapping_sub(upper_left);
                        let pa = (p.wrapping_sub(prev) as i32).unsigned_abs();
                        let pb = (p.wrapping_sub(upper) as i32).unsigned_abs();
                        let pc = (p.wrapping_sub(upper_left) as i32).unsigned_abs();
                        if pa <= pb && pa <= pc {
                            prev
                        } else if pb <= pc {
                            upper
                        } else {
                            upper_left
                        }
                    } else {
                        prev
                    };
                    let v = (predicted.wrapping_sub(u32::from(mem[src]))) as u8;
                    src += 1;
                    mem[size + i] = v;
                    prev = u32::from(v);
                    i += 3;
                }
            }
            let mut i = pos_r;
            while i + 2 < size {
                let g = mem[size + i + 1];
                mem[size + i] = mem[size + i].wrapping_add(g);
                mem[size + i + 2] = mem[size + i + 2].wrapping_add(g);
                i += 3;
            }
            true
        }
        VmKind::Audio => {
            let channels = r[0] as usize;
            if size > VM_MEMSIZE / 2 || channels > 128 || channels == 0 {
                return false;
            }
            let mut src = 0usize;
            for ch in 0..channels {
                let (mut prev_byte, mut prev_delta) = (0u32, 0u32);
                let mut dif = [0u32; 7];
                let (mut d1, mut d2, mut d3): (i32, i32, i32);
                d1 = 0;
                d2 = 0;
                let (mut k1, mut k2, mut k3) = (0i32, 0i32, 0i32);
                let mut i = ch;
                let mut count = 0u32;
                while i < size {
                    d3 = d2;
                    d2 = (prev_delta as i32).wrapping_sub(d1);
                    d1 = prev_delta as i32;
                    let mut predicted = (8u32.wrapping_mul(prev_byte))
                        .wrapping_add((k1.wrapping_mul(d1)) as u32)
                        .wrapping_add((k2.wrapping_mul(d2)) as u32)
                        .wrapping_add((k3.wrapping_mul(d3)) as u32);
                    predicted = (predicted >> 3) & 0xff;
                    let cur = u32::from(mem[src]);
                    src += 1;
                    predicted = predicted.wrapping_sub(cur);
                    mem[size + i] = predicted as u8;
                    prev_delta = (predicted.wrapping_sub(prev_byte) as u8 as i8) as i32 as u32;
                    prev_byte = predicted;
                    let d = ((cur as u8 as i8) as i32).wrapping_shl(3);
                    dif[0] = dif[0].wrapping_add(d.unsigned_abs());
                    dif[1] = dif[1].wrapping_add(d.wrapping_sub(d1).unsigned_abs());
                    dif[2] = dif[2].wrapping_add(d.wrapping_add(d1).unsigned_abs());
                    dif[3] = dif[3].wrapping_add(d.wrapping_sub(d2).unsigned_abs());
                    dif[4] = dif[4].wrapping_add(d.wrapping_add(d2).unsigned_abs());
                    dif[5] = dif[5].wrapping_add(d.wrapping_sub(d3).unsigned_abs());
                    dif[6] = dif[6].wrapping_add(d.wrapping_add(d3).unsigned_abs());
                    if count & 0x1f == 0 {
                        let mut min = dif[0];
                        let mut num = 0;
                        dif[0] = 0;
                        for (j, v) in dif.iter_mut().enumerate().skip(1) {
                            if *v < min {
                                min = *v;
                                num = j;
                            }
                            *v = 0;
                        }
                        match num {
                            1 if k1 >= -16 => k1 -= 1,
                            2 if k1 < 16 => k1 += 1,
                            3 if k2 >= -16 => k2 -= 1,
                            4 if k2 < 16 => k2 += 1,
                            5 if k3 >= -16 => k3 -= 1,
                            6 if k3 < 16 => k3 += 1,
                            _ => {}
                        }
                    }
                    i += channels;
                    count += 1;
                }
            }
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_and_zero_fill() {
        let mut w = Window::new(1 << 16).unwrap();
        w.start_file(false);
        for b in b"abc" {
            w.put(*b);
        }
        w.copy(3, 7);
        w.copy(100, 2);
        let mut out = [0u8; 32];
        let n = w.deliver(&mut out);
        assert_eq!(&out[..n], b"abcabcabca\0\0");
    }

    #[test]
    fn delta_filter_block() {
        let mut w = Window::new(1 << 16).unwrap();
        w.start_file(false);
        w.add_filter(Filter { start: 2, len: 4, op: FilterOp::Delta5 { channels: 2 } }).unwrap();
        for b in [9u8, 9, 0xff, 0xfe, 0xff, 0xfe, 7] {
            w.put(b);
        }
        let mut out = Vec::new();
        let mut buf = [0u8; 3];
        loop {
            let n = w.deliver(&mut buf);
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        assert_eq!(out, vec![9, 9, 1, 1, 3, 3, 7]);
    }
}
