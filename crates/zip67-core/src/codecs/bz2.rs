//! Our own bzip2 decoder: safe Rust, every value read from the stream is
//! checked, and blocks are decoded on several threads at once.
//!
//! bzip2 blocks start with a 48-bit magic number at any bit position. The
//! parallel path scans a window of compressed data for those magics,
//! decodes the blocks between them concurrently, and then checks that each
//! block ended exactly where the next one starts. Any doubt (a magic number
//! that happened to appear inside compressed data, damage, unusual layout)
//! makes it fall back to the strict sequential parser for that window, so
//! results never depend on luck.

use std::collections::VecDeque;
use std::io::{self, Read};

use crate::error::{Error, Result};

const BLOCK_MAGIC: u64 = 0x3141_5926_5359;
const EOS_MAGIC: u64 = 0x1772_4538_5090;
const MAX_GROUPS: usize = 6;
const MAX_ALPHA: usize = 258;
const MAX_CODE_LEN: i32 = 20;
const MAX_SELECTORS: usize = 18_002;
const WINDOW: usize = 12 << 20;

fn corrupt(what: &str) -> Error {
    Error::corrupt(format!("bzip2: {what}"))
}

/// MSB-first bit reader over a byte slice.
struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
    buf: u64,
    n: u32,
}

impl<'a> Bits<'a> {
    fn at(data: &'a [u8], bit: u64) -> Self {
        let mut b = Bits { data, pos: (bit / 8) as usize, buf: 0, n: 0 };
        let skip = (bit % 8) as u32;
        if skip > 0 {
            let _ = b.bits(skip);
        }
        b
    }
    #[inline]
    fn refill(&mut self) {
        while self.n <= 56 {
            let Some(&byte) = self.data.get(self.pos) else { return };
            self.buf |= u64::from(byte) << (56 - self.n);
            self.pos += 1;
            self.n += 8;
        }
    }
    #[inline]
    fn bits(&mut self, k: u32) -> Result<u32> {
        if self.n < k {
            self.refill();
            if self.n < k {
                return Err(Error::corrupt("bzip2: data ends inside a block"));
            }
        }
        let v = (self.buf >> (64 - k)) as u32;
        self.buf <<= k;
        self.n -= k;
        Ok(v)
    }
    /// Next `k` bits without consuming them (None near the end of data).
    #[inline]
    fn peek(&mut self, k: u32) -> Option<u32> {
        if self.n < k {
            self.refill();
            if self.n < k {
                return None;
            }
        }
        Some((self.buf >> (64 - k)) as u32)
    }
    #[inline]
    fn consume(&mut self, k: u32) {
        self.buf <<= k;
        self.n -= k;
    }
    #[inline]
    fn bit(&mut self) -> Result<bool> {
        Ok(self.bits(1)? == 1)
    }
    fn position(&self) -> u64 {
        self.pos as u64 * 8 - u64::from(self.n)
    }
}

/// bzip2's own CRC-32 (MSB first, polynomial 0x04C11DB7).
struct BzCrc;
impl BzCrc {
    const TABLE: [u32; 256] = {
        let mut t = [0u32; 256];
        let mut i = 0;
        while i < 256 {
            let mut c = (i as u32) << 24;
            let mut k = 0;
            while k < 8 {
                c = if c & 0x8000_0000 != 0 { (c << 1) ^ 0x04C1_1DB7 } else { c << 1 };
                k += 1;
            }
            t[i] = c;
            i += 1;
        }
        t
    };
}

const FAST_BITS: u32 = 10;

struct Huffman {
    limit: [i32; 21],
    base: [i32; 22],
    perm: [u16; MAX_ALPHA],
    min_len: i32,
    /// For every 10-bit prefix: (symbol << 5) | code length, or 0 if the
    /// code is longer than 10 bits.
    fast: Vec<u16>,
}

impl Huffman {
    fn new(lens: &[u8]) -> Result<Huffman> {
        let min_len = i32::from(*lens.iter().min().ok_or_else(|| corrupt("empty code table"))?);
        let max_len = i32::from(*lens.iter().max().unwrap_or(&0));
        let mut h = Huffman { limit: [0; 21], base: [0; 22], perm: [0; MAX_ALPHA], min_len, fast: vec![0; 1 << FAST_BITS] };
        let mut pp = 0;
        for len in min_len..=max_len {
            for (sym, &l) in lens.iter().enumerate() {
                if i32::from(l) == len {
                    h.perm[pp] = sym as u16;
                    pp += 1;
                }
            }
        }
        let mut count = [0i32; 22];
        for &l in lens {
            count[usize::from(l) + 1] += 1;
        }
        for i in 1..22 {
            count[i] += count[i - 1];
        }
        let mut vec = 0i32;
        for len in min_len..=max_len {
            let l = len as usize;
            vec += count[l + 1] - count[l];
            h.limit[l] = vec - 1;
            vec <<= 1;
        }
        h.base = count;
        for len in (min_len + 1)..=max_len {
            let l = len as usize;
            h.base[l] = ((h.limit[l - 1] + 1) << 1) - count[l];
        }
        // Lengths below min_len never match.
        for l in 0..min_len as usize {
            h.limit[l] = -1;
        }
        for l in (max_len as usize + 1)..21 {
            h.limit[l] = i32::MAX;
        }
        // Fill the fast table by decoding every 10-bit prefix the slow way
        // (only possible when some codes are short enough).
        let prefixes = if min_len <= FAST_BITS as i32 { 1u32 << FAST_BITS } else { 0 };
        for prefix in 0..prefixes {
            let mut len = min_len;
            let mut code = (prefix >> (FAST_BITS as i32 - len)) as i32;
            while len <= FAST_BITS as i32 && code > h.limit[len as usize] {
                len += 1;
                if len <= FAST_BITS as i32 {
                    code = (prefix >> (FAST_BITS as i32 - len)) as i32;
                }
            }
            if len <= FAST_BITS as i32 {
                let idx = code - h.base[len as usize];
                if idx >= 0 && (idx as usize) < lens.len() {
                    h.fast[prefix as usize] = (h.perm[idx as usize] << 5) | len as u16;
                }
            }
        }
        Ok(h)
    }

    #[inline]
    fn decode(&self, br: &mut Bits, alpha: usize) -> Result<usize> {
        if let Some(prefix) = br.peek(FAST_BITS) {
            let e = self.fast[prefix as usize];
            if e != 0 {
                br.consume(u32::from(e & 31));
                return Ok(usize::from(e >> 5));
            }
        }
        let mut len = self.min_len;
        let mut code = br.bits(len as u32)? as i32;
        loop {
            if code <= self.limit[len as usize] {
                break;
            }
            len += 1;
            if len > MAX_CODE_LEN {
                return Err(corrupt("bad Huffman code"));
            }
            code = (code << 1) | br.bits(1)? as i32;
        }
        let idx = code - self.base[len as usize];
        if idx < 0 || idx as usize >= alpha {
            return Err(corrupt("bad Huffman code"));
        }
        Ok(usize::from(self.perm[idx as usize]))
    }
}

/// Decodes one block. `br` is positioned right after the block magic.
/// Returns the stored block CRC; output is appended to `out`.
fn decode_block(br: &mut Bits, max_block: usize, out: &mut Vec<u8>, tt: &mut Vec<u32>) -> Result<u32> {
    let stored_crc = br.bits(32)?;
    if br.bit()? {
        return Err(Error::unsupported("bzip2 randomised blocks (made by bzip2 0.9.0, 1997)"));
    }
    let orig_ptr = br.bits(24)? as usize;

    let used = br.bits(16)?;
    let mut seq_to_unseq: Vec<u8> = Vec::with_capacity(256);
    for i in 0..16 {
        if used & (0x8000 >> i) != 0 {
            let bits = br.bits(16)?;
            for j in 0..16 {
                if bits & (0x8000 >> j) != 0 {
                    seq_to_unseq.push((i * 16 + j) as u8);
                }
            }
        }
    }
    if seq_to_unseq.is_empty() {
        return Err(corrupt("block uses no symbols"));
    }
    let alpha = seq_to_unseq.len() + 2;
    let groups = br.bits(3)? as usize;
    if !(2..=MAX_GROUPS).contains(&groups) {
        return Err(corrupt("bad number of code tables"));
    }
    let n_sel = br.bits(15)? as usize;
    if n_sel == 0 {
        return Err(corrupt("no selectors"));
    }
    let mut mtf_groups: [u8; MAX_GROUPS] = [0, 1, 2, 3, 4, 5];
    let mut selectors = Vec::with_capacity(n_sel.min(MAX_SELECTORS));
    for i in 0..n_sel {
        let mut j = 0usize;
        while br.bit()? {
            j += 1;
            if j >= groups {
                return Err(corrupt("bad selector"));
            }
        }
        // bzip2 1.0.8 accepts and ignores selectors beyond 18002.
        if i < MAX_SELECTORS {
            let v = mtf_groups[j];
            mtf_groups.copy_within(0..j, 1);
            mtf_groups[0] = v;
            selectors.push(v);
        }
    }
    let mut tables = Vec::with_capacity(groups);
    for _ in 0..groups {
        let mut lens = [0u8; MAX_ALPHA];
        let mut curr = br.bits(5)? as i32;
        for l in lens.iter_mut().take(alpha) {
            loop {
                if !(1..=MAX_CODE_LEN).contains(&curr) {
                    return Err(corrupt("bad code length"));
                }
                if !br.bit()? {
                    break;
                }
                if br.bit()? {
                    curr -= 1;
                } else {
                    curr += 1;
                }
            }
            *l = curr as u8;
        }
        tables.push(Huffman::new(&lens[..alpha])?);
    }

    // Huffman + run-length (RUNA/RUNB) + move-to-front decoding into tt.
    let eob = alpha - 1;
    tt.clear();
    let mut counts = [0u32; 256];
    let mut mtf: [u8; 256] = std::array::from_fn(|i| i as u8);
    let mut group = 0usize;
    let mut left_in_group = 0u32;
    let mut table = &tables[0];
    let mut next_sym = |br: &mut Bits| -> Result<usize> {
        if left_in_group == 0 {
            let s = *selectors.get(group).ok_or_else(|| corrupt("ran out of selectors"))?;
            table = tables.get(usize::from(s)).ok_or_else(|| corrupt("bad selector"))?;
            group += 1;
            left_in_group = 50;
        }
        left_in_group -= 1;
        table.decode(br, alpha)
    };
    let mut sym = next_sym(br)?;
    loop {
        if sym == eob {
            break;
        }
        if sym <= 1 {
            // A run of the front symbol, length in bijective base 2.
            let mut run: usize = 0;
            let mut weight: usize = 1;
            while sym <= 1 {
                run += weight << sym;
                weight <<= 1;
                if weight > (1 << 21) {
                    return Err(corrupt("run too long"));
                }
                sym = next_sym(br)?;
            }
            let byte = seq_to_unseq[usize::from(mtf[0])];
            if tt.len() + run > max_block {
                return Err(corrupt("block larger than declared"));
            }
            counts[usize::from(byte)] += run as u32;
            tt.extend(std::iter::repeat_n(u32::from(byte), run));
            continue;
        }
        let n = sym - 1;
        if n >= seq_to_unseq.len() {
            return Err(corrupt("bad move-to-front index"));
        }
        let v = mtf[n];
        mtf.copy_within(0..n, 1);
        mtf[0] = v;
        let byte = seq_to_unseq[usize::from(v)];
        if tt.len() >= max_block {
            return Err(corrupt("block larger than declared"));
        }
        counts[usize::from(byte)] += 1;
        tt.push(u32::from(byte));
        sym = next_sym(br)?;
    }
    let nblock = tt.len();
    if nblock == 0 || orig_ptr >= nblock {
        return Err(corrupt("bad block origin"));
    }

    // Inverse Burrows-Wheeler transform.
    let mut cf = [0u32; 256];
    let mut sum = 0u32;
    for (c, &n) in cf.iter_mut().zip(counts.iter()) {
        *c = sum;
        sum += n;
    }
    for i in 0..nblock {
        let b = (tt[i] & 0xff) as usize;
        let dst = cf[b] as usize;
        tt[dst] |= (i as u32) << 8;
        cf[b] += 1;
    }

    // Walk the permutation, undo the initial run-length coding and
    // compute the block CRC on the fly.
    let mut crc = !0u32;
    let mut t_pos = (tt[orig_ptr] >> 8) as usize;
    let mut last: i32 = -1;
    let mut run = 0u32;
    let start = out.len();
    out.reserve(nblock + nblock / 8);
    for _ in 0..nblock {
        let v = *tt.get(t_pos).ok_or_else(|| corrupt("bad block"))?;
        let b = (v & 0xff) as u8;
        t_pos = (v >> 8) as usize;
        if run == 4 {
            let rep = usize::from(b);
            if rep > 0 {
                let lb = last as u8;
                for _ in 0..rep {
                    crc = (crc << 8) ^ BzCrc::TABLE[((crc >> 24) as u8 ^ lb) as usize];
                }
                out.extend(std::iter::repeat_n(lb, rep));
            }
            run = 0;
            last = -1;
            continue;
        }
        crc = (crc << 8) ^ BzCrc::TABLE[((crc >> 24) as u8 ^ b) as usize];
        out.push(b);
        if i32::from(b) == last {
            run += 1;
        } else {
            last = i32::from(b);
            run = 1;
        }
    }
    let crc = !crc;
    if crc != stored_crc {
        out.truncate(start);
        return Err(Error::Checksum("bzip2 block".into()));
    }
    Ok(stored_crc)
}

/// Scans for magics using several threads (each part overlaps the next by
/// the 6 bytes a magic can span).
fn scan_parallel(data: &[u8], from_bit: u64, threads: usize) -> Vec<(u64, bool)> {
    let start = (from_bit / 8) as usize;
    let len = data.len().saturating_sub(start);
    if threads < 2 || len < (1 << 20) {
        return scan(data, from_bit);
    }
    let part = len.div_ceil(threads);
    let mut all: Vec<(u64, bool)> = std::thread::scope(|s| {
        let hs: Vec<_> = (0..threads)
            .map(|i| {
                let a = start + i * part;
                let b = (a + part + 6).min(data.len());
                s.spawn(move || {
                    let from = (a as u64 * 8).max(from_bit);
                    scan(&data[..b], from)
                })
            })
            .collect();
        hs.into_iter().flat_map(|h| h.join().unwrap_or_default()).collect()
    });
    all.sort_unstable();
    all.dedup();
    all
}

/// Finds all block / end-of-stream magics in `data` at or after `from_bit`.
fn scan(data: &[u8], from_bit: u64) -> Vec<(u64, bool)> {
    let mut found = Vec::new();
    let mut window: u64 = 0;
    let start_byte = (from_bit / 8) as usize;
    for (i, &b) in data.iter().enumerate().skip(start_byte) {
        window = (window << 8) | u64::from(b);
        if i < start_byte + 5 {
            continue;
        }
        // The 48 bits ending at bit offset (i+1)*8 - k, for k = 0..8.
        for k in (0..8u64).rev() {
            let v = (window >> k) & 0xFFFF_FFFF_FFFF;
            if v == BLOCK_MAGIC || v == EOS_MAGIC {
                let end = (i as u64 + 1) * 8 - k;
                let pos = end - 48;
                if pos >= from_bit {
                    found.push((pos, v == EOS_MAGIC));
                }
            }
        }
    }
    found
}

/// Streaming bzip2 decoder (multi-stream, multi-threaded).
pub struct BzDecoder<R: Read> {
    inner: R,
    threads: usize,
    buf: Vec<u8>,
    /// Current bit position inside `buf`.
    pos: u64,
    eof_in: bool,
    out: VecDeque<u8>,
    /// Inside a stream: (max block size, combined CRC so far).
    stream: Option<(usize, u32)>,
    streams_seen: u64,
    done: bool,
    /// Magic positions found in `buf` (valid until `buf` changes).
    cands: Option<Vec<(u64, bool)>>,
    tt: Vec<u32>,
}

impl<R: Read> BzDecoder<R> {
    pub fn new(inner: R, threads: usize) -> Self {
        BzDecoder { inner, threads: threads.max(1), buf: Vec::new(), pos: 0, eof_in: false, out: VecDeque::new(), stream: None, streams_seen: 0, done: false, cands: None, tt: Vec::new() }
    }

    fn fill(&mut self) -> Result<()> {
        self.cands = None;
        // Drop fully consumed bytes, keep the rest.
        let consumed = (self.pos / 8) as usize;
        if consumed > 0 {
            self.buf.drain(..consumed);
            self.pos -= consumed as u64 * 8;
        }
        if self.eof_in {
            return Ok(());
        }
        let want = WINDOW.saturating_sub(self.buf.len()).max(1 << 20);
        let start = self.buf.len();
        self.buf.resize(start + want, 0);
        let n = crate::io::read_full(&mut self.inner, &mut self.buf[start..])?;
        self.buf.truncate(start + n);
        if n < want {
            self.eof_in = true;
        }
        Ok(())
    }

    /// Strictly parses as many complete items as `buf` holds from `pos`.
    /// Returns false if it needs more input to continue.
    fn step_sequential(&mut self, out: &mut Vec<u8>) -> Result<bool> {
        let data = &self.buf[..];
        let Some((max_block, combined)) = self.stream else {
            // Expect a stream header at a byte boundary.
            let byte = self.pos.div_ceil(8) as usize;
            if data.len() < byte + 4 {
                return Ok(false);
            }
            let h = &data[byte..byte + 4];
            if &h[..3] != b"BZh" || !(b'1'..=b'9').contains(&h[3]) {
                if self.streams_seen > 0 {
                    // Trailing garbage after a complete stream: stop like bzip2.
                    self.done = true;
                    return Ok(true);
                }
                return Err(corrupt("not a bzip2 stream"));
            }
            self.stream = Some((usize::from(h[3] - b'0') * 100_000, 0));
            self.pos = (byte as u64 + 4) * 8;
            return Ok(true);
        };
        let mut br = Bits::at(data, self.pos);
        let magic = match br.bits(24).and_then(|a| br.bits(24).map(|b| (u64::from(a) << 24) | u64::from(b))) {
            Ok(m) => m,
            Err(_) if !self.eof_in => return Ok(false),
            Err(e) => return Err(e),
        };
        if magic == EOS_MAGIC {
            let stored = match br.bits(32) {
                Ok(s) => s,
                Err(_) if !self.eof_in => return Ok(false),
                Err(e) => return Err(e),
            };
            if stored != combined {
                return Err(Error::Checksum("bzip2 stream".into()));
            }
            self.pos = br.position().div_ceil(8) * 8;
            self.stream = None;
            self.streams_seen += 1;
            return Ok(true);
        }
        if magic != BLOCK_MAGIC {
            return Err(corrupt("bad block header"));
        }
        let before = out.len();
        match decode_block(&mut br, max_block, out, &mut self.tt) {
            Ok(crc) => {
                self.stream = Some((max_block, combined.rotate_left(1) ^ crc));
                self.pos = br.position();
                Ok(true)
            }
            Err(Error::Corrupt(m)) if m.contains("ends inside a block") && !self.eof_in => {
                out.truncate(before);
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }

    /// Tries to decode the blocks of the current window in parallel.
    /// Returns false when the layout is not simple enough (the caller then
    /// uses the sequential parser).
    fn step_parallel(&mut self, out: &mut Vec<u8>) -> Result<bool> {
        let Some((max_block, combined)) = self.stream else { return Ok(false) };
        if self.cands.is_none() {
            self.cands = Some(scan_parallel(&self.buf, self.pos, self.threads));
        }
        let data = &self.buf[..];
        let all = self.cands.as_deref().unwrap_or(&[]);
        let first = all.partition_point(|c| c.0 < self.pos);
        let cands = &all[first..];
        if cands.first().map(|c| c.0) != Some(self.pos) {
            return Ok(false);
        }
        // Blocks with a known end (the next candidate) form the batch.
        let mut segs: Vec<(u64, u64)> = Vec::new();
        for w in cands.windows(2) {
            if w[0].1 {
                break; // end-of-stream marker: handled sequentially
            }
            segs.push((w[0].0, w[1].0));
            if segs.len() >= 256 {
                break;
            }
        }
        if segs.len() < 2 {
            return Ok(false);
        }
        let threads = self.threads.min(segs.len());
        let next = std::sync::atomic::AtomicUsize::new(0);
        let slots: Vec<std::sync::Mutex<Option<Result<(Vec<u8>, u32, u64)>>>> = segs.iter().map(|_| std::sync::Mutex::new(None)).collect();
        std::thread::scope(|s| {
            for _ in 0..threads {
                s.spawn(|| {
                    let mut tt = Vec::new();
                    loop {
                        let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let Some(&(start, _)) = segs.get(i) else { break };
                        let mut br = Bits::at(data, start + 48);
                        let mut o = Vec::new();
                        let r = decode_block(&mut br, max_block, &mut o, &mut tt).map(|crc| (o, crc, br.position()));
                        if let Ok(mut slot) = slots[i].lock() {
                            *slot = Some(r);
                        }
                    }
                });
            }
        });
        let results: Vec<Result<(Vec<u8>, u32, u64)>> =
            slots.into_iter().map(|m| m.into_inner().ok().flatten().unwrap_or_else(|| Err(corrupt("block not decoded")))).collect();
        let mut comb = combined;
        let mut pos = self.pos;
        for (res, &(_, end)) in results.into_iter().zip(segs.iter()) {
            match res {
                Ok((o, crc, stop)) if stop <= end && end - stop < 8 && stop >= pos => {
                    // A block ends where the next magic begins (bzip2 does not
                    // pad between blocks, so `stop == end` in practice).
                    if stop != end {
                        break;
                    }
                    out.extend_from_slice(&o);
                    comb = comb.rotate_left(1) ^ crc;
                    pos = end;
                }
                _ => break,
            }
        }
        if pos == self.pos {
            return Ok(false);
        }
        self.pos = pos;
        self.stream = Some((max_block, comb));
        Ok(true)
    }

    fn produce(&mut self) -> Result<()> {
        let mut out = Vec::new();
        while out.is_empty() && !self.done {
            if self.buf.len() as u64 * 8 <= self.pos + 64 || (!self.eof_in && (self.buf.len() as u64 * 8 - self.pos) < (2 << 20) * 8) {
                self.fill()?;
            }
            if self.buf.len() as u64 * 8 <= self.pos {
                if self.stream.is_some() {
                    return Err(corrupt("stream ends without its end marker"));
                }
                if self.streams_seen == 0 {
                    return Err(corrupt("empty input"));
                }
                self.done = true;
                break;
            }
            let progressed = if self.threads > 1 && self.step_parallel(&mut out)? { true } else { self.step_sequential(&mut out)? };
            if !progressed {
                if self.eof_in {
                    return Err(corrupt("data ends inside a block"));
                }
                let before = self.buf.len();
                self.fill()?;
                if self.buf.len() == before && self.eof_in {
                    continue;
                }
            }
        }
        self.out.extend(out);
        Ok(())
    }
}

impl<R: Read> Read for BzDecoder<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.out.is_empty() {
            if self.done {
                return Ok(0);
            }
            self.produce()?;
            if self.out.is_empty() {
                return Ok(0);
            }
        }
        let (a, b) = self.out.as_slices();
        let src = if a.is_empty() { b } else { a };
        let n = buf.len().min(src.len());
        buf[..n].copy_from_slice(&src[..n]);
        self.out.drain(..n);
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn compress(data: &[u8], level: u32) -> Vec<u8> {
        let mut e = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::new(level));
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn sample(n: usize) -> Vec<u8> {
        let mut x = 12345u64;
        (0..n)
            .map(|i| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                if i % 7 < 3 { b'a' + (x % 3) as u8 } else { (x >> 20) as u8 }
            })
            .collect()
    }

    #[test]
    fn roundtrip_levels_and_threads() {
        for (n, level) in [(0usize, 9u32), (1, 9), (5000, 1), (250_000, 1), (2_500_000, 9)] {
            let data = sample(n);
            let packed = compress(&data, level);
            for threads in [1, 4] {
                let mut d = BzDecoder::new(&packed[..], threads);
                let mut out = Vec::new();
                d.read_to_end(&mut out).unwrap();
                assert_eq!(out, data, "n={n} level={level} threads={threads}");
            }
        }
    }

    #[test]
    fn runs_and_multistream() {
        let mut data = vec![7u8; 1_000_000];
        data.extend(b"abcabcabc".repeat(10_000));
        let mut packed = compress(&data, 3);
        packed.extend(compress(b"second stream", 9));
        let mut expect = data.clone();
        expect.extend(b"second stream");
        for threads in [1, 3] {
            let mut out = Vec::new();
            BzDecoder::new(&packed[..], threads).read_to_end(&mut out).unwrap();
            assert_eq!(out, expect);
        }
    }

    #[test]
    fn corruption_is_detected_not_panicking() {
        let data = sample(300_000);
        let packed = compress(&data, 9);
        for i in (10..packed.len()).step_by(997) {
            let mut p = packed.clone();
            p[i] ^= 0x10;
            for threads in [1, 2] {
                let mut out = Vec::new();
                let r = BzDecoder::new(&p[..], threads).read_to_end(&mut out);
                assert!(r.is_err() || out == data, "flip at {i}");
            }
        }
    }
}
