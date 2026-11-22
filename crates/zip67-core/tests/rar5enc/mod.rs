//! A minimal RAR5 *encoder*, for tests and speed checks only (67zip does
//! not create RAR archives): greedy LZ77 with hash chains, per-block
//! Huffman tables and repeat distances. The output is a valid RAR5 archive
//! that WinRAR, 7-Zip and 67zip extract.
#![allow(dead_code)]

const NC: usize = 306;
const DC: usize = 64;
const LDC: usize = 16;
const RC: usize = 44;
const DICT_LOG: u32 = 8; // 128 KiB << 8 = 32 MiB
const WINDOW: usize = (128 << 10) << DICT_LOG;
const BLOCK_SYMBOLS: usize = 1 << 18;

#[derive(Clone, Copy)]
enum Sym {
    Lit(u8),
    Match { len: u32, dist: u32 },
    Rep { idx: u32, len: u32 },
}

struct Bits {
    out: Vec<u8>,
    acc: u64,
    n: u32,
}

impl Bits {
    fn new() -> Self {
        Bits {
            out: Vec::new(),
            acc: 0,
            n: 0,
        }
    }
    fn put(&mut self, v: u32, bits: u32) {
        if bits == 0 {
            return;
        }
        self.acc = (self.acc << bits) | (u64::from(v) & ((1u64 << bits) - 1));
        self.n += bits;
        while self.n >= 8 {
            self.out.push((self.acc >> (self.n - 8)) as u8);
            self.n -= 8;
        }
    }
    fn total_bits(&self) -> u64 {
        self.out.len() as u64 * 8 + u64::from(self.n)
    }
    fn finish(mut self) -> Vec<u8> {
        if self.n > 0 {
            self.out.push((self.acc << (8 - self.n)) as u8);
        }
        self.out
    }
}

/// Huffman code lengths limited to 15 bits.
fn lengths(freq: &[u32]) -> Vec<u8> {
    let mut f: Vec<u64> = freq.iter().map(|&x| u64::from(x)).collect();
    loop {
        let mut nodes: Vec<(u64, Vec<usize>)> = f
            .iter()
            .enumerate()
            .filter(|&(_, &x)| x > 0)
            .map(|(i, &x)| (x, vec![i]))
            .collect();
        let mut len = vec![0u8; f.len()];
        if nodes.len() == 1 {
            len[nodes[0].1[0]] = 1;
            return len;
        }
        while nodes.len() > 1 {
            nodes.sort_by_key(|n| std::cmp::Reverse(n.0));
            let a = nodes.pop().unwrap();
            let b = nodes.pop().unwrap();
            for &s in a.1.iter().chain(b.1.iter()) {
                len[s] += 1;
            }
            let mut m = a.1;
            m.extend(b.1);
            nodes.push((a.0 + b.0, m));
        }
        if len.iter().all(|&l| l <= 15) {
            return len;
        }
        for x in f.iter_mut() {
            if *x > 0 {
                *x = (*x / 2).max(1);
            }
        }
    }
}

fn codes(len: &[u8]) -> Vec<u32> {
    let mut count = [0u32; 16];
    for &l in len {
        count[l as usize] += 1;
    }
    count[0] = 0;
    let mut next = [0u32; 16];
    let mut code = 0u32;
    for l in 1..16 {
        code = (code + count[l - 1]) << 1;
        next[l] = code;
    }
    len.iter()
        .map(|&l| {
            if l == 0 {
                0
            } else {
                let c = next[l as usize];
                next[l as usize] += 1;
                c
            }
        })
        .collect()
}

fn len_slot(len: u32) -> (u32, u32, u32) {
    // (slot, extra bits, extra value) for a length >= 2.
    let l = len - 2;
    if l < 8 {
        return (l, 0, 0);
    }
    for slot in 8..RC as u32 {
        let lb = slot / 4 - 1;
        let base = (4 | (slot & 3)) << lb;
        if l >= base && l < base + (1 << lb) {
            return (slot, lb, l - base);
        }
    }
    unreachable!("length too long")
}

fn dist_slot(dist: u32) -> (u32, u32, u32) {
    let d = dist - 1;
    if d < 4 {
        return (d, 0, 0);
    }
    let hb = 31 - d.leading_zeros();
    let slot = 2 * hb + ((d >> (hb - 1)) & 1);
    let db = hb - 1;
    let base = (2 | (slot & 1)) << db;
    (slot, db, d - base)
}

fn adjust(dist: u32) -> u32 {
    u32::from(dist > 0x100) + u32::from(dist > 0x2000) + u32::from(dist > 0x40000)
}

fn parse(data: &[u8]) -> Vec<Sym> {
    const HBITS: u32 = 20;
    let mut head = vec![u32::MAX; 1 << HBITS];
    let mut prev = vec![u32::MAX; data.len()];
    let hash = |p: usize| -> usize {
        ((u32::from_le_bytes([data[p], data[p + 1], data[p + 2], data[p + 3]])
            .wrapping_mul(0x9E37_79B1))
            >> (32 - HBITS)) as usize
    };
    let mut out = Vec::with_capacity(data.len() / 3);
    let mut old = [0u32; 4];
    let mut i = 0usize;
    let insert = |head: &mut Vec<u32>, prev: &mut Vec<u32>, p: usize| {
        if p + 4 <= data.len() {
            let h = hash(p);
            prev[p] = head[h];
            head[h] = p as u32;
        }
    };
    while i < data.len() {
        let mut best_len = 0usize;
        let mut best_dist = 0usize;
        // Repeat distances first.
        for (k, &d) in old.iter().enumerate() {
            let d = d as usize;
            if d == 0 || d > i {
                continue;
            }
            let mut l = 0;
            while i + l < data.len() && l < 4097 && data[i + l] == data[i + l - d] {
                l += 1;
            }
            if l >= 2 && l > best_len + 1 {
                best_len = l;
                best_dist = d;
                let _ = k;
            }
        }
        let rep_len = best_len;
        if i + 4 <= data.len() {
            let mut cand = head[hash(i)];
            let mut depth = 0;
            while cand != u32::MAX && depth < 16 {
                let c = cand as usize;
                let d = i - c;
                if d > WINDOW - 0x10000 {
                    break;
                }
                let mut l = 0;
                while i + l < data.len() && l < 4097 && data[c + l] == data[i + l] {
                    l += 1;
                }
                let need = 2 + adjust(d as u32) as usize;
                if l >= need.max(4) && l > best_len + if rep_len > 0 { 2 } else { 0 } {
                    best_len = l;
                    best_dist = d;
                }
                cand = prev[c];
                depth += 1;
            }
        }
        if best_len >= 2 {
            let dist = best_dist as u32;
            if let Some(k) = old.iter().position(|&d| d == dist) {
                let len = best_len.min(4097) as u32;
                out.push(Sym::Rep { idx: k as u32, len });
                let d = old[k];
                for j in (1..=k).rev() {
                    old[j] = old[j - 1];
                }
                old[0] = d;
                for p in i..i + len as usize {
                    insert(&mut head, &mut prev, p);
                }
                i += len as usize;
            } else {
                let len = (best_len as u32).min(4097 + adjust(dist));
                out.push(Sym::Match { len, dist });
                old = [dist, old[0], old[1], old[2]];
                for p in i..i + len as usize {
                    insert(&mut head, &mut prev, p);
                }
                i += len as usize;
            }
        } else {
            out.push(Sym::Lit(data[i]));
            insert(&mut head, &mut prev, i);
            i += 1;
        }
    }
    out
}

fn encode_block(syms: &[Sym], last: bool, out: &mut Vec<u8>) {
    let (mut fm, mut fd, mut fl, mut fr) = (
        vec![0u32; NC],
        vec![0u32; DC],
        vec![0u32; LDC],
        vec![0u32; RC],
    );
    for s in syms {
        match *s {
            Sym::Lit(b) => fm[b as usize] += 1,
            Sym::Match { len, dist } => {
                fm[262 + len_slot(len - adjust(dist)).0 as usize] += 1;
                let (ds, db, ex) = dist_slot(dist);
                fd[ds as usize] += 1;
                if db >= 4 {
                    fl[(ex & 15) as usize] += 1;
                }
            }
            Sym::Rep { idx, len } => {
                fm[258 + idx as usize] += 1;
                fr[len_slot(len).0 as usize] += 1;
            }
        }
    }
    let (lm, ld, ll, lr) = (lengths(&fm), lengths(&fd), lengths(&fl), lengths(&fr));
    let all: Vec<u8> = lm
        .iter()
        .chain(&ld)
        .chain(&ll)
        .chain(&lr)
        .copied()
        .collect();
    let mut bf = vec![0u32; 20];
    for &l in &all {
        bf[l as usize] += 1;
    }
    let lb = lengths(&bf);
    let cb = codes(&lb);
    let (cm, cd, cl, cr) = (codes(&lm), codes(&ld), codes(&ll), codes(&lr));
    let mut w = Bits::new();
    for &l in &lb {
        if l == 15 {
            w.put(15, 4);
            w.put(0, 4);
        } else {
            w.put(u32::from(l), 4);
        }
    }
    for &l in &all {
        w.put(cb[l as usize], u32::from(lb[l as usize]));
    }
    for s in syms {
        match *s {
            Sym::Lit(b) => w.put(cm[b as usize], u32::from(lm[b as usize])),
            Sym::Match { len, dist } => {
                let (s, lbits, lex) = len_slot(len - adjust(dist));
                let m = 262 + s as usize;
                w.put(cm[m], u32::from(lm[m]));
                w.put(lex, lbits);
                let (ds, db, ex) = dist_slot(dist);
                w.put(cd[ds as usize], u32::from(ld[ds as usize]));
                if db >= 4 {
                    w.put(ex >> 4, db - 4);
                    w.put(cl[(ex & 15) as usize], u32::from(ll[(ex & 15) as usize]));
                } else {
                    w.put(ex, db);
                }
            }
            Sym::Rep { idx, len } => {
                let m = 258 + idx as usize;
                w.put(cm[m], u32::from(lm[m]));
                let (s, lbits, lex) = len_slot(len);
                w.put(cr[s as usize], u32::from(lr[s as usize]));
                w.put(lex, lbits);
            }
        }
    }
    let bits = w.total_bits();
    let data = w.finish();
    let size = data.len() as u32;
    let bit_size = (bits - (u64::from(size) - 1) * 8) as u8;
    let flags = (bit_size - 1) | (2 << 3) | if last { 0x40 } else { 0 } | 0x80;
    let check = 0x5a ^ flags ^ (size as u8) ^ ((size >> 8) as u8) ^ ((size >> 16) as u8);
    out.extend_from_slice(&[
        flags,
        check,
        size as u8,
        (size >> 8) as u8,
        (size >> 16) as u8,
    ]);
    out.extend_from_slice(&data);
}

fn vint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

fn header(out: &mut Vec<u8>, body: &[u8]) {
    let mut h = Vec::new();
    vint(&mut h, body.len() as u64);
    h.extend_from_slice(body);
    out.extend_from_slice(&zip67_core::crc::crc32(&h).to_le_bytes());
    out.extend_from_slice(&h);
}

/// A RAR5 archive holding `files` (name, content), compressed with a
/// 32 MiB dictionary.
pub fn archive(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut arc = b"Rar!\x1a\x07\x01\x00".to_vec();
    let mut main = Vec::new();
    vint(&mut main, 1);
    vint(&mut main, 0);
    vint(&mut main, 0);
    header(&mut arc, &main);
    for (name, data) in files {
        let syms = parse(data);
        let mut packed = Vec::new();
        let blocks: Vec<&[Sym]> = syms.chunks(BLOCK_SYMBOLS).collect();
        for (k, b) in blocks.iter().enumerate() {
            encode_block(b, k + 1 == blocks.len(), &mut packed);
        }
        let mut f = Vec::new();
        vint(&mut f, 2); // file header
        vint(&mut f, 2); // data area present
        vint(&mut f, packed.len() as u64);
        vint(&mut f, 0x4); // CRC32 present
        vint(&mut f, data.len() as u64);
        vint(&mut f, 0o100644);
        f.extend_from_slice(&zip67_core::crc::crc32(data).to_le_bytes());
        let method = if packed.is_empty() { 0 } else { 3 << 7 };
        vint(&mut f, method | (u64::from(DICT_LOG) << 10));
        vint(&mut f, 1); // Unix
        vint(&mut f, name.len() as u64);
        f.extend_from_slice(name.as_bytes());
        header(&mut arc, &f);
        arc.extend_from_slice(&packed);
    }
    let mut end = Vec::new();
    vint(&mut end, 5);
    vint(&mut end, 0);
    vint(&mut end, 0);
    header(&mut arc, &end);
    arc
}
