//! UDF (ISO/IEC 13346) reading. Most images come from a small writer in
//! this file, written separately from the reader, so every feature and
//! every kind of damage can be produced on purpose. Images from
//! genisoimage and mkudffs are used too when those tools are installed.

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::Command;

use common::*;
use zip67_core::entry::EntryKind;
use zip67_core::{open, OpenOptions};

// ----- a small UDF writer ---------------------------------------------------

fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &b in data {
        crc ^= u16::from(b) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 { (crc << 1) ^ 0x1021 } else { crc << 1 };
        }
    }
    crc
}

fn put16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}
fn put32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
fn put64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

/// Writes the 16-byte descriptor tag over `d`, the whole descriptor.
fn tag(d: &mut [u8], ident: u16, loc: u32) {
    put16(d, 0, ident);
    put16(d, 2, 3);
    put16(d, 6, 1);
    put16(d, 10, (d.len() - 16) as u16);
    let crc = crc16(&d[16..]);
    put16(d, 8, crc);
    put32(d, 12, loc);
    d[4] = d[..16].iter().enumerate().filter(|(i, _)| *i != 4).fold(0u8, |s, (_, &x)| s.wrapping_add(x));
}

/// OSTA compressed Unicode: 8-bit when every character fits, else UTF-16BE.
fn cs0(s: &str) -> Vec<u8> {
    if s.chars().all(|c| (c as u32) < 256) {
        std::iter::once(8).chain(s.chars().map(|c| c as u8)).collect()
    } else {
        std::iter::once(16).chain(s.encode_utf16().flat_map(u16::to_be_bytes)).collect()
    }
}

fn dstring(field: &mut [u8], s: &str) {
    let v = cs0(s);
    field[..v.len()].copy_from_slice(&v);
    let last = field.len() - 1;
    field[last] = v.len() as u8;
}

fn regid(field: &mut [u8], id: &[u8], suffix: &[u8]) {
    field[1..1 + id.len()].copy_from_slice(id);
    field[24..24 + suffix.len()].copy_from_slice(suffix);
}

/// 2024-05-06 07:08:09 UTC.
fn stamp(b: &mut [u8]) {
    b[..12].copy_from_slice(&[0, 0x10, 0xE8, 0x07, 5, 6, 7, 8, 9, 0, 0, 0]);
}
const STAMP: i64 = 1_714_979_289;

#[derive(Clone, Copy, Debug)]
enum Style {
    /// One short_ad in the entry's own partition.
    Short,
    /// One long_ad into the data partition.
    Long,
    /// Data inside the file entry.
    Inline,
    /// Three extents in scattered places.
    Split,
    /// Recorded, then an unrecorded hole (zeros), then recorded again.
    Sparse,
    /// One extent per block, the descriptors continued in two more blocks.
    Chained,
}

enum N {
    Dir(String, Vec<N>),
    File(String, Vec<u8>, Style),
    Link(String, Vec<u8>),
}

fn file(name: &str, data: Vec<u8>, style: Style) -> N {
    N::File(name.into(), data, style)
}
fn dir(name: &str, children: Vec<N>) -> N {
    N::Dir(name.into(), children)
}

#[derive(Clone, Copy)]
struct Opts {
    bs: usize,
    /// UDF 2.50 metadata partition (Blu-ray style) instead of one partition.
    metadata: bool,
    /// Extended file entries (UDF 2.00+) instead of file entries.
    efe: bool,
    /// The metadata file in two pieces instead of one.
    fragmented: bool,
}

/// Physical block where file data starts in metadata mode.
const DATA_BASE: u32 = 1000;
/// Main and reserve volume descriptor sequences and the partition start.
const MAIN_VDS: u32 = 32;
const RESERVE_VDS: u32 = 48;
const PART_START: u32 = 300;

struct Writer {
    o: Opts,
    /// Blocks of the metadata partition, or of the only partition.
    meta: Vec<Vec<u8>>,
    /// File data blocks (metadata mode only), from DATA_BASE on.
    data: Vec<Vec<u8>>,
    next_id: u64,
}

impl Writer {
    fn meta_ref(&self) -> u16 {
        u16::from(self.o.metadata)
    }

    fn alloc_meta(&mut self, n: usize) -> u32 {
        let at = self.meta.len() as u32;
        self.meta.extend((0..n.max(1)).map(|_| vec![0u8; self.o.bs]));
        at
    }

    /// Room for `len` bytes of file data in the data partition.
    fn alloc_data(&mut self, len: usize) -> u32 {
        let n = len.div_ceil(self.o.bs).max(1);
        if self.o.metadata {
            let at = DATA_BASE + self.data.len() as u32;
            self.data.extend((0..n).map(|_| vec![0u8; self.o.bs]));
            at
        } else {
            self.alloc_meta(n)
        }
    }

    fn write_data(&mut self, lbn: u32, bytes: &[u8]) {
        let bs = self.o.bs;
        for (i, chunk) in bytes.chunks(bs).enumerate() {
            let blk = if self.o.metadata { &mut self.data[(lbn - DATA_BASE) as usize + i] } else { &mut self.meta[lbn as usize + i] };
            blk[..chunk.len()].copy_from_slice(chunk);
        }
    }

    fn long_ad(len: u64, lbn: u32, part: u16) -> Vec<u8> {
        let mut v = vec![0u8; 16];
        put32(&mut v, 0, len as u32);
        put32(&mut v, 4, lbn);
        put16(&mut v, 8, part);
        v
    }

    /// Stores file data; returns (allocation type, descriptors).
    fn store(&mut self, data: &[u8], style: Style) -> (u16, Vec<u8>) {
        let bs = self.o.bs;
        let dref = 0u16;
        match style {
            Style::Inline => (3, data.to_vec()),
            Style::Short => {
                // short_ads point into the entry's own partition.
                let lbn = self.alloc_meta(data.len().div_ceil(bs));
                for (i, chunk) in data.chunks(bs).enumerate() {
                    self.meta[lbn as usize + i][..chunk.len()].copy_from_slice(chunk);
                }
                let mut ad = vec![0u8; 8];
                put32(&mut ad, 0, data.len() as u32);
                put32(&mut ad, 4, lbn);
                (0, ad)
            }
            Style::Long => {
                let lbn = self.alloc_data(data.len());
                self.write_data(lbn, data);
                (1, Self::long_ad(data.len() as u64, lbn, dref))
            }
            Style::Split => {
                let cut1 = (data.len() / 3 / bs).max(1) * bs;
                let cut2 = cut1 + (data.len() / 3 / bs).max(1) * bs;
                let mut ads = Vec::new();
                for part in [&data[..cut1], &data[cut1..cut2], &data[cut2..]] {
                    self.alloc_data(bs); // a gap, so the extents aren't adjacent
                    let lbn = self.alloc_data(part.len());
                    self.write_data(lbn, part);
                    ads.extend(Self::long_ad(part.len() as u64, lbn, dref));
                }
                (1, ads)
            }
            Style::Sparse => {
                let (head, tail) = (2 * bs, data.len() - 2 * bs);
                assert!(data[head..tail].iter().all(|&b| b == 0));
                let a = self.alloc_data(head);
                self.write_data(a, &data[..head]);
                let b = self.alloc_data(data.len() - tail);
                self.write_data(b, &data[tail..]);
                let mut ads = Self::long_ad(head as u64, a, dref);
                ads.extend(Self::long_ad(((tail - head) as u64) | (1 << 30), 0, dref));
                ads.extend(Self::long_ad((data.len() - tail) as u64, b, dref));
                (1, ads)
            }
            Style::Chained => {
                let mut ads: Vec<Vec<u8>> = Vec::new();
                for chunk in data.chunks(bs) {
                    self.alloc_data(bs);
                    let lbn = self.alloc_data(chunk.len());
                    self.write_data(lbn, chunk);
                    ads.push(Self::long_ad(chunk.len() as u64, lbn, dref));
                }
                // Two descriptors in the entry, the rest in allocation extent
                // descriptors of three each.
                let mut groups: Vec<Vec<Vec<u8>>> = vec![ads.drain(..2.min(ads.len())).collect()];
                while !ads.is_empty() {
                    groups.push(ads.drain(..3.min(ads.len())).collect());
                }
                let aeds: Vec<u32> = (1..groups.len()).map(|_| self.alloc_meta(1)).collect();
                let mref = self.meta_ref();
                for (g, &at) in aeds.iter().enumerate() {
                    let mut area: Vec<u8> = groups[g + 1].concat();
                    if let Some(&next) = aeds.get(g + 1) {
                        area.extend(Self::long_ad(bs as u64 | (3 << 30), next, mref));
                    }
                    let blk = &mut self.meta[at as usize];
                    put32(blk, 20, area.len() as u32);
                    blk[24..24 + area.len()].copy_from_slice(&area);
                    let len = 24 + area.len();
                    tag(&mut blk[..len], 258, at);
                }
                let mut first: Vec<u8> = groups[0].concat();
                if let Some(&at) = aeds.first() {
                    first.extend(Self::long_ad(bs as u64 | (3 << 30), at, mref));
                }
                (1, first)
            }
        }
    }

    /// Writes a (extended) file entry into metadata block `lbn`.
    fn entry(&mut self, lbn: u32, file_type: u8, ad_type: u16, ads: &[u8], info_len: u64, perms: u32) {
        let efe = self.o.efe;
        let base = if efe { 216 } else { 176 };
        let len = base + ads.len();
        assert!(len <= self.o.bs, "entry too big for a block");
        self.next_id += 1;
        let id = self.next_id;
        let blk = &mut self.meta[lbn as usize];
        put16(blk, 20, 4); // strategy 4
        put16(blk, 24, 1);
        blk[27] = file_type;
        put16(blk, 34, ad_type);
        put32(blk, 36, 1000);
        put32(blk, 40, 1000);
        put32(blk, 44, perms);
        put16(blk, 48, 1);
        put64(blk, 56, info_len);
        if efe {
            put64(blk, 64, info_len);
            stamp(&mut blk[80..]);
            stamp(&mut blk[92..]);
            stamp(&mut blk[104..]);
            regid(&mut blk[168..200], b"*67zip tests", &[]);
            put64(blk, 200, id);
            put32(blk, 212, ads.len() as u32);
        } else {
            stamp(&mut blk[72..]);
            stamp(&mut blk[84..]);
            regid(&mut blk[128..160], b"*67zip tests", &[]);
            put64(blk, 160, id);
            put32(blk, 172, ads.len() as u32);
        }
        blk[base..len].copy_from_slice(ads);
        tag(&mut blk[..len], if efe { 266 } else { 261 }, lbn);
    }

    fn fid(characteristics: u8, name: &[u8], icb: u32, part: u16, bs: usize) -> Vec<u8> {
        let total = (38 + name.len() + 3) & !3;
        let mut f = vec![0u8; total];
        put16(&mut f, 16, 1);
        f[18] = characteristics;
        f[19] = name.len() as u8;
        f[20..36].copy_from_slice(&Self::long_ad(bs as u64, icb, part));
        f[38..38 + name.len()].copy_from_slice(name);
        tag(&mut f, 257, 0);
        f
    }

    /// Writes a folder whose entry goes to `me`; returns nothing, recursing.
    fn folder(&mut self, me: u32, parent: u32, children: &[N]) {
        let mref = self.meta_ref();
        let bs = self.o.bs;
        let mut fids = Self::fid(0x0A, &[], parent, mref, bs);
        let slots: Vec<u32> = children.iter().map(|_| self.alloc_meta(1)).collect();
        for (child, &at) in children.iter().zip(&slots) {
            let (name, ch) = match child {
                N::Dir(n, _) => (n, 0x02),
                N::File(n, ..) | N::Link(n, _) => (n, 0),
            };
            let encoded = if name.is_empty() { vec![] } else { cs0(name) };
            fids.extend(Self::fid(ch, &encoded, at, mref, bs));
        }
        for (child, &at) in children.iter().zip(&slots) {
            match child {
                N::Dir(_, kids) => self.folder(at, me, kids),
                N::File(_, data, style) => {
                    let (t, ads) = self.store(data, *style);
                    self.entry(at, 5, t, &ads, data.len() as u64, 0x14A5);
                }
                N::Link(_, raw) => self.entry(at, 12, 3, raw, raw.len() as u64, 0x7FFF),
            }
        }
        let lbn = self.alloc_meta(fids.len().div_ceil(bs));
        for (i, chunk) in fids.chunks(bs).enumerate() {
            self.meta[lbn as usize + i][..chunk.len()].copy_from_slice(chunk);
        }
        let mut ad = vec![0u8; 8];
        put32(&mut ad, 0, fids.len() as u32);
        put32(&mut ad, 4, lbn);
        self.entry(me, 4, 0, &ad, fids.len() as u64, 0x14A5);
    }
}

/// Builds a UDF image holding `tree`.
fn build(tree: &[N], o: Opts) -> Vec<u8> {
    let bs = o.bs;
    let mut w = Writer { o, meta: Vec::new(), data: Vec::new(), next_id: 16 };
    let fsd = w.alloc_meta(1);
    let root = w.alloc_meta(1);
    w.folder(root, root, tree);
    {
        let mref = w.meta_ref();
        let blk = &mut w.meta[fsd as usize];
        stamp(&mut blk[16..]);
        put16(blk, 28, 3);
        put16(blk, 30, 3);
        dstring(&mut blk[112..240], "67zip test");
        blk[400..416].copy_from_slice(&Writer::long_ad(bs as u64, root, mref));
        regid(&mut blk[416..448], b"*OSTA UDF Compliant", &[0x50, 0x02]);
        tag(&mut blk[..512], 256, fsd);
    }

    // The partition(s): blocks relative to PART_START.
    let mut part: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
    let mut maps = Vec::new();
    maps.extend([1u8, 6, 1, 0, 0, 0]);
    let mut lvd_meta_note = None;
    if o.metadata {
        // Metadata file at block 0, mirror at 1; its blocks in one run, or in
        // two with a gap.
        let n = w.meta.len() as u32;
        let half = n / 2;
        let (run1, run2) = (4u32, 4 + half + if o.fragmented { 3 } else { 0 });
        assert!(run2 + (n - half) < DATA_BASE);
        for (i, blk) in w.meta.iter().enumerate() {
            let i = i as u32;
            part.insert(if i < half { run1 + i } else { run2 + i - half }, blk.clone());
        }
        let mut ads = vec![0u8; 16];
        put32(&mut ads, 0, half * bs as u32);
        put32(&mut ads, 4, run1);
        put32(&mut ads, 8, (n - half) * bs as u32);
        put32(&mut ads, 12, run2);
        if !o.fragmented {
            ads.truncate(8);
            put32(&mut ads, 0, n * bs as u32);
        }
        for (at, ftype) in [(0u32, 250u8), (1, 251)] {
            let mut tmp = Writer { o: Opts { metadata: false, ..o }, meta: vec![vec![0u8; bs]; 2], data: Vec::new(), next_id: 1 };
            tmp.entry(at, ftype, 0, &ads, u64::from(n) * bs as u64, 0);
            part.insert(at, tmp.meta[at as usize].clone());
        }
        for (i, blk) in w.data.iter().enumerate() {
            part.insert(DATA_BASE + i as u32, blk.clone());
        }
        let mut m = vec![0u8; 64];
        m[0] = 2;
        m[1] = 64;
        regid(&mut m[4..36], b"*UDF Metadata Partition", &[0x50, 0x02]);
        put16(&mut m, 36, 1);
        put16(&mut m, 38, 0);
        put32(&mut m, 40, 0);
        put32(&mut m, 44, 1);
        put32(&mut m, 48, u32::MAX);
        put32(&mut m, 52, 32);
        put16(&mut m, 56, 1);
        maps.extend(m);
        lvd_meta_note = Some(());
    } else {
        for (i, blk) in w.meta.iter().enumerate() {
            part.insert(i as u32, blk.clone());
        }
    }
    let part_len = part.keys().last().map_or(1, |k| k + 1);
    let sectors = (PART_START + part_len + 16) as usize;
    let mut img = vec![0u8; sectors * bs];

    // Volume recognition sequence, 2048 bytes per descriptor.
    for (i, id) in [b"BEA01", b"NSR03", b"TEA01"].iter().enumerate() {
        let at = 32768 + i * 2048;
        img[at + 1..at + 6].copy_from_slice(*id);
        img[at + 6] = 1;
    }
    let sector = |img: &mut Vec<u8>, n: u32, f: &dyn Fn(&mut [u8])| {
        let at = n as usize * bs;
        f(&mut img[at..at + bs]);
    };
    for seq in [MAIN_VDS, RESERVE_VDS] {
        sector(&mut img, seq, &|b| {
            dstring(&mut b[24..56], "67ZIP_TEST");
            tag(&mut b[..512], 1, seq);
        });
        sector(&mut img, seq + 1, &|b| {
            put16(b, 20, 1);
            put16(b, 22, 0);
            regid(&mut b[24..56], b"+NSR03", &[]);
            put32(b, 184, 1);
            put32(b, 188, PART_START);
            put32(b, 192, part_len);
            tag(&mut b[..512], 5, seq + 1);
        });
        let maps = maps.clone();
        let meta = lvd_meta_note.is_some();
        sector(&mut img, seq + 2, &|b| {
            dstring(&mut b[84..212], "67zip test volume");
            put32(b, 212, bs as u32);
            regid(&mut b[216..248], b"*OSTA UDF Compliant", if meta { &[0x50, 0x02] } else { &[0x01, 0x02] });
            b[248..264].copy_from_slice(&Writer::long_ad(bs as u64, 0, u16::from(meta)));
            put32(b, 264, maps.len() as u32);
            put32(b, 268, if meta { 2 } else { 1 });
            b[440..440 + maps.len()].copy_from_slice(&maps);
            let len = 440 + maps.len();
            tag(&mut b[..len], 6, seq + 2);
        });
        sector(&mut img, seq + 3, &|b| tag(&mut b[..512], 8, seq + 3));
    }
    // Anchors at sector 256 and in the last sector (UDF wants two of three).
    let last = (sectors - 1) as u32;
    for at in [256, last] {
        sector(&mut img, at, &|b| {
            put32(b, 16, 4 * bs as u32);
            put32(b, 20, MAIN_VDS);
            put32(b, 24, 4 * bs as u32);
            put32(b, 28, RESERVE_VDS);
            tag(&mut b[..512], 2, at);
        });
    }
    for (lbn, blk) in part {
        let at = (PART_START + lbn) as usize * bs;
        img[at..at + bs].copy_from_slice(&blk);
    }
    img
}

// ----- helpers ---------------------------------------------------------------

fn sample_tree(bs: usize) -> (Vec<N>, BTreeMap<String, Vec<u8>>) {
    let mut sparse = noise(2 * bs, 3);
    sparse.extend(vec![0u8; 5 * bs]);
    sparse.extend(noise(bs + 123, 4));
    let files: Vec<(&str, Vec<u8>, Style)> = vec![
        ("short.txt", b"short and sweet\n".repeat(300), Style::Short),
        ("long.bin", noise(3 * bs + 17, 1), Style::Long),
        ("tiny.txt", b"inline!".to_vec(), Style::Inline),
        ("split.bin", noise(7 * bs + 5, 2), Style::Split),
        ("sparse.bin", sparse, Style::Sparse),
        ("chained.bin", noise(9 * bs - 1, 5), Style::Chained),
        ("empty", Vec::new(), Style::Long),
    ];
    let mut expect = BTreeMap::new();
    let mut top = Vec::new();
    for (name, data, style) in files {
        expect.insert(name.to_string(), data.clone());
        top.push(file(name, data, style));
    }
    let uni = "Ünïcødé ♠ 名前 – a name longer than sixty-four characters, as UDF allows.txt";
    expect.insert(format!("folder/{uni}"), b"unicode".to_vec());
    expect.insert("folder/deeper/more.txt".into(), b"more".to_vec());
    top.push(dir("folder", vec![file(uni, b"unicode".to_vec(), Style::Long), dir("deeper", vec![file("more.txt", b"more".to_vec(), Style::Short)])]));
    // A symlink "../short.txt": parent, then a name.
    let mut link = vec![3, 0, 0, 0, 5, 10, 0, 0];
    link.extend(cs0("short.txt"));
    top.push(N::Link("link".into(), link));
    (top, expect)
}

fn read_back(img: &Path) -> (BTreeMap<String, Vec<u8>>, Vec<String>, zip67_core::archive::ArchiveInfo) {
    let dir = tempfile::tempdir().unwrap();
    let rep = extract_all(img, dir.path(), None);
    let mut files = BTreeMap::new();
    for e in walkdir(dir.path()) {
        files.insert(e.strip_prefix(dir.path()).unwrap().to_string_lossy().into_owned(), fs::read(&e).unwrap());
    }
    let errors = rep.errors.iter().map(|e| format!("{e:?}")).collect();
    let info = open(img, &OpenOptions::default()).unwrap().info();
    (files, errors, info)
}

fn walkdir(p: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for e in fs::read_dir(p).unwrap() {
        let path = e.unwrap().path();
        let m = fs::symlink_metadata(&path).unwrap();
        if m.is_dir() {
            out.extend(walkdir(&path));
        } else if m.is_file() {
            out.push(path);
        }
    }
    out
}

fn write(dir: &Path, name: &str, img: &[u8]) -> std::path::PathBuf {
    let p = dir.join(name);
    fs::write(&p, img).unwrap();
    p
}

// ----- tests -----------------------------------------------------------------

#[test]
fn reads_every_layout() {
    let tmp = tempfile::tempdir().unwrap();
    for (bs, metadata, efe) in [(2048, false, false), (2048, false, true), (2048, true, true), (512, false, false), (512, true, true), (4096, false, true)] {
        let (tree, expect) = sample_tree(bs);
        let img = write(tmp.path(), &format!("t-{bs}-{metadata}-{efe}.img"), &build(&tree, Opts { bs, metadata, efe, fragmented: true }));
        let what = format!("bs {bs}, metadata {metadata}, efe {efe}");
        let r = open(&img, &OpenOptions::default()).unwrap_or_else(|e| panic!("{what}: {e}"));
        assert_eq!(r.archive_type().id(), "iso");
        let info = r.info();
        assert!(info.methods[0].starts_with(if metadata { "UDF 2.50" } else { "UDF 2.01" }), "{what}: {:?}", info.methods);
        assert!(info.problems.is_empty(), "{what}: {:?}", info.problems);
        let link = r.entries().iter().find(|e| e.path == "link").unwrap();
        assert_eq!((link.kind, link.link_target.as_deref()), (EntryKind::Symlink, Some("../short.txt")));
        let short = r.entries().iter().find(|e| e.path == "short.txt").unwrap();
        assert_eq!(short.mtime, Some(STAMP));
        assert_eq!(short.mode, Some(0o555));
        let (files, errors, _) = read_back(&img);
        // The link points outside the extraction folder, so it is refused.
        assert!(errors.len() <= 1, "{what}: {errors:?}");
        assert_eq!(files.keys().collect::<Vec<_>>(), expect.keys().collect::<Vec<_>>(), "{what}");
        for (name, data) in &expect {
            assert!(files[name] == *data, "{what}: {name} differs");
        }
        // Cross-check the writer with 7-Zip. It refuses whole images that hold
        // a symlink and can't read sparse or continued extents, fragmented
        // metadata files or 4096-byte sectors, so those are left out;
        // everything else must come out byte for byte.
        if let (Some(sz), true) = (seven_zip(), bs <= 2048) {
            let (mut tree, mut expect) = sample_tree(bs);
            tree.retain(|n| !matches!(n, N::Link(..) | N::File(_, _, Style::Sparse | Style::Chained)));
            expect.retain(|k, _| k != "sparse.bin" && k != "chained.bin");
            let plain = write(tmp.path(), "for-7z.img", &build(&tree, Opts { bs, metadata, efe, fragmented: false }));
            let out_dir = tmp.path().join(format!("7z-{bs}-{metadata}-{efe}"));
            let out = Command::new(sz).args(["x", "-y"]).arg(format!("-o{}", out_dir.display())).arg(&plain).output().unwrap();
            assert!(out.status.success(), "{what}: 7-Zip says\n{}", String::from_utf8_lossy(&out.stdout));
            for (name, data) in &expect {
                assert!(fs::read(out_dir.join(name)).unwrap() == *data, "{what}: 7-Zip reads {name} differently");
            }
        }
    }
}

#[test]
fn damage_is_contained() {
    let tmp = tempfile::tempdir().unwrap();
    let o = Opts { bs: 2048, metadata: true, efe: true, fragmented: true };
    let (tree, _) = sample_tree(o.bs);
    let good = build(&tree, o);
    let part = PART_START as usize * o.bs;

    // Broken metadata file: the mirror copy takes over.
    let mut img = good.clone();
    img[part + 4] ^= 0xFF;
    let p = write(tmp.path(), "mirror.img", &img);
    let (files, _, info) = read_back(&p);
    assert!(files.contains_key("split.bin"));
    assert!(info.problems.iter().any(|m| m.contains("mirror")), "{:?}", info.problems);

    // Broken main volume descriptors: the reserve sequence takes over.
    let mut img = good.clone();
    img[(MAIN_VDS as usize + 2) * o.bs + 4] ^= 0xFF;
    let p = write(tmp.path(), "reserve.img", &img);
    let (files, _, info) = read_back(&p);
    assert!(files.contains_key("folder/deeper/more.txt"));
    assert!(info.problems.iter().any(|m| m.contains("reserve")), "{:?}", info.problems);

    // Everything damaged: a clean error, no panic.
    let mut img = good.clone();
    img[(MAIN_VDS as usize + 2) * o.bs + 4] ^= 0xFF;
    img[(RESERVE_VDS as usize + 2) * o.bs + 4] ^= 0xFF;
    let p = write(tmp.path(), "dead.img", &img);
    assert!(open(&p, &OpenOptions::default()).is_err());
}

#[test]
fn hostile_folders() {
    let tmp = tempfile::tempdir().unwrap();
    let o = Opts { bs: 2048, metadata: false, efe: false, fragmented: false };
    // Names that try to climb out or hide a slash, and a folder that
    // contains its own ancestor (made by patching a normal image).
    let tree = vec![
        file("..", b"climb".to_vec(), Style::Long),
        file("a/b", b"slash".to_vec(), Style::Long),
        file("ok.txt", b"fine".to_vec(), Style::Long),
        dir("loop", vec![file("inside.txt", b"in".to_vec(), Style::Short)]),
    ];
    let mut img = build(&tree, o);
    // Rewrite "inside.txt"'s FID into a folder that is the root (block 1).
    let bs = o.bs;
    let part = PART_START as usize * bs;
    let needle = cs0("inside.txt");
    let pos = img[part..].windows(needle.len()).position(|w| w == needle.as_slice()).unwrap() + part;
    let fid = pos - 38;
    img[fid + 18] = 0x02;
    put32(&mut img, fid + 24, 1);
    let total = (38 + needle.len() + 3) & !3;
    let mut d = img[fid..fid + total].to_vec();
    tag(&mut d, 257, u32::from_le_bytes(img[fid + 12..fid + 16].try_into().unwrap()));
    img[fid..fid + total].copy_from_slice(&d);
    let p = write(tmp.path(), "hostile.img", &img);
    let r = open(&p, &OpenOptions::default()).unwrap();
    let names: Vec<&str> = r.entries().iter().map(|e| e.path.as_str()).collect();
    assert!(!names.iter().any(|n| n.split('/').any(|c| c == "..")), "{names:?}");
    assert!(names.contains(&"a_b") && names.contains(&"ok.txt"), "{names:?}");
    // The loop shows up as a folder once and is not followed forever.
    assert!(names.contains(&"loop/inside.txt"), "{names:?}");
    assert!(names.len() < 20, "{names:?}");
    assert!(r.info().problems.iter().any(|m| m.contains("invalid names")));
    let (files, _, _) = read_back(&p);
    assert_eq!(files.get("ok.txt").map(Vec::as_slice), Some(&b"fine"[..]));
}

#[test]
fn huge_sparse_file_is_listed_not_trusted() {
    let tmp = tempfile::tempdir().unwrap();
    let o = Opts { bs: 2048, metadata: false, efe: true, fragmented: false };
    // 100 unrecorded extents of almost 1 GiB: about 100 GiB of "zeros".
    let tree = vec![file("small.txt", b"x".to_vec(), Style::Long)];
    let mut img = build(&tree, o);
    let bs = o.bs;
    let part = PART_START as usize * bs;
    // Find small.txt's entry (EFE, tag 266) and turn it into the bomb.
    let mut fe_at = None;
    for b in 0..(img.len() - part) / bs {
        let at = part + b * bs;
        if u16::from_le_bytes([img[at], img[at + 1]]) == 266 && img[at + 27] == 5 {
            fe_at = Some((at, b as u32));
        }
    }
    let (at, lbn) = fe_at.unwrap();
    let ads_per_block = 100;
    let mut ads = Vec::new();
    for _ in 0..ads_per_block {
        ads.extend(Writer::long_ad(0x3FFF_F800 | (1 << 30), 0, 0));
    }
    let mut blk = vec![0u8; bs];
    let base = 216;
    blk[..base].copy_from_slice(&img[at..at + base]);
    let size = 0x3FFF_F800u64 * ads_per_block as u64;
    put64(&mut blk, 56, size);
    put32(&mut blk, 212, ads.len() as u32);
    blk[base..base + ads.len()].copy_from_slice(&ads);
    tag(&mut blk[..base + ads.len()], 266, lbn);
    img[at..at + bs].copy_from_slice(&blk);
    let p = write(tmp.path(), "bomb.img", &img);
    let r = open(&p, &OpenOptions::default()).unwrap();
    let e = r.entries().iter().find(|e| e.path == "small.txt").unwrap();
    assert_eq!(e.size, size);
    assert_eq!(e.packed_size, Some(0));
}

#[test]
fn genisoimage_bridge_uses_udf() {
    if Command::new("genisoimage").arg("--version").output().is_err() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let src = make_tree(tmp.path());
    let iso = tmp.path().join("bridge.iso");
    let st = Command::new("genisoimage").args(["-quiet", "-udf", "-input-charset", "utf-8", "-o"]).arg(&iso).arg(&src).status().unwrap();
    assert!(st.success());
    let r = open(&iso, &OpenOptions::default()).unwrap();
    assert!(r.info().methods[0].contains("UDF") && r.info().methods[0].contains("ISO 9660"), "{:?}", r.info().methods);
    let (files, errors, _) = read_back(&iso);
    assert!(errors.is_empty(), "{errors:?}");
    // UDF keeps the full Unicode names that plain ISO 9660 would shorten.
    for name in ["hello.txt", "sub/random.bin", "sub/deeper/ünïcödé 名前.txt", "run.sh"] {
        assert_eq!(files.get(name), Some(&fs::read(src.join(name)).unwrap()), "{name}");
    }
}

#[test]
fn mkudffs_volumes_open() {
    if Command::new("mkudffs").arg("--help").output().is_err() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    for (rev, bs, media) in [("1.02", 2048, "hd"), ("1.50", 512, "hd"), ("2.01", 2048, "hd"), ("2.01", 4096, "hd"), ("2.01", 2048, "dvdrw")] {
        let img = tmp.path().join(format!("m-{rev}-{bs}-{media}.img"));
        let st = Command::new("mkudffs")
            .arg(format!("--media-type={media}"))
            .arg(format!("--udfrev={rev}"))
            .arg(format!("--blocksize={bs}"))
            .arg("--label=Empty")
            .arg(&img)
            .arg("3000")
            .output()
            .unwrap();
        assert!(st.status.success());
        let r = open(&img, &OpenOptions::default()).unwrap_or_else(|e| panic!("{rev}/{bs}/{media}: {e}"));
        assert!(r.entries().is_empty());
        assert!(r.info().methods[0].starts_with(&format!("UDF {rev}")), "{:?}", r.info().methods);
    }
}

/// Writes sample images (fuzzing seeds): `UDF_DUMP=dir cargo test --test udf -- --ignored`.
#[test]
#[ignore]
fn dump_sample_images() {
    let dir = std::env::var("UDF_DUMP").unwrap();
    for (bs, metadata, efe, fragmented) in [(512, false, false, false), (512, true, true, true), (512, false, true, false), (2048, true, true, false)] {
        let (tree, _) = sample_tree(bs);
        fs::write(Path::new(&dir).join(format!("s-{bs}-{metadata}-{efe}.img")), build(&tree, Opts { bs, metadata, efe, fragmented })).unwrap();
    }
}
