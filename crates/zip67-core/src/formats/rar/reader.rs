//! `RarReader`: joins the headers of all volumes into one list of files,
//! and decodes them (solid streams in order, each file checked against its
//! CRC-32 or BLAKE2sp).

use std::collections::HashMap;
use std::io::{self, Read, Seek, SeekFrom};
use std::sync::{Arc, Mutex};

use super::blake2sp::Blake2sp;
use super::crypto::{self, Keys5};
use super::unpack::{FileDecoder, Unpacker, window_size};
use super::{Crypt, FileRec, KeyCache, Link, Version, VolumeHeaders, rar4, rar5};
use crate::archive::{ArchiveInfo, ArchiveReader, EntryVisitor, OpenOptions};
use crate::cipher::{AesKey, CbcDecryptReader};
use crate::detect::ArchiveType;
use crate::entry::{Entry, EntryKind};
use crate::error::{Error, Result};
use crate::io::{Progressed, ReadSeek, TakeExact};
use crate::limits::Limits;
use crate::password::Password;
use crate::progress::Progress;
use crate::util::normalize_path;

type SharedSrc = Arc<Mutex<Box<dyn ReadSeek>>>;

#[derive(Clone, Debug)]
struct Segment {
    vol: usize,
    offset: u64,
    len: u64,
}

struct Item {
    rec: FileRec,
    segs: Vec<Segment>,
    /// Why the data cannot be read (a volume is missing).
    missing: Option<String>,
}

pub struct RarReader {
    vols: Vec<SharedSrc>,
    items: Vec<Item>,
    entries: Vec<Entry>,
    /// Solid stream of each compressed item.
    groups: Vec<Option<usize>>,
    /// Dictionary to allocate for each solid stream.
    group_window: HashMap<usize, u64>,
    rar5: bool,
    password: Option<Password>,
    limits: Limits,
    keys: KeyCache,
    info: ArchiveInfo,
}

/// Reads the data segments of one file, across volumes.
struct SegReader {
    vols: Vec<SharedSrc>,
    segs: Vec<Segment>,
    idx: usize,
    off: u64,
}

impl Read for SegReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while self.idx < self.segs.len() && self.off >= self.segs[self.idx].len {
            self.idx += 1;
            self.off = 0;
        }
        let Some(s) = self.segs.get(self.idx) else { return Ok(0) };
        if buf.is_empty() {
            return Ok(0);
        }
        let n = buf.len().min((s.len - self.off).min(usize::MAX as u64) as usize);
        let vol = self.vols.get(s.vol).ok_or_else(|| io::Error::other("bad volume"))?;
        let mut src = vol.lock().map_err(|_| io::Error::other("volume lock"))?;
        src.seek(SeekFrom::Start(s.offset + self.off))?;
        let got = src.read(&mut buf[..n])?;
        if got == 0 {
            return Err(Error::corrupt("RAR data ends early (incomplete download?)").into());
        }
        self.off += got as u64;
        Ok(got)
    }
}

/// Checks CRC-32 and/or BLAKE2sp at the end of a file's data.
struct RarCheck<R> {
    inner: R,
    crc: crc32fast::Hasher,
    blake: Option<Blake2sp>,
    want_crc: Option<u32>,
    want_blake: Option<[u8; 32]>,
    mac: Option<Arc<Keys5>>,
    /// Encrypted without a way to check the password first: a mismatch
    /// most likely means a wrong password.
    unverified: bool,
    name: String,
    done: bool,
}

impl<R: Read> Read for RarCheck<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.done {
            return Ok(0);
        }
        let n = self.inner.read(buf)?;
        if n == 0 && !buf.is_empty() {
            self.done = true;
            let mut ok = true;
            if let Some(w) = self.want_crc {
                let mut got = self.crc.clone().finalize();
                if let Some(k) = &self.mac {
                    got = crypto::crc_mac(got, &k.hash_key);
                }
                ok &= got == w;
            }
            if let (Some(w), Some(b)) = (self.want_blake, self.blake.take()) {
                let mut got = b.finalize();
                if let Some(k) = &self.mac {
                    got = crypto::blake2_mac(&got, &k.hash_key);
                }
                ok &= got == w;
            }
            if !ok {
                return Err(if self.unverified { Error::WrongPassword } else { Error::Checksum(self.name.clone()) }.into());
            }
            return Ok(0);
        }
        self.crc.update(&buf[..n]);
        if let Some(b) = self.blake.as_mut() {
            b.update(&buf[..n]);
        }
        Ok(n)
    }
}

fn dict_text(d: u64) -> String {
    if d >= 1 << 30 && d.is_multiple_of(1 << 30) {
        format!("{}G", d >> 30)
    } else if d >= 1 << 20 && d.is_multiple_of(1 << 20) {
        format!("{}M", d >> 20)
    } else {
        format!("{}K", d >> 10)
    }
}

fn method_text(r: &FileRec) -> Option<String> {
    if r.dir || matches!(r.link, Link::Symlink(_) | Link::Hardlink(_) | Link::Copy(_)) {
        return None;
    }
    if r.method == 0 {
        return Some("Store".into());
    }
    let v = match r.version {
        Version::V5 { alg: 0 } => "RAR5".to_string(),
        Version::V5 { alg } => format!("RAR5 v{alg}"),
        Version::V3 { unp_ver } if unp_ver >= 29 => "RAR3".to_string(),
        Version::V3 { unp_ver } if unp_ver >= 20 => "RAR2".to_string(),
        Version::V3 { .. } => "RAR1.5".to_string(),
    };
    Some(format!("{v}:m{}:{}", r.method, dict_text(r.dict)))
}

fn clone_err(e: &Error) -> Error {
    match e {
        Error::WrongPassword => Error::WrongPassword,
        Error::PasswordRequired => Error::PasswordRequired,
        Error::Checksum(s) => Error::Checksum(s.clone()),
        Error::Unsupported(s) => Error::Unsupported(s.clone()),
        Error::LimitExceeded(s) => Error::LimitExceeded(s.clone()),
        Error::Corrupt(s) => Error::Corrupt(s.clone()),
        other => Error::Corrupt(other.to_string()),
    }
}

fn has_stream(r: &FileRec) -> bool {
    !r.dir && !matches!(r.link, Link::Symlink(_) | Link::Hardlink(_) | Link::Copy(_))
}

/// Finds where the archive may start: the signature at offset 0, or the
/// signatures inside a self-extracting program. Returns (offset, RAR5).
fn locate(src: &mut dyn ReadSeek, size: u64) -> Result<Vec<(u64, bool)>> {
    src.seek(SeekFrom::Start(0))?;
    let mut head = vec![0u8; size.min(4 << 20) as usize];
    let n = crate::io::read_full(src, &mut head)?;
    head.truncate(n);
    let kind = |p: usize| -> Option<bool> {
        if head.get(p..p + 8) == Some(&rar5::SIGNATURE[..]) {
            Some(true)
        } else if head.get(p..p + 7) == Some(&rar4::SIGNATURE[..]) {
            Some(false)
        } else {
            None
        }
    };
    if let Some(is5) = kind(0) {
        return Ok(vec![(0, is5)]);
    }
    if super::find_sfx_signature(&head).is_none() {
        return Ok(Vec::new());
    }
    let mut found = Vec::new();
    for (p, w) in head.windows(6).enumerate() {
        if w == b"Rar!\x1a\x07"
            && let Some(is5) = kind(p)
        {
            found.push((p as u64, is5));
            if found.len() >= 16 {
                break;
            }
        }
    }
    Ok(found)
}

fn read_headers(src: &mut dyn ReadSeek, size: u64, start: u64, is5: bool, opts: &OpenOptions, keys: &mut KeyCache) -> Result<VolumeHeaders> {
    let pw = opts.password.as_ref();
    if is5 {
        rar5::read_volume(src, size, start + 8, pw, keys, opts.limits.max_entries)
    } else {
        rar4::read_volume(src, size, start + 7, pw, keys, opts.limits.max_entries)
    }
}

impl RarReader {
    pub fn open(src: Box<dyn ReadSeek>, size: u64, opts: &OpenOptions) -> Result<Self> {
        Self::open_volumes(vec![(src, size)], opts)
    }

    /// Opens a multi-volume archive from its parts, in order.
    pub fn open_volumes(parts: Vec<(Box<dyn ReadSeek>, u64)>, opts: &OpenOptions) -> Result<Self> {
        let mut keys = KeyCache::default();
        let mut vols: Vec<SharedSrc> = Vec::new();
        let mut items: Vec<Item> = Vec::new();
        let mut pending: Option<usize> = None;
        let mut info = ArchiveInfo::default();
        let mut rar5 = false;
        let mut comment: Option<(usize, FileRec)> = None;
        let total = parts.len();
        let mut next_missing = false;
        for (vi, (mut src, size)) in parts.into_iter().enumerate() {
            let (start, is5, vh) = if vi == 0 {
                let candidates = locate(src.as_mut(), size)?;
                let mut res = None;
                let mut first_err = None;
                for (off, is5) in candidates {
                    match read_headers(src.as_mut(), size, off, is5, opts, &mut keys) {
                        Ok(vh) => {
                            res = Some((off, is5, vh));
                            break;
                        }
                        Err(e) if off == 0 || e.is_password_problem() => return Err(e),
                        Err(e) => {
                            first_err.get_or_insert(e);
                        }
                    }
                }
                match res {
                    Some(r) => r,
                    None => return Err(first_err.unwrap_or(Error::UnsupportedFormat)),
                }
            } else {
                let mut sig = [0u8; 8];
                src.seek(SeekFrom::Start(0))?;
                let n = crate::io::read_full(src.as_mut(), &mut sig)?;
                let is5 = n == 8 && &sig == rar5::SIGNATURE;
                if !is5 && !(n >= 7 && &sig[..7] == rar4::SIGNATURE) || is5 != rar5 {
                    info.problems.push(format!("part {} is not a volume of this archive", vi + 1));
                    next_missing = true;
                    break;
                }
                match read_headers(src.as_mut(), size, 0, is5, opts, &mut keys) {
                    Ok(vh) => (0, is5, vh),
                    Err(e) if e.is_password_problem() => return Err(e),
                    Err(e) => {
                        info.problems.push(format!("part {}: {e}", vi + 1));
                        next_missing = true;
                        break;
                    }
                }
            };
            if vi == 0 {
                rar5 = is5;
                info.offset = start;
                info.solid = vh.solid;
                info.encrypted_headers = vh.encrypted_headers;
                comment = vh.comment.clone().map(|c| (0, c));
            }
            info.physical_size += size;
            info.problems.extend(vh.warnings.iter().cloned());
            if vh.truncated && !vh.ended {
                info.problems.push(if vols.is_empty() {
                    "the archive ends unexpectedly (incomplete download?); files after that point are missing".to_string()
                } else {
                    format!("part {} of the archive ends unexpectedly (incomplete download?)", vi + 1)
                });
            }
            for rec in vh.files {
                if items.len() as u64 >= opts.limits.max_entries {
                    return Err(Error::limit("too many entries"));
                }
                if rec.name.len() > opts.limits.max_path_len {
                    return Err(Error::limit("entry name too long"));
                }
                let seg = Segment { vol: vi, offset: rec.data_offset, len: rec.data_len };
                let cut = rec.truncated && !rec.split_after;
                if rec.split_before {
                    if let Some(p) = pending.filter(|&p| items[p].rec.name == rec.name) {
                        let it = &mut items[p];
                        it.segs.push(seg);
                        it.rec.crc = rec.crc;
                        it.rec.blake2 = rec.blake2;
                        it.rec.split_after = rec.split_after;
                        if cut {
                            it.missing = Some("the archive ends inside this file's data (incomplete download?)".into());
                        }
                        pending = rec.split_after.then_some(p);
                        continue;
                    }
                    if let Some(p) = pending.take() {
                        items[p].missing = Some("the rest of this file is missing from the next part".into());
                    }
                    let after = rec.split_after;
                    items.push(Item { rec, segs: vec![seg], missing: Some("this file starts in an earlier part of the archive, which was not found".into()) });
                    pending = after.then_some(items.len() - 1);
                    continue;
                }
                if let Some(p) = pending.take() {
                    items[p].missing = Some("the rest of this file is missing from the next part".into());
                }
                let after = rec.split_after;
                let missing = cut.then(|| "the archive ends inside this file's data (incomplete download?)".to_string());
                items.push(Item { rec, segs: vec![seg], missing });
                if after {
                    pending = Some(items.len() - 1);
                }
            }
            vols.push(Arc::new(Mutex::new(src)));
            let continues = vh.more_volumes || (vh.volume && !vh.ended);
            if !continues {
                break;
            }
            if vi + 1 == total {
                next_missing = true;
            }
        }
        info.volumes = vols.len() as u32;
        if let Some(p) = pending {
            items[p].missing = Some(format!("this file continues in part {} of the archive, which is missing", vols.len() + 1));
        }
        if next_missing && pending.is_none() {
            info.problems.push(format!("the archive continues in part {}, which is missing", vols.len() + 1));
        }

        // Entries, solid streams.
        let mut entries = Vec::with_capacity(items.len());
        let mut groups = vec![None; items.len()];
        let mut group_dict: HashMap<usize, (u64, Option<u64>)> = HashMap::new();
        let mut cur: Option<usize> = None;
        let mut next_group = 0usize;
        let mut methods: Vec<String> = Vec::new();
        for (i, it) in items.iter().enumerate() {
            let r = &it.rec;
            if has_stream(r) && r.method != 0 {
                let g = match cur {
                    Some(g) if r.solid => g,
                    _ => {
                        next_group += 1;
                        next_group
                    }
                };
                cur = Some(g);
                groups[i] = Some(g);
                let e = group_dict.entry(g).or_insert((0, Some(0)));
                e.0 = e.0.max(r.dict);
                e.1 = match (e.1, r.size_known) {
                    (Some(t), true) => t.checked_add(r.size),
                    _ => None,
                };
            }
            let ftype = if r.unix { r.attr & 0o170000 } else { 0 };
            let kind = if r.dir {
                EntryKind::Dir
            } else {
                match r.link {
                    Link::Symlink(_) | Link::InData => EntryKind::Symlink,
                    Link::Hardlink(_) => EntryKind::Hardlink,
                    Link::Copy(_) => EntryKind::File,
                    Link::None if matches!(ftype, 0o010000 | 0o020000 | 0o060000 | 0o140000) => EntryKind::Special,
                    Link::None => EntryKind::File,
                }
            };
            let (path, unsafe_path) = normalize_path(&r.name);
            let mut e = Entry::new(i, path, kind);
            e.unsafe_path = unsafe_path;
            e.size = if has_stream(r) || matches!(r.link, Link::Copy(_)) { r.size } else { 0 };
            e.size_known = r.size_known;
            e.packed_size = Some(it.segs.iter().map(|s| s.len).sum());
            if let Some((s, ns)) = r.mtime {
                e.mtime = Some(s);
                e.mtime_nanos = ns;
            }
            e.mode = Some(if r.unix {
                (r.attr & 0o7777) as u32
            } else if r.attr & 1 != 0 {
                if r.dir { 0o555 } else { 0o444 }
            } else if r.dir {
                0o755
            } else {
                0o644
            });
            let mac = matches!(r.crypt, Some(Crypt::V5 { mac: true, .. }));
            e.crc32 = if mac || it.missing.is_some() { None } else { r.crc };
            e.encrypted = r.crypt.is_some();
            e.method = method_text(r);
            e.link_target = match &r.link {
                Link::Symlink(t) | Link::Hardlink(t) | Link::Copy(t) => Some(t.clone()),
                _ => None,
            };
            if info.solid {
                e.block = groups[i].map(|g| g as u32);
            }
            if let Some(m) = &e.method
                && !methods.contains(m)
            {
                methods.push(m.clone());
            }
            entries.push(e);
        }
        methods.sort();
        info.methods = methods;
        info.blocks = next_group as u64;
        info.encrypted_data = items.iter().any(|i| i.rec.crypt.is_some());
        info.format = if rar5 { "RAR5".into() } else { "RAR".into() };
        let group_window = group_dict.into_iter().map(|(g, (d, total))| (g, window_size(d, total))).collect();

        let mut reader =
            RarReader { vols, items, entries, groups, group_window, rar5, password: opts.password.clone(), limits: opts.limits.clone(), keys, info };
        if let Some((_, rec)) = comment
            && let Ok(bytes) = reader.read_comment(rec)
        {
            let text = if rar5 { String::from_utf8_lossy(&bytes).into_owned() } else { crate::util::decode_name(&bytes) };
            let text = text.trim_end_matches('\0').trim().to_string();
            if !text.is_empty() {
                reader.info.comment = Some(text);
            }
        }
        Ok(reader)
    }

    fn read_comment(&mut self, rec: FileRec) -> Result<Vec<u8>> {
        if rec.crypt.is_some() || !rec.size_known || rec.size > 1 << 20 {
            return Err(Error::unsupported("comment"));
        }
        let item = Item { segs: vec![Segment { vol: 0, offset: rec.data_offset, len: rec.data_len }], rec, missing: None };
        let (stream, _, _) = data_stream(&mut self.keys, &self.vols, self.password.as_ref(), &item)?;
        let mut out = Vec::new();
        if item.rec.method == 0 {
            TakeExact::new(stream, item.rec.size).read_to_end(&mut out)?;
        } else {
            let mut up = Unpacker::new(self.rar5, self.limits.max_decoder_memory);
            up.begin(false, window_size(item.rec.dict, Some(item.rec.size)))?;
            FileDecoder::new(&mut up, stream, Some(item.rec.size)).read_to_end(&mut out)?;
        }
        Ok(out)
    }
}

/// The (decrypted) packed data of an item. Also returns whether the
/// password was verified, and the key for checksum MACs.
/// Packed data, whether the password was verified, and the MAC key.
type DataStream = (Box<dyn Read + Send>, bool, Option<Arc<Keys5>>);

fn data_stream(keys: &mut KeyCache, vols: &[SharedSrc], pw: Option<&Password>, item: &Item) -> Result<DataStream> {
    let seg = SegReader { vols: vols.to_vec(), segs: item.segs.clone(), idx: 0, off: 0 };
    let Some(crypt) = &item.rec.crypt else { return Ok((Box::new(seg), true, None)) };
    if let Crypt::Unknown(what) = crypt {
        return Err(Error::unsupported(what.clone()));
    }
    let Some(pw) = pw else { return Err(Error::PasswordRequired) };
    match crypt {
        Crypt::V5 { lg2, salt, iv, check, mac } => {
            if *lg2 > crypto::MAX_KDF_LG2 {
                return Err(Error::unsupported("RAR5 key derivation count too high"));
            }
            let k = keys.rar5(pw, salt, *lg2);
            let verified = match check {
                Some(c) if *c != k.check => return Err(Error::WrongPassword),
                Some(_) => true,
                None => false,
            };
            let aes = AesKey::new(&k.key[..])?;
            let mac_key = mac.then(|| k.clone());
            Ok((Box::new(CbcDecryptReader::new(seg, aes, *iv)), verified, mac_key))
        }
        Crypt::V3 { salt } => {
            let (key, iv) = keys.rar3(pw, salt.as_ref());
            Ok((Box::new(CbcDecryptReader::new(seg, AesKey::new(&key[..])?, iv)), false, None))
        }
        Crypt::Unknown(_) => Err(Error::unsupported("encryption")),
    }
}

/// Outcome of decoding one file.
enum Done {
    Ok,
    /// The entry failed but the solid stream is intact.
    Entry(Error),
}

impl RarReader {
    /// Decodes item `data` (and delivers it as entry `deliver` when given).
    /// `Err` means the decoder state is lost.
    fn decode_item(
        &mut self,
        data: usize,
        up: &mut Option<Unpacker>,
        solid_continue: bool,
        deliver: Option<usize>,
        visitor: &mut dyn EntryVisitor,
        progress: &Progress,
    ) -> Result<Done> {
        let item = &self.items[data];
        let rec = &item.rec;
        if let Some(m) = &item.missing {
            return Err(Error::corrupt(m.clone()));
        }
        // An empty file needs no decoder unless a solid stream goes on
        // after it.
        let later_in_group = self.groups[data].is_some_and(|g| self.groups[data + 1..].contains(&Some(g)));
        if rec.size_known && rec.size == 0 && !later_in_group && rec.crypt.is_none() && !matches!(rec.link, Link::InData) {
            let Some(d) = deliver else { return Ok(Done::Ok) };
            let mut empty: &[u8] = &[];
            return match visitor.file(&self.entries[d], &mut empty) {
                Ok(()) => Ok(Done::Ok),
                Err(Error::Cancelled) => Err(Error::Cancelled),
                Err(e) => Ok(Done::Entry(e)),
            };
        }
        match rec.version {
            Version::V3 { unp_ver } if unp_ver < 29 && rec.method != 0 => {
                return Err(Error::unsupported("RAR 1.5 / 2.0 compression (archives made before 2000)"));
            }
            Version::V5 { alg } if alg != 0 => return Err(Error::unsupported("RAR 7 compression for dictionaries over 4 GB")),
            _ => {}
        }
        if rec.size_known && rec.size > self.limits.max_total_size {
            return Err(Error::limit("file is larger than the size limit"));
        }
        let (stream, verified, mac) = data_stream(&mut self.keys, &self.vols, self.password.as_ref(), item)?;
        let encrypted = rec.crypt.is_some();
        let expected = rec.size_known.then_some(rec.size);
        let packed: u64 = item.segs.iter().map(|s| s.len).sum();
        let mut window = 0;
        if rec.method != 0 {
            window = self.groups[data].and_then(|g| self.group_window.get(&g).copied()).unwrap_or_else(|| window_size(rec.dict, expected));
        }
        let name = deliver.map(|d| self.entries[d].path.clone()).unwrap_or_default();
        let is_link_data = matches!(rec.link, Link::InData);
        let mut decoder_holder;
        let source: Box<dyn Read + '_> = if rec.method == 0 {
            match expected {
                Some(s) => Box::new(TakeExact::new(stream, s)),
                None => stream,
            }
        } else if packed == 0 {
            if expected.unwrap_or(0) > 0 {
                return Err(Error::corrupt("the compressed data of this file is missing"));
            }
            Box::new(io::empty())
        } else {
            let u = up.get_or_insert_with(|| Unpacker::new(self.rar5, self.limits.max_decoder_memory));
            u.begin(solid_continue, window)?;
            decoder_holder = FileDecoder::new(u, stream, expected);
            Box::new(&mut decoder_holder)
        };
        let mut checked = RarCheck {
            inner: source,
            crc: crc32fast::Hasher::new(),
            blake: rec.blake2.map(|_| Blake2sp::new()),
            want_crc: rec.crc,
            want_blake: rec.blake2,
            mac,
            unverified: encrypted && !verified,
            name,
            done: false,
        };
        let Some(d) = deliver else {
            return match crate::io::drain(&mut checked) {
                Ok(_) => Ok(Done::Ok),
                Err(e) => Err(e.into()),
            };
        };
        let entry = &self.entries[d];
        progress.set_current(&entry.path);
        let res = if is_link_data {
            let mut t = Vec::new();
            match (&mut checked).take(4097).read_to_end(&mut t) {
                Ok(_) if t.len() > 4096 => Err(Error::corrupt("symlink target too long")),
                Ok(_) => visitor.symlink(entry, &String::from_utf8_lossy(&t)),
                Err(e) => Err(e.into()),
            }
        } else {
            let mut p = Progressed::new(&mut checked, progress);
            visitor.file(entry, &mut p)
        };
        let drained: Result<u64> = crate::io::drain(&mut checked).map_err(Error::from);
        let (mut err, stream_ok) = match (res, drained) {
            (Err(Error::Cancelled), _) => return Err(Error::Cancelled),
            (Ok(()), Ok(_)) => return Ok(Done::Ok),
            (Err(e), Ok(_)) => (e, true),
            (_, Err(e)) => (e, false),
        };
        if encrypted && !verified && matches!(err, Error::Corrupt(_) | Error::Io(_) | Error::Checksum(_)) {
            err = Error::WrongPassword;
        }
        if stream_ok || matches!(err, Error::Checksum(_) | Error::WrongPassword) { Ok(Done::Entry(err)) } else { Err(err) }
    }

    /// A RAR5 "file copy": the content of an earlier file, decoded again.
    fn extract_copy(&mut self, i: usize, target: &str, visitor: &mut dyn EntryVisitor, progress: &Progress) -> Result<()> {
        let (want, _) = normalize_path(target);
        let src = (0..i).rev().find(|&j| self.entries[j].path == want && has_stream(&self.items[j].rec));
        let Some(j) = src else {
            return visitor.entry_error(&self.entries[i], Error::corrupt(format!("the original of this file copy ({target}) is not in the archive")));
        };
        let mut up: Option<Unpacker> = None;
        let res = (|| -> Result<Done> {
            if let Some(g) = self.groups[j] {
                let first = (0..=j).find(|&k| self.groups[k] == Some(g)).unwrap_or(j);
                let mut started = false;
                for k in first..j {
                    if self.groups[k] == Some(g) {
                        if let Done::Entry(e) = self.decode_item(k, &mut up, started, None, visitor, progress)? {
                            return Err(e);
                        }
                        started = true;
                    }
                }
                self.decode_item(j, &mut up, started, Some(i), visitor, progress)
            } else {
                self.decode_item(j, &mut up, false, Some(i), visitor, progress)
            }
        })();
        match res {
            Ok(Done::Ok) => {
                progress.file_done();
                Ok(())
            }
            Ok(Done::Entry(e)) | Err(e) => {
                if matches!(e, Error::Cancelled) {
                    return Err(e);
                }
                visitor.entry_error(&self.entries[i], e)
            }
        }
    }
}

impl ArchiveReader for RarReader {
    fn archive_type(&self) -> ArchiveType {
        ArchiveType::RAR
    }
    fn entries(&self) -> &[Entry] {
        &self.entries
    }
    fn info(&self) -> ArchiveInfo {
        self.info.clone()
    }

    fn extract(&mut self, selected: &dyn Fn(&Entry) -> bool, visitor: &mut dyn EntryVisitor, progress: &Progress) -> Result<()> {
        let sel: Vec<bool> = self.entries.iter().map(selected).collect();
        let mut last_needed: HashMap<usize, usize> = HashMap::new();
        for (i, g) in self.groups.iter().enumerate() {
            if let (true, Some(g)) = (sel[i], g) {
                last_needed.insert(*g, i);
            }
        }
        let mut up: Option<Unpacker> = None;
        let mut broken: Option<(usize, Error)> = None;
        let mut prev_group: Option<usize> = None;
        for (i, &is_sel) in sel.iter().enumerate() {
            let group = self.groups[i];
            let needed = is_sel || group.is_some_and(|g| last_needed.get(&g).is_some_and(|&l| l > i));
            if !needed {
                continue;
            }
            progress.check()?;
            let rec = &self.items[i].rec;
            if rec.dir {
                visitor.dir(&self.entries[i])?;
                progress.file_done();
                continue;
            }
            let link = rec.link.clone();
            match link {
                Link::Symlink(t) => {
                    if let Err(e) = visitor.symlink(&self.entries[i], &t) {
                        visitor.entry_error(&self.entries[i], e)?;
                    }
                    progress.file_done();
                    continue;
                }
                Link::Hardlink(t) => {
                    if let Err(e) = visitor.hardlink(&self.entries[i], &t) {
                        visitor.entry_error(&self.entries[i], e)?;
                    }
                    progress.file_done();
                    continue;
                }
                Link::Copy(t) => {
                    self.extract_copy(i, &t, visitor, progress)?;
                    continue;
                }
                _ => {}
            }
            if self.entries[i].kind == EntryKind::Special {
                continue;
            }
            if let (Some(g), Some((bg, e))) = (group, broken.as_ref())
                && g == *bg
            {
                if is_sel {
                    visitor.entry_error(&self.entries[i], clone_err(e))?;
                }
                continue;
            }
            let solid_continue = group.is_some() && group == prev_group;
            if group.is_some() {
                prev_group = group;
            }
            let deliver = is_sel.then_some(i);
            match self.decode_item(i, &mut up, solid_continue, deliver, visitor, progress) {
                Ok(Done::Ok) => {
                    if is_sel {
                        progress.file_done();
                    }
                }
                Ok(Done::Entry(e)) => {
                    if is_sel {
                        visitor.entry_error(&self.entries[i], e)?;
                    }
                }
                Err(Error::Cancelled) => return Err(Error::Cancelled),
                Err(e @ Error::LimitExceeded(_)) if group.is_none() => visitor.entry_error(&self.entries[i], e)?,
                Err(e) => {
                    if let Some(g) = group {
                        let note = Error::Corrupt(format!("an earlier file in this solid archive could not be decoded ({e})"));
                        broken = Some((g, note));
                    }
                    if is_sel {
                        visitor.entry_error(&self.entries[i], e)?;
                    }
                }
            }
        }
        Ok(())
    }
}
