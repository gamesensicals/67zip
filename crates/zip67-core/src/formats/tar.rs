//! tar reader and writer (ustar + PAX + GNU long names), our own code.
//! Compressed tars are read as one stream; listing needs a full pass.

use std::io::{self, Read, Seek, SeekFrom, Write};

use crate::archive::{ArchiveInfo, ArchiveReader, EntryVisitor, OpenOptions};
use crate::codecs::{self, FinishWrite};
use crate::create::{ArchiveWriter, Item};
use crate::detect::{ArchiveType, Compression, Container};
use crate::entry::{Entry, EntryKind};
use crate::error::{Error, Result};
use crate::io::{Progressed, ReadSeek, SizeGuard};
use crate::limits::Limits;
use crate::progress::Progress;
use crate::util::{decode_name, normalize_path};

const BLOCK: usize = 512;
const MAX_META: u64 = 1 << 20;

fn parse_octal(field: &[u8]) -> Option<u64> {
    if field.first().is_some_and(|b| b & 0x80 != 0) {
        // GNU base-256: big-endian binary, top bit set (negative = 0xff).
        if field[0] == 0xff {
            return None;
        }
        let mut v: u64 = u64::from(field[0] & 0x7f);
        for &b in &field[1..] {
            v = v.checked_mul(256)?.checked_add(u64::from(b))?;
        }
        return Some(v);
    }
    let s: Vec<u8> = field.iter().copied().skip_while(|&b| b == b' ').take_while(|&b| b != 0 && b != b' ').collect();
    if s.is_empty() {
        return Some(0);
    }
    let mut v: u64 = 0;
    for b in s {
        if !(b'0'..=b'7').contains(&b) {
            return None;
        }
        v = v.checked_mul(8)?.checked_add(u64::from(b - b'0'))?;
    }
    Some(v)
}

fn cstr(field: &[u8]) -> &[u8] {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    &field[..end]
}

/// True if `h` (512 bytes) is a tar header with a valid checksum.
pub fn is_tar_header(h: &[u8]) -> bool {
    if h.len() < BLOCK || h.iter().all(|&b| b == 0) {
        return false;
    }
    let Some(stored) = parse_octal(&h[148..156]) else { return false };
    let mut unsigned: u64 = 0;
    let mut signed: i64 = 0;
    for (i, &b) in h[..BLOCK].iter().enumerate() {
        let b = if (148..156).contains(&i) { b' ' } else { b };
        unsigned += u64::from(b);
        signed += i64::from(b as i8);
    }
    stored == unsigned || stored as i64 == signed
}

/// Parsed header of one member, after PAX/GNU extensions were applied.
struct Member {
    entry: Entry,
    data_size: u64,
}

/// Reads tar members one after another from a stream.
struct TarStream<'a> {
    r: Box<dyn Read + Send + 'a>,
    seekable: Option<&'a mut dyn ReadSeek>,
    pos: u64,
    limits: &'a Limits,
    count: u64,
}

impl<'a> TarStream<'a> {
    fn read_block(&mut self, buf: &mut [u8; BLOCK]) -> Result<bool> {
        let n = if let Some(s) = self.seekable.as_mut() { crate::io::read_full(*s, buf)? } else { crate::io::read_full(&mut self.r, buf)? };
        self.pos += n as u64;
        if n == 0 {
            return Ok(false);
        }
        if n < BLOCK {
            return Err(Error::corrupt("tar header is truncated"));
        }
        Ok(true)
    }

    fn reader(&mut self) -> &mut dyn Read {
        match self.seekable.as_mut() {
            Some(s) => *s,
            None => &mut self.r,
        }
    }

    fn skip(&mut self, n: u64) -> Result<()> {
        if n == 0 {
            return Ok(());
        }
        if let Some(s) = self.seekable.as_mut() {
            s.seek(SeekFrom::Current(n as i64))?;
        } else {
            let copied = io::copy(&mut (&mut self.r).take(n), &mut io::sink())?;
            if copied != n {
                return Err(Error::corrupt("tar member data is truncated"));
            }
        }
        self.pos += n;
        Ok(())
    }

    fn read_meta(&mut self, size: u64) -> Result<Vec<u8>> {
        if size > MAX_META {
            return Err(Error::limit("tar extended header too large"));
        }
        let mut v = vec![0u8; size as usize];
        let n = crate::io::read_full(self.reader(), &mut v)?;
        if n as u64 != size {
            return Err(Error::corrupt("tar extended header truncated"));
        }
        self.pos += size;
        self.skip(padding(size))?;
        Ok(v)
    }

    /// Next member, or `None` at the end of the archive.
    fn next(&mut self) -> Result<Option<Member>> {
        let mut long_name: Option<Vec<u8>> = None;
        let mut long_link: Option<Vec<u8>> = None;
        let mut pax: Vec<(String, Vec<u8>)> = Vec::new();
        loop {
            let mut h = [0u8; BLOCK];
            if !self.read_block(&mut h)? {
                return Ok(None);
            }
            if h.iter().all(|&b| b == 0) {
                return Ok(None);
            }
            if !is_tar_header(&h) {
                return Err(Error::corrupt("tar header checksum mismatch"));
            }
            let typeflag = h[156];
            let size = parse_octal(&h[124..136]).ok_or_else(|| Error::corrupt("bad tar size field"))?;
            match typeflag {
                b'L' => {
                    long_name = Some(cstr(&self.read_meta(size)?).to_vec());
                    continue;
                }
                b'K' => {
                    long_link = Some(cstr(&self.read_meta(size)?).to_vec());
                    continue;
                }
                b'x' => {
                    pax = parse_pax(&self.read_meta(size)?)?;
                    continue;
                }
                b'g' => {
                    self.read_meta(size)?;
                    continue;
                }
                _ => {}
            }
            self.count += 1;
            if self.count > self.limits.max_entries {
                return Err(Error::limit("too many entries in tar archive"));
            }
            let ustar = &h[257..263] == b"ustar\0";
            let mut name_bytes = cstr(&h[0..100]).to_vec();
            if ustar && h[345] != 0 {
                let mut p = cstr(&h[345..500]).to_vec();
                p.push(b'/');
                p.extend_from_slice(&name_bytes);
                name_bytes = p;
            }
            if let Some(n) = long_name.take() {
                name_bytes = n;
            }
            let mut link = cstr(&h[157..257]).to_vec();
            if let Some(l) = long_link.take() {
                link = l;
            }
            let mut size = size;
            let mut mtime = parse_octal(&h[136..148]).map(|v| v as i64);
            let mut nanos = 0;
            let mut sparse = false;
            for (k, v) in &pax {
                match k.as_str() {
                    "path" => name_bytes = v.clone(),
                    "linkpath" => link = v.clone(),
                    "size" => {
                        size = std::str::from_utf8(v).ok().and_then(|s| s.parse().ok()).ok_or_else(|| Error::corrupt("bad PAX size"))?
                    }
                    "mtime" => {
                        if let Some((s, n)) = std::str::from_utf8(v).ok().and_then(parse_pax_time) {
                            mtime = Some(s);
                            nanos = n;
                        }
                    }
                    k if k.starts_with("GNU.sparse") => sparse = true,
                    _ => {}
                }
            }
            pax.clear();
            let name = decode_name(&name_bytes);
            if name.len() > self.limits.max_path_len {
                return Err(Error::limit("entry name too long"));
            }
            let mut kind = match typeflag {
                b'0' | 0 | b'7' => EntryKind::File,
                b'1' => EntryKind::Hardlink,
                b'2' => EntryKind::Symlink,
                b'5' => EntryKind::Dir,
                b'S' => {
                    sparse = true;
                    EntryKind::Special
                }
                _ => EntryKind::Special,
            };
            if kind == EntryKind::File && name.ends_with('/') {
                kind = EntryKind::Dir;
            }
            if sparse {
                kind = EntryKind::Special;
            }
            let (path, unsafe_path) = normalize_path(&name);
            let mut entry = Entry::new(self.count as usize - 1, path, kind);
            entry.unsafe_path = unsafe_path;
            let data_size = if matches!(kind, EntryKind::Dir | EntryKind::Symlink | EntryKind::Hardlink) { 0 } else { size };
            entry.size = if kind == EntryKind::File { size } else { 0 };
            entry.mtime = mtime;
            entry.mtime_nanos = nanos;
            entry.mode = parse_octal(&h[100..108]).map(|m| (m & 0o7777) as u32);
            if matches!(kind, EntryKind::Symlink | EntryKind::Hardlink) {
                entry.link_target = Some(decode_name(&link));
            }
            // Sparse or special members still occupy `size` bytes in the stream.
            let data_size = if kind == EntryKind::Special { size } else { data_size };
            return Ok(Some(Member { entry, data_size }));
        }
    }
}

fn padding(size: u64) -> u64 {
    (BLOCK as u64 - size % BLOCK as u64) % BLOCK as u64
}

fn parse_pax_time(s: &str) -> Option<(i64, u32)> {
    let (secs, frac) = match s.split_once('.') {
        Some((a, b)) => (a, b),
        None => (s, ""),
    };
    let secs: i64 = secs.parse().ok()?;
    let mut f: String = frac.chars().take(9).collect();
    while f.len() < 9 {
        f.push('0');
    }
    Some((secs, f.parse().unwrap_or(0)))
}

fn parse_pax(data: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    let mut out = Vec::new();
    let mut rest = data;
    while !rest.is_empty() {
        let sp = rest.iter().position(|&b| b == b' ').ok_or_else(|| Error::corrupt("bad PAX record"))?;
        let len: usize = std::str::from_utf8(&rest[..sp]).ok().and_then(|s| s.parse().ok()).ok_or_else(|| Error::corrupt("bad PAX record length"))?;
        if len <= sp + 1 || len > rest.len() {
            return Err(Error::corrupt("bad PAX record length"));
        }
        let rec = &rest[sp + 1..len];
        let rec = rec.strip_suffix(b"\n").unwrap_or(rec);
        if let Some(eq) = rec.iter().position(|&b| b == b'=') {
            out.push((String::from_utf8_lossy(&rec[..eq]).into_owned(), rec[eq + 1..].to_vec()));
        }
        rest = &rest[len..];
    }
    Ok(out)
}

pub struct TarReader {
    src: Box<dyn ReadSeek>,
    size: u64,
    compression: Compression,
    entries: Vec<Entry>,
    limits: Limits,
}

impl TarReader {
    pub fn open(mut src: Box<dyn ReadSeek>, size: u64, compression: Compression, opts: &OpenOptions) -> Result<Self> {
        let limits = opts.limits.clone();
        let mut entries = Vec::new();
        {
            src.seek(SeekFrom::Start(0))?;
            let mut stream = Self::stream(src.as_mut(), compression, &limits)?;
            while let Some(m) = stream.next()? {
                stream.skip(m.data_size + padding(m.data_size))?;
                entries.push(m.entry);
            }
        }
        Ok(TarReader { src, size, compression, entries, limits })
    }

    fn stream<'a>(src: &'a mut dyn ReadSeek, c: Compression, limits: &'a Limits) -> Result<TarStream<'a>> {
        if c == Compression::None {
            return Ok(TarStream { r: Box::new(io::empty()), seekable: Some(src), pos: 0, limits, count: 0 });
        }
        let r = codecs::decoder(c, Box::new(src), limits)?;
        Ok(TarStream { r, seekable: None, pos: 0, limits, count: 0 })
    }
}

impl ArchiveReader for TarReader {
    fn archive_type(&self) -> ArchiveType {
        ArchiveType::new(Container::Tar, self.compression)
    }
    fn entries(&self) -> &[Entry] {
        &self.entries
    }
    fn info(&self) -> ArchiveInfo {
        ArchiveInfo {
            format: self.archive_type().id(),
            physical_size: self.size,
            methods: if self.compression == Compression::None { vec![] } else { vec![self.compression.display().into()] },
            solid: self.compression != Compression::None,
            blocks: 1,
            volumes: 1,
            ..Default::default()
        }
    }
    fn extract(&mut self, selected: &dyn Fn(&Entry) -> bool, visitor: &mut dyn EntryVisitor, progress: &Progress) -> Result<()> {
        self.src.seek(SeekFrom::Start(0))?;
        let limits = self.limits.clone();
        let mut stream = Self::stream(self.src.as_mut(), self.compression, &limits)?;
        let mut idx = 0usize;
        while let Some(m) = stream.next()? {
            progress.check()?;
            // Use the stored listing (same order) so indices stay stable.
            let entry = self.entries.get(idx).cloned().unwrap_or(m.entry);
            idx += 1;
            let total = m.data_size + padding(m.data_size);
            if !selected(&entry) {
                stream.skip(total)?;
                continue;
            }
            progress.set_current(&entry.path);
            let res = match entry.kind {
                EntryKind::Dir => visitor.dir(&entry),
                EntryKind::Symlink => visitor.symlink(&entry, entry.link_target.as_deref().unwrap_or("")),
                EntryKind::Hardlink => visitor.hardlink(&entry, entry.link_target.as_deref().unwrap_or("")),
                EntryKind::Special => Ok(()),
                EntryKind::File => {
                    let r = stream.reader();
                    let guarded = SizeGuard::new(r.take(m.data_size), Some(m.data_size), limits.max_total_size);
                    let mut p = Progressed::new(guarded, progress);
                    let res = visitor.file(&entry, &mut p);
                    // Whatever the visitor left unread must be skipped.
                    let left = crate::io::drain(&mut p).unwrap_or(0);
                    let _ = left;
                    stream.pos += m.data_size;
                    stream.skip(padding(m.data_size))?;
                    match res {
                        Ok(()) => {
                            progress.file_done();
                            continue;
                        }
                        Err(e) => Err(e),
                    }
                }
            };
            if matches!(entry.kind, EntryKind::Dir | EntryKind::Symlink | EntryKind::Hardlink | EntryKind::Special) {
                stream.skip(total)?;
            }
            match res {
                Ok(()) => progress.file_done(),
                Err(Error::Cancelled) => return Err(Error::Cancelled),
                Err(e @ (Error::Checksum(_) | Error::UnsafePath(_) | Error::InvalidInput(_))) => visitor.entry_error(&entry, e)?,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

// ----- writer ----------------------------------------------------------------

pub struct TarWriter {
    out: Option<Box<dyn FinishWrite>>,
}

impl TarWriter {
    pub fn new(file: std::fs::File, c: Compression, level: u32, threads: usize) -> Result<Self> {
        let buffered: codecs::BoxWrite<'static> = Box::new(io::BufWriter::with_capacity(256 * 1024, file));
        Ok(TarWriter { out: Some(codecs::encoder(c, buffered, level, threads, None, 0)?) })
    }
    /// Writes tar data into any writer (used for nesting inside other formats).
    pub fn from_writer(w: Box<dyn FinishWrite>) -> Self {
        TarWriter { out: Some(w) }
    }

    fn w(&mut self) -> Result<&mut Box<dyn FinishWrite>> {
        self.out.as_mut().ok_or_else(|| Error::invalid("tar writer finished"))
    }
}

fn octal(field: &mut [u8], v: u64) -> bool {
    let digits = field.len() - 1;
    let s = format!("{v:0width$o}", width = digits);
    if s.len() > digits {
        return false;
    }
    field[..digits].copy_from_slice(s.as_bytes());
    field[digits] = 0;
    true
}

fn pax_record(key: &str, value: &[u8]) -> Vec<u8> {
    // "len key=value\n" where len counts itself.
    let base = key.len() + value.len() + 3;
    let mut len = base + base.to_string().len();
    if len.to_string().len() + base != len {
        len = base + len.to_string().len();
    }
    let mut r = format!("{len} {key}=").into_bytes();
    r.extend_from_slice(value);
    r.push(b'\n');
    r
}

fn header(name: &[u8], prefix: &[u8], item_mode: u32, uid: u32, gid: u32, size: u64, mtime: i64, typeflag: u8, link: &[u8]) -> [u8; BLOCK] {
    let mut h = [0u8; BLOCK];
    h[..name.len().min(100)].copy_from_slice(&name[..name.len().min(100)]);
    octal(&mut h[100..108], u64::from(item_mode & 0o7777));
    octal(&mut h[108..116], u64::from(uid).min(0o7777777));
    octal(&mut h[116..124], u64::from(gid).min(0o7777777));
    if !octal(&mut h[124..136], size) {
        // base-256 for huge sizes (PAX carries the exact value as well)
        h[124] = 0x80;
        h[128..136].copy_from_slice(&size.to_be_bytes());
    }
    octal(&mut h[136..148], mtime.clamp(0, 0o77777777777) as u64);
    h[156] = typeflag;
    h[157..157 + link.len().min(100)].copy_from_slice(&link[..link.len().min(100)]);
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    h[345..345 + prefix.len().min(155)].copy_from_slice(&prefix[..prefix.len().min(155)]);
    h[148..156].copy_from_slice(b"        ");
    let sum: u64 = h.iter().map(|&b| u64::from(b)).sum();
    let s = format!("{sum:06o}\0 ");
    h[148..156].copy_from_slice(s.as_bytes());
    h
}

/// Splits a path into ustar (prefix, name) if possible.
fn split_ustar(path: &[u8]) -> Option<(&[u8], &[u8])> {
    if path.len() <= 100 {
        return Some((&[], path));
    }
    for (i, &b) in path.iter().enumerate() {
        if b == b'/' && i <= 155 && path.len() - i - 1 <= 100 && path.len() - i - 1 > 0 {
            return Some((&path[..i], &path[i + 1..]));
        }
    }
    None
}

impl ArchiveWriter for TarWriter {
    fn add(&mut self, item: &Item, data: Option<&mut dyn Read>, progress: &Progress) -> Result<()> {
        let mut path = item.arcname.clone();
        let typeflag = match item.kind {
            EntryKind::Dir => {
                path.push('/');
                b'5'
            }
            EntryKind::Symlink => b'2',
            EntryKind::Hardlink => b'1',
            _ => b'0',
        };
        let link = item.link_target.clone().unwrap_or_default();
        let size = if item.kind == EntryKind::File { item.size } else { 0 };
        let pb = path.as_bytes();
        let split = split_ustar(pb);
        let mut pax = Vec::new();
        if split.is_none() || !path.is_ascii() {
            pax.extend(pax_record("path", pb));
        }
        if link.len() > 100 || !link.is_ascii() {
            pax.extend(pax_record("linkpath", link.as_bytes()));
        }
        if size > 0o77777777777 {
            pax.extend(pax_record("size", size.to_string().as_bytes()));
        }
        if item.mtime < 0 || item.mtime > 0o77777777777 || item.mtime_nanos != 0 {
            pax.extend(pax_record("mtime", format!("{}.{:09}", item.mtime, item.mtime_nanos).as_bytes()));
        }
        let w = self.w()?;
        if !pax.is_empty() {
            let h = header(b"././@PaxHeader", &[], 0o644, 0, 0, pax.len() as u64, item.mtime, b'x', &[]);
            w.write_all(&h)?;
            w.write_all(&pax)?;
            w.write_all(&vec![0u8; padding(pax.len() as u64) as usize])?;
        }
        let (prefix, name) = split.unwrap_or((&[], &pb[pb.len().saturating_sub(100)..]));
        let h = header(name, prefix, item.mode, item.uid, item.gid, size, item.mtime, typeflag, link.as_bytes());
        w.write_all(&h)?;
        if item.kind == EntryKind::File {
            let r = data.ok_or_else(|| Error::invalid("file data missing"))?;
            let mut limited = r.take(size);
            let n = crate::create::pump(&mut limited, w, progress)?;
            if n != size {
                return Err(Error::invalid(format!("{} changed size while it was being archived", item.arcname)));
            }
            w.write_all(&vec![0u8; padding(size) as usize])?;
            progress.add_packed(size);
        }
        Ok(())
    }

    fn finish(mut self: Box<Self>, _progress: &Progress) -> Result<()> {
        let mut w = self.out.take().ok_or_else(|| Error::invalid("tar writer finished"))?;
        w.write_all(&[0u8; BLOCK * 2])?;
        w.finish_box()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pax_len_is_self_consistent() {
        for n in [1usize, 50, 89, 90, 95, 99, 100, 990, 995, 1000] {
            let v = vec![b'a'; n];
            let r = pax_record("path", &v);
            let len: usize = std::str::from_utf8(&r[..r.iter().position(|&b| b == b' ').unwrap()]).unwrap().parse().unwrap();
            assert_eq!(len, r.len(), "value length {n}");
        }
    }

    #[test]
    fn octal_parsing() {
        assert_eq!(parse_octal(b"0000644\0"), Some(0o644));
        assert_eq!(parse_octal(b"   12 \0"), Some(0o12));
        assert_eq!(parse_octal(&[0x80, 0, 0, 0, 0, 0, 1, 0]), Some(256));
    }
}
