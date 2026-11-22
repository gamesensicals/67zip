//! ISO 9660 images (read only), our own code: plain ISO 9660 names, Joliet
//! (Unicode) names and Rock Ridge (POSIX names, permissions, symlinks,
//! times). Directory cycles and oversized structures are rejected.

use std::collections::HashSet;
use std::io::{Read, SeekFrom};

use crate::archive::{is_entry_local, ArchiveInfo, ArchiveReader, EntryVisitor, OpenOptions};
use crate::detect::ArchiveType;
use crate::entry::{Entry, EntryKind};
use crate::error::{Error, Result};
use crate::io::{Progressed, ReadSeek};
use crate::limits::Limits;
use crate::progress::Progress;
use crate::util::normalize_path;

const SECTOR: u64 = 2048;

#[derive(Clone, Debug)]
struct Extent {
    lba: u32,
    len: u32,
}

struct Rec {
    extent: Extent,
    is_dir: bool,
    multi: bool,
    name: String,
    mtime: Option<i64>,
    rr_name: Option<String>,
    mode: Option<u32>,
    link: Option<String>,
}

fn iso_time(b: &[u8]) -> Option<i64> {
    if b.len() < 7 || b[1] == 0 {
        return None;
    }
    let dt = jiff::civil::DateTime::new(1900 + i16::from(b[0]), b[1] as i8, b[2] as i8, b[3] as i8, b[4] as i8, b[5] as i8, 0).ok()?;
    let offset_secs = i32::from(b[6] as i8) * 15 * 60;
    let ts = dt.to_zoned_datetime(jiff::tz::TimeZone::UTC).ok()?.timestamp().as_second();
    Some(ts - i64::from(offset_secs))
}

fn plain_name(raw: &[u8]) -> String {
    let s = String::from_utf8_lossy(raw).into_owned();
    let s = s.split(';').next().unwrap_or("").to_string();
    s.strip_suffix('.').map(str::to_string).unwrap_or(s)
}

fn joliet_name(raw: &[u8]) -> String {
    let units: Vec<u16> = raw.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
    let s = String::from_utf16_lossy(&units);
    s.split(';').next().unwrap_or("").to_string()
}

/// Parses Rock Ridge entries in a system use area.
fn rock_ridge(mut su: &[u8], rec: &mut Rec) {
    let mut name = String::new();
    let mut link_parts: Vec<String> = Vec::new();
    let mut link_cont = false;
    while su.len() >= 4 {
        let sig = &su[..2];
        let len = usize::from(su[2]);
        if len < 4 || len > su.len() {
            break;
        }
        let body = &su[4..len];
        match sig {
            b"NM" if !body.is_empty() => {
                // flags: 1 = continues, 2 = ".", 4 = ".."
                if body[0] & 6 == 0 {
                    name.push_str(&String::from_utf8_lossy(&body[1..]));
                }
            }
            b"PX" if body.len() >= 8 => {
                rec.mode = Some(u32::from_le_bytes([body[0], body[1], body[2], body[3]]));
            }
            b"SL" if !body.is_empty() => {
                let mut comps = &body[1..];
                while comps.len() >= 2 {
                    let flags = comps[0];
                    let clen = usize::from(comps[1]);
                    if 2 + clen > comps.len() {
                        break;
                    }
                    let text = String::from_utf8_lossy(&comps[2..2 + clen]).into_owned();
                    let part = if flags & 2 != 0 {
                        ".".to_string()
                    } else if flags & 4 != 0 {
                        "..".to_string()
                    } else if flags & 8 != 0 {
                        String::new() // root: leading '/'
                    } else {
                        text
                    };
                    if link_cont {
                        if let Some(last) = link_parts.last_mut() {
                            last.push_str(&part);
                        }
                    } else {
                        link_parts.push(part);
                    }
                    link_cont = flags & 1 != 0;
                    comps = &comps[2 + clen..];
                }
            }
            b"TF" if !body.is_empty() => {
                let flags = body[0];
                let long = flags & 0x80 != 0;
                let size = if long { 17 } else { 7 };
                let mut off = 1;
                // order: creation, modify, access, attributes...
                if flags & 1 != 0 {
                    off += size;
                }
                if flags & 2 != 0 && !long && body.len() >= off + 7 {
                    rec.mtime = iso_time(&body[off..off + 7]);
                }
            }
            _ => {}
        }
        su = &su[len..];
    }
    if !name.is_empty() {
        rec.rr_name = Some(name);
    }
    if !link_parts.is_empty() {
        let joined = link_parts.join("/");
        rec.link = Some(if joined.is_empty() { "/".into() } else { joined });
    }
}

fn parse_record(r: &[u8], joliet: bool) -> Option<Rec> {
    if r.len() < 34 {
        return None;
    }
    let name_len = usize::from(r[32]);
    if 33 + name_len > r.len() {
        return None;
    }
    let raw = &r[33..33 + name_len];
    let name = if name_len == 1 && raw[0] <= 1 {
        String::new()
    } else if joliet {
        joliet_name(raw)
    } else {
        plain_name(raw)
    };
    let mut rec = Rec {
        extent: Extent { lba: u32::from_le_bytes([r[2], r[3], r[4], r[5]]), len: u32::from_le_bytes([r[10], r[11], r[12], r[13]]) },
        is_dir: r[25] & 2 != 0,
        multi: r[25] & 0x80 != 0,
        name,
        mtime: iso_time(&r[18..25]),
        rr_name: None,
        mode: None,
        link: None,
    };
    let su_start = 33 + name_len + usize::from(name_len % 2 == 0);
    if !joliet && su_start < r.len() {
        rock_ridge(&r[su_start..], &mut rec);
    }
    Some(rec)
}

pub struct IsoReader {
    src: Box<dyn ReadSeek>,
    size: u64,
    entries: Vec<Entry>,
    extents: Vec<Vec<Extent>>,
    limits: Limits,
    kind: &'static str,
}

impl IsoReader {
    fn read_at(src: &mut dyn ReadSeek, size: u64, offset: u64, len: usize) -> Result<Vec<u8>> {
        if offset.checked_add(len as u64).is_none_or(|e| e > size) {
            return Err(Error::corrupt("ISO structure points outside the image"));
        }
        src.seek(SeekFrom::Start(offset))?;
        let mut v = vec![0u8; len];
        src.read_exact(&mut v)?;
        Ok(v)
    }

    pub fn open(mut src: Box<dyn ReadSeek>, size: u64, opts: &OpenOptions) -> Result<Self> {
        let limits = opts.limits.clone();
        let mut pvd_root = None;
        let mut joliet_root = None;
        for i in 16..64u64 {
            let d = Self::read_at(src.as_mut(), size, i * SECTOR, SECTOR as usize)?;
            if &d[1..6] != b"CD001" {
                return Err(Error::corrupt("bad ISO volume descriptor"));
            }
            match d[0] {
                1 if pvd_root.is_none() => pvd_root = Some(d[156..190].to_vec()),
                2 if &d[88..90] == b"%/" && matches!(d[90], b'@' | b'C' | b'E') => joliet_root = Some(d[156..190].to_vec()),
                255 => break,
                _ => {}
            }
        }
        let pvd = pvd_root.ok_or_else(|| Error::corrupt("ISO without primary volume descriptor"))?;
        let root = parse_record(&pvd, false).ok_or_else(|| Error::corrupt("bad ISO root record"))?;
        // Rock Ridge is announced in the root's "." record.
        let first = Self::read_at(src.as_mut(), size, u64::from(root.extent.lba) * SECTOR, SECTOR as usize)?;
        let has_rr = {
            let dot = parse_record(&first[..usize::from(first[0]).min(first.len())], false);
            dot.is_some() && first.windows(2).take(usize::from(first[0])).any(|w| w == b"SP" || w == b"RR" || w == b"PX")
        };
        let (use_joliet, root_rec, kind) = match (&joliet_root, has_rr) {
            (_, true) => (false, root, "ISO 9660 + Rock Ridge"),
            (Some(j), false) => (true, parse_record(j, true).ok_or_else(|| Error::corrupt("bad Joliet root"))?, "ISO 9660 + Joliet"),
            (None, false) => (false, root, "ISO 9660"),
        };

        let mut entries = Vec::new();
        let mut extents: Vec<Vec<Extent>> = Vec::new();
        let mut visited = HashSet::new();
        let mut stack = vec![(String::new(), root_rec.extent.clone(), 0usize)];
        while let Some((prefix, ext, depth)) = stack.pop() {
            if depth > 64 {
                return Err(Error::corrupt("ISO folders nested too deeply"));
            }
            if !visited.insert(ext.lba) {
                continue; // directory cycle
            }
            if u64::from(ext.len) > limits.max_header_size.min(64 << 20) {
                return Err(Error::limit("ISO directory too large"));
            }
            let data = Self::read_at(src.as_mut(), size, u64::from(ext.lba) * SECTOR, ext.len as usize)?;
            let mut off = 0usize;
            let mut pending_multi: Option<usize> = None;
            while off < data.len() {
                let len = usize::from(data[off]);
                if len == 0 {
                    // Records never cross sectors: jump to the next one.
                    off = (off / SECTOR as usize + 1) * SECTOR as usize;
                    continue;
                }
                if off + len > data.len() {
                    break;
                }
                let Some(rec) = parse_record(&data[off..off + len], use_joliet) else { break };
                off += len;
                if rec.name.is_empty() && rec.rr_name.is_none() {
                    continue; // "." and ".."
                }
                let name = rec.rr_name.clone().unwrap_or_else(|| rec.name.clone());
                if name == "." || name == ".." || name.contains('/') || name.is_empty() {
                    continue;
                }
                let path = if prefix.is_empty() { name.clone() } else { format!("{prefix}/{name}") };
                if let Some(i) = pending_multi.take() {
                    // Further extents of a multi-extent file.
                    if entries.get(i).map(|e: &Entry| e.path == path).unwrap_or(false) {
                        extents[i].push(rec.extent.clone());
                        entries[i].size += u64::from(rec.extent.len);
                        if rec.multi {
                            pending_multi = Some(i);
                        }
                        continue;
                    }
                }
                if entries.len() as u64 >= limits.max_entries {
                    return Err(Error::limit("too many entries in ISO image"));
                }
                if path.len() > limits.max_path_len {
                    return Err(Error::limit("entry name too long"));
                }
                let kind = if rec.is_dir {
                    EntryKind::Dir
                } else if rec.link.is_some() {
                    EntryKind::Symlink
                } else {
                    EntryKind::File
                };
                let (norm, unsafe_path) = normalize_path(&path);
                let mut e = Entry::new(entries.len(), norm, kind);
                e.unsafe_path = unsafe_path;
                e.mtime = rec.mtime;
                e.mode = rec.mode.map(|m| m & 0o7777);
                e.link_target = rec.link.clone();
                if kind == EntryKind::File {
                    e.size = u64::from(rec.extent.len);
                    e.packed_size = Some(e.size);
                }
                if rec.is_dir {
                    stack.push((path, rec.extent.clone(), depth + 1));
                }
                if rec.multi {
                    pending_multi = Some(entries.len());
                }
                extents.push(if kind == EntryKind::File { vec![rec.extent] } else { vec![] });
                entries.push(e);
            }
        }
        Ok(IsoReader { src, size, entries, extents, limits, kind })
    }
}

impl ArchiveReader for IsoReader {
    fn archive_type(&self) -> ArchiveType {
        ArchiveType::ISO
    }
    fn entries(&self) -> &[Entry] {
        &self.entries
    }
    fn info(&self) -> ArchiveInfo {
        ArchiveInfo { format: "iso".into(), physical_size: self.size, methods: vec![self.kind.into()], volumes: 1, ..Default::default() }
    }
    fn extract(&mut self, selected: &dyn Fn(&Entry) -> bool, visitor: &mut dyn EntryVisitor, progress: &Progress) -> Result<()> {
        let _ = &self.limits;
        let mut order: Vec<usize> = (0..self.entries.len()).filter(|&i| selected(&self.entries[i])).collect();
        order.sort_by_key(|&i| self.extents[i].first().map(|e| e.lba).unwrap_or(0));
        for i in order {
            progress.check()?;
            let entry = &self.entries[i];
            progress.set_current(&entry.path);
            let res = match entry.kind {
                EntryKind::Dir => visitor.dir(entry),
                EntryKind::Symlink => visitor.symlink(entry, entry.link_target.as_deref().unwrap_or("")),
                EntryKind::File => {
                    let size = self.size;
                    let outside = self.extents[i].iter().any(|ext| (u64::from(ext.lba) * SECTOR).checked_add(u64::from(ext.len)).is_none_or(|e| e > size));
                    if outside {
                        Err(Error::corrupt("file data lies outside the image"))
                    } else {
                        let exts = self.extents[i].clone();
                        let mut chain = ExtentChain { src: self.src.as_mut(), exts, idx: 0, done_in_ext: 0 };
                        let mut p = Progressed::new(&mut chain, progress);
                        visitor.file(entry, &mut p)
                    }
                }
                _ => Ok(()),
            };
            match res {
                Ok(()) => progress.file_done(),
                Err(Error::Cancelled) => return Err(Error::Cancelled),
                Err(e) if is_entry_local(&e) => visitor.entry_error(entry, e)?,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

/// Reads a file's extents one after another, straight from the image.
struct ExtentChain<'a> {
    src: &'a mut dyn ReadSeek,
    exts: Vec<Extent>,
    idx: usize,
    done_in_ext: u64,
}

impl Read for ExtentChain<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        while let Some(ext) = self.exts.get(self.idx) {
            let left = u64::from(ext.len) - self.done_in_ext;
            if left == 0 {
                self.idx += 1;
                self.done_in_ext = 0;
                continue;
            }
            self.src.seek(SeekFrom::Start(u64::from(ext.lba) * SECTOR + self.done_in_ext))?;
            let n = buf.len().min(left.min(usize::MAX as u64) as usize);
            let got = self.src.read(&mut buf[..n])?;
            if got == 0 {
                return Err(Error::corrupt("ISO image ends early").into());
            }
            self.done_in_ext += got as u64;
            return Ok(got);
        }
        Ok(0)
    }
}
