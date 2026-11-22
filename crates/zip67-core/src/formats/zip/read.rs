//! Zip reader written for 67zip: central directory parsing with Zip64,
//! prefixed (self-extracting) files, Unicode names, Unix attributes,
//! encryption, and protection against overlapping-entry zip bombs.

use std::io::{BufReader, Read, Seek, SeekFrom};

use super::crypto::{aes_salt_len, zipcrypto_open, AesZipReader, ZipCryptoReader};
use crate::archive::{is_entry_local, ArchiveInfo, ArchiveReader, EntryVisitor, OpenOptions};
use crate::codecs;
use crate::detect::ArchiveType;
use crate::entry::{Entry, EntryKind};
use crate::error::{Error, Result};
use crate::io::{CrcCheck, Progressed, ReadSeek, SizeGuard, TakeExact};
use crate::limits::Limits;
use crate::password::Password;
use crate::progress::Progress;
use crate::util::{decode_name, dos_to_unix, filetime_to_unix, normalize_path, Bytes};

const EOCD_SIG: &[u8; 4] = b"PK\x05\x06";
const CD_SIG: u32 = 0x0201_4b50;
const LOCAL_SIG: u32 = 0x0403_4b50;

pub(crate) const M_STORE: u16 = 0;
pub(crate) const M_DEFLATE: u16 = 8;
pub(crate) const M_DEFLATE64: u16 = 9;
pub(crate) const M_BZIP2: u16 = 12;
pub(crate) const M_LZMA: u16 = 14;
pub(crate) const M_ZSTD: u16 = 93;
pub(crate) const M_XZ: u16 = 95;
pub(crate) const M_PPMD: u16 = 98;
pub(crate) const M_AES: u16 = 99;

pub fn method_name(m: u16) -> String {
    match m {
        M_STORE => "Store".into(),
        M_DEFLATE => "Deflate".into(),
        M_DEFLATE64 => "Deflate64".into(),
        M_BZIP2 => "BZip2".into(),
        M_LZMA => "LZMA".into(),
        M_ZSTD => "Zstd".into(),
        M_XZ => "XZ".into(),
        M_PPMD => "PPMd".into(),
        other => format!("Method {other}"),
    }
}

/// End-of-central-directory information.
#[derive(Debug, Clone)]
pub struct Eocd {
    pub record_pos: u64,
    pub entries: u64,
    pub cd_size: u64,
    pub cd_offset: u64,
    pub comment: Vec<u8>,
    /// Position of the first byte after the central directory.
    pub cd_end: u64,
}

/// Finds and parses the end-of-central-directory record (and Zip64 records).
pub fn find_eocd(src: &mut dyn ReadSeek) -> Result<Eocd> {
    let len = src.seek(SeekFrom::End(0))?;
    if len < 22 {
        return Err(Error::UnsupportedFormat);
    }
    let tail_len = len.min(22 + 65_535);
    let start = len - tail_len;
    src.seek(SeekFrom::Start(start))?;
    let mut tail = vec![0u8; tail_len as usize];
    src.read_exact(&mut tail)?;

    // Prefer a record whose comment length reaches exactly to the end.
    let mut found = None;
    let mut i = tail.len() - 22;
    loop {
        if &tail[i..i + 4] == EOCD_SIG {
            let clen = u16::from_le_bytes([tail[i + 20], tail[i + 21]]) as usize;
            if i + 22 + clen == tail.len() {
                found = Some(i);
                break;
            }
            if found.is_none() && i + 22 + clen <= tail.len() {
                found = Some(i);
            }
        }
        if i == 0 {
            break;
        }
        i -= 1;
    }
    let i = found.ok_or(Error::UnsupportedFormat)?;
    let mut b = Bytes::new(&tail[i + 4..], "zip end record");
    let _disk = b.u16()?;
    let _cd_disk = b.u16()?;
    let _n_disk = b.u16()?;
    let mut entries = b.u16()? as u64;
    let mut cd_size = b.u32()? as u64;
    let mut cd_offset = b.u32()? as u64;
    let clen = b.u16()? as usize;
    let comment = b.take(clen.min(b.remaining()))?.to_vec();
    let record_pos = start + i as u64;
    let mut cd_end = record_pos;

    // Zip64 locator sits right before the classic record.
    if record_pos >= 20 {
        src.seek(SeekFrom::Start(record_pos - 20))?;
        let mut loc = [0u8; 20];
        src.read_exact(&mut loc)?;
        if &loc[..4] == b"PK\x06\x07" {
            let z64_off = u64::from_le_bytes(loc[8..16].try_into().unwrap_or([0; 8]));
            // The stored offset is relative to the archive start; if data was
            // prepended, the record is found right before the locator instead.
            let candidates = [z64_off, record_pos.saturating_sub(20 + 56)];
            for pos in candidates {
                if pos + 56 > len {
                    continue;
                }
                src.seek(SeekFrom::Start(pos))?;
                let mut r = [0u8; 56];
                src.read_exact(&mut r)?;
                if &r[..4] == b"PK\x06\x06" {
                    let mut b = Bytes::new(&r[4..], "zip64 end record");
                    let _size = b.u64()?;
                    let _made = b.u16()?;
                    let _need = b.u16()?;
                    let _disk = b.u32()?;
                    let _cd_disk = b.u32()?;
                    let _n_disk = b.u64()?;
                    entries = b.u64()?;
                    cd_size = b.u64()?;
                    cd_offset = b.u64()?;
                    cd_end = pos;
                    break;
                }
            }
        }
    }
    Ok(Eocd { record_pos, entries, cd_size, cd_offset, comment, cd_end })
}

#[derive(Clone, Debug)]
struct Meta {
    method: u16,
    flags: u16,
    crc: u32,
    csize: u64,
    usize: u64,
    local_offset: u64,
    dos_time: u16,
    aes: Option<(u8, u16, u16)>, // (strength, real method, AE version)
    /// Upper bound for this entry's data: next local header or the CD.
    limit: u64,
}

pub struct ZipReader {
    src: Box<dyn ReadSeek>,
    size: u64,
    base: u64,
    entries: Vec<Entry>,
    metas: Vec<Meta>,
    comment: Option<String>,
    password: Option<Password>,
    limits: Limits,
    warnings: Vec<String>,
    cd_size: u64,
}

fn host_is_dos(made_by: u16) -> bool {
    matches!(made_by >> 8, 0 | 11 | 14)
}

impl ZipReader {
    pub fn open(mut src: Box<dyn ReadSeek>, size: u64, opts: &OpenOptions) -> Result<Self> {
        let limits = opts.limits.clone();
        let eocd = find_eocd(src.as_mut())?;
        let mut warnings = Vec::new();
        if eocd.cd_size > limits.max_header_size || eocd.cd_size > size {
            return Err(Error::limit("zip central directory is too large"));
        }
        if eocd.entries > limits.max_entries {
            return Err(Error::limit("too many entries in zip archive"));
        }
        // Where the CD really is tells us how many bytes were prepended.
        let real_cd_start = eocd.cd_end.checked_sub(eocd.cd_size).ok_or_else(|| Error::corrupt("bad central directory size"))?;
        let base = real_cd_start.checked_sub(eocd.cd_offset).ok_or_else(|| Error::corrupt("bad central directory offset"))?;
        if base > 0 {
            warnings.push(format!("{base} bytes of data before the zip archive (self-extracting stub?)"));
        }
        src.seek(SeekFrom::Start(real_cd_start))?;
        let mut cd = vec![0u8; eocd.cd_size as usize];
        src.read_exact(&mut cd)?;
        let mut b = Bytes::new(&cd, "zip central directory");

        let mut entries = Vec::new();
        let mut metas = Vec::new();
        while b.remaining() >= 46 {
            if b.u32()? != CD_SIG {
                break;
            }
            if entries.len() as u64 >= limits.max_entries {
                return Err(Error::limit("too many entries in zip archive"));
            }
            let made_by = b.u16()?;
            let _needed = b.u16()?;
            let flags = b.u16()?;
            let method = b.u16()?;
            let dos_time = b.u16()?;
            let dos_date = b.u16()?;
            let crc = b.u32()?;
            let mut csize = b.u32()? as u64;
            let mut usize = b.u32()? as u64;
            let name_len = b.u16()? as usize;
            let extra_len = b.u16()? as usize;
            let comment_len = b.u16()? as usize;
            let _disk = b.u16()?;
            let _int_attr = b.u16()?;
            let ext_attr = b.u32()?;
            let mut local_offset = b.u32()? as u64;
            let raw_name = b.take(name_len)?;
            let extra = b.take(extra_len)?;
            let comment = b.take(comment_len)?;

            let mut mtime = dos_to_unix(dos_date, dos_time);
            let mut nanos = 0;
            let mut unicode_name = None;
            let mut aes = None;
            let mut e = Bytes::new(extra, "zip extra field");
            while e.remaining() >= 4 {
                let id = e.u16()?;
                let len = e.u16()? as usize;
                if len > e.remaining() {
                    break;
                }
                let data = e.take(len)?;
                let mut d = Bytes::new(data, "zip extra field");
                match id {
                    0x0001 => {
                        if usize == 0xFFFF_FFFF {
                            usize = d.u64()?;
                        }
                        if csize == 0xFFFF_FFFF {
                            csize = d.u64()?;
                        }
                        if local_offset == 0xFFFF_FFFF {
                            local_offset = d.u64()?;
                        }
                    }
                    0x5455 if !data.is_empty() => {
                        let fl = d.u8()?;
                        if fl & 1 != 0 && d.remaining() >= 4 {
                            mtime = Some(d.u32()? as i32 as i64);
                            nanos = 0;
                        }
                    }
                    0x000a if len >= 32 => {
                        d.skip(4)?;
                        while d.remaining() >= 4 {
                            let tag = d.u16()?;
                            let sz = d.u16()? as usize;
                            if tag == 1 && sz >= 8 {
                                let (s, n) = filetime_to_unix(d.u64()?);
                                mtime = Some(s);
                                nanos = n;
                                break;
                            }
                            d.skip(sz.min(d.remaining()))?;
                        }
                    }
                    0x7075 if len > 5 => {
                        if d.u8()? == 1 && d.u32()? == crate::crc::crc32(raw_name) {
                            if let Ok(s) = std::str::from_utf8(d.rest()) {
                                unicode_name = Some(s.to_string());
                            }
                        }
                    }
                    0x9901 if len >= 7 => {
                        let ver = d.u16()?;
                        let _vendor = d.u16()?;
                        let strength = d.u8()?;
                        let real = d.u16()?;
                        aes = Some((strength, real, ver));
                    }
                    _ => {}
                }
            }

            let mut name = if flags & 0x800 != 0 {
                String::from_utf8_lossy(raw_name).into_owned()
            } else if let Some(u) = unicode_name {
                u
            } else {
                decode_name(raw_name)
            };
            if host_is_dos(made_by) {
                name = name.replace('\\', "/");
            }
            if name.len() > limits.max_path_len {
                return Err(Error::limit("entry name too long"));
            }
            let unix = matches!(made_by >> 8, 3 | 19) && (ext_attr >> 16) != 0;
            let mode = ext_attr >> 16;
            let kind = if name.ends_with('/') || (ext_attr & 0x10 != 0 && host_is_dos(made_by)) {
                EntryKind::Dir
            } else if unix {
                match mode & 0o170000 {
                    0o040000 => EntryKind::Dir,
                    0o120000 => EntryKind::Symlink,
                    0o100000 | 0 => EntryKind::File,
                    _ => EntryKind::Special,
                }
            } else {
                EntryKind::File
            };
            let (path, unsafe_path) = normalize_path(&name);
            let encrypted = flags & 1 != 0;
            let real_method = aes.map(|a| a.1).unwrap_or(method);
            let mut method_str = method_name(real_method);
            if encrypted {
                method_str = match aes {
                    Some((s, _, _)) => format!("AES-{} {method_str}", [0, 128, 192, 256].get(s as usize).copied().unwrap_or(0)),
                    None => format!("ZipCrypto {method_str}"),
                };
            }
            let mut entry = Entry::new(entries.len(), path, kind);
            entry.unsafe_path = unsafe_path;
            entry.size = usize;
            entry.packed_size = Some(csize);
            entry.mtime = mtime;
            entry.mtime_nanos = nanos;
            entry.mode = if unix { Some(mode & 0o7777) } else { None };
            entry.crc32 = if aes.is_some_and(|a| a.2 == 2) { None } else { Some(crc) };
            entry.encrypted = encrypted;
            entry.method = Some(method_str);
            if !comment.is_empty() {
                entry.comment = Some(decode_name(comment));
            }
            entries.push(entry);
            metas.push(Meta { method, flags, crc, csize, usize, local_offset, dos_time, aes, limit: 0 });
        }

        // Each entry's data must end before the next local header starts.
        // Overlapping entries are how "non-recursive" zip bombs work.
        let mut order: Vec<usize> = (0..metas.len()).collect();
        order.sort_by_key(|&i| metas[i].local_offset);
        for w in order.windows(2) {
            if metas[w[0]].local_offset == metas[w[1]].local_offset && metas[w[0]].csize + metas[w[1]].csize > 0 {
                return Err(Error::limit("entries share the same data (zip bomb)"));
            }
        }
        for (k, &i) in order.iter().enumerate() {
            let next = order.get(k + 1).map(|&j| metas[j].local_offset).unwrap_or(eocd.cd_offset);
            metas[i].limit = next;
        }

        let comment = if eocd.comment.is_empty() { None } else { Some(decode_name(&eocd.comment)) };
        Ok(ZipReader {
            src,
            size,
            base,
            entries,
            metas,
            comment,
            password: opts.password.clone(),
            limits,
            warnings,
            cd_size: eocd.cd_size,
        })
    }

    /// Builds the full decoding pipeline for entry `i`, reading from `src`.
    fn entry_reader<'a>(
        src: &'a mut dyn ReadSeek,
        base: u64,
        file_size: u64,
        meta: &Meta,
        entry: &Entry,
        password: Option<&Password>,
        limits: &Limits,
    ) -> Result<Box<dyn Read + Send + 'a>> {
        let local = base + meta.local_offset;
        src.seek(SeekFrom::Start(local))?;
        let mut h = [0u8; 30];
        src.read_exact(&mut h)?;
        let mut b = Bytes::new(&h, "zip local header");
        if b.u32()? != LOCAL_SIG {
            return Err(Error::corrupt("local header signature missing"));
        }
        b.skip(22)?;
        let name_len = b.u16()? as u64;
        let extra_len = b.u16()? as u64;
        let data_start = local + 30 + name_len + extra_len;
        let data_end = data_start.checked_add(meta.csize).ok_or_else(|| Error::corrupt("size overflow"))?;
        if data_end > file_size {
            return Err(Error::corrupt("entry data runs past the end of the file"));
        }
        if data_end > base + meta.limit {
            return Err(Error::limit("entry overlaps the next entry (zip bomb)"));
        }
        src.seek(SeekFrom::Start(data_start))?;
        let raw = TakeExact::new(src, meta.csize);

        let mut method = meta.method;
        let decrypted: Box<dyn Read + Send + 'a> = if meta.flags & 1 != 0 {
            if meta.flags & 0x40 != 0 {
                return Err(Error::unsupported("PKWARE strong encryption"));
            }
            let pw = password.ok_or(Error::PasswordRequired)?;
            if let Some((strength, real, _)) = meta.aes {
                method = real;
                let overhead = aes_salt_len(strength)? as u64 + 2 + 10;
                let len = meta.csize.checked_sub(overhead).ok_or_else(|| Error::corrupt("AES entry too small"))?;
                Box::new(AesZipReader::open(raw, pw, strength, len)?)
            } else {
                let mut raw = raw;
                let mut hdr = [0u8; 12];
                raw.read_exact(&mut hdr)?;
                let check = if meta.flags & 8 != 0 { (meta.dos_time >> 8) as u8 } else { (meta.crc >> 24) as u8 };
                let keys = zipcrypto_open(pw, &hdr, check)?;
                Box::new(ZipCryptoReader { inner: raw, keys })
            }
        } else {
            Box::new(raw)
        };

        let decoded: Box<dyn Read + Send + 'a> = match method {
            M_STORE => decrypted,
            M_DEFLATE => Box::new(codecs::deflate::InflateReader::new(BufReader::with_capacity(64 * 1024, decrypted))),
            M_BZIP2 => Box::new(codecs::bz2::BzDecoder::new(decrypted, 1)),
            M_LZMA => {
                let mut r = decrypted;
                let mut hdr = [0u8; 9];
                r.read_exact(&mut hdr)?;
                let props_len = u16::from_le_bytes([hdr[2], hdr[3]]);
                if props_len != 5 {
                    return Err(Error::corrupt("unexpected LZMA properties size"));
                }
                let dict = u32::from_le_bytes([hdr[5], hdr[6], hdr[7], hdr[8]]);
                if u64::from(dict) > limits.max_decoder_memory {
                    return Err(Error::limit("LZMA dictionary too large"));
                }
                let dict = dict.min(meta.usize.max(4096).min(u32::MAX as u64) as u32);
                let size = if meta.flags & 2 != 0 { u64::MAX } else { meta.usize };
                Box::new(
                    lzma_rust2::LzmaReader::new_with_props(BufReader::new(r), size, hdr[4], dict, None)
                        .map_err(|e| Error::corrupt(format!("lzma: {e}")))?,
                )
            }
            M_ZSTD => Box::new(codecs::zstd::ZstdReader::new(BufReader::new(decrypted), limits.max_decoder_memory)),
            M_XZ => Box::new(lzma_rust2::XzReader::new(BufReader::new(decrypted), true)),
            M_PPMD => {
                let mut r = decrypted;
                let mut p = [0u8; 2];
                r.read_exact(&mut p)?;
                let v = u16::from_le_bytes(p);
                let order = u32::from(v & 0xf) + 1;
                let mem = (u32::from((v >> 4) & 0xff) + 1) << 20;
                let restore = if v >> 12 == 0 { ppmd_rust::RestoreMethod::Restart } else { ppmd_rust::RestoreMethod::CutOff };
                if u64::from(mem) > limits.max_decoder_memory {
                    return Err(Error::limit("PPMd model too large"));
                }
                Box::new(
                    ppmd_rust::Ppmd8Decoder::new(BufReader::new(r), order, mem, restore)
                        .map_err(|e| Error::corrupt(format!("ppmd: {e:?}")))?,
                )
            }
            M_DEFLATE64 => return Err(Error::unsupported("Deflate64 compression")),
            other => return Err(Error::unsupported(format!("zip compression method {other}"))),
        };
        let guarded = SizeGuard::new(decoded, Some(meta.usize), limits.max_total_size);
        Ok(Box::new(CrcCheck::new(guarded, entry.crc32, &entry.path)))
    }
}

impl ArchiveReader for ZipReader {
    fn archive_type(&self) -> ArchiveType {
        ArchiveType::ZIP
    }
    fn entries(&self) -> &[Entry] {
        &self.entries
    }
    fn info(&self) -> ArchiveInfo {
        let mut methods: Vec<String> = self.entries.iter().filter_map(|e| e.method.clone()).collect();
        methods.sort();
        methods.dedup();
        ArchiveInfo {
            format: "zip".into(),
            physical_size: self.size,
            methods,
            solid: false,
            blocks: self.entries.len() as u64,
            encrypted_headers: false,
            encrypted_data: self.entries.iter().any(|e| e.encrypted),
            comment: self.comment.clone(),
            volumes: 1,
            headers_size: Some(self.cd_size),
            offset: self.base,
            warnings: self.warnings.clone(),
        }
    }

    fn extract(&mut self, selected: &dyn Fn(&Entry) -> bool, visitor: &mut dyn EntryVisitor, progress: &Progress) -> Result<()> {
        let mut order: Vec<usize> = (0..self.entries.len()).filter(|&i| selected(&self.entries[i])).collect();
        order.sort_by_key(|&i| self.metas[i].local_offset);
        for i in order {
            progress.check()?;
            let entry = &self.entries[i];
            progress.set_current(&entry.path);
            let res = match entry.kind {
                EntryKind::Dir => visitor.dir(entry),
                EntryKind::Special | EntryKind::Hardlink => Ok(()),
                EntryKind::File | EntryKind::Symlink => {
                    match Self::entry_reader(self.src.as_mut(), self.base, self.size, &self.metas[i], entry, self.password.as_ref(), &self.limits) {
                        Err(e) => Err(e),
                        Ok(r) => {
                            if entry.kind == EntryKind::Symlink {
                                let mut target = Vec::new();
                                match r.take(4097).read_to_end(&mut target) {
                                    Err(e) => Err(e.into()),
                                    Ok(_) if target.len() > 4096 => Err(Error::corrupt("symlink target too long")),
                                    Ok(n) => {
                                        progress.add_done(n as u64);
                                        visitor.symlink(entry, &String::from_utf8_lossy(&target))
                                    }
                                }
                            } else {
                                let mut r = Progressed::new(r, progress);
                                visitor.file(entry, &mut r)
                            }
                        }
                    }
                }
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
