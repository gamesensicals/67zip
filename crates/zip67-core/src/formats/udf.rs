//! UDF images (ISO/IEC 13346 = ECMA-167, OSTA UDF 1.02 to 2.60), read only,
//! our own code. UDF is the file system of DVDs, Blu-rays and many `.iso`
//! files; it often sits next to an ISO 9660 one ("UDF bridge"), in which
//! case UDF is used because it keeps long Unicode names, big files and
//! permissions.
//!
//! Supported: the volume recognition sequence, anchor and volume
//! descriptors (with the reserve copy as fallback), physical, sparable
//! (without remapping) and metadata partitions (with the mirror as
//! fallback), file entries and extended file entries, ICB indirect
//! entries, short/long/extended allocation descriptors with continuation
//! extents, data embedded in the entry, sparse extents, OSTA compressed
//! Unicode names, symlinks, times and permissions.
//!
//! Not supported: virtual partitions (VAT, packet-written CD-R).
//!
//! Everything read from the image is checked: descriptor checksums and
//! CRCs, addresses against partition and image bounds, and counts against
//! limits. Directory loops and shared directory data are detected, and the
//! total amount of directory data read is capped.

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

/// Volume structure descriptors start at byte 32768, one per 2048 bytes.
const VRS_START: u64 = 32768;
const VRS_STEP: u64 = 2048;

// Descriptor tag identifiers (ECMA-167 3/7.2.1 and 4/7.2.1).
const TAG_PVD: u16 = 1;
const TAG_AVDP: u16 = 2;
const TAG_VDP: u16 = 3;
const TAG_PD: u16 = 5;
const TAG_LVD: u16 = 6;
const TAG_TD: u16 = 8;
const TAG_FSD: u16 = 256;
const TAG_FID: u16 = 257;
const TAG_AED: u16 = 258;
const TAG_IE: u16 = 259;
const TAG_FE: u16 = 261;
const TAG_EFE: u16 = 266;

// Limits for structures no sane image comes close to.
const MAX_VDS_SECTORS: u64 = 4096;
const MAX_VDP_HOPS: usize = 16;
const MAX_PARTITION_MAPS: usize = 64;
const MAX_ADS: usize = 1 << 20;
const MAX_AED_HOPS: usize = 1 << 16;
const MAX_INDIRECT: usize = 64;
const MAX_DEPTH: usize = 128;
const MAX_DIR_BYTES: u64 = 64 << 20;
const MAX_SYMLINK_BYTES: u64 = 64 << 10;

fn u16le(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}
fn u32le(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}
fn u64le(b: &[u8], at: usize) -> u64 {
    u64::from(u32le(b, at)) | (u64::from(u32le(b, at + 4)) << 32)
}

/// CRC-CCITT (x^16 + x^12 + x^5 + 1, initial value 0) used by descriptor tags.
pub(crate) fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &b in data {
        crc ^= u16::from(b) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 { (crc << 1) ^ 0x1021 } else { crc << 1 };
        }
    }
    crc
}

/// Checks a descriptor tag (checksum, CRC and, if given, the recorded
/// location) and returns its identifier.
fn check_tag(b: &[u8], location: Option<u32>) -> Option<u16> {
    if b.len() < 16 {
        return None;
    }
    let sum = b[..16].iter().enumerate().filter(|(i, _)| *i != 4).fold(0u8, |s, (_, &x)| s.wrapping_add(x));
    if sum != b[4] {
        return None;
    }
    let crc_len = usize::from(u16le(b, 10));
    let body = b.get(16..16 + crc_len)?;
    if crc16(body) != u16le(b, 8) {
        return None;
    }
    if let Some(loc) = location
        && u32le(b, 12) != loc
    {
        return None;
    }
    Some(u16le(b, 0))
}

/// Decodes OSTA compressed Unicode (UDF 2.1.1): 8-bit or UTF-16BE.
fn osta_string(b: &[u8]) -> Option<String> {
    let (&id, rest) = b.split_first()?;
    match id {
        // Latin-1 by the book, but some writers (genisoimage) store UTF-8 here.
        8 | 254 => Some(match std::str::from_utf8(rest) {
            Ok(utf8) => utf8.to_string(),
            Err(_) => rest.iter().map(|&c| char::from(c)).collect(),
        }),
        16 | 255 => {
            let units: Vec<u16> = rest.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
            Some(String::from_utf16_lossy(&units))
        }
        _ => None,
    }
}

/// A fixed-size "dstring": the last byte holds the used length.
fn dstring(field: &[u8]) -> String {
    let Some((&len, data)) = field.split_last() else { return String::new() };
    let len = usize::from(len).min(data.len());
    if len == 0 {
        return String::new();
    }
    osta_string(&data[..len]).unwrap_or_default().trim_end_matches('\0').to_string()
}

/// ECMA-167 1/7.3 timestamp to Unix seconds and nanoseconds.
fn udf_time(b: &[u8]) -> Option<(i64, u32)> {
    let type_tz = u16le(b, 0);
    let year = i16::from_le_bytes([b[2], b[3]]);
    let (month, day, hour, min, sec) = (b[4], b[5], b[6], b[7], b[8]);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || min > 59 || sec > 59 || year < 1 {
        return None;
    }
    let dt = jiff::civil::DateTime::new(year, month as i8, day as i8, hour as i8, min as i8, sec as i8, 0).ok()?;
    let mut ts = dt.to_zoned_datetime(jiff::tz::TimeZone::UTC).ok()?.timestamp().as_second();
    let mut offset = i32::from(type_tz & 0x0FFF);
    if offset & 0x800 != 0 {
        offset -= 0x1000;
    }
    if type_tz >> 12 == 1 && offset != -2047 && offset.abs() <= 1440 {
        ts -= i64::from(offset) * 60;
    }
    let nanos = u32::from(b[9].min(99)) * 10_000_000 + u32::from(b[10].min(99)) * 100_000 + u32::from(b[11].min(99)) * 1000;
    Some((ts, nanos))
}

/// Looks for "NSR02"/"NSR03" in the volume recognition sequence. Its
/// descriptors are 2048 bytes apart, or one sector apart on media with
/// bigger sectors.
pub fn has_udf_vrs(src: &mut dyn ReadSeek, size: u64) -> bool {
    [VRS_STEP, 4096].into_iter().any(|step| vrs_with_step(src, size, step))
}

fn vrs_with_step(src: &mut dyn ReadSeek, size: u64, step: u64) -> bool {
    let mut seen_bea = false;
    for i in 0..64u64 {
        let at = VRS_START + i * step;
        if at + 7 > size || src.seek(SeekFrom::Start(at)).is_err() {
            return false;
        }
        let mut d = [0u8; 7];
        if src.read_exact(&mut d).is_err() {
            return false;
        }
        match &d[1..6] {
            b"BEA01" => seen_bea = true,
            b"NSR02" | b"NSR03" => return seen_bea,
            b"CD001" | b"CDW02" | b"BOOT2" => {}
            b"TEA01" => seen_bea = false,
            _ => return false,
        }
    }
    false
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct LbAddr {
    lbn: u32,
    part: u16,
}

fn long_ad(b: &[u8]) -> (u32, LbAddr) {
    (u32le(b, 0), LbAddr { lbn: u32le(b, 4), part: u16le(b, 8) })
}

/// Where a piece of file data comes from.
#[derive(Clone, Debug)]
enum Piece {
    /// Bytes at an offset of the image.
    Disk { offset: u64, len: u64 },
    /// Allocated but unrecorded, or sparse: reads as zeros.
    Zero(u64),
    /// Small files stored inside their file entry.
    Inline(Vec<u8>),
}

impl Piece {
    fn len(&self) -> u64 {
        match self {
            Piece::Disk { len, .. } | Piece::Zero(len) => *len,
            Piece::Inline(v) => v.len() as u64,
        }
    }
}

#[derive(Clone, Debug)]
enum Map {
    /// Type 1 map, or a sparable partition (read without remapping).
    Physical { start: u64, blocks: u64 },
    /// UDF 2.50+ metadata partition: blocks are those of the metadata file.
    Metadata { runs: Vec<(u64, u64)> },
}

/// What a file entry says about one file.
struct Node {
    file_type: u8,
    info_len: u64,
    pieces: Vec<Piece>,
    mtime: Option<(i64, u32)>,
    mode: u32,
}

struct Volume<'a> {
    src: &'a mut dyn ReadSeek,
    size: u64,
    bs: u64,
    maps: Vec<Map>,
}

impl Volume<'_> {
    fn read_at(&mut self, offset: u64, len: usize) -> Result<Vec<u8>> {
        if offset.checked_add(len as u64).is_none_or(|e| e > self.size) {
            return Err(Error::corrupt("UDF structure points outside the image"));
        }
        self.src.seek(SeekFrom::Start(offset))?;
        let mut v = vec![0u8; len];
        self.src.read_exact(&mut v)?;
        Ok(v)
    }

    fn sector(&mut self, n: u64) -> Result<Vec<u8>> {
        let at = n.checked_mul(self.bs).ok_or_else(|| Error::corrupt("UDF sector number overflows"))?;
        self.read_at(at, self.bs as usize)
    }

    /// Byte offset in the image of a logical block.
    fn block_offset(&self, a: LbAddr) -> Result<u64> {
        let bad = || Error::corrupt("UDF address outside its partition");
        match self.maps.get(usize::from(a.part)).ok_or_else(|| Error::corrupt("UDF address uses a missing partition"))? {
            Map::Physical { start, blocks } => {
                if u64::from(a.lbn) >= *blocks {
                    return Err(bad());
                }
                Ok((start + u64::from(a.lbn)) * self.bs)
            }
            Map::Metadata { runs } => {
                let mut want = u64::from(a.lbn) * self.bs;
                for &(offset, len) in runs {
                    if want < len {
                        return Ok(offset + want);
                    }
                    want -= len;
                }
                Err(bad())
            }
        }
    }

    fn block(&mut self, a: LbAddr) -> Result<Vec<u8>> {
        let at = self.block_offset(a)?;
        self.read_at(at, self.bs as usize)
    }

    /// Image ranges of `len` bytes starting at a logical block; metadata
    /// partitions may split them.
    fn runs(&self, a: LbAddr, len: u64) -> Result<Vec<(u64, u64)>> {
        let bad = || Error::corrupt("UDF extent outside its partition");
        match self.maps.get(usize::from(a.part)).ok_or_else(|| Error::corrupt("UDF extent uses a missing partition"))? {
            Map::Physical { start, blocks } => {
                let end_blocks = u64::from(a.lbn) + len.div_ceil(self.bs);
                if end_blocks > *blocks {
                    return Err(bad());
                }
                Ok(vec![((start + u64::from(a.lbn)) * self.bs, len)])
            }
            Map::Metadata { runs } => {
                let mut skip = u64::from(a.lbn) * self.bs;
                let mut left = len;
                let mut out = Vec::new();
                for &(offset, rlen) in runs {
                    if left == 0 {
                        break;
                    }
                    if skip >= rlen {
                        skip -= rlen;
                        continue;
                    }
                    let n = (rlen - skip).min(left);
                    out.push((offset + skip, n));
                    left -= n;
                    skip = 0;
                }
                if left > 0 {
                    return Err(bad());
                }
                Ok(out)
            }
        }
    }

    /// Reads the file entry at `icb`, following indirect entries.
    fn node(&mut self, mut icb: LbAddr) -> Result<Node> {
        for _ in 0..MAX_INDIRECT {
            let b = self.block(icb)?;
            let tag = check_tag(&b, Some(icb.lbn)).ok_or_else(|| Error::corrupt("damaged UDF file entry"))?;
            match tag {
                TAG_IE => {
                    let (_, next) = long_ad(&b[36..52]);
                    icb = next;
                    continue;
                }
                TAG_FE | TAG_EFE => {}
                _ => return Err(Error::corrupt("UDF file entry expected")),
            }
            // UDF strategy 4096: the ICB's second entry, if recorded, is an
            // indirect entry pointing to a newer file entry.
            if u16le(&b, 20) == 4096 && u16le(&b, 24) > 1 {
                let next = LbAddr { lbn: icb.lbn.wrapping_add(1), part: icb.part };
                if let Ok(nb) = self.block(next)
                    && check_tag(&nb, Some(next.lbn)) == Some(TAG_IE)
                {
                    icb = next;
                    continue;
                }
            }
            return self.parse_entry(&b, tag == TAG_EFE, icb);
        }
        Err(Error::corrupt("too many UDF indirect entries"))
    }

    fn parse_entry(&mut self, b: &[u8], extended: bool, icb: LbAddr) -> Result<Node> {
        let (mtime_at, ea_len_at, base) = if extended { (92, 208, 216) } else { (84, 168, 176) };
        let file_type = b[27];
        let flags = u16le(b, 34);
        let perms = u32le(b, 44);
        let info_len = u64le(b, 56);
        let ea_len = u32le(b, ea_len_at) as usize;
        let ad_len = u32le(b, ea_len_at + 4) as usize;
        let ads_at = base + ea_len;
        let ads = b.get(ads_at..ads_at.saturating_add(ad_len)).ok_or_else(|| Error::corrupt("UDF file entry larger than a block"))?;
        let mode = ((perms >> 10) & 7) << 6 | ((perms >> 5) & 7) << 3 | (perms & 7);
        let pieces = match flags & 7 {
            3 => {
                if info_len > ads.len() as u64 {
                    return Err(Error::corrupt("UDF embedded data is shorter than the file"));
                }
                vec![Piece::Inline(ads[..info_len as usize].to_vec())]
            }
            t @ 0..=2 => self.pieces(t, ads, icb.part, info_len)?,
            _ => return Err(Error::corrupt("unknown UDF allocation descriptor type")),
        };
        Ok(Node { file_type, info_len, pieces, mtime: udf_time(&b[mtime_at..mtime_at + 12]), mode })
    }

    /// Turns allocation descriptors into data pieces, `info_len` bytes long.
    fn pieces(&mut self, ad_type: u16, first: &[u8], part: u16, info_len: u64) -> Result<Vec<Piece>> {
        let ad_size = match ad_type {
            0 => 8,
            1 => 16,
            _ => 20,
        };
        let mut out: Vec<Piece> = Vec::new();
        let mut total = 0u64;
        let mut count = 0usize;
        let mut hops = 0usize;
        let mut area = first.to_vec();
        let mut seen_aed = HashSet::new();
        'areas: loop {
            let mut next_area = None;
            for ad in area.chunks_exact(ad_size) {
                if total >= info_len {
                    break 'areas;
                }
                count += 1;
                if count > MAX_ADS {
                    return Err(Error::limit("UDF file has too many extents"));
                }
                let raw_len = u32le(ad, 0);
                let (kind, len) = (raw_len >> 30, u64::from(raw_len & 0x3FFF_FFFF));
                if len == 0 {
                    break 'areas;
                }
                let addr = match ad_type {
                    0 => LbAddr { lbn: u32le(ad, 4), part },
                    1 => long_ad(ad).1,
                    _ => LbAddr { lbn: u32le(ad, 12), part: u16le(ad, 16) },
                };
                if kind == 3 {
                    next_area = Some(addr);
                    break;
                }
                let take = len.min(info_len - total);
                if kind == 0 {
                    for (offset, n) in self.runs(addr, take)? {
                        out.push(Piece::Disk { offset, len: n });
                    }
                } else {
                    out.push(Piece::Zero(take));
                }
                total += take;
            }
            let Some(at) = next_area else { break };
            hops += 1;
            if hops > MAX_AED_HOPS || !seen_aed.insert(at) {
                return Err(Error::corrupt("UDF allocation extents form a loop"));
            }
            let b = self.block(at)?;
            if check_tag(&b, Some(at.lbn)) != Some(TAG_AED) {
                return Err(Error::corrupt("damaged UDF allocation extent"));
            }
            let len = u32le(&b, 20) as usize;
            area = b.get(24..24usize.saturating_add(len)).ok_or_else(|| Error::corrupt("UDF allocation extent larger than a block"))?.to_vec();
        }
        if total < info_len {
            return Err(Error::corrupt("UDF file is longer than its extents"));
        }
        Ok(out)
    }

    /// Reads small metadata (directories, symlinks) completely.
    fn read_pieces(&mut self, pieces: &[Piece], cap: u64) -> Result<Vec<u8>> {
        let total: u64 = pieces.iter().map(Piece::len).sum();
        if total > cap {
            return Err(Error::limit("UDF directory or link too large"));
        }
        let mut out = Vec::with_capacity(total as usize);
        for p in pieces {
            match p {
                Piece::Disk { offset, len } => out.extend(self.read_at(*offset, *len as usize)?),
                Piece::Zero(len) => out.resize(out.len() + *len as usize, 0),
                Piece::Inline(v) => out.extend_from_slice(v),
            }
        }
        Ok(out)
    }
}

/// Parses an ECMA-167 symlink: a list of path components.
fn symlink_target(data: &[u8]) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();
    let mut absolute = false;
    let mut at = 0;
    while at + 4 <= data.len() {
        let (kind, len) = (data[at], usize::from(data[at + 1]));
        let ident = data.get(at + 4..at + 4 + len)?;
        match kind {
            1 | 2 => {
                absolute = true;
                parts.clear();
            }
            3 => parts.push("..".into()),
            4 => parts.push(".".into()),
            5 => {
                let name = osta_string(ident)?;
                if name.is_empty() || name.contains(['/', '\0']) {
                    return None;
                }
                parts.push(name);
            }
            _ => return None,
        }
        at += 4 + len;
    }
    let joined = parts.join("/");
    Some(if absolute { format!("/{joined}") } else { joined })
}

/// What the UDF parser found.
struct Parsed {
    entries: Vec<Entry>,
    data: Vec<Vec<Piece>>,
    revision: Option<u16>,
    label: String,
    problems: Vec<String>,
}

fn find_block_size(src: &mut dyn ReadSeek, size: u64) -> Option<(u64, Vec<u8>)> {
    for bs in [2048u64, 512, 1024, 4096] {
        let sectors = size / bs;
        for n in [256, sectors.saturating_sub(1), sectors.saturating_sub(257)] {
            if n < 256 || (n + 1) * bs > size {
                continue;
            }
            if src.seek(SeekFrom::Start(n * bs)).is_err() {
                continue;
            }
            let mut b = vec![0u8; bs as usize];
            if src.read_exact(&mut b).is_ok() && check_tag(&b, Some(n as u32)) == Some(TAG_AVDP) {
                return Some((bs, b));
            }
        }
    }
    None
}

#[derive(Default)]
struct Descriptors {
    pvd: Option<Vec<u8>>,
    lvd: Option<Vec<u8>>,
    pds: Vec<Vec<u8>>,
}

/// Reads one volume descriptor sequence.
fn read_vds(vol: &mut Volume, mut loc: u64, len: u64) -> Result<Descriptors> {
    let mut d = Descriptors::default();
    let mut left = (len / vol.bs).min(MAX_VDS_SECTORS);
    let mut hops = 0;
    let mut read = 0;
    while left > 0 && read < MAX_VDS_SECTORS {
        let b = vol.sector(loc)?;
        read += 1;
        let Some(tag) = check_tag(&b, Some(loc as u32)) else { break };
        // Later copies (higher sequence number) prevail.
        let newer = |old: &Option<Vec<u8>>| old.as_ref().is_none_or(|o| u32le(&b, 16) >= u32le(o, 16));
        match tag {
            TAG_PVD if newer(&d.pvd) => d.pvd = Some(b),
            TAG_LVD if newer(&d.lvd) => d.lvd = Some(b),
            TAG_PD => {
                let num = u16le(&b, 22);
                match d.pds.iter_mut().find(|p| u16le(p, 22) == num) {
                    Some(p) if u32le(&b, 16) >= u32le(p, 16) => *p = b,
                    Some(_) => {}
                    None => d.pds.push(b),
                }
            }
            TAG_VDP => {
                hops += 1;
                if hops > MAX_VDP_HOPS {
                    break;
                }
                left = (u64::from(u32le(&b, 20)) / vol.bs).min(MAX_VDS_SECTORS);
                loc = u64::from(u32le(&b, 24));
                continue;
            }
            TAG_TD => break,
            _ => {}
        }
        loc += 1;
        left -= 1;
    }
    Ok(d)
}

fn parse(src: &mut dyn ReadSeek, size: u64, limits: &Limits) -> Result<Parsed> {
    let (bs, avdp) = find_block_size(src, size).ok_or_else(|| Error::corrupt("UDF anchor descriptor not found"))?;
    let mut vol = Volume { src, size, bs, maps: Vec::new() };
    let mut problems = Vec::new();

    // The main volume descriptor sequence, then the reserve copy.
    let mut desc = Descriptors::default();
    for (i, at) in [16usize, 24].into_iter().enumerate() {
        match read_vds(&mut vol, u64::from(u32le(&avdp, at + 4)), u64::from(u32le(&avdp, at))) {
            Ok(d) if d.lvd.is_some() && !d.pds.is_empty() => {
                if i == 1 {
                    problems.push("the main UDF volume descriptors are damaged; the reserve copy was used".to_string());
                }
                desc = d;
                break;
            }
            _ => {}
        }
    }
    let lvd = desc.lvd.ok_or_else(|| Error::corrupt("UDF logical volume descriptor not found"))?;
    if u64::from(u32le(&lvd, 212)) != bs {
        return Err(Error::Unsupported("UDF volumes whose block size differs from the sector size".into()));
    }
    // Domain "*OSTA UDF Compliant": the revision follows the identifier.
    let revision = (&lvd[217..236] == b"*OSTA UDF Compliant").then(|| u16le(&lvd, 240));
    let label = dstring(&lvd[84..212]);
    let label = if label.is_empty() { desc.pvd.as_ref().map(|p| dstring(&p[24..56])).unwrap_or_default() } else { label };

    // Partition maps.
    let map_count = u32le(&lvd, 268) as usize;
    let table_len = u32le(&lvd, 264) as usize;
    if map_count > MAX_PARTITION_MAPS || 440 + table_len > lvd.len() {
        return Err(Error::corrupt("bad UDF partition map table"));
    }
    let table = &lvd[440..440 + table_len];
    let partition = |num: u16| -> Result<(u64, u64)> {
        let pd = desc.pds.iter().find(|p| u16le(p, 22) == num).ok_or_else(|| Error::corrupt("UDF partition descriptor missing"))?;
        Ok((u64::from(u32le(pd, 188)), u64::from(u32le(pd, 192))))
    };
    enum Pending {
        Ready(Map),
        Metadata { part: u16, file: u32, mirror: u32 },
    }
    let mut pending = Vec::new();
    let mut at = 0;
    for _ in 0..map_count {
        let (kind, len) = (*table.get(at).unwrap_or(&0), usize::from(*table.get(at + 1).unwrap_or(&0)));
        let m = table.get(at..at + len).filter(|_| len >= 6).ok_or_else(|| Error::corrupt("bad UDF partition map"))?;
        match (kind, len) {
            (1, 6) => {
                let (start, blocks) = partition(u16le(m, 4))?;
                pending.push(Pending::Ready(Map::Physical { start, blocks }));
            }
            (2, 64) => {
                let ident = &m[5..28];
                let num = u16le(m, 38);
                if ident.starts_with(b"*UDF Metadata Partition") {
                    pending.push(Pending::Metadata { part: num, file: u32le(m, 40), mirror: u32le(m, 44) });
                } else if ident.starts_with(b"*UDF Sparable Partition") {
                    let (start, blocks) = partition(num)?;
                    pending.push(Pending::Ready(Map::Physical { start, blocks }));
                } else if ident.starts_with(b"*UDF Virtual Partition") {
                    return Err(Error::Unsupported("UDF virtual partitions (packet-written CD-R)".into()));
                } else {
                    return Err(Error::Unsupported("this kind of UDF partition".into()));
                }
            }
            _ => return Err(Error::corrupt("bad UDF partition map")),
        }
        at += len;
    }
    // Metadata partitions live in the physical partition with the same number:
    // map it first, then read the metadata file (or its mirror) through it.
    vol.maps = pending.iter().map(|p| match p {
        Pending::Ready(m) => m.clone(),
        Pending::Metadata { .. } => Map::Physical { start: 0, blocks: 0 },
    }).collect();
    for (i, p) in pending.iter().enumerate() {
        let Pending::Metadata { part, file, mirror } = p else { continue };
        let (start, blocks) = partition(*part)?;
        let phys = vol.maps.len();
        vol.maps.push(Map::Physical { start, blocks });
        let mut runs = None;
        for (n, loc) in [*file, *mirror].into_iter().enumerate() {
            let got = vol.node(LbAddr { lbn: loc, part: phys as u16 }).and_then(|node| {
                node.pieces
                    .iter()
                    .map(|p| match p {
                        Piece::Disk { offset, len } => Ok((*offset, *len)),
                        _ => Err(Error::corrupt("UDF metadata file has holes")),
                    })
                    .collect::<Result<Vec<_>>>()
            });
            if let Ok(r) = got {
                if n == 1 {
                    problems.push("the UDF metadata file is damaged; its mirror copy was used".to_string());
                }
                runs = Some(r);
                break;
            }
        }
        vol.maps.pop();
        vol.maps[i] = Map::Metadata { runs: runs.ok_or_else(|| Error::corrupt("UDF metadata file unreadable"))? };
    }

    // File set descriptor -> root directory.
    let (_, fsd_at) = long_ad(&lvd[248..264]);
    let fsd = vol.block(fsd_at)?;
    if check_tag(&fsd, Some(fsd_at.lbn)) != Some(TAG_FSD) {
        return Err(Error::corrupt("UDF file set descriptor not found"));
    }
    let (_, root) = long_ad(&fsd[400..416]);

    let mut entries: Vec<Entry> = Vec::new();
    let mut data: Vec<Vec<Piece>> = Vec::new();
    let mut seen_dirs = HashSet::new();
    let mut seen_dir_data = HashSet::new();
    let mut budget = limits.max_header_size.min(512 << 20);
    let mut skipped = 0u64;
    let mut stack = vec![(String::new(), root, 0usize)];
    while let Some((prefix, icb, depth)) = stack.pop() {
        if depth > MAX_DEPTH {
            return Err(Error::corrupt("UDF folders nested too deeply"));
        }
        if !seen_dirs.insert(icb) {
            continue; // the same folder reached twice: a loop
        }
        let shown = if prefix.is_empty() { "/".to_string() } else { crate::util::safe_display(&prefix) };
        let dir = match vol.node(icb) {
            Ok(d) if d.file_type == 4 => d,
            Ok(_) if depth == 0 => return Err(Error::corrupt("UDF root is not a folder")),
            Ok(_) => continue,
            Err(e) if depth == 0 => return Err(e),
            Err(e) => {
                problems.push(format!("UDF folder \"{shown}\" can't be read: {e}"));
                continue;
            }
        };
        if let Some(Piece::Disk { offset, .. }) = dir.pieces.first()
            && !seen_dir_data.insert(*offset)
        {
            continue; // two folders sharing their contents
        }
        let cap = MAX_DIR_BYTES.min(limits.max_header_size).min(budget);
        let raw = match vol.read_pieces(&dir.pieces, cap) {
            Ok(r) => r,
            Err(e @ Error::LimitExceeded(_)) => return Err(e),
            Err(e) if depth == 0 => return Err(e),
            Err(e) => {
                problems.push(format!("UDF folder \"{shown}\" can't be read: {e}"));
                continue;
            }
        };
        budget -= raw.len() as u64;
        let mut off = 0usize;
        while off + 38 <= raw.len() {
            let f = &raw[off..];
            let (l_fi, l_iu) = (usize::from(f[19]), usize::from(u16le(f, 36)));
            let total = (38 + l_iu + l_fi + 3) & !3;
            if u16le(f, 0) == 0 && f[..16].iter().all(|&b| b == 0) {
                break; // padding at the end of the folder
            }
            if total > f.len() || check_tag(&f[..total], None) != Some(TAG_FID) {
                problems.push(format!("a damaged entry in UDF folder \"{shown}\" stopped its listing"));
                break;
            }
            off += total;
            let characteristics = f[18];
            if characteristics & 0x0C != 0 {
                continue; // parent ("..") or deleted
            }
            let (_, child) = long_ad(&f[20..36]);
            let name = osta_string(&f[38 + l_iu..38 + l_iu + l_fi]).unwrap_or_default().replace(['/', '\0'], "_");
            if name.is_empty() || name == "." || name == ".." {
                skipped += 1;
                continue;
            }
            let path = if prefix.is_empty() { name } else { format!("{prefix}/{name}") };
            if entries.len() as u64 >= limits.max_entries {
                return Err(Error::limit("too many entries in UDF image"));
            }
            if path.len() > limits.max_path_len {
                return Err(Error::limit("entry name too long"));
            }
            let node = match vol.node(child) {
                Ok(n) => n,
                Err(e @ Error::LimitExceeded(_)) => return Err(e),
                Err(e) => {
                    problems.push(format!("\"{}\": {e}", crate::util::safe_display(&path)));
                    continue;
                }
            };
            let kind = match node.file_type {
                4 => EntryKind::Dir,
                0 | 5 | 249 => EntryKind::File,
                12 => EntryKind::Symlink,
                _ => EntryKind::Special,
            };
            let (norm, unsafe_path) = normalize_path(&path);
            let mut e = Entry::new(entries.len(), norm, kind);
            e.unsafe_path = unsafe_path;
            if let Some((secs, nanos)) = node.mtime {
                e.mtime = Some(secs);
                e.mtime_nanos = nanos;
            }
            e.mode = Some(node.mode);
            let mut pieces = Vec::new();
            match kind {
                EntryKind::File => {
                    e.size = node.info_len;
                    e.packed_size = Some(node.pieces.iter().filter(|p| !matches!(p, Piece::Zero(_))).map(Piece::len).sum());
                    pieces = node.pieces;
                }
                EntryKind::Symlink => match vol.read_pieces(&node.pieces, MAX_SYMLINK_BYTES).ok().and_then(|d| symlink_target(&d)) {
                    Some(t) => e.link_target = Some(t),
                    None => {
                        problems.push(format!("\"{}\": damaged symbolic link", crate::util::safe_display(&path)));
                        continue;
                    }
                },
                EntryKind::Dir => stack.push((path, child, depth + 1)),
                _ => {}
            }
            entries.push(e);
            data.push(pieces);
        }
    }
    if skipped > 0 {
        problems.push(format!("{skipped} UDF entries with invalid names were skipped"));
    }
    Ok(Parsed { entries, data, revision, label, problems })
}

pub struct UdfReader {
    src: Box<dyn ReadSeek>,
    size: u64,
    entries: Vec<Entry>,
    data: Vec<Vec<Piece>>,
    method: String,
    problems: Vec<String>,
}

impl UdfReader {
    pub fn open(mut src: Box<dyn ReadSeek>, size: u64, opts: &OpenOptions) -> Result<Self> {
        let p = parse(src.as_mut(), size, &opts.limits)?;
        Ok(Self::from_parsed(src, size, p, false))
    }

    /// Opens a disc image: UDF when present and readable, else ISO 9660.
    pub fn open_disc(mut src: Box<dyn ReadSeek>, size: u64, opts: &OpenOptions) -> Result<Box<dyn ArchiveReader>> {
        if !has_udf_vrs(src.as_mut(), size) {
            return Ok(Box::new(super::iso::IsoReader::open(src, size, opts)?));
        }
        let udf = parse(src.as_mut(), size, &opts.limits);
        let has_iso9660 = {
            let mut d = [0u8; 6];
            src.seek(SeekFrom::Start(VRS_START)).is_ok() && src.read_exact(&mut d).is_ok() && &d[1..6] == b"CD001"
        };
        match udf {
            Ok(p) => Ok(Box::new(Self::from_parsed(src, size, p, has_iso9660))),
            Err(e @ (Error::LimitExceeded(_) | Error::Cancelled | Error::Io(_))) => Err(e),
            Err(e) if has_iso9660 => {
                let mut iso = super::iso::IsoReader::open(src, size, opts)?;
                iso.problems.push(format!("the UDF file system can't be read ({e}); showing the ISO 9660 one instead"));
                Ok(Box::new(iso))
            }
            Err(e) => Err(e),
        }
    }

    fn from_parsed(src: Box<dyn ReadSeek>, size: u64, p: Parsed, bridge: bool) -> Self {
        let mut method = match p.revision {
            Some(r) => format!("UDF {}.{:02x}", r >> 8, r & 0xFF),
            None => "UDF".to_string(),
        };
        if bridge {
            method.push_str(" + ISO 9660");
        }
        if !p.label.is_empty() {
            method.push_str(&format!(" \"{}\"", crate::util::safe_display(&p.label)));
        }
        UdfReader { src, size, entries: p.entries, data: p.data, method, problems: p.problems }
    }
}

impl ArchiveReader for UdfReader {
    fn archive_type(&self) -> ArchiveType {
        ArchiveType::ISO
    }
    fn entries(&self) -> &[Entry] {
        &self.entries
    }
    fn info(&self) -> ArchiveInfo {
        ArchiveInfo {
            format: "iso".into(),
            physical_size: self.size,
            methods: vec![self.method.clone()],
            volumes: 1,
            problems: self.problems.clone(),
            ..Default::default()
        }
    }
    fn extract(&mut self, selected: &dyn Fn(&Entry) -> bool, visitor: &mut dyn EntryVisitor, progress: &Progress) -> Result<()> {
        let first_offset = |pieces: &[Piece]| pieces.iter().find_map(|p| if let Piece::Disk { offset, .. } = p { Some(*offset) } else { None }).unwrap_or(0);
        let mut order: Vec<usize> = (0..self.entries.len()).filter(|&i| selected(&self.entries[i])).collect();
        order.sort_by_key(|&i| first_offset(&self.data[i]));
        for i in order {
            progress.check()?;
            let entry = &self.entries[i];
            progress.set_current(&entry.path);
            let res = match entry.kind {
                EntryKind::Dir => visitor.dir(entry),
                EntryKind::Symlink => visitor.symlink(entry, entry.link_target.as_deref().unwrap_or("")),
                EntryKind::File => {
                    let size = self.size;
                    if self.data[i].iter().any(|p| matches!(p, Piece::Disk { offset, len } if offset.checked_add(*len).is_none_or(|e| e > size))) {
                        Err(Error::corrupt("file data lies outside the image"))
                    } else {
                        let mut r = PieceReader { src: self.src.as_mut(), pieces: &self.data[i], idx: 0, done: 0 };
                        let mut p = Progressed::new(&mut r, progress);
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

/// Reads a file's pieces one after another.
struct PieceReader<'a> {
    src: &'a mut dyn ReadSeek,
    pieces: &'a [Piece],
    idx: usize,
    done: u64,
}

impl Read for PieceReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        while let Some(p) = self.pieces.get(self.idx) {
            let left = p.len() - self.done;
            if left == 0 {
                self.idx += 1;
                self.done = 0;
                continue;
            }
            let n = buf.len().min(usize::try_from(left).unwrap_or(usize::MAX));
            let got = match p {
                Piece::Disk { offset, .. } => {
                    self.src.seek(SeekFrom::Start(offset + self.done))?;
                    let got = self.src.read(&mut buf[..n])?;
                    if got == 0 {
                        return Err(Error::corrupt("UDF image ends early").into());
                    }
                    got
                }
                Piece::Zero(_) => {
                    buf[..n].fill(0);
                    n
                }
                Piece::Inline(v) => {
                    let start = self.done as usize;
                    buf[..n].copy_from_slice(&v[start..start + n]);
                    n
                }
            };
            self.done += got as u64;
            return Ok(got);
        }
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc_matches_the_ecma_167_example() {
        // ECMA-167 7.2.6: the CRC of bytes 0x70 0x6A 0x77 is 0x3299.
        assert_eq!(crc16(&[0x70, 0x6A, 0x77]), 0x3299);
    }

    #[test]
    fn names_and_links() {
        assert_eq!(osta_string(&[8, b'a', b'b']).as_deref(), Some("ab"));
        assert_eq!(osta_string(&[16, 0, b'a', 0x26, 0x60]).as_deref(), Some("a\u{2660}"));
        assert_eq!(osta_string(&[7, b'a']), None);
        // 8-bit names: Latin-1, unless the bytes are UTF-8.
        assert_eq!(osta_string(&[8, 0xFC]).as_deref(), Some("\u{fc}"));
        assert_eq!(osta_string(&[8, 0xC3, 0xBC]).as_deref(), Some("\u{fc}"));
        // "/" then "..", "x"
        let link = [2, 0, 0, 0, 3, 0, 0, 0, 5, 2, 0, 0, 8, b'x'];
        assert_eq!(symlink_target(&link).as_deref(), Some("/../x"));
        // A component may not smuggle in a slash.
        assert_eq!(symlink_target(&[5, 4, 0, 0, 8, b'a', b'/', b'b']), None);
    }

    #[test]
    fn timestamps() {
        // 2024-02-29 12:30:15 local time at UTC+1, plus 0.5 s.
        let t = [60, 0x10, 0xE8, 0x07, 2, 29, 12, 30, 15, 50, 0, 0];
        let (secs, nanos) = udf_time(&t).unwrap();
        assert_eq!(secs, 1_709_209_815 - 3600);
        assert_eq!(nanos, 500_000_000);
        assert!(udf_time(&[0; 12]).is_none());
    }
}
