//! 7z header structures, parsing and serialisation (see 7-Zip's
//! 7zFormat.txt). Every count read from the file is checked against the
//! bytes that remain before anything is allocated.

use crate::error::{Error, Result};
use crate::util::Bytes;

pub const SIGNATURE: [u8; 6] = [b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C];

pub mod id {
    pub const END: u8 = 0x00;
    pub const HEADER: u8 = 0x01;
    pub const ARCHIVE_PROPERTIES: u8 = 0x02;
    pub const ADDITIONAL_STREAMS_INFO: u8 = 0x03;
    pub const MAIN_STREAMS_INFO: u8 = 0x04;
    pub const FILES_INFO: u8 = 0x05;
    pub const PACK_INFO: u8 = 0x06;
    pub const UNPACK_INFO: u8 = 0x07;
    pub const SUBSTREAMS_INFO: u8 = 0x08;
    pub const SIZE: u8 = 0x09;
    pub const CRC: u8 = 0x0A;
    pub const FOLDER: u8 = 0x0B;
    pub const CODERS_UNPACK_SIZE: u8 = 0x0C;
    pub const NUM_UNPACK_STREAM: u8 = 0x0D;
    pub const EMPTY_STREAM: u8 = 0x0E;
    pub const EMPTY_FILE: u8 = 0x0F;
    pub const ANTI: u8 = 0x10;
    pub const NAME: u8 = 0x11;
    pub const CTIME: u8 = 0x12;
    pub const ATIME: u8 = 0x13;
    pub const MTIME: u8 = 0x14;
    pub const WIN_ATTRIBUTES: u8 = 0x15;
    pub const ENCODED_HEADER: u8 = 0x17;
    pub const DUMMY: u8 = 0x19;
}

#[derive(Clone, Debug, Default)]
pub struct Coder {
    pub id: Vec<u8>,
    pub num_in: usize,
    pub num_out: usize,
    pub props: Vec<u8>,
}

#[derive(Clone, Debug, Default)]
pub struct Folder {
    pub coders: Vec<Coder>,
    /// (in stream index, out stream index)
    pub bind_pairs: Vec<(usize, usize)>,
    /// In stream indices fed directly from pack streams, in pack order.
    pub packed: Vec<usize>,
    /// Size of every coder out stream.
    pub unpack_sizes: Vec<u64>,
    pub crc: Option<u32>,
    /// Index of this folder's first pack stream.
    pub first_pack: usize,
    pub num_substreams: u64,
}

impl Folder {
    pub fn total_in(&self) -> usize {
        self.coders.iter().map(|c| c.num_in).sum()
    }
    pub fn total_out(&self) -> usize {
        self.coders.iter().map(|c| c.num_out).sum()
    }
    /// The out stream that is not consumed by another coder.
    pub fn main_out(&self) -> Option<usize> {
        (0..self.total_out()).find(|o| !self.bind_pairs.iter().any(|&(_, out)| out == *o))
    }
    pub fn unpack_size(&self) -> u64 {
        self.main_out()
            .and_then(|o| self.unpack_sizes.get(o).copied())
            .unwrap_or(0)
    }
    /// (coder index, first in index, first out index) owning out stream `o`.
    pub fn coder_of_out(&self, o: usize) -> Option<(usize, usize, usize)> {
        let (mut ins, mut outs) = (0, 0);
        for (i, c) in self.coders.iter().enumerate() {
            if o >= outs && o < outs + c.num_out {
                return Some((i, ins, outs));
            }
            ins += c.num_in;
            outs += c.num_out;
        }
        None
    }
    pub fn is_encrypted(&self) -> bool {
        self.coders.iter().any(|c| c.id == super::coders::ID_AES)
    }
}

#[derive(Clone, Debug, Default)]
pub struct StreamsInfo {
    pub pack_pos: u64,
    pub pack_sizes: Vec<u64>,
    pub folders: Vec<Folder>,
    /// Per folder, sizes of its substreams.
    pub sub_sizes: Vec<Vec<u64>>,
    /// Per folder, CRCs of its substreams.
    pub sub_crcs: Vec<Vec<Option<u32>>>,
}

#[derive(Clone, Debug, Default)]
pub struct FileRecord {
    pub name: String,
    pub has_stream: bool,
    pub is_dir: bool,
    pub is_anti: bool,
    pub mtime: Option<u64>,
    pub attrib: Option<u32>,
}

#[derive(Clone, Debug, Default)]
pub struct Header {
    pub streams: StreamsInfo,
    pub files: Vec<FileRecord>,
}

/// 7z variable-length number.
pub fn read_number(b: &mut Bytes) -> Result<u64> {
    let first = b.u8()?;
    let mut mask = 0x80u8;
    let mut value = 0u64;
    for i in 0..8 {
        if first & mask == 0 {
            let high = u64::from(first & mask.wrapping_sub(1));
            value |= high << (8 * i);
            return Ok(value);
        }
        value |= u64::from(b.u8()?) << (8 * i);
        mask >>= 1;
    }
    Ok(value)
}

pub fn write_number(out: &mut Vec<u8>, mut v: u64) {
    let mut first = 0u8;
    let mut mask = 0x80u8;
    let mut i = 0;
    while i < 8 {
        if v < (1u64 << (7 * (i + 1))) {
            first |= (v >> (8 * i)) as u8;
            break;
        }
        first |= mask;
        mask >>= 1;
        i += 1;
    }
    out.push(first);
    while i > 0 {
        out.push(v as u8);
        v >>= 8;
        i -= 1;
    }
}

fn count(b: &mut Bytes, what: &str, max: u64) -> Result<usize> {
    let n = read_number(b)?;
    if n > max {
        return Err(Error::corrupt(format!("7z header: too many {what}")));
    }
    Ok(n as usize)
}

fn bool_vector(b: &mut Bytes, n: usize) -> Result<Vec<bool>> {
    let bytes = b.take(n.div_ceil(8))?;
    Ok((0..n)
        .map(|i| bytes[i / 8] & (0x80 >> (i % 8)) != 0)
        .collect())
}

fn defined_vector(b: &mut Bytes, n: usize) -> Result<Vec<bool>> {
    let all = b.u8()?;
    if all != 0 {
        Ok(vec![true; n])
    } else {
        bool_vector(b, n)
    }
}

fn digests(b: &mut Bytes, n: usize) -> Result<Vec<Option<u32>>> {
    let defined = defined_vector(b, n)?;
    defined
        .into_iter()
        .map(|d| if d { b.u32().map(Some) } else { Ok(None) })
        .collect()
}

fn expect(b: &mut Bytes, want: u8) -> Result<()> {
    let got = b.u8()?;
    if got != want {
        return Err(Error::corrupt(format!(
            "7z header: expected property {want:#x}, found {got:#x}"
        )));
    }
    Ok(())
}

fn read_folder(b: &mut Bytes) -> Result<Folder> {
    let num_coders = count(b, "coders", 64)?;
    if num_coders == 0 {
        return Err(Error::corrupt("7z folder without coders"));
    }
    let mut coders = Vec::with_capacity(num_coders);
    for _ in 0..num_coders {
        let flags = b.u8()?;
        if flags & 0x80 != 0 {
            return Err(Error::unsupported("7z alternative coder methods"));
        }
        let id = b.take((flags & 0x0f) as usize)?.to_vec();
        let (num_in, num_out) = if flags & 0x10 != 0 {
            (count(b, "streams", 64)?, count(b, "streams", 64)?)
        } else {
            (1, 1)
        };
        let props = if flags & 0x20 != 0 {
            let n = count(b, "property bytes", b.remaining() as u64)?;
            b.take(n)?.to_vec()
        } else {
            Vec::new()
        };
        coders.push(Coder {
            id,
            num_in,
            num_out,
            props,
        });
    }
    let mut f = Folder {
        coders,
        ..Default::default()
    };
    let total_out = f.total_out();
    let total_in = f.total_in();
    if total_out == 0 {
        return Err(Error::corrupt("7z folder without outputs"));
    }
    for _ in 0..total_out - 1 {
        let i = count(b, "streams", total_in as u64)?;
        let o = count(b, "streams", total_out as u64)?;
        f.bind_pairs.push((i, o));
    }
    let num_packed = total_in
        .checked_sub(f.bind_pairs.len())
        .ok_or_else(|| Error::corrupt("7z folder bind pairs"))?;
    if num_packed == 1 {
        let free = (0..total_in)
            .find(|i| !f.bind_pairs.iter().any(|&(bi, _)| bi == *i))
            .ok_or_else(|| Error::corrupt("7z folder streams"))?;
        f.packed.push(free);
    } else {
        for _ in 0..num_packed {
            f.packed.push(count(b, "streams", total_in as u64)?);
        }
    }
    Ok(f)
}

fn read_streams_info(b: &mut Bytes) -> Result<StreamsInfo> {
    let mut s = StreamsInfo::default();
    loop {
        match b.u8()? {
            id::END => break,
            id::PACK_INFO => {
                s.pack_pos = read_number(b)?;
                let n = count(b, "pack streams", b.remaining() as u64)?;
                loop {
                    match b.u8()? {
                        id::END => break,
                        id::SIZE => {
                            s.pack_sizes = (0..n).map(|_| read_number(b)).collect::<Result<_>>()?;
                        }
                        id::CRC => {
                            digests(b, n)?;
                        }
                        _ => return Err(Error::corrupt("7z pack info")),
                    }
                }
                if s.pack_sizes.len() != n {
                    s.pack_sizes.resize(n, 0);
                }
            }
            id::UNPACK_INFO => {
                expect(b, id::FOLDER)?;
                let n = count(b, "folders", b.remaining() as u64)?;
                if b.u8()? != 0 {
                    return Err(Error::unsupported("7z external folder data"));
                }
                let mut first_pack = 0;
                for _ in 0..n {
                    let mut f = read_folder(b)?;
                    f.first_pack = first_pack;
                    f.num_substreams = 1;
                    first_pack += f.packed.len();
                    s.folders.push(f);
                }
                expect(b, id::CODERS_UNPACK_SIZE)?;
                for f in &mut s.folders {
                    f.unpack_sizes = (0..f.total_out())
                        .map(|_| read_number(b))
                        .collect::<Result<_>>()?;
                }
                loop {
                    match b.u8()? {
                        id::END => break,
                        id::CRC => {
                            let c = digests(b, s.folders.len())?;
                            for (f, c) in s.folders.iter_mut().zip(c) {
                                f.crc = c;
                            }
                        }
                        _ => return Err(Error::corrupt("7z unpack info")),
                    }
                }
            }
            id::SUBSTREAMS_INFO => {
                let mut t = b.u8()?;
                if t == id::NUM_UNPACK_STREAM {
                    for f in &mut s.folders {
                        f.num_substreams = read_number(b)?;
                        if f.num_substreams > b.remaining() as u64 * 8 + 1 {
                            return Err(Error::corrupt("7z: too many substreams"));
                        }
                    }
                    t = b.u8()?;
                }
                let mut sizes = Vec::with_capacity(s.folders.len());
                let with_sizes = t == id::SIZE;
                for f in &s.folders {
                    let n = f.num_substreams as usize;
                    let mut v = Vec::with_capacity(n.min(1 << 20));
                    if n == 0 {
                        sizes.push(v);
                        continue;
                    }
                    let mut sum = 0u64;
                    if with_sizes {
                        for _ in 0..n - 1 {
                            let x = read_number(b)?;
                            sum = sum
                                .checked_add(x)
                                .ok_or_else(|| Error::corrupt("7z substream sizes"))?;
                            v.push(x);
                        }
                    }
                    let total = f.unpack_size();
                    if with_sizes || n == 1 {
                        let last = total.checked_sub(sum).ok_or_else(|| {
                            Error::corrupt("7z substream sizes exceed folder size")
                        })?;
                        v.push(last);
                    } else {
                        return Err(Error::corrupt("7z substream sizes missing"));
                    }
                    sizes.push(v);
                }
                if with_sizes {
                    t = b.u8()?;
                }
                // CRCs are listed for substreams whose CRC is not already
                // known from the folder (a folder with one substream and a CRC).
                let mut crcs: Vec<Vec<Option<u32>>> = s
                    .folders
                    .iter()
                    .map(|f| {
                        if f.num_substreams == 1 && f.crc.is_some() {
                            vec![f.crc]
                        } else {
                            vec![None; f.num_substreams as usize]
                        }
                    })
                    .collect();
                loop {
                    match t {
                        id::END => break,
                        id::CRC => {
                            let need: usize = s
                                .folders
                                .iter()
                                .filter(|f| !(f.num_substreams == 1 && f.crc.is_some()))
                                .map(|f| f.num_substreams as usize)
                                .sum();
                            let d = digests(b, need)?;
                            let mut it = d.into_iter();
                            for (fi, f) in s.folders.iter().enumerate() {
                                if f.num_substreams == 1 && f.crc.is_some() {
                                    continue;
                                }
                                for c in crcs[fi].iter_mut() {
                                    *c = it.next().flatten();
                                }
                            }
                        }
                        _ => return Err(Error::corrupt("7z substreams info")),
                    }
                    t = b.u8()?;
                }
                s.sub_sizes = sizes;
                s.sub_crcs = crcs;
            }
            _ => return Err(Error::corrupt("7z streams info")),
        }
    }
    if s.sub_sizes.is_empty() {
        s.sub_sizes = s.folders.iter().map(|f| vec![f.unpack_size()]).collect();
        s.sub_crcs = s.folders.iter().map(|f| vec![f.crc]).collect();
    }
    Ok(s)
}

fn read_times(b: &mut Bytes, n: usize) -> Result<Vec<Option<u64>>> {
    let defined = defined_vector(b, n)?;
    if b.u8()? != 0 {
        return Err(Error::unsupported("7z external time data"));
    }
    defined
        .into_iter()
        .map(|d| if d { b.u64().map(Some) } else { Ok(None) })
        .collect()
}

fn read_files(b: &mut Bytes, max_entries: u64) -> Result<Vec<FileRecord>> {
    let n = count(b, "files", max_entries.min(b.remaining() as u64 * 8 + 1))?;
    let mut files = vec![
        FileRecord {
            has_stream: true,
            ..Default::default()
        };
        n
    ];
    let mut empty_stream: Vec<bool> = vec![false; n];
    let mut empty_file: Vec<bool> = Vec::new();
    let mut anti: Vec<bool> = Vec::new();
    loop {
        let t = b.u8()?;
        if t == id::END {
            break;
        }
        let size = read_number(b)?;
        if size > b.remaining() as u64 {
            return Err(Error::corrupt("7z file property too large"));
        }
        let data = b.take(size as usize)?;
        let mut d = Bytes::new(data, "7z file property");
        let num_empty = empty_stream.iter().filter(|&&e| e).count();
        match t {
            id::EMPTY_STREAM => empty_stream = bool_vector(&mut d, n)?,
            id::EMPTY_FILE => empty_file = bool_vector(&mut d, num_empty)?,
            id::ANTI => anti = bool_vector(&mut d, num_empty)?,
            id::NAME => {
                if d.u8()? != 0 {
                    return Err(Error::unsupported("7z external names"));
                }
                let raw = d.rest();
                let units: Vec<u16> = raw
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                let mut names = units.split(|&u| u == 0);
                for f in files.iter_mut() {
                    let u = names
                        .next()
                        .ok_or_else(|| Error::corrupt("7z: missing file names"))?;
                    f.name = String::from_utf16_lossy(u);
                }
            }
            id::MTIME => {
                let t = read_times(&mut d, n)?;
                for (f, t) in files.iter_mut().zip(t) {
                    f.mtime = t;
                }
            }
            id::WIN_ATTRIBUTES => {
                let defined = defined_vector(&mut d, n)?;
                if d.u8()? != 0 {
                    return Err(Error::unsupported("7z external attributes"));
                }
                for (f, def) in files.iter_mut().zip(defined) {
                    if def {
                        f.attrib = Some(d.u32()?);
                    }
                }
            }
            _ => {} // CTime, ATime, StartPos, Dummy, unknown: ignored
        }
    }
    let mut ei = 0;
    for (i, f) in files.iter_mut().enumerate() {
        if empty_stream[i] {
            f.has_stream = false;
            let is_empty_file = empty_file.get(ei).copied().unwrap_or(false);
            f.is_anti = anti.get(ei).copied().unwrap_or(false);
            f.is_dir = !is_empty_file;
            ei += 1;
        }
        if let Some(a) = f.attrib {
            if a & 0x10 != 0 && !f.has_stream {
                f.is_dir = true;
            }
        }
    }
    Ok(files)
}

fn skip_archive_properties(b: &mut Bytes) -> Result<()> {
    loop {
        let t = b.u8()?;
        if t == id::END {
            return Ok(());
        }
        let n = read_number(b)?;
        if n > b.remaining() as u64 {
            return Err(Error::corrupt("7z archive properties"));
        }
        b.skip(n as usize)?;
    }
}

/// Parses a plain (not encoded) header that starts with `kHeader`.
pub fn read_header(data: &[u8], max_entries: u64) -> Result<Header> {
    let mut b = Bytes::new(data, "7z header");
    expect(&mut b, id::HEADER)?;
    let mut h = Header::default();
    loop {
        match b.u8()? {
            id::END => break,
            id::ARCHIVE_PROPERTIES => skip_archive_properties(&mut b)?,
            id::ADDITIONAL_STREAMS_INFO => {
                read_streams_info(&mut b)?;
            }
            id::MAIN_STREAMS_INFO => h.streams = read_streams_info(&mut b)?,
            id::FILES_INFO => h.files = read_files(&mut b, max_entries)?,
            other => {
                return Err(Error::corrupt(format!(
                    "7z header: unexpected property {other:#x}"
                )));
            }
        }
    }
    Ok(h)
}

/// Parses the streams info that follows `kEncodedHeader`.
pub fn read_encoded_header_info(data: &[u8]) -> Result<StreamsInfo> {
    let mut b = Bytes::new(data, "7z encoded header");
    expect(&mut b, id::ENCODED_HEADER)?;
    read_streams_info(&mut b)
}

// ----- writing -------------------------------------------------------------

fn write_bool_vector(out: &mut Vec<u8>, v: &[bool]) {
    let mut byte = 0u8;
    let mut mask = 0x80u8;
    for &x in v {
        if x {
            byte |= mask;
        }
        mask >>= 1;
        if mask == 0 {
            out.push(byte);
            byte = 0;
            mask = 0x80;
        }
    }
    if mask != 0x80 {
        out.push(byte);
    }
}

pub fn write_folder(out: &mut Vec<u8>, f: &Folder) {
    write_number(out, f.coders.len() as u64);
    for c in &f.coders {
        let complex = c.num_in != 1 || c.num_out != 1;
        let mut flags = c.id.len() as u8;
        if complex {
            flags |= 0x10;
        }
        if !c.props.is_empty() {
            flags |= 0x20;
        }
        out.push(flags);
        out.extend_from_slice(&c.id);
        if complex {
            write_number(out, c.num_in as u64);
            write_number(out, c.num_out as u64);
        }
        if !c.props.is_empty() {
            write_number(out, c.props.len() as u64);
            out.extend_from_slice(&c.props);
        }
    }
    for &(i, o) in &f.bind_pairs {
        write_number(out, i as u64);
        write_number(out, o as u64);
    }
    if f.packed.len() > 1 {
        for &p in &f.packed {
            write_number(out, p as u64);
        }
    }
}

pub fn write_streams_info(out: &mut Vec<u8>, s: &StreamsInfo) {
    out.push(id::PACK_INFO);
    write_number(out, s.pack_pos);
    write_number(out, s.pack_sizes.len() as u64);
    out.push(id::SIZE);
    for &p in &s.pack_sizes {
        write_number(out, p);
    }
    out.push(id::END);

    out.push(id::UNPACK_INFO);
    out.push(id::FOLDER);
    write_number(out, s.folders.len() as u64);
    out.push(0);
    for f in &s.folders {
        write_folder(out, f);
    }
    out.push(id::CODERS_UNPACK_SIZE);
    for f in &s.folders {
        for &u in &f.unpack_sizes {
            write_number(out, u);
        }
    }
    if s.folders.iter().all(|f| f.crc.is_some()) && !s.folders.is_empty() {
        out.push(id::CRC);
        out.push(1);
        for f in &s.folders {
            out.extend_from_slice(&f.crc.unwrap_or(0).to_le_bytes());
        }
    }
    out.push(id::END);

    if !s.sub_sizes.is_empty() {
        out.push(id::SUBSTREAMS_INFO);
        if s.sub_sizes.iter().any(|v| v.len() != 1) {
            out.push(id::NUM_UNPACK_STREAM);
            for v in &s.sub_sizes {
                write_number(out, v.len() as u64);
            }
        }
        if s.sub_sizes.iter().any(|v| v.len() > 1) {
            out.push(id::SIZE);
            for v in &s.sub_sizes {
                for &x in v.iter().take(v.len().saturating_sub(1)) {
                    write_number(out, x);
                }
            }
        }
        let crcs: Vec<u32> = s
            .sub_crcs
            .iter()
            .flatten()
            .map(|c| c.unwrap_or(0))
            .collect();
        if !crcs.is_empty() {
            out.push(id::CRC);
            out.push(1);
            for c in crcs {
                out.extend_from_slice(&c.to_le_bytes());
            }
        }
        out.push(id::END);
    }
    out.push(id::END);
}

pub fn write_files(out: &mut Vec<u8>, files: &[FileRecord]) {
    out.push(id::FILES_INFO);
    write_number(out, files.len() as u64);
    let empty: Vec<bool> = files.iter().map(|f| !f.has_stream).collect();
    if empty.iter().any(|&e| e) {
        let mut v = Vec::new();
        write_bool_vector(&mut v, &empty);
        out.push(id::EMPTY_STREAM);
        write_number(out, v.len() as u64);
        out.extend_from_slice(&v);
        let empty_files: Vec<bool> = files
            .iter()
            .filter(|f| !f.has_stream)
            .map(|f| !f.is_dir)
            .collect();
        if empty_files.iter().any(|&e| e) {
            let mut v = Vec::new();
            write_bool_vector(&mut v, &empty_files);
            out.push(id::EMPTY_FILE);
            write_number(out, v.len() as u64);
            out.extend_from_slice(&v);
        }
    }
    let mut names = vec![0u8];
    for f in files {
        for u in f.name.encode_utf16() {
            names.extend_from_slice(&u.to_le_bytes());
        }
        names.extend_from_slice(&[0, 0]);
    }
    out.push(id::NAME);
    write_number(out, names.len() as u64);
    out.extend_from_slice(&names);

    if files.iter().all(|f| f.mtime.is_some()) && !files.is_empty() {
        out.push(id::MTIME);
        write_number(out, 2 + 8 * files.len() as u64);
        out.push(1);
        out.push(0);
        for f in files {
            out.extend_from_slice(&f.mtime.unwrap_or(0).to_le_bytes());
        }
    }
    if files.iter().all(|f| f.attrib.is_some()) && !files.is_empty() {
        out.push(id::WIN_ATTRIBUTES);
        write_number(out, 2 + 4 * files.len() as u64);
        out.push(1);
        out.push(0);
        for f in files {
            out.extend_from_slice(&f.attrib.unwrap_or(0).to_le_bytes());
        }
    }
    out.push(id::END);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_roundtrip() {
        for v in [
            0u64,
            1,
            0x7f,
            0x80,
            0x3fff,
            0x4000,
            1 << 20,
            1 << 35,
            u64::MAX - 1,
            u64::MAX,
        ] {
            let mut out = Vec::new();
            write_number(&mut out, v);
            let mut b = Bytes::new(&out, "t");
            assert_eq!(read_number(&mut b).unwrap(), v, "{v:#x}");
            assert!(b.is_empty());
        }
    }
}
