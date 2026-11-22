//! gzip framing (RFC 1952): our own header/trailer code around deflate.

use std::io::{self, BufRead, Read, Write};

use super::deflate::InflateReader;
use crate::error::{Error, Result};

const FTEXT: u8 = 1;
const FHCRC: u8 = 2;
const FEXTRA: u8 = 4;
const FNAME: u8 = 8;
const FCOMMENT: u8 = 16;

/// Information from a gzip member header.
#[derive(Debug, Default, Clone)]
pub struct GzipHeader {
    pub name: Option<String>,
    pub comment: Option<String>,
    pub mtime: u32,
    pub os: u8,
}

fn read_zstring<R: BufRead>(r: &mut R, max: usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let mut b = [0u8; 1];
        r.read_exact(&mut b)?;
        if b[0] == 0 {
            return Ok(out);
        }
        if out.len() >= max {
            return Err(Error::corrupt("gzip header string too long"));
        }
        out.push(b[0]);
    }
}

/// Parses a gzip member header; the reader is left at the deflate data.
pub fn read_header<R: BufRead>(r: &mut R) -> Result<GzipHeader> {
    let mut h = [0u8; 10];
    r.read_exact(&mut h)?;
    if h[0] != 0x1f || h[1] != 0x8b {
        return Err(Error::corrupt("not a gzip stream"));
    }
    if h[2] != 8 {
        return Err(Error::unsupported("gzip compression method other than deflate"));
    }
    let flags = h[3];
    let _ = FTEXT;
    let mut hdr = GzipHeader {
        mtime: u32::from_le_bytes([h[4], h[5], h[6], h[7]]),
        os: h[9],
        ..Default::default()
    };
    if flags & FEXTRA != 0 {
        let mut l = [0u8; 2];
        r.read_exact(&mut l)?;
        let len = u16::from_le_bytes(l) as u64;
        io::copy(&mut r.by_ref().take(len), &mut io::sink())?;
    }
    if flags & FNAME != 0 {
        hdr.name = Some(crate::util::decode_name(&read_zstring(r, 65_536)?));
    }
    if flags & FCOMMENT != 0 {
        hdr.comment = Some(crate::util::decode_name(&read_zstring(r, 1 << 20)?));
    }
    if flags & FHCRC != 0 {
        let mut c = [0u8; 2];
        r.read_exact(&mut c)?;
    }
    Ok(hdr)
}

/// Decodes a (possibly multi-member) gzip stream and checks every trailer.
pub struct GzipReader<R: BufRead> {
    inflate: InflateReader<R>,
    crc: crc32fast::Hasher,
    size: u32,
    started: bool,
    finished: bool,
}

impl<R: BufRead> GzipReader<R> {
    pub fn new(inner: R) -> Self {
        GzipReader {
            inflate: InflateReader::new(inner),
            crc: crc32fast::Hasher::new(),
            size: 0,
            started: false,
            finished: false,
        }
    }

    fn finish_member(&mut self) -> Result<bool> {
        let r = self.inflate.get_mut();
        let mut t = [0u8; 8];
        r.read_exact(&mut t).map_err(|_| Error::corrupt("gzip trailer missing"))?;
        let crc = u32::from_le_bytes([t[0], t[1], t[2], t[3]]);
        let isize = u32::from_le_bytes([t[4], t[5], t[6], t[7]]);
        let got = std::mem::replace(&mut self.crc, crc32fast::Hasher::new()).finalize();
        if crc != got {
            return Err(Error::Checksum("gzip data".into()));
        }
        if isize != self.size {
            return Err(Error::corrupt("gzip size field does not match"));
        }
        self.size = 0;
        // Another member follows only if the next bytes are a gzip magic;
        // anything else (zero padding, garbage) ends the stream.
        let next = r.fill_buf()?;
        if next.len() >= 2 && next[0] == 0x1f && next[1] == 0x8b {
            read_header(r)?;
            self.inflate.reset();
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

impl<R: BufRead> Read for GzipReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.finished || buf.is_empty() {
            return Ok(0);
        }
        if !self.started {
            read_header(self.inflate.get_mut())?;
            self.started = true;
        }
        loop {
            let n = self.inflate.read(buf)?;
            if n > 0 {
                self.crc.update(&buf[..n]);
                self.size = self.size.wrapping_add(n as u32);
                return Ok(n);
            }
            if self.inflate.is_done() {
                if !self.finish_member()? {
                    self.finished = true;
                    return Ok(0);
                }
            } else {
                return Ok(0);
            }
        }
    }
}

/// Writes a single-member gzip stream.
pub struct GzipWriter<W: Write> {
    enc: flate2::write::DeflateEncoder<W>,
    crc: crc32fast::Hasher,
    size: u32,
}

impl<W: Write> GzipWriter<W> {
    pub fn new(mut inner: W, level: u32, name: Option<&str>, mtime: u32) -> Result<Self> {
        let flags = if name.is_some() { FNAME } else { 0 };
        let xfl = if level >= 9 { 2 } else if level <= 1 { 4 } else { 0 };
        let m = mtime.to_le_bytes();
        inner.write_all(&[0x1f, 0x8b, 8, flags, m[0], m[1], m[2], m[3], xfl, 3])?;
        if let Some(n) = name {
            // Latin-1 is what the RFC asks for; we store UTF-8 bytes without
            // NULs, which is what every modern gzip does in practice.
            inner.write_all(&n.replace('\0', "").into_bytes())?;
            inner.write_all(&[0])?;
        }
        Ok(GzipWriter {
            enc: flate2::write::DeflateEncoder::new(inner, flate2::Compression::new(level.min(9))),
            crc: crc32fast::Hasher::new(),
            size: 0,
        })
    }

    pub fn finish(self) -> Result<W> {
        let mut w = self.enc.finish()?;
        w.write_all(&self.crc.finalize().to_le_bytes())?;
        w.write_all(&self.size.to_le_bytes())?;
        Ok(w)
    }
}

impl<W: Write> Write for GzipWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.enc.write(buf)?;
        self.crc.update(&buf[..n]);
        self.size = self.size.wrapping_add(n as u32);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.enc.flush()
    }
}

/// Compresses one buffer into a complete gzip member (used for parallel
/// compression: concatenated members are a valid gzip file).
pub fn gzip_member(data: &[u8], level: u32) -> Result<Vec<u8>> {
    let mut w = GzipWriter::new(Vec::with_capacity(data.len() / 3 + 64), level, None, 0)?;
    w.write_all(data)?;
    w.finish()
}
