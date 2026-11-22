//! Zip writer: streams each file once, then patches sizes and CRC into the
//! local header (output must be seekable). Writes Zip64 records only when
//! needed, UTF-8 names, Unix attributes and WinZip AES-256 encryption.

use std::io::{self, Read, Seek, SeekFrom, Write};

use super::crypto::AesZipWriter;
use super::read::{M_AES, M_BZIP2, M_DEFLATE, M_LZMA, M_STORE, M_XZ, M_ZSTD};
use crate::codecs::{self, BoxWrite, FinishWrite};
use crate::create::{ArchiveWriter, Item, Method};
use crate::detect::Compression;
use crate::entry::EntryKind;
use crate::error::{Error, Result};
use crate::password::Password;
use crate::progress::Progress;
use crate::util::unix_to_dos;

struct CdRecord {
    name: Vec<u8>,
    flags: u16,
    method: u16,
    dos_time: u16,
    dos_date: u16,
    crc: u32,
    csize: u64,
    usize: u64,
    offset: u64,
    ext_attr: u32,
    mtime: Option<i32>,
    aes_method: Option<u16>,
    version_needed: u16,
}

pub struct ZipWriter<W: Write + Seek + Send> {
    out: W,
    records: Vec<CdRecord>,
    method: Method,
    level: u32,
    threads: usize,
    password: Option<Password>,
}

fn zip_method_id(m: Method) -> Result<u16> {
    Ok(match m {
        Method::Copy => M_STORE,
        Method::Deflate => M_DEFLATE,
        Method::Bzip2 => M_BZIP2,
        Method::Lzma => M_LZMA,
        Method::Zstd => M_ZSTD,
        Method::Xz => M_XZ,
        other => {
            return Err(Error::invalid(format!(
                "{other:?} is not available for zip archives"
            )));
        }
    })
}

/// Writes 32-bit sizes/offsets, signalling "see Zip64 extra" with 0xFFFFFFFF.
fn u32_or_max(v: u64) -> u32 {
    if v >= 0xFFFF_FFFF {
        0xFFFF_FFFF
    } else {
        v as u32
    }
}

impl<W: Write + Seek + Send> ZipWriter<W> {
    pub fn new(
        out: W,
        method: Method,
        level: u32,
        threads: usize,
        password: Option<Password>,
    ) -> Result<Self> {
        zip_method_id(method)?;
        Ok(ZipWriter {
            out,
            records: Vec::new(),
            method,
            level,
            threads,
            password,
        })
    }

    fn encoder<'a>(
        method: Method,
        lvl: u32,
        threads: usize,
        w: BoxWrite<'a>,
    ) -> Result<Box<dyn FinishWrite + 'a>> {
        Ok(match method {
            Method::Copy => codecs::encoder(Compression::None, w, 0, 1, None, 0)?,
            Method::Deflate => Box::new(DeflateW(flate2::write::DeflateEncoder::new(
                w,
                flate2::Compression::new(codecs::deflate_level(lvl)),
            ))),
            Method::Bzip2 => codecs::encoder(Compression::Bzip2, w, lvl, threads, None, 0)?,
            Method::Xz => codecs::encoder(Compression::Xz, w, lvl, threads, None, 0)?,
            Method::Zstd => codecs::encoder(Compression::Zstd, w, lvl, threads, None, 0)?,
            Method::Lzma => {
                let mut w = w;
                let opts = codecs::lzma_options(lvl);
                // 7-Zip compatible header: version 9.20, props size 5.
                w.write_all(&[9, 20, 5, 0])?;
                let enc = lzma_rust2::LzmaWriter::new_no_header(w, &opts, true)?;
                Box::new(LzmaZipW {
                    enc: Some(enc),
                    header_done: false,
                    opts,
                })
            }
            other => {
                return Err(Error::invalid(format!(
                    "{other:?} is not available for zip archives"
                )));
            }
        })
    }
}

struct DeflateW<'a>(flate2::write::DeflateEncoder<BoxWrite<'a>>);
impl Write for DeflateW<'_> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.0.write(b)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}
impl FinishWrite for DeflateW<'_> {
    fn finish_box(self: Box<Self>) -> Result<()> {
        self.0.finish()?.flush()?;
        Ok(())
    }
}

/// LZMA in zip: [ver, ver, 5, 0] + 5 props bytes + raw LZMA with end marker.
struct LzmaZipW<'a> {
    enc: Option<lzma_rust2::LzmaWriter<BoxWrite<'a>>>,
    header_done: bool,
    opts: lzma_rust2::LzmaOptions,
}
impl LzmaZipW<'_> {
    fn header(&mut self) -> io::Result<()> {
        if !self.header_done {
            self.header_done = true;
            let enc = self
                .enc
                .as_mut()
                .ok_or_else(|| io::Error::other("finished"))?;
            let props = enc.props();
            let dict = self.opts.dict_size.to_le_bytes();
            // Written straight to the underlying writer: the range encoder
            // has not emitted anything yet at this point.
            let inner = enc.inner_mut();
            inner.write_all(&[props, dict[0], dict[1], dict[2], dict[3]])?;
        }
        Ok(())
    }
}
impl Write for LzmaZipW<'_> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.header()?;
        self.enc
            .as_mut()
            .ok_or_else(|| io::Error::other("finished"))?
            .write(b)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl FinishWrite for LzmaZipW<'_> {
    fn finish_box(mut self: Box<Self>) -> Result<()> {
        self.header()?;
        let enc = self.enc.take().ok_or_else(|| Error::invalid("finished"))?;
        enc.finish()?.flush()?;
        Ok(())
    }
}

/// Lets an encoder write into `&mut W` while we keep ownership of `W`.
struct Borrowed<'a, W: Write>(&'a mut W, &'a mut u64);
impl<W: Write> Write for Borrowed<'_, W> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        let n = self.0.write(b)?;
        *self.1 += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl<W: Write + Seek + Send> ArchiveWriter for ZipWriter<W> {
    fn add(&mut self, item: &Item, data: Option<&mut dyn Read>, progress: &Progress) -> Result<()> {
        let mut name = item.arcname.clone();
        if item.kind == EntryKind::Dir && !name.ends_with('/') {
            name.push('/');
        }
        let name_bytes = name.into_bytes();
        if name_bytes.len() > 0xFFFF {
            return Err(Error::invalid("file name too long for zip"));
        }
        let (dos_date, dos_time) = unix_to_dos(item.mtime);
        let ut = i32::try_from(item.mtime).ok();
        let type_bits = match item.kind {
            EntryKind::Dir => 0o040000,
            EntryKind::Symlink => 0o120000,
            _ => 0o100000,
        };
        let ext_attr = ((type_bits | (item.mode & 0o7777)) << 16)
            | if item.kind == EntryKind::Dir { 0x10 } else { 0 };

        let is_dir = item.kind == EntryKind::Dir;
        let symlink = item.kind == EntryKind::Symlink;
        // Directories and symlinks are stored; small files too (no gain).
        let method = if is_dir || symlink || item.size == 0 {
            Method::Copy
        } else {
            self.method
        };
        let method_id = zip_method_id(method)?;
        let encrypt = self.password.is_some() && !is_dir;
        let zip64 = item.size >= 0xFFFF_0000;

        let mut flags: u16 = 0x0800; // UTF-8 names
        if encrypt {
            flags |= 1;
        }
        if method == Method::Lzma {
            flags |= 2; // end marker present
        }
        let header_method = if encrypt { M_AES } else { method_id };
        let version_needed: u16 = if zip64 {
            45
        } else {
            match method {
                Method::Copy if !is_dir && !encrypt => 10,
                Method::Bzip2 => 46,
                Method::Lzma | Method::Xz | Method::Zstd => 63,
                _ => 20,
            }
        }
        .max(if encrypt { 51 } else { 0 });

        let offset = self.out.stream_position()?;
        let mut extra = Vec::new();
        if zip64 {
            extra.extend_from_slice(&1u16.to_le_bytes());
            extra.extend_from_slice(&16u16.to_le_bytes());
            extra.extend_from_slice(&[0u8; 16]);
        }
        if let Some(t) = ut {
            extra.extend_from_slice(&0x5455u16.to_le_bytes());
            extra.extend_from_slice(&5u16.to_le_bytes());
            extra.push(1);
            extra.extend_from_slice(&t.to_le_bytes());
        }
        if encrypt {
            extra.extend_from_slice(&0x9901u16.to_le_bytes());
            extra.extend_from_slice(&7u16.to_le_bytes());
            extra.extend_from_slice(&2u16.to_le_bytes()); // AE-2: no CRC, HMAC only
            extra.extend_from_slice(b"AE");
            extra.push(3); // AES-256
            extra.extend_from_slice(&method_id.to_le_bytes());
        }
        let mut lh = Vec::with_capacity(30 + name_bytes.len() + extra.len());
        lh.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        lh.extend_from_slice(&version_needed.to_le_bytes());
        lh.extend_from_slice(&flags.to_le_bytes());
        lh.extend_from_slice(&header_method.to_le_bytes());
        lh.extend_from_slice(&dos_time.to_le_bytes());
        lh.extend_from_slice(&dos_date.to_le_bytes());
        lh.extend_from_slice(&[0u8; 12]); // crc, csize, usize: patched later
        lh.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        lh.extend_from_slice(&(extra.len() as u16).to_le_bytes());
        lh.extend_from_slice(&name_bytes);
        lh.extend_from_slice(&extra);
        self.out.write_all(&lh)?;

        let mut crc = crc32fast::Hasher::new();
        let mut usize = 0u64;
        let _ = &mut crc;
        let mut csize = 0u64;
        if !is_dir {
            let link_bytes;
            let mut link_reader;
            let src: &mut dyn Read = if symlink {
                link_bytes = item.link_target.clone().unwrap_or_default().into_bytes();
                link_reader = &link_bytes[..];
                &mut link_reader
            } else {
                data.ok_or_else(|| Error::invalid("file data missing"))?
            };
            let mut out = Borrowed(&mut self.out, &mut csize);
            let (lvl, threads) = (self.level, self.threads);
            let (c, n) = if let Some(pw) = &self.password {
                let mut aes = AesZipWriter::new(&mut out, pw)?;
                let r = compress_stream(
                    src,
                    Box::new(&mut aes),
                    method,
                    lvl,
                    threads,
                    progress,
                    !symlink,
                )?;
                // Appends the authentication code after the encrypted data.
                aes.finish()?;
                r
            } else {
                compress_stream(
                    src,
                    Box::new(&mut out),
                    method,
                    lvl,
                    threads,
                    progress,
                    !symlink,
                )?
            };
            crc = c;
            usize = n;
        }
        progress.add_packed(csize);
        if !zip64 && (usize >= 0xFFFF_FFFF || csize >= 0xFFFF_FFFF) {
            return Err(Error::invalid("file grew while it was being compressed"));
        }
        let crc = crc.finalize();
        let stored_crc = if encrypt { 0 } else { crc };
        let end = self.out.stream_position()?;
        self.out.seek(SeekFrom::Start(offset + 14))?;
        self.out.write_all(&stored_crc.to_le_bytes())?;
        if zip64 {
            self.out.write_all(&[0xFF; 8])?;
            self.out
                .seek(SeekFrom::Start(offset + 30 + name_bytes.len() as u64 + 4))?;
            self.out.write_all(&usize.to_le_bytes())?;
            self.out.write_all(&csize.to_le_bytes())?;
        } else {
            self.out.write_all(&(csize as u32).to_le_bytes())?;
            self.out.write_all(&(usize as u32).to_le_bytes())?;
        }
        self.out.seek(SeekFrom::Start(end))?;

        self.records.push(CdRecord {
            name: name_bytes,
            flags,
            method: header_method,
            dos_time,
            dos_date,
            crc: stored_crc,
            csize,
            usize,
            offset,
            ext_attr,
            mtime: ut,
            aes_method: if encrypt { Some(method_id) } else { None },
            version_needed,
        });
        Ok(())
    }

    fn finish(mut self: Box<Self>, _progress: &Progress) -> Result<()> {
        let cd_start = self.out.stream_position()?;
        for r in &self.records {
            let mut z64 = Vec::new();
            if r.usize >= 0xFFFF_FFFF {
                z64.extend_from_slice(&r.usize.to_le_bytes());
            }
            if r.csize >= 0xFFFF_FFFF {
                z64.extend_from_slice(&r.csize.to_le_bytes());
            }
            if r.offset >= 0xFFFF_FFFF {
                z64.extend_from_slice(&r.offset.to_le_bytes());
            }
            let mut extra = Vec::new();
            if !z64.is_empty() {
                extra.extend_from_slice(&1u16.to_le_bytes());
                extra.extend_from_slice(&(z64.len() as u16).to_le_bytes());
                extra.extend_from_slice(&z64);
            }
            if let Some(t) = r.mtime {
                extra.extend_from_slice(&0x5455u16.to_le_bytes());
                extra.extend_from_slice(&5u16.to_le_bytes());
                extra.push(1);
                extra.extend_from_slice(&t.to_le_bytes());
            }
            if let Some(m) = r.aes_method {
                extra.extend_from_slice(&0x9901u16.to_le_bytes());
                extra.extend_from_slice(&7u16.to_le_bytes());
                extra.extend_from_slice(&2u16.to_le_bytes());
                extra.extend_from_slice(b"AE");
                extra.push(3);
                extra.extend_from_slice(&m.to_le_bytes());
            }
            let need = if z64.is_empty() {
                r.version_needed
            } else {
                r.version_needed.max(45)
            };
            let mut h = Vec::with_capacity(46 + r.name.len() + extra.len());
            h.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
            h.extend_from_slice(&((3u16 << 8) | 63).to_le_bytes());
            h.extend_from_slice(&need.to_le_bytes());
            h.extend_from_slice(&r.flags.to_le_bytes());
            h.extend_from_slice(&r.method.to_le_bytes());
            h.extend_from_slice(&r.dos_time.to_le_bytes());
            h.extend_from_slice(&r.dos_date.to_le_bytes());
            h.extend_from_slice(&r.crc.to_le_bytes());
            h.extend_from_slice(&u32_or_max(r.csize).to_le_bytes());
            h.extend_from_slice(&u32_or_max(r.usize).to_le_bytes());
            h.extend_from_slice(&(r.name.len() as u16).to_le_bytes());
            h.extend_from_slice(&(extra.len() as u16).to_le_bytes());
            h.extend_from_slice(&0u16.to_le_bytes()); // comment
            h.extend_from_slice(&0u16.to_le_bytes()); // disk
            h.extend_from_slice(&0u16.to_le_bytes()); // internal attributes
            h.extend_from_slice(&r.ext_attr.to_le_bytes());
            h.extend_from_slice(&u32_or_max(r.offset).to_le_bytes());
            h.extend_from_slice(&r.name);
            h.extend_from_slice(&extra);
            self.out.write_all(&h)?;
        }
        let cd_end = self.out.stream_position()?;
        let cd_size = cd_end - cd_start;
        let n = self.records.len() as u64;
        let need64 = n >= 0xFFFF || cd_start >= 0xFFFF_FFFF || cd_size >= 0xFFFF_FFFF;
        if need64 {
            let mut r = Vec::with_capacity(56 + 20);
            r.extend_from_slice(b"PK\x06\x06");
            r.extend_from_slice(&44u64.to_le_bytes());
            r.extend_from_slice(&((3u16 << 8) | 63).to_le_bytes());
            r.extend_from_slice(&45u16.to_le_bytes());
            r.extend_from_slice(&0u32.to_le_bytes());
            r.extend_from_slice(&0u32.to_le_bytes());
            r.extend_from_slice(&n.to_le_bytes());
            r.extend_from_slice(&n.to_le_bytes());
            r.extend_from_slice(&cd_size.to_le_bytes());
            r.extend_from_slice(&cd_start.to_le_bytes());
            r.extend_from_slice(b"PK\x06\x07");
            r.extend_from_slice(&0u32.to_le_bytes());
            r.extend_from_slice(&cd_end.to_le_bytes());
            r.extend_from_slice(&1u32.to_le_bytes());
            self.out.write_all(&r)?;
        }
        let mut e = Vec::with_capacity(22);
        e.extend_from_slice(b"PK\x05\x06");
        e.extend_from_slice(&[0u8; 4]);
        let n16 = if n >= 0xFFFF { 0xFFFF } else { n as u16 };
        e.extend_from_slice(&n16.to_le_bytes());
        e.extend_from_slice(&n16.to_le_bytes());
        e.extend_from_slice(&u32_or_max(cd_size).to_le_bytes());
        e.extend_from_slice(&u32_or_max(cd_start).to_le_bytes());
        e.extend_from_slice(&0u16.to_le_bytes());
        self.out.write_all(&e)?;
        self.out.flush()?;
        Ok(())
    }
}

fn compress_stream(
    src: &mut dyn Read,
    sink: BoxWrite<'_>,
    method: Method,
    lvl: u32,
    threads: usize,
    progress: &Progress,
    count: bool,
) -> Result<(crc32fast::Hasher, u64)> {
    let mut enc = ZipWriter::<std::fs::File>::encoder(method, lvl, threads, sink)?;
    let mut crc = crc32fast::Hasher::new();
    let mut total = 0u64;
    let mut buf = vec![0u8; crate::io::BUF_SIZE];
    loop {
        progress.check()?;
        let n = match src.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        };
        crc.update(&buf[..n]);
        total += n as u64;
        if count {
            progress.add_done(n as u64);
        }
        enc.write_all(&buf[..n])?;
    }
    enc.finish_box()?;
    Ok((crc, total))
}
