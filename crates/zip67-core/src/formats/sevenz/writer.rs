//! 7z writer: files stream into solid folders (multi-threaded LZMA2 by
//! default), optional AES-256 for data and file names, LZMA-compressed
//! header, CRC-32 for every file.

use std::fs::File;
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use zeroize::Zeroizing;

use super::coders::{self, aes_props, derive_key, lzma2_prop_from_dict};
use super::header::{self, Coder, FileRecord, Folder, StreamsInfo, SIGNATURE};
use crate::cipher::{AesKey, CbcEncryptWriter};
use crate::codecs::{self, BoxWrite, FinishWrite};
use crate::create::{ArchiveWriter, CreateOptions, Item, Method};
use crate::entry::EntryKind;
use crate::error::{Error, Result};
use crate::progress::Progress;
use crate::util::unix_to_filetime;

const AES_CYCLES: u8 = 19;
const SOLID_BLOCK_LIMIT: u64 = 2 << 30;

type Out = Arc<Mutex<BufWriter<File>>>;

/// Writes into the shared output file and counts bytes.
struct SharedOut {
    out: Out,
    count: Arc<AtomicU64>,
}
impl Write for SharedOut {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        let mut o = self.out.lock().map_err(|_| io::Error::other("output lock poisoned"))?;
        let n = o.write(b)?;
        self.count.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.out.lock().map_err(|_| io::Error::other("output lock poisoned"))?.flush()
    }
}

type AesSlot = Arc<Mutex<Option<CbcEncryptWriter<SharedOut>>>>;

/// Write end that feeds the AES layer (kept outside so it can be finished
/// explicitly after the compressor).
struct AesIn {
    slot: AesSlot,
    count: Arc<AtomicU64>,
}
impl Write for AesIn {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        let mut g = self.slot.lock().map_err(|_| io::Error::other("aes lock poisoned"))?;
        let w = g.as_mut().ok_or_else(|| io::Error::other("aes finished"))?;
        let n = w.write(b)?;
        self.count.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct CurFolder {
    enc: Box<dyn FinishWrite>,
    coders: Vec<Coder>,
    aes: Option<AesSlot>,
    pack_count: Arc<AtomicU64>,
    mid_count: Arc<AtomicU64>,
    unpack: u64,
    sizes: Vec<u64>,
    crcs: Vec<Option<u32>>,
}

pub struct SevenZWriter {
    out: Out,
    method: Method,
    level: u32,
    dict: u32,
    threads: usize,
    solid: bool,
    key: Option<Zeroizing<[u8; 32]>>,
    encrypt_names: bool,
    files: Vec<FileRecord>,
    streams: StreamsInfo,
    cur: Option<CurFolder>,
    pos: u64,
}

fn ppmd_params(level: u32) -> (u32, u32) {
    match level {
        0..=3 => (4, 4 << 20),
        4..=5 => (6, 16 << 20),
        6..=7 => (16, 64 << 20),
        _ => (32, 192 << 20),
    }
}

fn random_iv() -> Result<[u8; 16]> {
    let mut iv = [0u8; 16];
    getrandom::fill(&mut iv).map_err(|_| Error::invalid("no secure random number source"))?;
    Ok(iv)
}

macro_rules! fw {
    ($name:ident, $ty:ty) => {
        struct $name($ty);
        impl Write for $name {
            fn write(&mut self, b: &[u8]) -> io::Result<usize> {
                self.0.write(b)
            }
            fn flush(&mut self) -> io::Result<()> {
                self.0.flush()
            }
        }
    };
}
fw!(Lzma2W, lzma_rust2::Lzma2Writer<BoxWrite<'static>>);
fw!(Lzma2MtW, lzma_rust2::Lzma2WriterMt<BoxWrite<'static>>);
fw!(LzmaW, lzma_rust2::LzmaWriter<BoxWrite<'static>>);
fw!(PpmdW, ppmd_rust::Ppmd7Encoder<BoxWrite<'static>>);
fw!(DeflW, flate2::write::DeflateEncoder<BoxWrite<'static>>);
impl FinishWrite for Lzma2W {
    fn finish_box(self: Box<Self>) -> Result<()> {
        self.0.finish()?.flush()?;
        Ok(())
    }
}
impl FinishWrite for Lzma2MtW {
    fn finish_box(self: Box<Self>) -> Result<()> {
        self.0.finish()?.flush()?;
        Ok(())
    }
}
impl FinishWrite for LzmaW {
    fn finish_box(self: Box<Self>) -> Result<()> {
        self.0.finish()?.flush()?;
        Ok(())
    }
}
impl FinishWrite for PpmdW {
    fn finish_box(self: Box<Self>) -> Result<()> {
        self.0.finish(false)?.flush()?;
        Ok(())
    }
}
impl FinishWrite for DeflW {
    fn finish_box(self: Box<Self>) -> Result<()> {
        self.0.finish()?.flush()?;
        Ok(())
    }
}

impl SevenZWriter {
    pub fn new(file: File, opts: &CreateOptions) -> Result<Self> {
        let mut out = BufWriter::with_capacity(1 << 20, file);
        out.write_all(&[0u8; 32])?; // signature header, patched at the end
        let method = opts.effective_method();
        if !Method::for_type(crate::detect::ArchiveType::SEVEN_Z).contains(&method) {
            return Err(Error::invalid(format!("{} is not available for 7z archives", method.name())));
        }
        let preset = codecs::lzma_preset(opts.level);
        let dict = opts.dict_size.unwrap_or_else(|| lzma_rust2::LzmaOptions::with_preset(preset).dict_size);
        let key = match &opts.password {
            Some(p) if !p.is_empty() => Some(derive_key(p, &[], AES_CYCLES)?),
            Some(_) => return Err(Error::invalid("the password is empty")),
            None => None,
        };
        Ok(SevenZWriter {
            out: Arc::new(Mutex::new(out)),
            method,
            level: opts.level,
            dict,
            threads: opts.threads.max(1),
            solid: opts.solid,
            encrypt_names: opts.encrypt_names && key.is_some(),
            key,
            files: Vec::new(),
            streams: StreamsInfo::default(),
            cur: None,
            pos: 0,
        })
    }

    fn start_folder(&mut self) -> Result<()> {
        let pack_count = Arc::new(AtomicU64::new(0));
        let mid_count = Arc::new(AtomicU64::new(0));
        let sink = SharedOut { out: self.out.clone(), count: pack_count.clone() };
        let mut coders_list = Vec::new();
        let (stage, aes): (BoxWrite<'static>, Option<AesSlot>) = match &self.key {
            Some(k) => {
                let iv = random_iv()?;
                let slot: AesSlot = Arc::new(Mutex::new(Some(CbcEncryptWriter::new(sink, AesKey::new(&k[..])?, iv))));
                coders_list.push(Coder { id: coders::ID_AES.to_vec(), num_in: 1, num_out: 1, props: aes_props(AES_CYCLES, &iv) });
                (Box::new(AesIn { slot: slot.clone(), count: mid_count.clone() }), Some(slot))
            }
            None => (Box::new(sink), None),
        };
        let preset = codecs::lzma_preset(self.level);
        let (enc, coder): (Box<dyn FinishWrite>, Coder) = match self.method {
            Method::Lzma2 => {
                let mut o = lzma_rust2::Lzma2Options::with_preset(preset);
                o.lzma_options.dict_size = self.dict;
                let props = vec![lzma2_prop_from_dict(self.dict)];
                let coder = Coder { id: coders::ID_LZMA2.to_vec(), num_in: 1, num_out: 1, props };
                if self.threads > 1 {
                    o.set_chunk_size(NonZeroU64::new((u64::from(self.dict) * 2).max(1 << 20)));
                    (Box::new(Lzma2MtW(lzma_rust2::Lzma2WriterMt::new(stage, o, self.threads as u32)?)), coder)
                } else {
                    (Box::new(Lzma2W(lzma_rust2::Lzma2Writer::new(stage, o))), coder)
                }
            }
            Method::Lzma => {
                let mut o = lzma_rust2::LzmaOptions::with_preset(preset);
                o.dict_size = self.dict;
                let w = lzma_rust2::LzmaWriter::new_no_header(stage, &o, false)?;
                let mut props = vec![w.props()];
                props.extend_from_slice(&self.dict.to_le_bytes());
                (Box::new(LzmaW(w)), Coder { id: coders::ID_LZMA.to_vec(), num_in: 1, num_out: 1, props })
            }
            Method::Ppmd => {
                let (order, mem) = ppmd_params(self.level);
                let w = ppmd_rust::Ppmd7Encoder::new(stage, order, mem).map_err(|e| Error::invalid(format!("ppmd: {e:?}")))?;
                let mut props = vec![order as u8];
                props.extend_from_slice(&mem.to_le_bytes());
                (Box::new(PpmdW(w)), Coder { id: coders::ID_PPMD.to_vec(), num_in: 1, num_out: 1, props })
            }
            Method::Bzip2 => (
                codecs::encoder(crate::detect::Compression::Bzip2, stage, self.level, self.threads, None, 0)?,
                Coder { id: coders::ID_BZIP2.to_vec(), num_in: 1, num_out: 1, props: vec![] },
            ),
            Method::Deflate => (
                Box::new(DeflW(flate2::write::DeflateEncoder::new(stage, flate2::Compression::new(codecs::deflate_level(self.level))))),
                Coder { id: coders::ID_DEFLATE.to_vec(), num_in: 1, num_out: 1, props: vec![] },
            ),
            Method::Copy => (
                codecs::encoder(crate::detect::Compression::None, stage, 0, 1, None, 0)?,
                Coder { id: coders::ID_COPY.to_vec(), num_in: 1, num_out: 1, props: vec![] },
            ),
            other => return Err(Error::invalid(format!("{} is not available for 7z archives", other.name()))),
        };
        // Coder 0 produces the folder output; the AES coder (if any) feeds it.
        coders_list.insert(0, coder);
        self.cur = Some(CurFolder { enc, coders: coders_list, aes, pack_count, mid_count, unpack: 0, sizes: Vec::new(), crcs: Vec::new() });
        Ok(())
    }

    fn finish_folder(&mut self) -> Result<()> {
        let Some(cur) = self.cur.take() else { return Ok(()) };
        cur.enc.finish_box()?;
        if let Some(slot) = &cur.aes {
            let w = slot.lock().map_err(|_| Error::invalid("aes lock"))?.take().ok_or_else(|| Error::invalid("aes finished"))?;
            w.finish()?.flush()?;
        }
        let pack = cur.pack_count.load(Ordering::Relaxed);
        let mut folder = Folder { coders: cur.coders, first_pack: self.streams.pack_sizes.len(), num_substreams: cur.sizes.len() as u64, ..Default::default() };
        if cur.aes.is_some() {
            folder.bind_pairs = vec![(0, 1)];
            folder.packed = vec![1];
            folder.unpack_sizes = vec![cur.unpack, cur.mid_count.load(Ordering::Relaxed)];
        } else {
            folder.packed = vec![0];
            folder.unpack_sizes = vec![cur.unpack];
        }
        self.streams.pack_sizes.push(pack);
        self.streams.folders.push(folder);
        self.streams.sub_sizes.push(cur.sizes);
        self.streams.sub_crcs.push(cur.crcs);
        self.pos += pack;
        Ok(())
    }

    fn attrib(item: &Item) -> u32 {
        let (type_bits, win) = match item.kind {
            EntryKind::Dir => (0o040000u32, 0x10u32),
            EntryKind::Symlink => (0o120000, 0x20),
            _ => (0o100000, 0x20),
        };
        let ro = if item.mode & 0o222 == 0 { 0x01 } else { 0 };
        ((type_bits | (item.mode & 0o7777)) << 16) | 0x8000 | win | ro
    }

    /// Compresses (and maybe encrypts) the header into a packed stream.
    fn encode_header(&mut self, raw: &[u8]) -> Result<Vec<u8>> {
        let mut lzma_opts = lzma_rust2::LzmaOptions::with_preset(5);
        lzma_opts.dict_size = (raw.len() as u32).next_power_of_two().clamp(1 << 16, 1 << 24);
        let mut packed = Vec::new();
        let w = lzma_rust2::LzmaWriter::new_no_header(&mut packed, &lzma_opts, false)?;
        let props_byte = w.props();
        let mut w = w;
        w.write_all(raw)?;
        w.finish()?;
        let mut lzma_props = vec![props_byte];
        lzma_props.extend_from_slice(&lzma_opts.dict_size.to_le_bytes());
        let lzma_coder = Coder { id: coders::ID_LZMA.to_vec(), num_in: 1, num_out: 1, props: lzma_props };
        let mut folder = Folder { first_pack: 0, num_substreams: 1, crc: Some(crate::crc::crc32(raw)), ..Default::default() };
        let data = if let (true, Some(k)) = (self.encrypt_names, &self.key) {
            let iv = random_iv()?;
            let mut enc = CbcEncryptWriter::new(Vec::new(), AesKey::new(&k[..])?, iv);
            enc.write_all(&packed)?;
            let ct = enc.finish()?;
            folder.coders = vec![lzma_coder, Coder { id: coders::ID_AES.to_vec(), num_in: 1, num_out: 1, props: aes_props(AES_CYCLES, &iv) }];
            folder.bind_pairs = vec![(0, 1)];
            folder.packed = vec![1];
            folder.unpack_sizes = vec![raw.len() as u64, packed.len() as u64];
            ct
        } else {
            folder.coders = vec![lzma_coder];
            folder.packed = vec![0];
            folder.unpack_sizes = vec![raw.len() as u64];
            packed
        };
        let si = StreamsInfo { pack_pos: self.pos, pack_sizes: vec![data.len() as u64], folders: vec![folder], sub_sizes: vec![], sub_crcs: vec![] };
        {
            let mut o = self.out.lock().map_err(|_| Error::invalid("lock"))?;
            o.write_all(&data)?;
        }
        self.pos += data.len() as u64;
        let mut next = vec![header::id::ENCODED_HEADER];
        header::write_streams_info(&mut next, &si);
        Ok(next)
    }
}

impl ArchiveWriter for SevenZWriter {
    fn add(&mut self, item: &Item, data: Option<&mut dyn Read>, progress: &Progress) -> Result<()> {
        let mtime = Some(unix_to_filetime(item.mtime, item.mtime_nanos));
        let attrib = Some(Self::attrib(item));
        let name = item.arcname.trim_matches('/').to_string();
        let has_data = match item.kind {
            EntryKind::Dir => false,
            EntryKind::Symlink => item.link_target.as_deref().is_some_and(|t| !t.is_empty()),
            _ => item.size > 0,
        };
        if !has_data {
            self.files.push(FileRecord { name, has_stream: false, is_dir: item.kind == EntryKind::Dir, is_anti: false, mtime, attrib });
            return Ok(());
        }
        if self.cur.is_none() {
            self.start_folder()?;
        }
        let link;
        let mut link_reader: &[u8];
        let src: &mut dyn Read = if item.kind == EntryKind::Symlink {
            link = item.link_target.clone().unwrap_or_default().into_bytes();
            link_reader = &link[..];
            &mut link_reader
        } else {
            data.ok_or_else(|| Error::invalid("file data missing"))?
        };
        let cur = self.cur.as_mut().ok_or_else(|| Error::invalid("no folder"))?;
        let mut crc = crc32fast::Hasher::new();
        let mut n = 0u64;
        let mut buf = vec![0u8; crate::io::BUF_SIZE];
        loop {
            progress.check()?;
            let k = match src.read(&mut buf) {
                Ok(0) => break,
                Ok(k) => k,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            };
            crc.update(&buf[..k]);
            cur.enc.write_all(&buf[..k])?;
            n += k as u64;
            if item.kind != EntryKind::Symlink {
                progress.add_done(k as u64);
            }
        }
        if n == 0 {
            // The file turned out empty: store it as an empty file.
            self.files.push(FileRecord { name, has_stream: false, is_dir: false, is_anti: false, mtime, attrib });
            return Ok(());
        }
        cur.unpack += n;
        cur.sizes.push(n);
        cur.crcs.push(Some(crc.finalize()));
        self.files.push(FileRecord { name, has_stream: true, is_dir: false, is_anti: false, mtime, attrib });
        progress.add_packed(0);
        if !self.solid || cur.unpack >= SOLID_BLOCK_LIMIT {
            self.finish_folder()?;
        }
        Ok(())
    }

    fn finish(mut self: Box<Self>, progress: &Progress) -> Result<()> {
        self.finish_folder()?;
        progress.add_packed(self.pos);
        let (next, next_off) = if self.files.is_empty() {
            (Vec::new(), 0)
        } else {
            let mut raw = vec![header::id::HEADER];
            if !self.streams.folders.is_empty() {
                raw.push(header::id::MAIN_STREAMS_INFO);
                header::write_streams_info(&mut raw, &self.streams);
            }
            header::write_files(&mut raw, &self.files);
            raw.push(header::id::END);
            let next = if raw.len() > 64 || self.encrypt_names { self.encode_header(&raw)? } else { raw };
            (next, self.pos)
        };
        let next_crc = crate::crc::crc32(&next);
        let mut o = self.out.lock().map_err(|_| Error::invalid("lock"))?;
        o.write_all(&next)?;
        let mut start = Vec::with_capacity(20);
        start.extend_from_slice(&next_off.to_le_bytes());
        start.extend_from_slice(&(next.len() as u64).to_le_bytes());
        start.extend_from_slice(&next_crc.to_le_bytes());
        let mut sig = Vec::with_capacity(32);
        sig.extend_from_slice(&SIGNATURE);
        sig.extend_from_slice(&[0, 4]);
        sig.extend_from_slice(&crate::crc::crc32(&start).to_le_bytes());
        sig.extend_from_slice(&start);
        o.seek(SeekFrom::Start(0))?;
        o.write_all(&sig)?;
        o.flush()?;
        o.get_ref().sync_data().ok();
        Ok(())
    }
}
