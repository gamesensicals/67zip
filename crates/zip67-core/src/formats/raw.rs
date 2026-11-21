//! A single compressed file (`.gz`, `.bz2`, `.xz`, `.zst`, `.lzma`, `.lz`)
//! presented as an archive with one entry.

use std::io::{self, BufReader, Read, Seek, SeekFrom};

use crate::archive::{ArchiveInfo, ArchiveReader, EntryVisitor, OpenOptions};
use crate::codecs::{self, FinishWrite};
use crate::create::{ArchiveWriter, Item};
use crate::detect::{ArchiveType, Compression, Container};
use crate::entry::{Entry, EntryKind};
use crate::error::{Error, Result};
use crate::io::{Progressed, ReadSeek, SizeGuard};
use crate::limits::Limits;
use crate::progress::Progress;

pub struct RawReader {
    src: Box<dyn ReadSeek>,
    size: u64,
    compression: Compression,
    entries: Vec<Entry>,
    limits: Limits,
}

fn strip_suffix(name: &str, c: Compression) -> String {
    let lower = name.to_ascii_lowercase();
    let suffix = format!(".{}", c.suffix());
    if lower.ends_with(&suffix) && name.len() > suffix.len() {
        return name[..name.len() - suffix.len()].to_string();
    }
    format!("{name}.out")
}

impl RawReader {
    pub fn open(mut src: Box<dyn ReadSeek>, size: u64, archive_name: &str, compression: Compression, opts: &OpenOptions) -> Result<Self> {
        let mut name = strip_suffix(archive_name, compression);
        let mut mtime = None;
        let mut usize = 0u64;
        let mut known = false;
        match compression {
            Compression::Gzip => {
                src.seek(SeekFrom::Start(0))?;
                let mut br = BufReader::new(&mut src);
                let h = codecs::gzip::read_header(&mut br)?;
                if let Some(n) = h.name {
                    // Only the last component, never a path.
                    let n = n.rsplit(['/', '\\']).next().unwrap_or("").to_string();
                    if !n.is_empty() && n != "." && n != ".." {
                        name = n;
                    }
                }
                if h.mtime != 0 {
                    mtime = Some(i64::from(h.mtime));
                }
                drop(br);
                if size >= 18 {
                    src.seek(SeekFrom::End(-4))?;
                    let mut t = [0u8; 4];
                    src.read_exact(&mut t)?;
                    usize = u64::from(u32::from_le_bytes(t)); // modulo 4 GiB: a hint only
                }
            }
            Compression::Xz => {
                src.seek(SeekFrom::Start(0))?;
                if let Ok(n) = lzma_rust2::xz_uncompressed_size(&mut src) {
                    usize = n;
                    known = true;
                }
            }
            _ => {}
        }
        let mut e = Entry::new(0, name, EntryKind::File);
        e.size = usize;
        e.size_known = known;
        e.packed_size = Some(size);
        e.mtime = mtime;
        e.method = Some(compression.display().into());
        Ok(RawReader { src, size, compression, entries: vec![e], limits: opts.limits.clone() })
    }
}

impl ArchiveReader for RawReader {
    fn archive_type(&self) -> ArchiveType {
        ArchiveType::new(Container::Raw, self.compression)
    }
    fn entries(&self) -> &[Entry] {
        &self.entries
    }
    fn info(&self) -> ArchiveInfo {
        ArchiveInfo {
            format: self.archive_type().id(),
            physical_size: self.size,
            methods: vec![self.compression.display().into()],
            volumes: 1,
            blocks: 1,
            ..Default::default()
        }
    }
    fn extract(&mut self, selected: &dyn Fn(&Entry) -> bool, visitor: &mut dyn EntryVisitor, progress: &Progress) -> Result<()> {
        let entry = self.entries[0].clone();
        if !selected(&entry) {
            return Ok(());
        }
        self.src.seek(SeekFrom::Start(0))?;
        progress.set_current(&entry.path);
        let packed = Progressed::packed(&mut self.src, progress);
        let dec = codecs::decoder(self.compression, Box::new(packed), &self.limits)?;
        let expected = if entry.size_known { Some(entry.size) } else { None };
        let guarded = SizeGuard::new(dec, expected, self.limits.max_total_size);
        let mut r = Progressed::new(guarded, progress);
        visitor.file(&entry, &mut r)?;
        progress.file_done();
        Ok(())
    }
}

pub struct RawWriter {
    out: Option<Box<dyn FinishWrite>>,
    written: bool,
}

impl RawWriter {
    pub fn new(file: std::fs::File, c: Compression, level: u32, threads: usize, name: Option<&str>) -> Result<Self> {
        let base = name.and_then(|n| n.rsplit('/').next());
        let buffered: codecs::BoxWrite<'static> = Box::new(io::BufWriter::with_capacity(256 * 1024, file));
        Ok(RawWriter { out: Some(codecs::encoder(c, buffered, level, threads, base, 0)?), written: false })
    }
}

impl ArchiveWriter for RawWriter {
    fn add(&mut self, item: &Item, data: Option<&mut dyn Read>, progress: &Progress) -> Result<()> {
        if item.kind != EntryKind::File {
            return Err(Error::invalid("only a single file can be compressed into this format"));
        }
        if self.written {
            return Err(Error::invalid("this format holds exactly one file"));
        }
        self.written = true;
        let w = self.out.as_mut().ok_or_else(|| Error::invalid("finished"))?;
        let r = data.ok_or_else(|| Error::invalid("file data missing"))?;
        crate::create::pump(r, w, progress)?;
        Ok(())
    }
    fn finish(mut self: Box<Self>, _progress: &Progress) -> Result<()> {
        self.out.take().ok_or_else(|| Error::invalid("finished"))?.finish_box()
    }
}
