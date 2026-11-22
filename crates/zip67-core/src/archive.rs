//! The common interface every archive format implements, and `open`.

use std::io::Read;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::detect::{ArchiveType, Container};
use crate::entry::Entry;
use crate::error::{Error, Result};
use crate::io::ReadSeek;
use crate::limits::Limits;
use crate::password::Password;
use crate::progress::Progress;

/// Options for opening an archive.
#[derive(Clone, Debug, Default)]
pub struct OpenOptions {
    pub password: Option<Password>,
    pub limits: Limits,
    /// Worker threads for decoders that can use several (0 = automatic).
    pub threads: usize,
    /// Skip detection and use this type.
    pub format: Option<ArchiveType>,
    /// For split zips (`.z01` ... `.zip`): start offset of every part in the
    /// joined stream, because offsets inside such zips are per part.
    pub volume_offsets: Vec<u64>,
}

/// Archive-wide properties, for the "Info" dialog.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ArchiveInfo {
    pub format: String,
    pub physical_size: u64,
    pub methods: Vec<String>,
    pub solid: bool,
    pub blocks: u64,
    pub encrypted_headers: bool,
    pub encrypted_data: bool,
    pub comment: Option<String>,
    pub volumes: u32,
    pub headers_size: Option<u64>,
    /// Bytes before the archive start (self-extracting stubs).
    pub offset: u64,
    pub warnings: Vec<String>,
    /// Damage found while opening (truncated archive, broken headers);
    /// reported with every extraction and test.
    #[serde(default)]
    pub problems: Vec<String>,
}

/// Receives entries during extraction/testing, in archive order.
pub trait EntryVisitor {
    /// File content. Read `data` to the end: checksums are verified at EOF.
    fn file(&mut self, entry: &Entry, data: &mut dyn Read) -> Result<()>;
    fn dir(&mut self, _entry: &Entry) -> Result<()> {
        Ok(())
    }
    fn symlink(&mut self, _entry: &Entry, _target: &str) -> Result<()> {
        Ok(())
    }
    fn hardlink(&mut self, _entry: &Entry, _target: &str) -> Result<()> {
        Ok(())
    }
    /// A recoverable error in one entry. Return `Ok(())` to go on with the
    /// next entry, or the error to stop.
    fn entry_error(&mut self, _entry: &Entry, err: Error) -> Result<()> {
        Err(err)
    }
}

/// A readable archive.
pub trait ArchiveReader: Send {
    fn archive_type(&self) -> ArchiveType;
    fn entries(&self) -> &[Entry];
    fn info(&self) -> ArchiveInfo;
    /// Decodes the selected entries in archive order and hands them to the
    /// visitor. Unselected entries are skipped (or decoded and discarded when
    /// the format is solid).
    fn extract(
        &mut self,
        selected: &dyn Fn(&Entry) -> bool,
        visitor: &mut dyn EntryVisitor,
        progress: &Progress,
    ) -> Result<()>;
}

/// True for errors that only affect one entry of a random-access archive.
pub fn is_entry_local(err: &Error) -> bool {
    matches!(
        err,
        Error::Checksum(_)
            | Error::Corrupt(_)
            | Error::WrongPassword
            | Error::Unsupported(_)
            | Error::PasswordRequired
            | Error::UnsafePath(_)
            | Error::InvalidInput(_)
    )
}

/// Opens an archive file. Split archives (`.001`, `.part1.7z`, `.z01`,
/// ...) are joined automatically, from whichever part is given.
pub fn open(path: &Path, opts: &OpenOptions) -> Result<Box<dyn ArchiveReader>> {
    let set = crate::source::volume_set(path)?;
    let Some(set) = set else {
        let (src, size) = crate::source::open_source(path)?;
        return open_reader(src, size, &crate::source::logical_name(path), opts);
    };
    let n = set.parts.len();
    if matches!(
        set.scheme,
        crate::source::Scheme::PartBeforeExt | crate::source::Scheme::RarOld
    ) && starts_with_rar(&set.parts[0])
    {
        // RAR volumes each have their own headers: not a byte-level split.
        let mut parts = Vec::with_capacity(n);
        for p in &set.parts {
            let f = std::fs::File::open(p)?;
            let len = f.metadata()?.len();
            parts.push((
                Box::new(std::io::BufReader::with_capacity(64 * 1024, f)) as Box<dyn ReadSeek>,
                len,
            ));
        }
        return Ok(Box::new(crate::formats::rar::RarReader::open_volumes(
            parts, opts,
        )?));
    }
    let mut opts = opts.clone();
    if set.scheme == crate::source::Scheme::SplitZip {
        opts.volume_offsets = set.offsets()?;
        opts.format = Some(ArchiveType::ZIP);
    }
    let mv = crate::source::MultiVolume::open(&set.parts)?;
    let size = mv.len();
    match open_reader(Box::new(mv), size, &set.logical, &opts) {
        Ok(reader) => Ok(Box::new(WithVolumes {
            inner: reader,
            volumes: n as u32,
        })),
        Err(e @ (Error::Corrupt(_) | Error::UnsupportedFormat)) => Err(Error::Corrupt(format!(
            "{e}. This is a split archive and {n} part{} {} found; a later part may be missing or incomplete",
            if n == 1 { "" } else { "s" },
            if n == 1 { "was" } else { "were" }
        ))),
        Err(e) => Err(e),
    }
}

fn starts_with_rar(path: &Path) -> bool {
    let mut head = [0u8; 8];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut head))
        .is_ok()
        && crate::formats::rar::is_rar(&head)
}

/// Opens an archive from any seekable source.
pub fn open_reader(
    mut src: Box<dyn ReadSeek>,
    size: u64,
    name: &str,
    opts: &OpenOptions,
) -> Result<Box<dyn ArchiveReader>> {
    let t = match opts.format {
        Some(t) => t,
        None => crate::detect::detect(src.as_mut(), name, &opts.limits)?,
    };
    match t.container {
        Container::Zip => Ok(Box::new(crate::formats::zip::ZipReader::open(
            src, size, opts,
        )?)),
        Container::Tar => Ok(Box::new(crate::formats::tar::TarReader::open(
            src,
            size,
            t.compression,
            opts,
        )?)),
        Container::Raw => Ok(Box::new(crate::formats::raw::RawReader::open(
            src,
            size,
            name,
            t.compression,
            opts,
        )?)),
        Container::SevenZ => Ok(Box::new(crate::formats::sevenz::SevenZReader::open(
            src, size, opts,
        )?)),
        Container::Iso => Ok(Box::new(crate::formats::iso::IsoReader::open(
            src, size, opts,
        )?)),
        Container::Rar => Ok(Box::new(crate::formats::rar::RarReader::open(
            src, size, opts,
        )?)),
    }
}

struct WithVolumes {
    inner: Box<dyn ArchiveReader>,
    volumes: u32,
}

impl ArchiveReader for WithVolumes {
    fn archive_type(&self) -> ArchiveType {
        self.inner.archive_type()
    }
    fn entries(&self) -> &[Entry] {
        self.inner.entries()
    }
    fn info(&self) -> ArchiveInfo {
        let mut i = self.inner.info();
        i.volumes = self.volumes;
        i
    }
    fn extract(
        &mut self,
        selected: &dyn Fn(&Entry) -> bool,
        visitor: &mut dyn EntryVisitor,
        progress: &Progress,
    ) -> Result<()> {
        self.inner.extract(selected, visitor, progress)
    }
}
