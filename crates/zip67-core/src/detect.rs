//! Archive type model and detection by content (magic bytes) and name.

use std::io::{Read, SeekFrom};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::io::ReadSeek;
use crate::limits::Limits;

/// The structure that holds the entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Container {
    SevenZ,
    Zip,
    Tar,
    /// A single compressed file (`.gz`, `.xz`, ...), shown as one entry.
    Raw,
    Iso,
    /// RAR (reading only).
    Rar,
}

/// Stream compression wrapped around the container (tar and raw only).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Compression {
    None,
    Gzip,
    Bzip2,
    Xz,
    Zstd,
    Lzma,
    Lzip,
}

impl Compression {
    pub fn suffix(self) -> &'static str {
        match self {
            Compression::None => "",
            Compression::Gzip => "gz",
            Compression::Bzip2 => "bz2",
            Compression::Xz => "xz",
            Compression::Zstd => "zst",
            Compression::Lzma => "lzma",
            Compression::Lzip => "lz",
        }
    }
    pub fn display(self) -> &'static str {
        match self {
            Compression::None => "None",
            Compression::Gzip => "GZip",
            Compression::Bzip2 => "BZip2",
            Compression::Xz => "XZ",
            Compression::Zstd => "Zstandard",
            Compression::Lzma => "LZMA",
            Compression::Lzip => "LZip",
        }
    }
    pub const ALL: [Compression; 6] = [
        Compression::Gzip,
        Compression::Bzip2,
        Compression::Xz,
        Compression::Zstd,
        Compression::Lzma,
        Compression::Lzip,
    ];
}

/// Full archive type, e.g. tar + gzip.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ArchiveType {
    pub container: Container,
    pub compression: Compression,
}

impl ArchiveType {
    pub const fn new(container: Container, compression: Compression) -> Self {
        ArchiveType { container, compression }
    }
    pub const SEVEN_Z: ArchiveType = ArchiveType::new(Container::SevenZ, Compression::None);
    pub const ZIP: ArchiveType = ArchiveType::new(Container::Zip, Compression::None);
    pub const TAR: ArchiveType = ArchiveType::new(Container::Tar, Compression::None);
    pub const ISO: ArchiveType = ArchiveType::new(Container::Iso, Compression::None);
    pub const RAR: ArchiveType = ArchiveType::new(Container::Rar, Compression::None);

    /// Short id such as `7z`, `zip`, `tar.gz`, `xz`.
    pub fn id(&self) -> String {
        match (self.container, self.compression) {
            (Container::SevenZ, _) => "7z".into(),
            (Container::Zip, _) => "zip".into(),
            (Container::Iso, _) => "iso".into(),
            (Container::Rar, _) => "rar".into(),
            (Container::Tar, Compression::None) => "tar".into(),
            (Container::Tar, c) => format!("tar.{}", c.suffix()),
            (Container::Raw, c) => c.suffix().into(),
        }
    }

    pub fn from_id(id: &str) -> Option<Self> {
        let id = id.trim().trim_start_matches('.').to_ascii_lowercase();
        let comp = |s: &str| -> Option<Compression> {
            Some(match s {
                "gz" | "gzip" | "tgz" => Compression::Gzip,
                "bz2" | "bzip2" | "tbz" | "tbz2" => Compression::Bzip2,
                "xz" | "txz" => Compression::Xz,
                "zst" | "zstd" | "tzst" => Compression::Zstd,
                "lzma" => Compression::Lzma,
                "lz" | "lzip" => Compression::Lzip,
                _ => return None,
            })
        };
        Some(match id.as_str() {
            "7z" => Self::SEVEN_Z,
            "zip" => Self::ZIP,
            "tar" => Self::TAR,
            "iso" => Self::ISO,
            "rar" | "cbr" => Self::RAR,
            "tgz" | "tbz" | "tbz2" | "txz" | "tzst" => ArchiveType::new(Container::Tar, comp(&id)?),
            s if s.starts_with("tar.") => ArchiveType::new(Container::Tar, comp(&s[4..])?),
            s => ArchiveType::new(Container::Raw, comp(s)?),
        })
    }

    /// File name extension including the dot, e.g. `.tar.gz`.
    pub fn extension(&self) -> String {
        format!(".{}", self.id())
    }

    /// Human readable name for menus.
    pub fn display_name(&self) -> String {
        match (self.container, self.compression) {
            (Container::SevenZ, _) => "7z".into(),
            (Container::Zip, _) => "Zip".into(),
            (Container::Iso, _) => "ISO image".into(),
            (Container::Rar, _) => "RAR".into(),
            (Container::Tar, Compression::None) => "Tar".into(),
            (Container::Tar, c) => format!("Tar + {}", c.display()),
            (Container::Raw, c) => c.display().into(),
        }
    }

    pub fn can_write(&self) -> bool {
        !matches!(self.container, Container::Iso | Container::Rar)
    }
    pub fn supports_encryption(&self) -> bool {
        matches!(self.container, Container::SevenZ | Container::Zip)
    }
    pub fn holds_many_files(&self) -> bool {
        !matches!(self.container, Container::Raw)
    }
    /// Can entries be added/removed in place (by rewriting)?
    pub fn can_update(&self) -> bool {
        matches!(self.container, Container::SevenZ | Container::Zip | Container::Tar)
    }

    /// Guess from a file name alone (split-part names count as their
    /// archive: `a.part2.7z`, `a.7z.001`, `a.z01` ...).
    pub fn from_file_name(name: &str) -> Option<Self> {
        Self::from_plain_name(&crate::source::logical_name_str(name))
    }

    /// Guess from the extension, without looking at split-part names.
    pub fn from_plain_name(name: &str) -> Option<Self> {
        let lower = name.to_ascii_lowercase();
        let lower = lower.as_str();
        for (suffix, t) in [
            (".tar.gz", "tar.gz"),
            (".tgz", "tar.gz"),
            (".taz", "tar.gz"),
            (".tar.bz2", "tar.bz2"),
            (".tbz2", "tar.bz2"),
            (".tbz", "tar.bz2"),
            (".tb2", "tar.bz2"),
            (".tar.xz", "tar.xz"),
            (".txz", "tar.xz"),
            (".tar.zst", "tar.zst"),
            (".tzst", "tar.zst"),
            (".tar.lzma", "tar.lzma"),
            (".tar.lz", "tar.lz"),
            (".7z", "7z"),
            (".zip", "zip"),
            (".jar", "zip"),
            (".apk", "zip"),
            (".xpi", "zip"),
            (".cbz", "zip"),
            (".epub", "zip"),
            (".tar", "tar"),
            (".iso", "iso"),
            (".rar", "rar"),
            (".cbr", "rar"),
            (".gz", "gz"),
            (".bz2", "bz2"),
            (".xz", "xz"),
            (".zst", "zst"),
            (".lzma", "lzma"),
            (".lz", "lz"),
        ] {
            if lower.ends_with(suffix) {
                return Self::from_id(t);
            }
        }
        None
    }
}

const SIG_7Z: [u8; 6] = [b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C];

fn compression_magic(head: &[u8]) -> Option<Compression> {
    if head.starts_with(&[0x1f, 0x8b]) {
        Some(Compression::Gzip)
    } else if head.starts_with(b"BZh") && head.len() > 3 && (b'1'..=b'9').contains(&head[3]) {
        Some(Compression::Bzip2)
    } else if head.starts_with(&[0xFD, b'7', b'z', b'X', b'Z', 0]) {
        Some(Compression::Xz)
    } else if head.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        Some(Compression::Zstd)
    } else if head.starts_with(b"LZIP") {
        Some(Compression::Lzip)
    } else {
        None
    }
}

/// Looks like a `.lzma` ("LZMA alone") header: props byte, dict size and
/// an uncompressed size that is either known or -1.
fn looks_like_lzma_alone(head: &[u8]) -> bool {
    if head.len() < 13 || head[0] >= 9 * 5 * 5 {
        return false;
    }
    let dict = u32::from_le_bytes([head[1], head[2], head[3], head[4]]);
    let power_of_two_ish = dict.is_power_of_two() || (dict & (dict - 1)).count_ones() <= 1;
    let size = u64::from_le_bytes(head[5..13].try_into().unwrap_or([0; 8]));
    dict >= 4096 && power_of_two_ish && (size == u64::MAX || size < (1 << 48))
}

/// Detects the archive type from the content, falling back to the name.
pub fn detect(src: &mut dyn ReadSeek, name: &str, limits: &Limits) -> Result<ArchiveType> {
    src.seek(SeekFrom::Start(0))?;
    let mut head = vec![0u8; 64 * 1024];
    let n = crate::io::read_full(src, &mut head)?;
    head.truncate(n);

    if head.starts_with(&SIG_7Z) {
        return Ok(ArchiveType::SEVEN_Z);
    }
    if head.starts_with(b"PK\x03\x04") || head.starts_with(b"PK\x05\x06") || head.starts_with(b"PK\x07\x08") || head.starts_with(b"PK00PK") {
        return Ok(ArchiveType::ZIP);
    }
    if crate::formats::rar::is_rar(&head) {
        return Ok(ArchiveType::RAR);
    }
    if let Some(c) = compression_magic(&head) {
        src.seek(SeekFrom::Start(0))?;
        let inner = peek_decoded_tar(src, c, limits);
        return Ok(if inner { ArchiveType::new(Container::Tar, c) } else { ArchiveType::new(Container::Raw, c) });
    }
    if head.len() >= 512 && crate::formats::tar::is_tar_header(&head[..512]) {
        return Ok(ArchiveType::TAR);
    }
    // ISO 9660: "CD001" at sector 16 + 1.
    let mut iso = [0u8; 6];
    if src.seek(SeekFrom::Start(0x8000)).is_ok() && crate::io::read_full(src, &mut iso)? == 6 && &iso[1..6] == b"CD001" {
        return Ok(ArchiveType::ISO);
    }
    let by_name = ArchiveType::from_file_name(name);
    if by_name.is_some_and(|t| t.compression == Compression::Lzma) && looks_like_lzma_alone(&head) {
        src.seek(SeekFrom::Start(0))?;
        let inner = peek_decoded_tar(src, Compression::Lzma, limits);
        return Ok(ArchiveType::new(if inner { Container::Tar } else { Container::Raw }, Compression::Lzma));
    }
    // Self-extracting RAR archives.
    if crate::formats::rar::find_sfx_signature(&head).is_some() || (head.starts_with(b"MZ") && sfx_rar(src)?) {
        return Ok(ArchiveType::RAR);
    }
    // Self-extracting or prefixed zip files: look for the end record.
    if crate::formats::zip::find_eocd(src).is_ok() {
        return Ok(ArchiveType::ZIP);
    }
    // 7z SFX: signature somewhere in the first 1 MiB at a 4-byte boundary... keep simple:
    if let Some(pos) = head.windows(6).position(|w| w == SIG_7Z) {
        if pos > 0 {
            return Err(Error::unsupported("self-extracting 7z archives (open the .exe with 67zip after renaming is not needed; support is planned)"));
        }
    }
    Err(Error::UnsupportedFormat)
}

/// Looks for a RAR signature in the first 4 MiB of a program.
fn sfx_rar(src: &mut dyn ReadSeek) -> Result<bool> {
    src.seek(SeekFrom::Start(0))?;
    let mut head = vec![0u8; 4 << 20];
    let n = crate::io::read_full(src, &mut head)?;
    head.truncate(n);
    Ok(crate::formats::rar::find_sfx_signature(&head).is_some())
}

fn peek_decoded_tar(src: &mut dyn ReadSeek, c: Compression, limits: &Limits) -> bool {
    let mut bytes = Vec::new();
    {
        let reader: &mut dyn ReadSeek = src;
        let boxed: Box<dyn Read + Send + '_> = Box::new(LimitedPeek { inner: reader, left: 4 << 20 });
        if let Ok(b) = crate::codecs::peek_decoded(c, boxed, 512, limits) {
            bytes = b;
        }
    }
    bytes.len() == 512 && crate::formats::tar::is_tar_header(&bytes)
}

/// Reads at most `left` bytes (so detection never decodes a whole file).
struct LimitedPeek<'a> {
    inner: &'a mut dyn ReadSeek,
    left: u64,
}

impl Read for LimitedPeek<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.left == 0 {
            return Ok(0);
        }
        let n = buf.len().min(self.left as usize);
        let got = self.inner.read(&mut buf[..n])?;
        self.left -= got as u64;
        Ok(got)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_roundtrip() {
        for id in ["7z", "zip", "rar", "tar", "tar.gz", "tar.bz2", "tar.xz", "tar.zst", "tar.lz", "gz", "xz", "zst", "lzma", "iso"] {
            assert_eq!(ArchiveType::from_id(id).unwrap().id(), id);
        }
        assert_eq!(ArchiveType::from_file_name("x.TGZ").unwrap().id(), "tar.gz");
        assert_eq!(ArchiveType::from_file_name("a.7z.001").unwrap().id(), "7z");
    }
}
