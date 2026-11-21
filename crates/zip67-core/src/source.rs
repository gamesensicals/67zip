//! Opening archive files, including split volumes (`name.7z.001`, `.002`...).

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crate::error::Result;
use crate::io::ReadSeek;

/// If `path` is the first part of a split archive, returns all parts.
pub fn volume_parts(path: &Path) -> Option<Vec<PathBuf>> {
    let name = path.file_name()?.to_str()?;
    let stem = name.strip_suffix(".001")?;
    let dir = path.parent().unwrap_or(Path::new("."));
    let mut parts = vec![path.to_path_buf()];
    for i in 2..100_000u32 {
        let p = dir.join(format!("{stem}.{i:03}"));
        if !p.is_file() {
            break;
        }
        parts.push(p);
    }
    Some(parts)
}

/// Strips a `.001` volume suffix: `a.7z.001` -> `a.7z`.
pub fn logical_name(path: &Path) -> String {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    name.strip_suffix(".001").unwrap_or(name).to_string()
}

/// Opens an archive file (or all parts of a split archive) for reading.
pub fn open_source(path: &Path) -> Result<(Box<dyn ReadSeek>, u64)> {
    if let Some(parts) = volume_parts(path) {
        if parts.len() > 1 {
            let mv = MultiVolume::open(&parts)?;
            let len = mv.len;
            return Ok((Box::new(mv), len));
        }
    }
    let f = File::open(path)?;
    let len = f.metadata()?.len();
    Ok((Box::new(io::BufReader::with_capacity(64 * 1024, f)), len))
}

/// Several files read as one continuous, seekable stream.
pub struct MultiVolume {
    files: Vec<(File, u64, u64)>, // (file, start offset, length)
    len: u64,
    pos: u64,
}

impl MultiVolume {
    pub fn open(parts: &[PathBuf]) -> Result<Self> {
        let mut files = Vec::with_capacity(parts.len());
        let mut start = 0u64;
        for p in parts {
            let f = File::open(p)?;
            let l = f.metadata()?.len();
            files.push((f, start, l));
            start += l;
        }
        Ok(MultiVolume { files, len: start, pos: 0 })
    }
}

impl Read for MultiVolume {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.len || buf.is_empty() {
            return Ok(0);
        }
        let idx = self.files.partition_point(|(_, s, l)| s + l <= self.pos);
        let Some((f, start, l)) = self.files.get_mut(idx) else { return Ok(0) };
        let off = self.pos - *start;
        f.seek(SeekFrom::Start(off))?;
        let n = buf.len().min((*l - off) as usize);
        let got = f.read(&mut buf[..n])?;
        self.pos += got as u64;
        Ok(got)
    }
}

impl Seek for MultiVolume {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(p) => Some(p),
            SeekFrom::End(d) => self.len.checked_add_signed(d),
            SeekFrom::Current(d) => self.pos.checked_add_signed(d),
        };
        match new {
            Some(p) => {
                self.pos = p;
                Ok(p)
            }
            None => Err(io::Error::new(io::ErrorKind::InvalidInput, "seek before start")),
        }
    }
}
