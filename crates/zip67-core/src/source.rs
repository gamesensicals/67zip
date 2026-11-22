//! Opening archive files, including split archives in all common naming
//! schemes, from whichever part the user picked:
//!
//! | Scheme          | Example                                        |
//! |-----------------|------------------------------------------------|
//! | numbered        | `backup.7z.001`, `.002`, ... (any width; `.000` start too) |
//! | part before ext | `backup.part1.7z`, `backup.part01.rar`         |
//! | part after ext  | `backup.7z.part1`, `backup.zip.part001`        |
//! | split zip       | `backup.z01`, `backup.z02`, ..., `backup.zip`  |
//! | old RAR volumes | `backup.rar`, `backup.r00`, `backup.r01`, ...   |
//! | letters (split) | `backup.tar.gz.aa`, `.ab`, ...                 |

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::io::ReadSeek;

/// How the parts of a split archive are named.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    Numbered,
    PartBeforeExt,
    PartAfterExt,
    /// PKZIP split archive: parts `.z01`... then `.zip` last. Offsets inside
    /// are relative to each part, unlike the other schemes, which are plain
    /// byte-level splits of one file.
    SplitZip,
    /// RAR volumes named the old way: `.rar` first, then `.r00` ... `.r99`,
    /// `.s00` ... Each is a RAR volume with its own headers.
    RarOld,
    Letters,
}

/// What a file name says about being one part of a split archive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartName {
    /// Name of the whole archive, e.g. `backup.7z`.
    pub logical: String,
    /// Number of this part, counting from 1.
    pub number: u64,
    pub scheme: Scheme,
    prefix: String,
    suffix: String,
    width: usize,
    /// Number in the name of the first part (0 or 1).
    first: u64,
}

fn is_archive_ext(name: &str) -> bool {
    crate::detect::ArchiveType::from_plain_name(name).is_some()
}

fn letters_to_number(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() != 2 || !b.iter().all(u8::is_ascii_lowercase) {
        return None;
    }
    Some(u64::from(b[0] - b'a') * 26 + u64::from(b[1] - b'a'))
}

fn number_to_letters(n: u64) -> Option<String> {
    if n >= 26 * 26 {
        return None;
    }
    Some(format!(
        "{}{}",
        (b'a' + (n / 26) as u8) as char,
        (b'a' + (n % 26) as u8) as char
    ))
}

/// Recognises split-archive part names (no file system access).
pub fn parse_part_name(name: &str) -> Option<PartName> {
    let (base, last) = name.rsplit_once('.')?;
    if base.is_empty() {
        return None;
    }
    let lower = last.to_ascii_lowercase();
    // backup.z01 (split zip, the .zip part is handled by `volume_set`)
    if lower.len() >= 3 && lower.starts_with('z') && lower[1..].bytes().all(|b| b.is_ascii_digit())
    {
        let n: u64 = lower[1..].parse().ok()?;
        if n >= 1 {
            return Some(PartName {
                logical: format!("{base}.zip"),
                number: n,
                scheme: Scheme::SplitZip,
                prefix: format!("{base}.{}", &last[..1]),
                suffix: String::new(),
                width: 2,
                first: 1,
            });
        }
    }
    // backup.r00 (old RAR volumes; backup.rar is the first part)
    if lower.len() == 3
        && (b'r'..=b'y').contains(&lower.as_bytes()[0])
        && lower[1..].bytes().all(|b| b.is_ascii_digit())
    {
        let letter = u64::from(lower.as_bytes()[0] - b'r');
        let n: u64 = lower[1..].parse().ok()?;
        let upper = last.as_bytes()[0].is_ascii_uppercase();
        return Some(PartName {
            logical: format!("{base}.{}", if upper { "RAR" } else { "rar" }),
            number: 2 + letter * 100 + n,
            scheme: Scheme::RarOld,
            prefix: format!("{base}."),
            suffix: if upper { "RAR".into() } else { "rar".into() },
            width: 2,
            first: 1,
        });
    }
    // backup.7z.part1
    if lower.len() > 4
        && lower.starts_with("part")
        && lower[4..].bytes().all(|b| b.is_ascii_digit())
    {
        let n: u64 = lower[4..].parse().ok()?;
        return Some(PartName {
            logical: base.to_string(),
            number: n,
            scheme: Scheme::PartAfterExt,
            prefix: format!("{base}.{}", &last[..4]),
            suffix: String::new(),
            width: lower.len() - 4,
            first: 1,
        });
    }
    // backup.part1.7z, backup.part01.tar.gz
    let lname = name.to_ascii_lowercase();
    let mut search_end = lname.len();
    while let Some(at) = lname[..search_end].rfind(".part") {
        search_end = at;
        let digits_start = at + 5;
        let digits_len = lname[digits_start..]
            .bytes()
            .take_while(u8::is_ascii_digit)
            .count();
        let after = digits_start + digits_len;
        if at == 0 || digits_len == 0 || lname.as_bytes().get(after) != Some(&b'.') {
            continue;
        }
        let ext = &name[after + 1..];
        let ext_ok = !ext.is_empty()
            && (!ext.contains('.') && ext.len() <= 8 || is_archive_ext(&format!("x.{ext}")));
        if !ext_ok {
            continue;
        }
        let n: u64 = lname[digits_start..after].parse().ok()?;
        let stem = &name[..at];
        return Some(PartName {
            logical: format!("{stem}.{ext}"),
            number: n,
            scheme: Scheme::PartBeforeExt,
            prefix: format!("{stem}{}", &name[at..digits_start]),
            suffix: format!(".{ext}"),
            width: digits_len,
            first: 1,
        });
    }
    // backup.7z.001 (2-digit numbers only after an archive extension)
    if last.bytes().all(|b| b.is_ascii_digit())
        && (last.len() >= 3 || (last.len() == 2 && is_archive_ext(base)))
    {
        let n: u64 = last.parse().ok()?;
        let first = if last.len() == 2 { 0 } else { 1 };
        return Some(PartName {
            logical: base.to_string(),
            number: n + 1 - first,
            scheme: Scheme::Numbered,
            prefix: format!("{base}."),
            suffix: String::new(),
            width: last.len(),
            first,
        });
    }
    // backup.tar.gz.aa (only after an archive extension, and never a real
    // extension like .gz or .xz itself)
    if let Some(n) = letters_to_number(last) {
        if is_archive_ext(base) && !is_archive_ext(&format!("x.{last}")) {
            return Some(PartName {
                logical: base.to_string(),
                number: n + 1,
                scheme: Scheme::Letters,
                prefix: format!("{base}."),
                suffix: String::new(),
                width: 2,
                first: 0,
            });
        }
    }
    None
}

impl PartName {
    /// File name of part `n` (1-based) with the given number width.
    fn name_of(&self, n: u64, width: usize) -> Option<String> {
        if self.scheme == Scheme::RarOld {
            if n == 1 {
                return Some(format!("{}{}", self.prefix, self.suffix));
            }
            let k = n - 2;
            if k >= 800 {
                return None;
            }
            let letter = (b'r' + (k / 100) as u8) as char;
            let letter = if self.suffix == "RAR" {
                letter.to_ascii_uppercase()
            } else {
                letter
            };
            return Some(format!("{}{letter}{:02}", self.prefix, k % 100));
        }
        let raw = n + self.first - 1;
        let mid = match self.scheme {
            Scheme::Letters => number_to_letters(raw)?,
            _ => format!("{raw:0width$}"),
        };
        Some(format!("{}{}{}", self.prefix, mid, self.suffix))
    }
}

/// Name of the whole archive for a part name (`a.part2.7z` -> `a.7z`), or
/// the name itself.
pub fn logical_name_str(name: &str) -> String {
    parse_part_name(name)
        .map(|p| p.logical)
        .unwrap_or_else(|| name.to_string())
}

/// All parts of a split archive.
#[derive(Clone, Debug)]
pub struct VolumeSet {
    pub parts: Vec<PathBuf>,
    pub logical: String,
    pub scheme: Scheme,
}

impl VolumeSet {
    /// Start offset of every part in the joined stream.
    pub fn offsets(&self) -> Result<Vec<u64>> {
        let mut v = Vec::with_capacity(self.parts.len());
        let mut at = 0u64;
        for p in &self.parts {
            v.push(at);
            at += std::fs::metadata(p)?.len();
        }
        Ok(v)
    }
}

fn find_split_zip_last(dir: &Path, base: &str) -> Option<PathBuf> {
    ["zip", "ZIP", "Zip"]
        .iter()
        .map(|e| dir.join(format!("{base}.{e}")))
        .find(|p| p.is_file())
}

/// Finds all parts when `path` belongs to a split archive. `Ok(None)` for
/// ordinary files. Errors name the first missing part.
pub fn volume_set(path: &Path) -> Result<Option<VolumeSet>> {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return Ok(None);
    };
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        _ => PathBuf::from("."),
    };
    // The .zip file of a split zip is its last part.
    let lower = name.to_ascii_lowercase();
    let mut parsed = parse_part_name(name);
    if parsed.is_none() && lower.ends_with(".zip") && name.len() > 4 {
        let base = &name[..name.len() - 4];
        for z in ["z01", "Z01"] {
            if dir.join(format!("{base}.{z}")).is_file() {
                parsed = parse_part_name(&format!("{base}.{z}"));
                break;
            }
        }
    }
    if parsed.is_none() && lower.ends_with(".rar") && name.len() > 4 {
        let base = &name[..name.len() - 4];
        for r in ["r00", "R00"] {
            if dir.join(format!("{base}.{r}")).is_file() {
                parsed = parse_part_name(&format!("{base}.{r}"));
                break;
            }
        }
    }
    let Some(p) = parsed else { return Ok(None) };

    // Unpadded series (part1 ... part10) are found with width 1.
    let mut width = p.width;
    if !p.name_of(1, width).is_some_and(|n| dir.join(n).is_file())
        && width > 1
        && dir.join(p.name_of(1, 1).unwrap_or_default()).is_file()
    {
        width = 1;
    }
    let mut parts = Vec::new();
    let mut n = 1u64;
    while n <= 100_000 {
        let Some(candidate) = p.name_of(n, width).map(|f| dir.join(f)) else {
            break;
        };
        if !candidate.is_file() {
            break;
        }
        parts.push(candidate);
        n += 1;
    }
    let missing = n;
    let gap_after = p
        .name_of(missing + 1, width)
        .is_some_and(|f| dir.join(f).is_file());
    if parts.is_empty() {
        let first = p.name_of(1, width).unwrap_or_default();
        return Err(Error::invalid(format!(
            "the first part of this split archive ({first}) is missing"
        )));
    }
    if gap_after || p.number > missing && p.scheme != Scheme::SplitZip {
        let which = p.name_of(missing, width).unwrap_or_default();
        return Err(Error::invalid(format!(
            "part {missing} of this split archive ({which}) is missing"
        )));
    }
    if p.scheme == Scheme::SplitZip {
        let base = p
            .logical
            .strip_suffix(".zip")
            .unwrap_or(&p.logical)
            .to_string();
        match find_split_zip_last(&dir, &base) {
            Some(z) => parts.push(z),
            None => {
                return Err(Error::invalid(format!(
                    "the last part of this split zip ({base}.zip) is missing"
                )));
            }
        }
    }
    Ok(Some(VolumeSet {
        parts,
        logical: p.logical,
        scheme: p.scheme,
    }))
}

/// Parts of a split archive (just the file itself otherwise).
pub fn volume_parts(path: &Path) -> Option<Vec<PathBuf>> {
    volume_set(path).ok().flatten().map(|s| s.parts)
}

/// The archive's own name, without split-part decoration.
pub fn logical_name(path: &Path) -> String {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if let Ok(Some(set)) = volume_set(path) {
        return set.logical;
    }
    logical_name_str(name)
}

/// Opens an archive file (or all parts of a split archive) for reading.
pub fn open_source(path: &Path) -> Result<(Box<dyn ReadSeek>, u64)> {
    if let Some(set) = volume_set(path)? {
        let mv = MultiVolume::open(&set.parts)?;
        let len = mv.len;
        return Ok((Box::new(mv), len));
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
    pub fn len(&self) -> u64 {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub fn open(parts: &[PathBuf]) -> Result<Self> {
        let mut files = Vec::with_capacity(parts.len());
        let mut start = 0u64;
        for p in parts {
            let f = File::open(p)?;
            let l = f.metadata()?.len();
            files.push((f, start, l));
            start += l;
        }
        Ok(MultiVolume {
            files,
            len: start,
            pos: 0,
        })
    }
}

impl Read for MultiVolume {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.len || buf.is_empty() {
            return Ok(0);
        }
        let idx = self.files.partition_point(|(_, s, l)| s + l <= self.pos);
        let Some((f, start, l)) = self.files.get_mut(idx) else {
            return Ok(0);
        };
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
            None => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before start",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        let p = parse_part_name("backup.7z.003").unwrap();
        assert_eq!(
            (p.logical.as_str(), p.number, p.scheme),
            ("backup.7z", 3, Scheme::Numbered)
        );
        let p = parse_part_name("backup.part02.rar").unwrap();
        assert_eq!(
            (p.logical.as_str(), p.number, p.scheme),
            ("backup.rar", 2, Scheme::PartBeforeExt)
        );
        let p = parse_part_name("Backup.Part10.7Z").unwrap();
        assert_eq!((p.logical.as_str(), p.number), ("Backup.7Z", 10));
        let p = parse_part_name("backup.zip.part1").unwrap();
        assert_eq!(
            (p.logical.as_str(), p.scheme),
            ("backup.zip", Scheme::PartAfterExt)
        );
        let p = parse_part_name("backup.z07").unwrap();
        assert_eq!(
            (p.logical.as_str(), p.number, p.scheme),
            ("backup.zip", 7, Scheme::SplitZip)
        );
        let p = parse_part_name("backup.r00").unwrap();
        assert_eq!(
            (p.logical.as_str(), p.number, p.scheme),
            ("backup.rar", 2, Scheme::RarOld)
        );
        assert_eq!(parse_part_name("backup.s01").unwrap().number, 103);
        assert_eq!(p.name_of(1, 2).unwrap(), "backup.rar");
        assert_eq!(p.name_of(102, 2).unwrap(), "backup.s00");
        let p = parse_part_name("backup.tar.gz.ab").unwrap();
        assert_eq!(
            (p.logical.as_str(), p.number, p.scheme),
            ("backup.tar.gz", 2, Scheme::Letters)
        );
        let p = parse_part_name("backup.7z.00").unwrap();
        assert_eq!(p.number, 1);
        // Not parts:
        assert!(parse_part_name("backup.tar.gz").is_none());
        assert!(parse_part_name("photo.jpg").is_none());
        assert!(parse_part_name("notes.ab").is_none());
        assert!(parse_part_name("track.12").is_none());
        assert_eq!(logical_name_str("x.part3.zip"), "x.zip");
        assert_eq!(logical_name_str("x.part3.tar.gz"), "x.tar.gz");
        assert!(parse_part_name("report.part.txt").is_none());
    }

    #[test]
    fn finds_parts_from_any_part() {
        let tmp = std::env::temp_dir().join(format!("67zip-vol-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let mk = |n: &str| std::fs::write(tmp.join(n), b"x").unwrap();
        for n in [
            "a.part1.7z",
            "a.part2.7z",
            "a.part3.7z",
            "b.7z.001",
            "b.7z.002",
            "c.z01",
            "c.z02",
            "c.zip",
            "d.part1.rar",
            "d.part3.rar",
            "e.part1.7z",
            "e.part10.7z",
            "f.rar",
            "f.r00",
            "f.r01",
        ] {
            mk(n);
        }
        for i in 2..=9 {
            mk(&format!("e.part{i}.7z"));
        }
        let s = volume_set(&tmp.join("a.part2.7z")).unwrap().unwrap();
        assert_eq!(s.parts.len(), 3);
        assert_eq!(s.logical, "a.7z");
        assert_eq!(
            volume_set(&tmp.join("b.7z.002"))
                .unwrap()
                .unwrap()
                .parts
                .len(),
            2
        );
        let z = volume_set(&tmp.join("c.zip")).unwrap().unwrap();
        assert_eq!(z.scheme, Scheme::SplitZip);
        assert!(z.parts.last().unwrap().ends_with("c.zip"));
        assert_eq!(
            volume_set(&tmp.join("c.z02")).unwrap().unwrap().parts.len(),
            3
        );
        let err = volume_set(&tmp.join("d.part1.rar"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("part 2"), "{err}");
        // Unpadded series up to part10, opened from part10.
        assert_eq!(
            volume_set(&tmp.join("e.part10.7z"))
                .unwrap()
                .unwrap()
                .parts
                .len(),
            10
        );
        assert!(volume_set(&tmp.join("plain.7z")).unwrap().is_none());
        let f = volume_set(&tmp.join("f.r01")).unwrap().unwrap();
        assert_eq!(
            (f.parts.len(), f.scheme, f.logical.as_str()),
            (3, Scheme::RarOld, "f.rar")
        );
        assert!(f.parts[0].ends_with("f.rar"));
        assert_eq!(
            volume_set(&tmp.join("f.rar")).unwrap().unwrap().parts.len(),
            3
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
