//! Splitting a file into volumes (`name.001`, `name.002`, ...) and joining.

use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::progress::Progress;

/// Parses sizes like `100m`, `4g`, `700000k`, `1024` (bytes).
pub fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim().to_ascii_lowercase();
    let (num, mul) = match s.chars().last()? {
        'b' => (&s[..s.len() - 1], 1),
        'k' => (&s[..s.len() - 1], 1 << 10),
        'm' => (&s[..s.len() - 1], 1 << 20),
        'g' => (&s[..s.len() - 1], 1 << 30),
        't' => (&s[..s.len() - 1], 1u64 << 40),
        _ => (&s[..], 1),
    };
    let v: f64 = num.trim().parse().ok()?;
    if v <= 0.0 {
        return None;
    }
    Some((v * mul as f64) as u64)
}

pub fn split_file(path: &Path, part_size: u64, progress: &Progress) -> Result<Vec<PathBuf>> {
    if part_size == 0 {
        return Err(Error::invalid("volume size must be larger than 0"));
    }
    let total = fs::metadata(path)?.len();
    let parts = total.div_ceil(part_size).max(1);
    if parts > 99_999 {
        return Err(Error::invalid("volume size too small (more than 99999 parts)"));
    }
    let mut r = BufReader::with_capacity(1 << 20, File::open(path)?);
    let name = path.file_name().and_then(|n| n.to_str()).ok_or_else(|| Error::invalid("bad file name"))?;
    let dir = path.parent().unwrap_or(Path::new("."));
    let mut out = Vec::new();
    let width = if parts > 999 { 5 } else { 3 };
    for i in 1..=parts {
        progress.check()?;
        let p = dir.join(format!("{name}.{i:0width$}"));
        let mut w = BufWriter::new(fs::OpenOptions::new().write(true).create_new(true).open(&p)?);
        let n = crate::io::copy_checked(&mut (&mut r).take(part_size), &mut w, progress)?;
        progress.add_done(n);
        w.flush()?;
        out.push(p);
    }
    Ok(out)
}

/// Joins `first` (`x.001`) and the following parts into `output`.
pub fn combine(first: &Path, output: &Path, progress: &Progress) -> Result<u64> {
    let parts = crate::source::volume_set(first)?.ok_or_else(|| Error::invalid("this is not a part of a split file"))?.parts;
    let total: u64 = parts.iter().filter_map(|p| fs::metadata(p).ok()).map(|m| m.len()).sum();
    progress.set_total(total);
    let mut w = BufWriter::new(fs::OpenOptions::new().write(true).create_new(true).open(output)?);
    let mut n = 0;
    for p in parts {
        let mut r = BufReader::new(File::open(&p)?);
        let k = crate::io::copy_checked(&mut r, &mut w, progress)?;
        progress.add_done(k);
        n += k;
    }
    w.flush()?;
    Ok(n)
}

#[cfg(test)]
mod tests {
    #[test]
    fn sizes() {
        assert_eq!(super::parse_size("100m"), Some(100 << 20));
        assert_eq!(super::parse_size("1.5k"), Some(1536));
        assert_eq!(super::parse_size("0"), None);
    }
}
