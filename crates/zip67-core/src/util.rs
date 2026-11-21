//! Small helpers: bounds-checked byte parsing, path normalisation, times.

use crate::error::{Error, Result};

/// Bounds-checked little-endian reader over a byte slice. Every read that
/// would run past the end returns [`Error::Corrupt`] instead of panicking.
pub struct Bytes<'a> {
    buf: &'a [u8],
    pos: usize,
    what: &'static str,
}

impl<'a> Bytes<'a> {
    pub fn new(buf: &'a [u8], what: &'static str) -> Self {
        Bytes { buf, pos: 0, what }
    }
    pub fn pos(&self) -> usize {
        self.pos
    }
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }
    fn short(&self) -> Error {
        Error::Corrupt(format!("{} is truncated", self.what))
    }
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if n > self.remaining() {
            return Err(self.short());
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    pub fn skip(&mut self, n: usize) -> Result<()> {
        self.take(n).map(|_| ())
    }
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    pub fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }
    pub fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    pub fn u64(&mut self) -> Result<u64> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_le_bytes(a))
    }
    pub fn rest(&mut self) -> &'a [u8] {
        let s = &self.buf[self.pos..];
        self.pos = self.buf.len();
        s
    }
}

/// Converts a stored archive path into the normalised form used by
/// [`crate::Entry::path`]. Returns the path and whether it was unsafe
/// (absolute, or containing `..`).
pub fn normalize_path(raw: &str) -> (String, bool) {
    let mut unsafe_path = raw.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for part in raw.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                unsafe_path = true;
                parts.push("..");
            }
            p => parts.push(p),
        }
    }
    (parts.join("/"), unsafe_path)
}

/// Lossy conversion of raw name bytes: UTF-8 if valid, else CP437 (the
/// historic default code page of zip files).
pub fn decode_name(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(s) => s.to_string(),
        Err(_) => bytes.iter().map(|&b| cp437(b)).collect(),
    }
}

fn cp437(b: u8) -> char {
    const HIGH: [char; 128] = [
        'Ç', 'ü', 'é', 'â', 'ä', 'à', 'å', 'ç', 'ê', 'ë', 'è', 'ï', 'î', 'ì', 'Ä', 'Å', 'É', 'æ',
        'Æ', 'ô', 'ö', 'ò', 'û', 'ù', 'ÿ', 'Ö', 'Ü', '¢', '£', '¥', '₧', 'ƒ', 'á', 'í', 'ó', 'ú',
        'ñ', 'Ñ', 'ª', 'º', '¿', '⌐', '¬', '½', '¼', '¡', '«', '»', '░', '▒', '▓', '│', '┤', '╡',
        '╢', '╖', '╕', '╣', '║', '╗', '╝', '╜', '╛', '┐', '└', '┴', '┬', '├', '─', '┼', '╞', '╟',
        '╚', '╔', '╩', '╦', '╠', '═', '╬', '╧', '╨', '╤', '╥', '╙', '╘', '╒', '╓', '╫', '╪', '┘',
        '┌', '█', '▄', '▌', '▐', '▀', 'α', 'ß', 'Γ', 'π', 'Σ', 'σ', 'µ', 'τ', 'Φ', 'Θ', 'Ω', 'δ',
        '∞', 'φ', 'ε', '∩', '≡', '±', '≥', '≤', '⌠', '⌡', '÷', '≈', '°', '∙', '·', '√', 'ⁿ', '²',
        '■', '\u{a0}',
    ];
    if b < 0x80 { b as char } else { HIGH[(b - 0x80) as usize] }
}

/// MS-DOS date/time (local time) to Unix seconds.
pub fn dos_to_unix(date: u16, time: u16) -> Option<i64> {
    let year = 1980 + (date >> 9) as i16;
    let month = ((date >> 5) & 0x0f) as i8;
    let day = (date & 0x1f) as i8;
    let hour = (time >> 11) as i8;
    let minute = ((time >> 5) & 0x3f) as i8;
    let second = (((time & 0x1f) * 2) as i8).min(59);
    let dt = jiff::civil::DateTime::new(year, month, day, hour, minute, second, 0).ok()?;
    let zoned = dt.to_zoned_datetime(jiff::tz::TimeZone::system()).ok()?;
    Some(zoned.timestamp().as_second())
}

/// Unix seconds to MS-DOS (date, time) in local time, clamped to 1980..2107.
pub fn unix_to_dos(secs: i64) -> (u16, u16) {
    let fallback = ((1 << 5) | 1, 0); // 1980-01-01 00:00
    let Ok(ts) = jiff::Timestamp::from_second(secs) else { return fallback };
    let z = ts.to_zoned_datetime(jiff::tz::TimeZone::system());
    let year = z.year();
    if year < 1980 {
        return fallback;
    }
    if year > 2107 {
        return ((127 << 9) | (12 << 5) | 31, (23 << 11) | (59 << 5) | 29);
    }
    let date = (((year - 1980) as u16) << 9) | ((z.month() as u16) << 5) | z.day() as u16;
    let time = ((z.hour() as u16) << 11) | ((z.minute() as u16) << 5) | (z.second() as u16 / 2);
    (date, time)
}

/// Windows FILETIME (100 ns ticks since 1601) to Unix seconds + nanoseconds.
pub fn filetime_to_unix(ft: u64) -> (i64, u32) {
    const EPOCH_DIFF: i64 = 11_644_473_600;
    let secs = (ft / 10_000_000) as i64 - EPOCH_DIFF;
    let nanos = ((ft % 10_000_000) * 100) as u32;
    (secs, nanos)
}

/// Unix seconds + nanoseconds to Windows FILETIME.
pub fn unix_to_filetime(secs: i64, nanos: u32) -> u64 {
    const EPOCH_DIFF: i64 = 11_644_473_600;
    let s = secs.saturating_add(EPOCH_DIFF).max(0) as u64;
    s.saturating_mul(10_000_000).saturating_add(u64::from(nanos / 100))
}

/// Human readable size, e.g. `12.3 MiB`.
pub fn human_size(n: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    format!("{v:.1} {}", UNITS[u])
}

/// Number of worker threads to use by default.
pub fn default_threads() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1).clamp(1, 256)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize() {
        assert_eq!(normalize_path("a/./b//c/"), ("a/b/c".into(), false));
        assert_eq!(normalize_path("/etc/passwd"), ("etc/passwd".into(), true));
        assert_eq!(normalize_path("../../x"), ("../../x".into(), true));
    }

    #[test]
    fn dos_roundtrip() {
        let t = 1_700_000_000; // even second
        let (d, tm) = unix_to_dos(t);
        assert_eq!(dos_to_unix(d, tm), Some(t));
    }

    #[test]
    fn bytes_never_panic() {
        let mut b = Bytes::new(&[1, 2, 3], "test");
        assert_eq!(b.u16().unwrap(), 0x0201);
        assert!(b.u32().is_err());
    }
}
