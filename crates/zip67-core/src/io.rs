//! Reader/writer adapters used by all formats: exact sizes, checksums,
//! progress reporting and cancellation.

use std::io::{self, Read, Seek, Write};

use crate::error::Error;
use crate::progress::Progress;

/// Anything we can read and seek, and move to another thread.
pub trait ReadSeek: Read + Seek + Send {}
impl<T: Read + Seek + Send> ReadSeek for T {}

pub const BUF_SIZE: usize = 256 * 1024;

/// Reads exactly `limit` bytes from `inner`; fails if `inner` ends sooner.
pub struct TakeExact<R> {
    inner: R,
    left: u64,
}

impl<R: Read> TakeExact<R> {
    pub fn new(inner: R, limit: u64) -> Self {
        TakeExact { inner, left: limit }
    }
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Read for TakeExact<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.left == 0 || buf.is_empty() {
            return Ok(0);
        }
        let n = buf.len().min(self.left.min(usize::MAX as u64) as usize);
        let got = self.inner.read(&mut buf[..n])?;
        if got == 0 {
            return Err(Error::corrupt("compressed data ends too early").into());
        }
        self.left -= got as u64;
        Ok(got)
    }
}

/// Guards the *output* of a decoder: it must produce exactly `expected`
/// bytes when the size is known; never more than `max` bytes otherwise.
pub struct SizeGuard<R> {
    inner: R,
    expected: Option<u64>,
    max: u64,
    produced: u64,
    finished: bool,
}

impl<R: Read> SizeGuard<R> {
    pub fn new(inner: R, expected: Option<u64>, max: u64) -> Self {
        SizeGuard { inner, expected, max, produced: 0, finished: false }
    }
}

impl<R: Read> Read for SizeGuard<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.finished || buf.is_empty() {
            return Ok(0);
        }
        let want = match self.expected {
            Some(exp) => {
                let left = exp - self.produced;
                if left == 0 {
                    // Probe for extra data the archive did not declare.
                    let mut probe = [0u8; 1];
                    if self.inner.read(&mut probe)? != 0 {
                        return Err(Error::corrupt("entry is larger than its declared size").into());
                    }
                    self.finished = true;
                    return Ok(0);
                }
                buf.len().min(left.min(usize::MAX as u64) as usize)
            }
            None => buf.len(),
        };
        let n = self.inner.read(&mut buf[..want])?;
        if n == 0 {
            if let Some(exp) = self.expected {
                if self.produced != exp {
                    return Err(Error::corrupt("entry is smaller than its declared size").into());
                }
            }
            self.finished = true;
            return Ok(0);
        }
        self.produced += n as u64;
        if self.produced > self.max {
            return Err(Error::limit("entry is larger than the size limit").into());
        }
        Ok(n)
    }
}

/// Verifies a CRC-32 when the stream ends.
pub struct CrcCheck<R> {
    inner: R,
    hasher: crc32fast::Hasher,
    expected: Option<u32>,
    name: String,
    done: bool,
}

impl<R: Read> CrcCheck<R> {
    pub fn new(inner: R, expected: Option<u32>, name: &str) -> Self {
        CrcCheck { inner, hasher: crc32fast::Hasher::new(), expected, name: name.to_string(), done: false }
    }
}

impl<R: Read> Read for CrcCheck<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.done {
            return Ok(0);
        }
        let n = self.inner.read(buf)?;
        if n == 0 && !buf.is_empty() {
            self.done = true;
            if let Some(exp) = self.expected {
                let got = self.hasher.clone().finalize();
                if got != exp {
                    return Err(Error::Checksum(self.name.clone()).into());
                }
            }
            return Ok(0);
        }
        self.hasher.update(&buf[..n]);
        Ok(n)
    }
}

/// Stays failed after the first error: decoders must not be called again
/// once they reported damage (their state is undefined then), even when a
/// caller drains the rest of a stream.
pub struct Fused<R> {
    inner: R,
    failed: Option<(io::ErrorKind, String)>,
}

impl<R: Read> Fused<R> {
    pub fn new(inner: R) -> Self {
        Fused { inner, failed: None }
    }
}

impl<R: Read> Read for Fused<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some((kind, msg)) = &self.failed {
            return Err(io::Error::new(*kind, msg.clone()));
        }
        match self.inner.read(buf) {
            Err(e) if e.kind() != io::ErrorKind::Interrupted => {
                self.failed = Some((e.kind(), e.to_string()));
                Err(e)
            }
            r => r,
        }
    }
}

/// Counts bytes into a [`Progress`] and honours cancel/pause.
pub struct Progressed<'p, R> {
    inner: R,
    progress: &'p Progress,
    packed: bool,
}

impl<'p, R: Read> Progressed<'p, R> {
    /// Counts into `done` (uncompressed bytes).
    pub fn new(inner: R, progress: &'p Progress) -> Self {
        Progressed { inner, progress, packed: false }
    }
    /// Counts into `packed` (compressed bytes) instead.
    pub fn packed(inner: R, progress: &'p Progress) -> Self {
        Progressed { inner, progress, packed: true }
    }
}

impl<R: Read> Read for Progressed<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.progress.check()?;
        let n = self.inner.read(buf)?;
        if self.packed {
            self.progress.add_packed(n as u64);
        } else {
            self.progress.add_done(n as u64);
        }
        Ok(n)
    }
}

/// Counts bytes written through it.
pub struct CountingWriter<W> {
    pub inner: W,
    pub count: u64,
}

impl<W: Write> CountingWriter<W> {
    pub fn new(inner: W) -> Self {
        CountingWriter { inner, count: 0 }
    }
}

impl<W: Write> Write for CountingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.count += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Reads and discards everything left in `r`.
pub fn drain<R: Read + ?Sized>(r: &mut R) -> io::Result<u64> {
    io::copy(r, &mut io::sink())
}

/// Copies with a large buffer, checking for cancellation between chunks.
pub fn copy_checked<R: Read + ?Sized, W: Write + ?Sized>(
    r: &mut R,
    w: &mut W,
    progress: &Progress,
) -> crate::Result<u64> {
    let mut buf = vec![0u8; BUF_SIZE];
    let mut total = 0u64;
    loop {
        progress.check()?;
        let n = match r.read(&mut buf) {
            Ok(0) => return Ok(total),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        };
        w.write_all(&buf[..n])?;
        total += n as u64;
    }
}

/// Reads up to `buf.len()` bytes, stopping only at end of stream.
pub fn read_full<R: Read + ?Sized>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}
