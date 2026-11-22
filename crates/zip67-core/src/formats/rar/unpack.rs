//! Drives the RAR5 / RAR 2.9 decoders for one file at a time and turns
//! their output into a `Read` stream with exact size checks. The decoder
//! state is kept between files of a solid archive.

use std::io::{self, Read};

use super::bits::Input;
use super::unpack3::Unpack3;
use super::unpack5::Unpack5;
use super::window::{MARGIN, Window};
use crate::error::{Error, Result};

/// Bytes decoded per step before output is handed on.
const BUDGET: u64 = 1 << 20;
/// Smallest dictionary allocated (filters need whole blocks in memory).
const MIN_WINDOW: u64 = 8 << 20;

pub struct Unpacker {
    win: Option<Window>,
    v5: Option<Unpack5>,
    v3: Option<Unpack3>,
    rar5: bool,
    max_memory: u64,
}

/// Dictionary size worth allocating: the declared one, but never more than
/// the data that can actually be referenced.
pub fn window_size(dict: u64, stream_bytes: Option<u64>) -> u64 {
    let useful = match stream_bytes {
        Some(n) => dict.min(n.saturating_add(2 * MARGIN).checked_next_power_of_two().unwrap_or(u64::MAX)),
        None => dict,
    };
    useful.max(MIN_WINDOW)
}

impl Unpacker {
    pub fn new(rar5: bool, max_memory: u64) -> Self {
        Unpacker { win: None, v5: None, v3: None, rar5, max_memory }
    }

    /// Prepares for the next file. `solid` continues the previous file's
    /// stream; `window` is the dictionary size it needs.
    pub fn begin(&mut self, solid: bool, window: u64) -> Result<()> {
        if window > self.max_memory {
            return Err(Error::limit(format!("the RAR dictionary ({} MiB) is larger than the memory limit", window >> 20)));
        }
        let window = usize::try_from(window).map_err(|_| Error::limit("RAR dictionary too large"))?;
        match self.win.as_mut() {
            Some(w) if w.size() >= window => {}
            Some(w) if solid => w.grow(window)?,
            _ => self.win = Some(Window::new(window)?),
        }
        if let Some(w) = self.win.as_mut() {
            w.start_file(solid);
        }
        if self.rar5 {
            self.v5.get_or_insert_with(Unpack5::new).start_file(solid);
        } else {
            let mem = self.max_memory;
            self.v3.get_or_insert_with(|| Unpack3::new(mem)).start_file(solid);
        }
        Ok(())
    }

    fn finished(&self) -> bool {
        if self.rar5 { self.v5.as_ref().is_none_or(|u| u.finished) } else { self.v3.as_ref().is_none_or(|u| u.finished) }
    }

    fn step(&mut self, inp: &mut Input) -> Result<()> {
        let win = self.win.as_mut().ok_or_else(|| Error::corrupt("RAR decoder not started"))?;
        if self.rar5 {
            self.v5.as_mut().ok_or_else(|| Error::corrupt("RAR decoder not started"))?.decode(inp, win, BUDGET)
        } else {
            self.v3.as_mut().ok_or_else(|| Error::corrupt("RAR decoder not started"))?.decode(inp, win, BUDGET)
        }
    }
}

/// The decoded content of one file.
pub struct FileDecoder<'a> {
    up: &'a mut Unpacker,
    inp: Input,
    expected: Option<u64>,
    produced: u64,
    done: bool,
}

impl<'a> FileDecoder<'a> {
    pub fn new(up: &'a mut Unpacker, input: Box<dyn Read + Send>, expected: Option<u64>) -> Self {
        FileDecoder { up, inp: Input::new(input), expected, produced: 0, done: false }
    }

    /// One read from the window, decoding more when needed.
    fn pull(&mut self, buf: &mut [u8]) -> Result<usize> {
        loop {
            let finished = self.up.finished();
            let win = self.up.win.as_mut().ok_or_else(|| Error::corrupt("RAR decoder not started"))?;
            let n = win.deliver(buf);
            if n > 0 {
                return Ok(n);
            }
            if finished {
                if win.has_unfinished_filter() {
                    return Err(Error::corrupt("RAR data: a filter block runs past the end of the file"));
                }
                return Ok(0);
            }
            if win.space() == 0 {
                return Err(Error::corrupt("RAR data: filter block larger than the dictionary"));
            }
            self.up.step(&mut self.inp)?;
            if let Some(e) = self.inp.take_error() {
                return Err(e.into());
            }
        }
    }

    /// After the declared size: the stream must end here (RAR5), or any
    /// extra output is dropped like WinRAR does (older versions).
    fn finish(&mut self) -> Result<()> {
        let mut scratch = vec![0u8; 64 * 1024];
        let mut extra = 0u64;
        loop {
            let n = self.pull(&mut scratch)?;
            if n == 0 {
                return Ok(());
            }
            if self.up.rar5 {
                return Err(Error::corrupt("entry is larger than its declared size"));
            }
            extra += n as u64;
            if extra > 4 << 20 {
                return Ok(());
            }
        }
    }
}

impl Read for FileDecoder<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.done || buf.is_empty() {
            return Ok(0);
        }
        let want = match self.expected {
            Some(e) => buf.len().min((e - self.produced).min(usize::MAX as u64) as usize),
            None => buf.len(),
        };
        if want == 0 {
            self.done = true;
            self.finish()?;
            return Ok(0);
        }
        let n = self.pull(&mut buf[..want])?;
        if n == 0 {
            self.done = true;
            if let Some(e) = self.expected
                && self.produced < e
            {
                return Err(Error::corrupt("RAR data ends before the end of the file (damaged or incomplete archive)").into());
            }
            return Ok(0);
        }
        self.produced += n as u64;
        Ok(n)
    }
}
