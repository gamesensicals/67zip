//! LZMA2 decoding with our own safety layer around the lzma-rust2 decoder:
//!
//! * `Lzma2Guard` checks the chunk structure (control bytes, sizes, the
//!   properties byte, dictionary resets) of the data on its way into the
//!   decoder and stops malformed streams early. Fuzzing found that
//!   lzma-rust2 0.25 loops forever on an LZMA chunk that arrives before any
//!   properties were set; the guard rejects such streams.
//! * `Lzma2StreamReader` drives the library's step-by-step decoder itself and
//!   fails when a step makes no progress, so no other stuck state can hang.

use std::io::{self, BufRead, BufReader, Read};

use lzma_rust2::{Action, Lzma2Stream, Status};

use crate::error::Error;

enum State {
    Control,
    Header { ctrl: u8, got: usize, need: usize, buf: [u8; 5] },
    Data { left: usize },
    Ended,
}

/// Pass-through reader that validates LZMA2 chunk headers.
pub struct Lzma2Guard<R> {
    inner: R,
    state: State,
    have_dict: bool,
    have_props: bool,
}

impl<R: Read> Lzma2Guard<R> {
    pub fn new(inner: R) -> Self {
        Lzma2Guard { inner, state: State::Control, have_dict: false, have_props: false }
    }

    fn bad(msg: &str) -> io::Error {
        Error::corrupt(format!("LZMA2: {msg}")).into()
    }

    fn check(&mut self, data: &[u8]) -> io::Result<()> {
        let mut i = 0;
        while i < data.len() {
            match &mut self.state {
                State::Ended => return Ok(()),
                State::Data { left } => {
                    let n = (*left).min(data.len() - i);
                    *left -= n;
                    i += n;
                    if *left == 0 {
                        self.state = State::Control;
                    }
                }
                State::Control => {
                    let c = data[i];
                    i += 1;
                    match c {
                        0 => self.state = State::Ended,
                        1 | 2 => {
                            if c == 1 {
                                self.have_dict = true;
                                // An uncompressed chunk with dictionary reset
                                // does not reset the LZMA state/properties.
                            } else if !self.have_dict {
                                return Err(Self::bad("stream does not start with a dictionary reset"));
                            }
                            self.state = State::Header { ctrl: c, got: 0, need: 2, buf: [0; 5] };
                        }
                        3..=0x7f => return Err(Self::bad("invalid control byte")),
                        _ => {
                            let reset = (c >> 5) & 3;
                            if reset == 3 {
                                self.have_dict = true;
                            }
                            if !self.have_dict {
                                return Err(Self::bad("stream does not start with a dictionary reset"));
                            }
                            if reset >= 2 {
                                self.have_props = true;
                            } else if !self.have_props {
                                return Err(Self::bad("compressed chunk before its properties"));
                            }
                            let need = if reset >= 2 { 5 } else { 4 };
                            self.state = State::Header { ctrl: c, got: 0, need, buf: [0; 5] };
                        }
                    }
                }
                State::Header { ctrl, got, need, buf } => {
                    buf[*got] = data[i];
                    *got += 1;
                    i += 1;
                    if *got == *need {
                        let (ctrl, buf) = (*ctrl, *buf);
                        let left = if ctrl < 0x80 {
                            usize::from(u16::from_be_bytes([buf[0], buf[1]])) + 1
                        } else {
                            if *need == 5 {
                                let p = buf[4];
                                if p >= 9 * 5 * 5 {
                                    return Err(Self::bad("invalid properties"));
                                }
                                let lc = p % 9;
                                let lp = (p / 9) % 5;
                                if lc + lp > 4 {
                                    return Err(Self::bad("invalid properties"));
                                }
                            }
                            usize::from(u16::from_be_bytes([buf[2], buf[3]])) + 1
                        };
                        self.state = State::Data { left };
                    }
                }
            }
        }
        Ok(())
    }
}

impl<R: Read> Read for Lzma2Guard<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.check(&buf[..n])?;
        Ok(n)
    }
}

/// Single-threaded LZMA2 decoder with a no-progress check.
pub struct Lzma2StreamReader<R> {
    inner: R,
    st: Lzma2Stream,
    done: bool,
}

impl<R: BufRead> Lzma2StreamReader<R> {
    pub fn new(inner: R, dict: u32) -> Self {
        Lzma2StreamReader { inner, st: Lzma2Stream::new(dict), done: false }
    }
}

impl<R: BufRead> Read for Lzma2StreamReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.done || buf.is_empty() {
            return Ok(0);
        }
        let mut idle = 0;
        loop {
            let input = self.inner.fill_buf()?;
            let eof = input.is_empty();
            let action = if eof { Action::Finish } else { Action::Run };
            let r = self.st.process(input, buf, action).map_err(|e| io::Error::from(Error::corrupt(format!("LZMA2: {e}"))))?;
            self.inner.consume(r.bytes_consumed);
            if r.status == Status::StreamEnd {
                self.done = true;
                return Ok(r.bytes_produced);
            }
            if r.bytes_produced > 0 {
                return Ok(r.bytes_produced);
            }
            if r.bytes_consumed == 0 {
                idle += 1;
                if eof || idle > 4 {
                    return Err(Error::corrupt("LZMA2 data ends early or makes no progress").into());
                }
            } else {
                idle = 0;
            }
        }
    }
}

/// Builds a guarded LZMA2 decoder (multi-threaded when `threads` > 1).
pub fn decoder<'a, R: Read + Send + 'a>(input: R, dict: u32, threads: usize) -> Box<dyn Read + Send + 'a>
where
    R: 'static,
{
    let guarded = Lzma2Guard::new(input);
    if threads > 1 {
        Box::new(lzma_rust2::Lzma2ReaderMt::new(guarded, dict, None, threads as u32))
    } else {
        Box::new(Lzma2StreamReader::new(BufReader::with_capacity(128 * 1024, guarded), dict))
    }
}
