//! AES modes built on the audited RustCrypto AES block cipher:
//! CBC (7z) and little-endian CTR (WinZip AES). The block cipher itself is
//! never implemented here; only the simple, well-defined mode logic is.

use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use aes::{Aes128, Aes192, Aes256, Block};
use std::io::{self, Read, Write};

use crate::error::{Error, Result};

/// An AES key of any supported size.
pub enum AesKey {
    A128(Box<Aes128>),
    A192(Box<Aes192>),
    A256(Box<Aes256>),
}

impl AesKey {
    pub fn new(key: &[u8]) -> Result<Self> {
        Ok(match key.len() {
            16 => AesKey::A128(Box::new(
                Aes128::new_from_slice(key).map_err(|_| Error::invalid("bad key"))?,
            )),
            24 => AesKey::A192(Box::new(
                Aes192::new_from_slice(key).map_err(|_| Error::invalid("bad key"))?,
            )),
            32 => AesKey::A256(Box::new(
                Aes256::new_from_slice(key).map_err(|_| Error::invalid("bad key"))?,
            )),
            _ => return Err(Error::invalid("AES key must be 16, 24 or 32 bytes")),
        })
    }
    pub fn encrypt_blocks(&self, blocks: &mut [Block]) {
        match self {
            AesKey::A128(c) => c.encrypt_blocks(blocks),
            AesKey::A192(c) => c.encrypt_blocks(blocks),
            AesKey::A256(c) => c.encrypt_blocks(blocks),
        }
    }
    pub fn decrypt_blocks(&self, blocks: &mut [Block]) {
        match self {
            AesKey::A128(c) => c.decrypt_blocks(blocks),
            AesKey::A192(c) => c.decrypt_blocks(blocks),
            AesKey::A256(c) => c.decrypt_blocks(blocks),
        }
    }
}

fn to_blocks(buf: &[u8]) -> Vec<Block> {
    buf.chunks_exact(16)
        .map(|c| {
            let mut b = Block::default();
            b.copy_from_slice(c);
            b
        })
        .collect()
}

/// WinZip-style AES-CTR: 128-bit little-endian counter starting at 1.
pub struct CtrLe {
    key: AesKey,
    counter: u128,
    stream: [u8; 16 * 16],
    pos: usize,
}

impl CtrLe {
    pub fn new(key: AesKey) -> Self {
        CtrLe {
            key,
            counter: 1,
            stream: [0; 256],
            pos: 256,
        }
    }
    fn refill(&mut self) {
        let mut blocks: Vec<Block> = (0..16)
            .map(|i| {
                let mut b = Block::default();
                b.copy_from_slice(&(self.counter.wrapping_add(i)).to_le_bytes());
                b
            })
            .collect();
        self.counter = self.counter.wrapping_add(16);
        self.key.encrypt_blocks(&mut blocks);
        for (i, b) in blocks.iter().enumerate() {
            self.stream[i * 16..i * 16 + 16].copy_from_slice(b);
        }
        self.pos = 0;
    }
    /// XORs the keystream into `buf` (encrypts or decrypts).
    pub fn apply(&mut self, buf: &mut [u8]) {
        for b in buf {
            if self.pos == self.stream.len() {
                self.refill();
            }
            *b ^= self.stream[self.pos];
            self.pos += 1;
        }
    }
}

/// AES-CBC decryption of a stream whose length is a multiple of 16
/// (7z pads with zeros; the decoders after it know the real size).
pub struct CbcDecryptReader<R> {
    inner: R,
    key: AesKey,
    iv: [u8; 16],
    out: Vec<u8>,
    out_pos: usize,
    eof: bool,
}

impl<R: Read> CbcDecryptReader<R> {
    pub fn new(inner: R, key: AesKey, iv: [u8; 16]) -> Self {
        CbcDecryptReader {
            inner,
            key,
            iv,
            out: Vec::new(),
            out_pos: 0,
            eof: false,
        }
    }
}

impl<R: Read> Read for CbcDecryptReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.out_pos == self.out.len() {
            if self.eof {
                return Ok(0);
            }
            let mut ct = vec![0u8; 64 * 1024];
            let n = crate::io::read_full(&mut self.inner, &mut ct)?;
            if n < ct.len() {
                self.eof = true;
            }
            // A partial trailing block cannot be decrypted; 7z never writes one.
            ct.truncate(n - n % 16);
            if ct.is_empty() {
                return Ok(0);
            }
            let mut blocks = to_blocks(&ct);
            self.key.decrypt_blocks(&mut blocks);
            let mut plain = vec![0u8; ct.len()];
            let mut prev = self.iv;
            for (i, b) in blocks.iter().enumerate() {
                let c = &ct[i * 16..i * 16 + 16];
                for j in 0..16 {
                    plain[i * 16 + j] = b[j] ^ prev[j];
                }
                prev.copy_from_slice(c);
            }
            self.iv = prev;
            self.out = plain;
            self.out_pos = 0;
        }
        let n = buf.len().min(self.out.len() - self.out_pos);
        buf[..n].copy_from_slice(&self.out[self.out_pos..self.out_pos + n]);
        self.out_pos += n;
        Ok(n)
    }
}

/// AES-CBC encryption, zero-padding the last block (7z convention).
pub struct CbcEncryptWriter<W: Write> {
    inner: W,
    key: AesKey,
    iv: [u8; 16],
    pending: Vec<u8>,
}

impl<W: Write> CbcEncryptWriter<W> {
    pub fn new(inner: W, key: AesKey, iv: [u8; 16]) -> Self {
        CbcEncryptWriter {
            inner,
            key,
            iv,
            pending: Vec::with_capacity(64 * 1024),
        }
    }
    fn encrypt_full_blocks(&mut self) -> io::Result<()> {
        let full = self.pending.len() - self.pending.len() % 16;
        if full == 0 {
            return Ok(());
        }
        let mut out = Vec::with_capacity(full);
        for c in self.pending[..full].chunks_exact(16) {
            let mut b = Block::default();
            for j in 0..16 {
                b[j] = c[j] ^ self.iv[j];
            }
            self.key.encrypt_blocks(std::slice::from_mut(&mut b));
            self.iv.copy_from_slice(&b);
            out.extend_from_slice(&b);
        }
        self.inner.write_all(&out)?;
        self.pending.drain(..full);
        Ok(())
    }
    pub fn finish(mut self) -> Result<W> {
        if !self.pending.len().is_multiple_of(16) {
            let pad = 16 - self.pending.len() % 16;
            self.pending.extend(std::iter::repeat_n(0u8, pad));
        }
        self.encrypt_full_blocks()?;
        Ok(self.inner)
    }
}

impl<W: Write> Write for CbcEncryptWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.pending.extend_from_slice(buf);
        if self.pending.len() >= 64 * 1024 {
            self.encrypt_full_blocks()?;
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
