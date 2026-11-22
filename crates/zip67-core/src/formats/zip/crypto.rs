//! Zip encryption: WinZip AES (read and write) and the old PKWARE
//! "ZipCrypto" (read only, because it is broken and must not be created).

use std::io::{self, Read, Write};

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use zeroize::Zeroizing;

use crate::cipher::{AesKey, CtrLe};
use crate::crc::crc32_byte;
use crate::error::{Error, Result};
use crate::password::Password;

// ----- ZipCrypto ---------------------------------------------------------

#[derive(Clone)]
pub struct ZipCryptoKeys([u32; 3]);

impl ZipCryptoKeys {
    pub fn new(password: &[u8]) -> Self {
        let mut k = ZipCryptoKeys([0x1234_5678, 0x2345_6789, 0x3456_7890]);
        for &b in password {
            k.update(b);
        }
        k
    }
    fn update(&mut self, b: u8) {
        let k = &mut self.0;
        k[0] = crc32_byte(k[0], b);
        k[1] = k[1]
            .wrapping_add(k[0] & 0xff)
            .wrapping_mul(134_775_813)
            .wrapping_add(1);
        k[2] = crc32_byte(k[2], (k[1] >> 24) as u8);
    }
    fn stream_byte(&self) -> u8 {
        let t = (self.0[2] | 2) & 0xffff;
        ((t.wrapping_mul(t ^ 1)) >> 8) as u8
    }
    pub fn decrypt(&mut self, buf: &mut [u8]) {
        for b in buf {
            let p = *b ^ self.stream_byte();
            self.update(p);
            *b = p;
        }
    }
}

/// Checks the 12-byte ZipCrypto header against the expected check byte.
pub fn zipcrypto_open(password: &Password, header: &[u8; 12], check: u8) -> Result<ZipCryptoKeys> {
    let mut keys = ZipCryptoKeys::new(password.as_bytes());
    let mut h = *header;
    keys.decrypt(&mut h);
    if h[11] != check {
        return Err(Error::WrongPassword);
    }
    Ok(keys)
}

pub struct ZipCryptoReader<R> {
    pub inner: R,
    pub keys: ZipCryptoKeys,
}

impl<R: Read> Read for ZipCryptoReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.keys.decrypt(&mut buf[..n]);
        Ok(n)
    }
}

// ----- WinZip AES ----------------------------------------------------------

pub fn aes_salt_len(strength: u8) -> Result<usize> {
    match strength {
        1 => Ok(8),
        2 => Ok(12),
        3 => Ok(16),
        _ => Err(Error::corrupt("unknown AES key strength")),
    }
}

fn aes_key_len(strength: u8) -> usize {
    match strength {
        1 => 16,
        2 => 24,
        _ => 32,
    }
}

/// Derives (cipher, mac, password verifier) as specified by WinZip.
fn aes_derive(
    password: &Password,
    salt: &[u8],
    strength: u8,
) -> Result<(CtrLe, Hmac<Sha1>, [u8; 2])> {
    let kl = aes_key_len(strength);
    let mut out = Zeroizing::new(vec![0u8; 2 * kl + 2]);
    pbkdf2::pbkdf2_hmac::<Sha1>(password.as_bytes(), salt, 1000, &mut out);
    let ctr = CtrLe::new(AesKey::new(&out[..kl])?);
    let mac = <Hmac<Sha1> as KeyInit>::new_from_slice(&out[kl..2 * kl])
        .map_err(|_| Error::invalid("hmac key"))?;
    Ok((ctr, mac, [out[2 * kl], out[2 * kl + 1]]))
}

/// Decrypts WinZip AES data and verifies its authentication code at the end.
/// `inner` must be positioned right after salt and verifier.
pub struct AesZipReader<R: Read> {
    inner: Option<crate::io::TakeExact<R>>,
    tail: Option<R>,
    ctr: CtrLe,
    mac: Option<Hmac<Sha1>>,
}

impl<R: Read> AesZipReader<R> {
    pub fn open(mut raw: R, password: &Password, strength: u8, data_len: u64) -> Result<Self> {
        let mut salt = vec![0u8; aes_salt_len(strength)?];
        raw.read_exact(&mut salt)?;
        let mut verifier = [0u8; 2];
        raw.read_exact(&mut verifier)?;
        let (ctr, mac, expect) = aes_derive(password, &salt, strength)?;
        if verifier != expect {
            return Err(Error::WrongPassword);
        }
        Ok(AesZipReader {
            inner: Some(crate::io::TakeExact::new(raw, data_len)),
            tail: None,
            ctr,
            mac: Some(mac),
        })
    }
}

impl<R: Read> Read for AesZipReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let Some(inner) = self.inner.as_mut() else {
            return Ok(0);
        };
        let n = inner.read(buf)?;
        if n > 0 {
            if let Some(m) = self.mac.as_mut() {
                m.update(&buf[..n]);
            }
            self.ctr.apply(&mut buf[..n]);
            return Ok(n);
        }
        if buf.is_empty() {
            return Ok(0);
        }
        // End of encrypted data: check the 10-byte authentication code
        // before reporting end of stream, so tampered data is rejected.
        let mut raw = self.inner.take().expect("inner present").into_inner();
        let mut tag = [0u8; 10];
        raw.read_exact(&mut tag)?;
        self.tail = Some(raw);
        let mac = self.mac.take().expect("mac present");
        mac.verify_truncated_left(&tag).map_err(|_| {
            io::Error::from(Error::corrupt(
                "AES authentication failed (data was modified or damaged)",
            ))
        })?;
        Ok(0)
    }
}

/// Encrypts data in WinZip AES format (AES-256). Writes salt and verifier
/// on creation and the authentication code on `finish`.
pub struct AesZipWriter<W: Write> {
    inner: W,
    ctr: CtrLe,
    mac: Hmac<Sha1>,
    buf: Vec<u8>,
}

impl<W: Write> AesZipWriter<W> {
    pub fn new(mut inner: W, password: &Password) -> Result<Self> {
        let mut salt = [0u8; 16];
        getrandom::fill(&mut salt).map_err(|_| Error::invalid("no secure random number source"))?;
        let (ctr, mac, verifier) = aes_derive(password, &salt, 3)?;
        inner.write_all(&salt)?;
        inner.write_all(&verifier)?;
        Ok(AesZipWriter {
            inner,
            ctr,
            mac,
            buf: Vec::new(),
        })
    }
    pub fn finish(mut self) -> Result<W> {
        let tag = self.mac.finalize().into_bytes();
        self.inner.write_all(&tag[..10])?;
        Ok(self.inner)
    }
    /// Bytes added around the data: salt + verifier + tag.
    pub const OVERHEAD: u64 = 16 + 2 + 10;
}

impl<W: Write> Write for AesZipWriter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.buf.clear();
        self.buf.extend_from_slice(data);
        self.ctr.apply(&mut self.buf);
        self.mac.update(&self.buf);
        self.inner.write_all(&self.buf)?;
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
