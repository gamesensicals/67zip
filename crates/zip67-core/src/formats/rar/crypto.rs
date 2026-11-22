//! RAR encryption: key derivation for RAR5 (PBKDF2-HMAC-SHA256, AES-256)
//! and RAR 2.9-4.x (an iterated SHA-1 scheme, AES-128), password check
//! values, and the keyed checksums of encrypted RAR5 files. The ciphers
//! are the audited RustCrypto ones; only the key derivation is here.

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::password::Password;

type HmacSha256 = Hmac<Sha256>;

/// Longest password WinRAR uses (longer ones are cut, like WinRAR does).
const MAX_PASSWORD_CHARS: usize = 127;
/// Highest RAR5 KDF iteration count exponent WinRAR accepts.
pub const MAX_KDF_LG2: u8 = 24;

fn truncated(p: &Password) -> Zeroizing<String> {
    Zeroizing::new(p.as_str().chars().take(MAX_PASSWORD_CHARS).collect())
}

/// Keys derived from a RAR5 password and salt.
pub struct Keys5 {
    pub key: Zeroizing<[u8; 32]>,
    /// Key for turning checksums into MACs.
    pub hash_key: Zeroizing<[u8; 32]>,
    /// Value compared with the password check stored in the archive.
    pub check: [u8; 8],
}

pub fn derive5(password: &Password, salt: &[u8; 16], lg2: u8) -> Keys5 {
    let pw = truncated(password);
    let base = HmacSha256::new_from_slice(pw.as_bytes()).unwrap_or_else(|_| HmacSha256::new_from_slice(&[]).expect("empty HMAC key"));
    let mut m = base.clone();
    m.update(salt);
    m.update(&[0, 0, 0, 1]);
    let mut u: [u8; 32] = m.finalize().into_bytes().into();
    let mut f = Zeroizing::new(u);
    let mut out = [Zeroizing::new([0u8; 32]), Zeroizing::new([0u8; 32]), Zeroizing::new([0u8; 32])];
    // Fuzzing builds use few rounds so the fuzzer gets past the key
    // derivation; the code path is the same.
    let lg2 = if cfg!(fuzzing) { lg2.min(4) } else { lg2.min(MAX_KDF_LG2) };
    let counts = [(1u32 << lg2) - 1, 16, 16];
    for (k, &n) in counts.iter().enumerate() {
        for _ in 0..n {
            let mut m = base.clone();
            m.update(&u);
            u = m.finalize().into_bytes().into();
            for (a, b) in f.iter_mut().zip(u.iter()) {
                *a ^= b;
            }
        }
        *out[k] = *f;
    }
    let mut check = [0u8; 8];
    for (i, b) in out[2].iter().enumerate() {
        check[i % 8] ^= b;
    }
    let [key, hash_key, _] = out;
    Keys5 { key, hash_key, check }
}

/// The stored password check is 8 bytes and the first 4 bytes of their
/// SHA-256; a mismatch there means the check itself is damaged.
pub fn check_value_valid(check: &[u8; 12]) -> bool {
    let d = Sha256::digest(&check[..8]);
    d[..4] == check[8..12]
}

/// CRC-32 as stored for files encrypted with checksum MACs.
pub fn crc_mac(crc: u32, hash_key: &[u8; 32]) -> u32 {
    let Ok(mut m) = HmacSha256::new_from_slice(hash_key) else { return crc };
    m.update(&crc.to_le_bytes());
    let d = m.finalize().into_bytes();
    let mut v = 0u32;
    for (i, b) in d.iter().enumerate() {
        v ^= u32::from(*b) << ((i & 3) * 8);
    }
    v
}

/// BLAKE2sp digest as stored for files encrypted with checksum MACs.
pub fn blake2_mac(digest: &[u8; 32], hash_key: &[u8; 32]) -> [u8; 32] {
    let Ok(mut m) = HmacSha256::new_from_slice(hash_key) else { return *digest };
    m.update(digest);
    m.finalize().into_bytes().into()
}

/// SHA-1 with RAR 2.9's quirk: when a call hashes whole 64-byte blocks
/// straight from the caller's buffer, the expanded message words are
/// written back into that buffer. RAR 3.x key derivation depends on it
/// for long passwords.
#[derive(Clone)]
struct Sha1Rar {
    h: [u32; 5],
    count: u64,
    buf: [u8; 64],
}

impl Sha1Rar {
    fn new() -> Self {
        Sha1Rar { h: [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0], count: 0, buf: [0; 64] }
    }

    /// Returns the last 16 expanded message words.
    fn transform(h: &mut [u32; 5], block: &[u8]) -> [u32; 16] {
        let mut w = [0u32; 16];
        for (i, x) in w.iter_mut().enumerate() {
            *x = u32::from_be_bytes([block[i * 4], block[i * 4 + 1], block[i * 4 + 2], block[i * 4 + 3]]);
        }
        let [mut a, mut b, mut c, mut d, mut e] = *h;
        for t in 0..80 {
            if t >= 16 {
                w[t & 15] = (w[(t + 13) & 15] ^ w[(t + 8) & 15] ^ w[(t + 2) & 15] ^ w[t & 15]).rotate_left(1);
            }
            let (f, k) = match t {
                0..=19 => ((b & c) | (!b & d), 0x5A82_7999),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6u32),
            };
            let tmp = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(w[t & 15]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }
        for (x, v) in h.iter_mut().zip([a, b, c, d, e]) {
            *x = x.wrapping_add(v);
        }
        w
    }

    fn update_impl(&mut self, data: &mut [u8], write_back: bool) {
        let len = data.len();
        let j = (self.count & 63) as usize;
        self.count += len as u64;
        let mut i = 0;
        let mut j = j;
        if j + len > 63 {
            i = 64 - j;
            self.buf[j..].copy_from_slice(&data[..i]);
            let b = self.buf;
            Self::transform(&mut self.h, &b);
            while i + 63 < len {
                let w = Self::transform(&mut self.h, &data[i..i + 64]);
                if write_back {
                    for (k, x) in w.iter().enumerate() {
                        data[i + k * 4..i + k * 4 + 4].copy_from_slice(&x.to_le_bytes());
                    }
                }
                i += 64;
            }
            j = 0;
        }
        self.buf[j..j + len - i].copy_from_slice(&data[i..]);
    }

    fn finalize(&self) -> [u8; 20] {
        let mut s = self.clone();
        let bits = self.count.wrapping_mul(8);
        let mut pad = vec![0x80u8];
        let rem = ((self.count + 1) % 64) as usize;
        pad.extend(std::iter::repeat_n(0u8, if rem <= 56 { 56 - rem } else { 120 - rem }));
        pad.extend_from_slice(&bits.to_be_bytes());
        s.update_impl(&mut pad, false);
        let mut out = [0u8; 20];
        for (i, x) in s.h.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&x.to_be_bytes());
        }
        out
    }
}

/// RAR 2.9-4.x key and IV for AES-128 from a password and 8-byte salt.
pub fn derive3(password: &Password, salt: Option<&[u8; 8]>) -> (Zeroizing<[u8; 16]>, [u8; 16]) {
    let pw = truncated(password);
    let mut raw = Zeroizing::new(Vec::with_capacity(pw.len() * 2 + 8));
    for u in pw.encode_utf16() {
        raw.extend_from_slice(&u.to_le_bytes());
    }
    if let Some(s) = salt {
        raw.extend_from_slice(s);
    }
    let mut sha = Sha1Rar::new();
    let mut iv = [0u8; 16];
    const ROUNDS: u32 = if cfg!(fuzzing) { 0x40 } else { 0x40000 };
    for i in 0..ROUNDS {
        sha.update_impl(&mut raw, true);
        let mut num = [i as u8, (i >> 8) as u8, (i >> 16) as u8];
        sha.update_impl(&mut num, false);
        if i % (ROUNDS / 16) == 0 {
            iv[(i / (ROUNDS / 16)) as usize] = sha.finalize()[19];
        }
    }
    let d = sha.finalize();
    let mut key = Zeroizing::new([0u8; 16]);
    for i in 0..4 {
        for j in 0..4 {
            key[i * 4 + j] = d[i * 4 + 3 - j];
        }
    }
    (key, iv)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha1_matches_standard_without_long_blocks() {
        let mut s = Sha1Rar::new();
        let mut data = b"abc".to_vec();
        s.update_impl(&mut data, true);
        let hex: String = s.finalize().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "a9993e364706816aba3e25717850c26c9cd0d89d");
        let mut s = Sha1Rar::new();
        let mut long = vec![b'a'; 1000];
        s.update_impl(&mut long, false);
        let std = sha1::Sha1::digest(vec![b'a'; 1000]);
        assert_eq!(s.finalize()[..], std[..]);
    }
}
