//! Checksums and hashes of files (the "CRC/SHA" menu).

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::Digest;

use crate::error::Result;
use crate::progress::Progress;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HashKind {
    Crc32,
    Crc64,
    Md5,
    Sha1,
    Sha256,
    Sha512,
    Blake3,
}

impl HashKind {
    pub const ALL: [HashKind; 7] = [
        HashKind::Crc32,
        HashKind::Crc64,
        HashKind::Sha256,
        HashKind::Sha1,
        HashKind::Sha512,
        HashKind::Blake3,
        HashKind::Md5,
    ];
    pub fn name(self) -> &'static str {
        match self {
            HashKind::Crc32 => "CRC32",
            HashKind::Crc64 => "CRC64",
            HashKind::Md5 => "MD5",
            HashKind::Sha1 => "SHA-1",
            HashKind::Sha256 => "SHA-256",
            HashKind::Sha512 => "SHA-512",
            HashKind::Blake3 => "BLAKE3",
        }
    }
    pub fn from_name(s: &str) -> Option<Self> {
        let s = s.to_ascii_lowercase().replace('-', "");
        HashKind::ALL
            .into_iter()
            .find(|k| k.name().to_ascii_lowercase().replace('-', "") == s)
    }
}

enum State {
    Crc32(crc32fast::Hasher),
    Crc64(crate::crc::Crc64),
    Md5(md5::Md5),
    Sha1(sha1::Sha1),
    Sha256(sha2::Sha256),
    Sha512(sha2::Sha512),
    Blake3(Box<blake3::Hasher>),
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub struct MultiHasher {
    states: Vec<(HashKind, State)>,
}

impl MultiHasher {
    pub fn new(kinds: &[HashKind]) -> Self {
        let states = kinds
            .iter()
            .map(|&k| {
                (
                    k,
                    match k {
                        HashKind::Crc32 => State::Crc32(crc32fast::Hasher::new()),
                        HashKind::Crc64 => State::Crc64(crate::crc::Crc64::new()),
                        HashKind::Md5 => State::Md5(md5::Md5::new()),
                        HashKind::Sha1 => State::Sha1(sha1::Sha1::new()),
                        HashKind::Sha256 => State::Sha256(sha2::Sha256::new()),
                        HashKind::Sha512 => State::Sha512(sha2::Sha512::new()),
                        HashKind::Blake3 => State::Blake3(Box::new(blake3::Hasher::new())),
                    },
                )
            })
            .collect();
        MultiHasher { states }
    }
    pub fn update(&mut self, data: &[u8]) {
        for (_, s) in &mut self.states {
            match s {
                State::Crc32(h) => h.update(data),
                State::Crc64(h) => h.update(data),
                State::Md5(h) => h.update(data),
                State::Sha1(h) => h.update(data),
                State::Sha256(h) => h.update(data),
                State::Sha512(h) => h.update(data),
                State::Blake3(h) => {
                    h.update(data);
                }
            }
        }
    }
    pub fn finish(self) -> Vec<(HashKind, String)> {
        self.states
            .into_iter()
            .map(|(k, s)| {
                let v = match s {
                    State::Crc32(h) => format!("{:08X}", h.finalize()),
                    State::Crc64(h) => format!("{:016X}", h.finalize()),
                    State::Md5(h) => hex(&h.finalize()),
                    State::Sha1(h) => hex(&h.finalize()),
                    State::Sha256(h) => hex(&h.finalize()),
                    State::Sha512(h) => hex(&h.finalize()),
                    State::Blake3(h) => h.finalize().to_hex().to_string(),
                };
                (k, v)
            })
            .collect()
    }
}

pub fn hash_reader(
    r: &mut dyn Read,
    kinds: &[HashKind],
    progress: &Progress,
) -> Result<(u64, Vec<(HashKind, String)>)> {
    let mut h = MultiHasher::new(kinds);
    let mut buf = vec![0u8; 1 << 20];
    let mut total = 0u64;
    loop {
        progress.check()?;
        let n = crate::io::read_full(r, &mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        total += n as u64;
        progress.add_done(n as u64);
        if n < buf.len() {
            break;
        }
    }
    Ok((total, h.finish()))
}

pub fn hash_file(
    path: &Path,
    kinds: &[HashKind],
    progress: &Progress,
) -> Result<(u64, Vec<(HashKind, String)>)> {
    let mut f = BufReader::new(File::open(path)?);
    hash_reader(&mut f, kinds, progress)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_values() {
        let p = Progress::new();
        let (_, v) = hash_reader(
            &mut &b"abc"[..],
            &[HashKind::Crc32, HashKind::Sha256, HashKind::Md5],
            &p,
        )
        .unwrap();
        assert_eq!(v[0].1, "352441C2");
        assert_eq!(
            v[1].1,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(v[2].1, "900150983cd24fb0d6963f7d28e17f72");
    }
}
