//! 7z coders: turning a folder's coder graph into one decoding stream,
//! method names, and the 7zAES key derivation.

use std::collections::HashMap;
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::header::Folder;
use crate::cipher::{AesKey, CbcDecryptReader};
use crate::error::{Error, Result};
use crate::io::{ReadSeek, TakeExact};
use crate::limits::Limits;
use crate::password::Password;

pub const ID_COPY: &[u8] = &[0x00];
pub const ID_DELTA: &[u8] = &[0x03];
pub const ID_BCJ_X86: &[u8] = &[0x03, 0x03, 0x01, 0x03];
pub const ID_BCJ2: &[u8] = &[0x03, 0x03, 0x01, 0x1b];
pub const ID_PPC: &[u8] = &[0x03, 0x03, 0x02, 0x05];
pub const ID_IA64: &[u8] = &[0x03, 0x03, 0x04, 0x01];
pub const ID_ARM: &[u8] = &[0x03, 0x03, 0x05, 0x01];
pub const ID_ARMT: &[u8] = &[0x03, 0x03, 0x07, 0x01];
pub const ID_SPARC: &[u8] = &[0x03, 0x03, 0x08, 0x05];
pub const ID_ARM64: &[u8] = &[0x0a];
pub const ID_RISCV: &[u8] = &[0x0b];
pub const ID_LZMA: &[u8] = &[0x03, 0x01, 0x01];
pub const ID_LZMA2: &[u8] = &[0x21];
pub const ID_PPMD: &[u8] = &[0x03, 0x04, 0x01];
pub const ID_DEFLATE: &[u8] = &[0x04, 0x01, 0x08];
pub const ID_DEFLATE64: &[u8] = &[0x04, 0x01, 0x09];
pub const ID_BZIP2: &[u8] = &[0x04, 0x02, 0x02];
pub const ID_AES: &[u8] = &[0x06, 0xf1, 0x07, 0x01];
pub const ID_ZSTD: &[u8] = &[0x04, 0xf7, 0x11, 0x01];

pub fn lzma2_dict_from_prop(b: u8) -> Result<u32> {
    if b > 40 {
        return Err(Error::corrupt("bad LZMA2 dictionary size"));
    }
    if b == 40 {
        return Ok(u32::MAX);
    }
    Ok((2 | u32::from(b & 1)) << (b / 2 + 11))
}

pub fn lzma2_prop_from_dict(dict: u32) -> u8 {
    (0..40u8).find(|&b| lzma2_dict_from_prop(b).unwrap_or(0) >= dict).unwrap_or(40)
}

fn log2_name(v: u64) -> String {
    if v.is_power_of_two() {
        format!("{}", v.trailing_zeros())
    } else if v.is_multiple_of(1 << 20) {
        format!("{}m", v >> 20)
    } else if v.is_multiple_of(1 << 10) {
        format!("{}k", v >> 10)
    } else {
        v.to_string()
    }
}

/// 7-Zip style method name, e.g. `LZMA2:24`, `BCJ`, `7zAES`.
pub fn method_name(id: &[u8], props: &[u8]) -> String {
    match id {
        ID_COPY => "Copy".into(),
        ID_LZMA2 => match props.first().map(|&b| lzma2_dict_from_prop(b)) {
            Some(Ok(d)) => format!("LZMA2:{}", log2_name(u64::from(d))),
            _ => "LZMA2".into(),
        },
        ID_LZMA if props.len() >= 5 => {
            let d = u32::from_le_bytes([props[1], props[2], props[3], props[4]]);
            format!("LZMA:{}", log2_name(u64::from(d)))
        }
        ID_LZMA => "LZMA".into(),
        ID_PPMD if props.len() >= 5 => {
            let mem = u32::from_le_bytes([props[1], props[2], props[3], props[4]]);
            format!("PPMd:o{}:mem{}", props[0], log2_name(u64::from(mem)))
        }
        ID_PPMD => "PPMd".into(),
        ID_BCJ_X86 => "BCJ".into(),
        ID_BCJ2 => "BCJ2".into(),
        ID_PPC => "PPC".into(),
        ID_IA64 => "IA64".into(),
        ID_ARM => "ARM".into(),
        ID_ARMT => "ARMT".into(),
        ID_SPARC => "SPARC".into(),
        ID_ARM64 => "ARM64".into(),
        ID_RISCV => "RISCV".into(),
        ID_DELTA => format!("Delta:{}", props.first().map(|&b| u32::from(b) + 1).unwrap_or(1)),
        ID_DEFLATE => "Deflate".into(),
        ID_DEFLATE64 => "Deflate64".into(),
        ID_BZIP2 => "BZip2".into(),
        ID_AES => "7zAES".into(),
        ID_ZSTD => "ZSTD".into(),
        other => other.iter().map(|b| format!("{b:02X}")).collect(),
    }
}

/// Human readable description of a folder's coders, outermost first.
pub fn folder_methods(f: &Folder) -> String {
    f.coders.iter().map(|c| method_name(&c.id, &c.props)).collect::<Vec<_>>().join(" ")
}

// ----- 7zAES ---------------------------------------------------------------

pub struct AesParams {
    pub cycles: u8,
    pub salt: Vec<u8>,
    pub iv: [u8; 16],
}

pub fn parse_aes_props(p: &[u8]) -> Result<AesParams> {
    let b0 = *p.first().ok_or_else(|| Error::corrupt("7zAES properties missing"))?;
    let cycles = b0 & 0x3f;
    let mut iv = [0u8; 16];
    if b0 & 0xc0 == 0 {
        return Ok(AesParams { cycles, salt: Vec::new(), iv });
    }
    let b1 = *p.get(1).ok_or_else(|| Error::corrupt("7zAES properties truncated"))?;
    let salt_len = usize::from((b0 >> 7) & 1) + usize::from(b1 >> 4);
    let iv_len = usize::from((b0 >> 6) & 1) + usize::from(b1 & 0x0f);
    if p.len() < 2 + salt_len + iv_len || iv_len > 16 {
        return Err(Error::corrupt("7zAES properties truncated"));
    }
    let salt = p[2..2 + salt_len].to_vec();
    iv[..iv_len].copy_from_slice(&p[2 + salt_len..2 + salt_len + iv_len]);
    Ok(AesParams { cycles, salt, iv })
}

pub fn aes_props(cycles: u8, iv: &[u8; 16]) -> Vec<u8> {
    // no salt, 16-byte IV: b0 = 0x40 | cycles, b1 = (iv_len - 1)
    let mut v = vec![0x40 | cycles, 0x0f];
    v.extend_from_slice(iv);
    v
}

/// 7-Zip's key derivation: SHA-256 over 2^cycles rounds of
/// (salt || UTF-16LE password || 64-bit counter).
pub fn derive_key(password: &Password, salt: &[u8], cycles: u8) -> Result<Zeroizing<[u8; 32]>> {
    let pw = password.utf16le();
    let mut key = Zeroizing::new([0u8; 32]);
    if cycles == 0x3f {
        let mut buf = Zeroizing::new(Vec::new());
        buf.extend_from_slice(salt);
        buf.extend_from_slice(&pw);
        let n = buf.len().min(32);
        key[..n].copy_from_slice(&buf[..n]);
        return Ok(key);
    }
    if cycles > 24 {
        return Err(Error::unsupported("7zAES key derivation with more than 2^24 rounds"));
    }
    let mut sha = Sha256::new();
    let mut block = Zeroizing::new(Vec::with_capacity(salt.len() + pw.len() + 8));
    for round in 0u64..(1u64 << cycles) {
        block.clear();
        block.extend_from_slice(salt);
        block.extend_from_slice(&pw);
        block.extend_from_slice(&round.to_le_bytes());
        sha.update(&block[..]);
    }
    key.copy_from_slice(&sha.finalize());
    Ok(key)
}

type KeyCache = Mutex<HashMap<(Vec<u8>, u8), Zeroizing<[u8; 32]>>>;

// ----- shared source ---------------------------------------------------------

pub type SharedSrc = Arc<Mutex<Box<dyn ReadSeek>>>;

/// An independent reader over a byte range of a shared file.
pub struct RangeReader {
    src: SharedSrc,
    pos: u64,
    end: u64,
}

impl RangeReader {
    pub fn new(src: SharedSrc, start: u64, len: u64) -> Self {
        RangeReader { src, pos: start, end: start.saturating_add(len) }
    }
}

impl Read for RangeReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.end || buf.is_empty() {
            return Ok(0);
        }
        let n = buf.len().min((self.end - self.pos).min(usize::MAX as u64) as usize);
        let mut src = self.src.lock().map_err(|_| io::Error::other("source lock poisoned"))?;
        src.seek(SeekFrom::Start(self.pos))?;
        let got = src.read(&mut buf[..n])?;
        if got == 0 {
            return Err(Error::corrupt("7z data ends before its declared size").into());
        }
        self.pos += got as u64;
        Ok(got)
    }
}

// ----- decoding --------------------------------------------------------------

pub type BoxR = Box<dyn Read + Send + 'static>;

pub struct DecodeCtx<'a> {
    pub src: &'a SharedSrc,
    /// Absolute file offsets and sizes of all pack streams.
    pub pack_offsets: &'a [u64],
    pub pack_sizes: &'a [u64],
    pub password: Option<&'a Password>,
    pub limits: &'a Limits,
    pub threads: usize,
    pub keys: &'a KeyCache,
}

fn check_mem(limits: &Limits, bytes: u64, what: &str) -> Result<()> {
    if bytes > limits.max_decoder_memory {
        return Err(Error::limit(format!("{what} needs {} of memory", crate::util::human_size(bytes))));
    }
    Ok(())
}

/// A reader producing the folder's main (unpacked) stream.
pub fn folder_reader(folder: &Folder, ctx: &DecodeCtx) -> Result<BoxR> {
    let out = folder.main_out().ok_or_else(|| Error::corrupt("7z folder has no main output"))?;
    out_reader(folder, out, ctx, 0)
}

fn out_reader(folder: &Folder, out: usize, ctx: &DecodeCtx, depth: usize) -> Result<BoxR> {
    if depth > 16 {
        return Err(Error::corrupt("7z coder graph too deep"));
    }
    let (ci, in_base, _) = folder.coder_of_out(out).ok_or_else(|| Error::corrupt("7z coder graph"))?;
    let coder = &folder.coders[ci];
    let mut inputs: Vec<BoxR> = Vec::with_capacity(coder.num_in);
    for j in 0..coder.num_in {
        let in_idx = in_base + j;
        if let Some(&(_, bound_out)) = folder.bind_pairs.iter().find(|&&(i, _)| i == in_idx) {
            inputs.push(out_reader(folder, bound_out, ctx, depth + 1)?);
        } else {
            let k = folder.packed.iter().position(|&p| p == in_idx).ok_or_else(|| Error::corrupt("7z coder input not connected"))?;
            let pi = folder.first_pack + k;
            let (off, len) = (
                *ctx.pack_offsets.get(pi).ok_or_else(|| Error::corrupt("7z pack stream missing"))?,
                *ctx.pack_sizes.get(pi).ok_or_else(|| Error::corrupt("7z pack stream missing"))?,
            );
            let r = RangeReader::new(ctx.src.clone(), off, len);
            inputs.push(Box::new(BufReader::with_capacity(256 * 1024, r)));
        }
    }
    let size = *folder.unpack_sizes.get(out).ok_or_else(|| Error::corrupt("7z unpack size missing"))?;
    let r = coder_reader(&coder.id, &coder.props, inputs, size, ctx)?;
    Ok(Box::new(TakeExact::new(r, size)))
}

fn one(mut inputs: Vec<BoxR>) -> Result<BoxR> {
    if inputs.len() != 1 {
        return Err(Error::corrupt("7z coder expects one input"));
    }
    Ok(inputs.remove(0))
}

fn coder_reader(id: &[u8], props: &[u8], inputs: Vec<BoxR>, size: u64, ctx: &DecodeCtx) -> Result<BoxR> {
    let lim = ctx.limits;
    let small_dict = |d: u32| d.min(size.max(4096).min(u64::from(u32::MAX)) as u32);
    Ok(match id {
        ID_COPY => one(inputs)?,
        ID_LZMA2 => {
            let d = lzma2_dict_from_prop(*props.first().ok_or_else(|| Error::corrupt("LZMA2 properties missing"))?)?;
            let d = small_dict(d);
            check_mem(lim, u64::from(d), "LZMA2 dictionary")?;
            let input = one(inputs)?;
            let mut threads = ctx.threads.max(1) as u64;
            // Several threads only pay off for big streams, and each needs
            // its own dictionary.
            if size <= u64::from(d) * 2 || u64::from(d) * threads > lim.max_decoder_memory {
                threads = 1;
            }
            if threads > 1 {
                Box::new(lzma_rust2::Lzma2ReaderMt::new(input, d, None, threads as u32))
            } else {
                Box::new(lzma_rust2::Lzma2Reader::new(input, d, None))
            }
        }
        ID_LZMA => {
            if props.len() < 5 {
                return Err(Error::corrupt("LZMA properties missing"));
            }
            let d = small_dict(u32::from_le_bytes([props[1], props[2], props[3], props[4]]));
            check_mem(lim, u64::from(d), "LZMA dictionary")?;
            Box::new(lzma_rust2::LzmaReader::new_with_props(one(inputs)?, size, props[0], d, None).map_err(|e| Error::corrupt(format!("lzma: {e}")))?)
        }
        ID_PPMD => {
            if props.len() < 5 {
                return Err(Error::corrupt("PPMd properties missing"));
            }
            let order = u32::from(props[0]);
            let mem = u32::from_le_bytes([props[1], props[2], props[3], props[4]]);
            check_mem(lim, u64::from(mem), "PPMd model")?;
            Box::new(ppmd_rust::Ppmd7Decoder::new(one(inputs)?, order, mem).map_err(|e| Error::corrupt(format!("ppmd: {e:?}")))?)
        }
        ID_BZIP2 => Box::new(bzip2::read::MultiBzDecoder::new(one(inputs)?)),
        ID_DEFLATE => Box::new(crate::codecs::deflate::InflateReader::new(BufReader::new(one(inputs)?))),
        ID_ZSTD => Box::new(crate::codecs::zstd::ZstdReader::new(BufReader::new(one(inputs)?), lim.max_decoder_memory)),
        ID_DELTA => Box::new(lzma_rust2::filter::delta::DeltaReader::new(one(inputs)?, usize::from(props.first().copied().unwrap_or(0)) + 1)),
        ID_BCJ_X86 => Box::new(lzma_rust2::filter::bcj::BcjReader::new_x86(one(inputs)?, 0)),
        ID_PPC => Box::new(lzma_rust2::filter::bcj::BcjReader::new_ppc(one(inputs)?, 0)),
        ID_IA64 => Box::new(lzma_rust2::filter::bcj::BcjReader::new_ia64(one(inputs)?, 0)),
        ID_ARM => Box::new(lzma_rust2::filter::bcj::BcjReader::new_arm(one(inputs)?, 0)),
        ID_ARMT => Box::new(lzma_rust2::filter::bcj::BcjReader::new_arm_thumb(one(inputs)?, 0)),
        ID_SPARC => Box::new(lzma_rust2::filter::bcj::BcjReader::new_sparc(one(inputs)?, 0)),
        ID_ARM64 => Box::new(lzma_rust2::filter::bcj::BcjReader::new_arm64(one(inputs)?, start_pos(props))),
        ID_RISCV => Box::new(lzma_rust2::filter::bcj::BcjReader::new_riscv(one(inputs)?, start_pos(props))),
        ID_BCJ2 => {
            if inputs.len() != 4 {
                return Err(Error::corrupt("BCJ2 expects four inputs"));
            }
            Box::new(lzma_rust2::filter::bcj2::Bcj2Reader::new(inputs, size))
        }
        ID_AES => {
            let pw = ctx.password.ok_or(Error::PasswordRequired)?;
            let p = parse_aes_props(props)?;
            let cache_key = (p.salt.clone(), p.cycles);
            let key = {
                let mut cache = ctx.keys.lock().map_err(|_| Error::invalid("key cache poisoned"))?;
                match cache.get(&cache_key) {
                    Some(k) => k.clone(),
                    None => {
                        let k = derive_key(pw, &p.salt, p.cycles)?;
                        cache.insert(cache_key, k.clone());
                        k
                    }
                }
            };
            Box::new(CbcDecryptReader::new(one(inputs)?, AesKey::new(&key[..])?, p.iv))
        }
        ID_DEFLATE64 => return Err(Error::unsupported("Deflate64 compression")),
        other => return Err(Error::unsupported(format!("7z method {}", method_name(other, props)))),
    })
}

fn start_pos(props: &[u8]) -> usize {
    if props.len() >= 4 {
        u32::from_le_bytes([props[0], props[1], props[2], props[3]]) as usize
    } else {
        0
    }
}

