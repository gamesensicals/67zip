//! RAR5 archive headers: variable-length integers, CRC-protected blocks,
//! optional header encryption, file and service headers with their extra
//! records (encryption, BLAKE2 hash, times, links).

use std::io::SeekFrom;

use super::crypto;
use super::{Crypt, FileRec, Link, Version, VolumeHeaders};
use crate::cipher::AesKey;
use crate::error::{Error, Result};
use crate::io::ReadSeek;
use crate::password::Password;

pub const SIGNATURE: &[u8; 8] = b"Rar!\x1a\x07\x01\x00";
const MAX_HEADER: u64 = 2 << 20;

fn bad(msg: &str) -> Error {
    Error::corrupt(format!("RAR5 header: {msg}"))
}

/// Cursor over one header's bytes.
pub(crate) struct Rd<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Rd<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        Rd { b, p: 0 }
    }
    pub fn vint(&mut self) -> Result<u64> {
        let mut v = 0u64;
        for i in 0..10 {
            let byte = *self.b.get(self.p).ok_or_else(|| bad("truncated number"))?;
            self.p += 1;
            v |= u64::from(byte & 0x7f) << (7 * i);
            if byte & 0x80 == 0 {
                return Ok(v);
            }
        }
        Err(bad("number too long"))
    }
    pub fn take(&mut self, n: u64) -> Result<&'a [u8]> {
        let n = usize::try_from(n).map_err(|_| bad("length"))?;
        let end = self.p.checked_add(n).filter(|&e| e <= self.b.len()).ok_or_else(|| bad("field runs past the header"))?;
        let s = &self.b[self.p..end];
        self.p = end;
        Ok(s)
    }
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    pub fn u32(&mut self) -> Result<u32> {
        let s = self.take(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
    pub fn u64(&mut self) -> Result<u64> {
        let s = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        Ok(u64::from_le_bytes(a))
    }
    pub fn arr<const N: usize>(&mut self) -> Result<[u8; N]> {
        let s = self.take(N as u64)?;
        let mut a = [0u8; N];
        a.copy_from_slice(s);
        Ok(a)
    }
}

/// Reads the volume's headers starting right after the signature at `start`.
pub(crate) fn read_volume(
    src: &mut dyn ReadSeek,
    size: u64,
    start: u64,
    password: Option<&Password>,
    keys: &mut super::KeyCache,
    max_entries: u64,
) -> Result<VolumeHeaders> {
    let mut vh = VolumeHeaders::default();
    let mut pos = start;
    let mut header_key: Option<(AesKey, bool)> = None;
    let mut count = 0u64;
    loop {
        if pos >= size {
            vh.truncated = true;
            break;
        }
        count += 1;
        if count > max_entries.saturating_add(1000) {
            return Err(Error::limit("too many RAR headers"));
        }
        src.seek(SeekFrom::Start(pos))?;
        let (raw, consumed) = match &header_key {
            None => match read_plain(src, size - pos) {
                Ok(v) => v,
                Err(e) if count > 1 => {
                    vh.warnings.push(format!("{e}"));
                    vh.truncated = true;
                    break;
                }
                Err(e) => return Err(e),
            },
            Some((key, verified)) => match read_encrypted(src, size - pos, key) {
                Ok(v) => v,
                Err(Error::Checksum(_)) if vh.files.is_empty() && !*verified => return Err(Error::WrongPassword),
                Err(e) => {
                    vh.warnings.push(format!("{e}"));
                    vh.truncated = true;
                    break;
                }
            },
        };
        let mut r = Rd::new(&raw);
        let htype = r.vint()?;
        let hflags = r.vint()?;
        let extra_size = if hflags & 1 != 0 { r.vint()? } else { 0 };
        let data_size = if hflags & 2 != 0 { r.vint()? } else { 0 };
        let data_pos = pos + consumed;
        let next = data_pos.checked_add(data_size).ok_or_else(|| bad("data size"))?;
        let body_end =
            raw.len().checked_sub(usize::try_from(extra_size).map_err(|_| bad("extra size"))?).ok_or_else(|| bad("extra area larger than header"))?;
        if body_end < r.p {
            return Err(bad("extra area overlaps the header fields"));
        }
        let extra = &raw[body_end..];
        let body = &raw[r.p..body_end];
        match htype {
            1 => {
                let mut b = Rd::new(body);
                let flags = b.vint()?;
                vh.volume = flags & 1 != 0;
                vh.solid = flags & 4 != 0;
                vh.locked = flags & 0x10 != 0;
                if flags & 2 != 0 {
                    vh.volume_number = Some(b.vint()?);
                }
            }
            2 | 3 => {
                let mut rec = match parse_file(body, extra) {
                    Ok(r) => r,
                    Err(e) => {
                        vh.warnings.push(format!("{e}; the files after it were not read"));
                        vh.truncated = true;
                        break;
                    }
                };
                rec.split_before = hflags & 0x08 != 0;
                rec.split_after = hflags & 0x10 != 0;
                rec.data_offset = data_pos;
                rec.data_len = data_size;
                if next > size {
                    rec.data_len = size.saturating_sub(data_pos);
                    rec.truncated = true;
                    vh.truncated = true;
                }
                if htype == 2 {
                    vh.files.push(rec);
                } else if rec.name == "CMT" {
                    vh.comment = Some(rec);
                }
            }
            4 => {
                let mut b = Rd::new(body);
                if b.vint()? != 0 {
                    return Err(Error::unsupported("RAR5 header encryption version"));
                }
                let flags = b.vint()?;
                let lg2 = b.u8()?;
                let salt: [u8; 16] = b.arr()?;
                let check: Option<[u8; 12]> = if flags & 1 != 0 { Some(b.arr()?) } else { None };
                vh.encrypted_headers = true;
                let Some(pw) = password else { return Err(Error::PasswordRequired) };
                if lg2 > crypto::MAX_KDF_LG2 {
                    return Err(Error::unsupported("RAR5 key derivation count too high"));
                }
                let k = keys.rar5(pw, &salt, lg2);
                let mut verified = false;
                if let Some(c) = check
                    && crypto::check_value_valid(&c)
                {
                    if c[..8] != k.check {
                        return Err(Error::WrongPassword);
                    }
                    verified = true;
                }
                header_key = Some((AesKey::new(&k.key[..])?, verified));
            }
            5 => {
                let mut b = Rd::new(body);
                let flags = b.vint()?;
                vh.more_volumes = flags & 1 != 0;
                vh.ended = true;
                break;
            }
            _ => {}
        }
        if next > size && htype != 2 && htype != 3 {
            vh.truncated = true;
            break;
        }
        pos = next;
    }
    Ok(vh)
}

/// Reads one unencrypted header; returns its bytes after the size field
/// and the number of bytes the header occupied.
fn read_plain(src: &mut dyn ReadSeek, left: u64) -> Result<(Vec<u8>, u64)> {
    let mut head = [0u8; 7];
    let n = crate::io::read_full(src, &mut head)?;
    if n < 5 {
        return Err(bad("archive ends inside a header (incomplete download?)"));
    }
    let crc = u32::from_le_bytes([head[0], head[1], head[2], head[3]]);
    let mut r = Rd::new(&head[4..n]);
    let hsize = r.vint()?;
    let vlen = r.p as u64;
    if hsize == 0 || hsize > MAX_HEADER {
        return Err(bad("bad header size"));
    }
    let total = 4 + vlen + hsize;
    if total > left {
        return Err(bad("archive ends inside a header (incomplete download?)"));
    }
    let mut all = vec![0u8; (vlen + hsize) as usize];
    let have = n - 4;
    all[..have].copy_from_slice(&head[4..n]);
    src.read_exact(&mut all[have..])?;
    if crate::crc::crc32(&all) != crc {
        return Err(Error::Checksum("RAR5 header".into()));
    }
    Ok((all.split_off(vlen as usize), total))
}

/// Reads one encrypted header: 16-byte IV, then AES-256-CBC data padded to
/// 16 bytes holding the usual CRC, size and fields.
fn read_encrypted(src: &mut dyn ReadSeek, left: u64, key: &AesKey) -> Result<(Vec<u8>, u64)> {
    let mut iv = [0u8; 16];
    let mut first = [0u8; 16];
    if left < 32 {
        return Err(bad("archive ends inside a header (incomplete download?)"));
    }
    src.read_exact(&mut iv)?;
    src.read_exact(&mut first)?;
    let mut dec = cbc_decrypt(key, &iv, &first);
    let mut r = Rd::new(&dec[4..]);
    let hsize = r.vint().map_err(|_| Error::Checksum("RAR5 header".into()))?;
    let vlen = r.p as u64;
    if hsize == 0 || hsize > MAX_HEADER {
        return Err(Error::Checksum("RAR5 header".into()));
    }
    let total = (4 + vlen + hsize).div_ceil(16) * 16;
    if 16 + total > left {
        return Err(bad("archive ends inside a header (incomplete download?)"));
    }
    if total > 16 {
        let mut rest = vec![0u8; (total - 16) as usize];
        src.read_exact(&mut rest)?;
        let mut all_ct = first.to_vec();
        all_ct.extend_from_slice(&rest);
        dec = cbc_decrypt(key, &iv, &all_ct);
    }
    let crc = u32::from_le_bytes([dec[0], dec[1], dec[2], dec[3]]);
    let body = &dec[4..(4 + vlen + hsize) as usize];
    if crate::crc::crc32(body) != crc {
        return Err(Error::Checksum("RAR5 header".into()));
    }
    Ok((body[vlen as usize..].to_vec(), 16 + total))
}

pub(crate) fn cbc_decrypt(key: &AesKey, iv: &[u8; 16], ct: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ct.len());
    let mut prev = *iv;
    for c in ct.chunks_exact(16) {
        let mut b = aes::Block::default();
        b.copy_from_slice(c);
        key.decrypt_blocks(std::slice::from_mut(&mut b));
        for j in 0..16 {
            out.push(b[j] ^ prev[j]);
        }
        prev.copy_from_slice(c);
    }
    out
}

fn parse_file(body: &[u8], extra: &[u8]) -> Result<FileRec> {
    let mut b = Rd::new(body);
    let fflags = b.vint()?;
    let unp_size = b.vint()?;
    let attr = b.vint()?;
    let mtime = if fflags & 2 != 0 { Some(b.u32()?) } else { None };
    let crc = if fflags & 4 != 0 { Some(b.u32()?) } else { None };
    let ci = b.vint()?;
    let host = b.vint()?;
    let nlen = b.vint()?;
    if nlen > 64 * 1024 {
        return Err(bad("name too long"));
    }
    let name_raw = b.take(nlen)?;
    let mut name = String::from_utf8_lossy(name_raw).into_owned();
    if host == 0 {
        // Backslash is not a path separator in RAR5, and not valid in
        // Windows names.
        name = name.replace('\\', "_");
    }
    let alg = (ci & 0x3f) as u8;
    let method = ((ci >> 7) & 7) as u8;
    let dict = if alg == 0 { (128u64 << 10) << ((ci >> 10) & 0xf) } else { (128u64 << 10) << ((ci >> 10) & 0x1f) };
    let mut rec = FileRec {
        name,
        dir: fflags & 1 != 0,
        size: unp_size,
        size_known: fflags & 8 == 0,
        mtime: mtime.map(|t| (i64::from(t), 0)),
        attr,
        unix: host == 1,
        crc,
        method,
        dict,
        version: Version::V5 { alg },
        solid: ci & 0x40 != 0,
        ..Default::default()
    };
    if dict > (1 << 40) {
        return Err(bad("dictionary size"));
    }
    // Damaged extra records are skipped (like WinRAR does); a damaged
    // encryption record makes the file unreadable rather than plain.
    let mut x = Rd::new(extra);
    while x.p < extra.len() {
        let Ok(size) = x.vint() else { break };
        let Ok(rec_bytes) = x.take(size) else { break };
        let mut f = Rd::new(rec_bytes);
        let Ok(kind) = f.vint() else { continue };
        if let Err(e) = extra_record(&mut rec, kind, &mut f)
            && kind == 1
        {
            rec.crypt = Some(Crypt::Unknown(format!("damaged encryption header ({e})")));
        }
    }
    Ok(rec)
}

fn extra_record(rec: &mut FileRec, kind: u64, f: &mut Rd) -> Result<()> {
    {
        match kind {
            1 => {
                if f.vint()? != 0 {
                    rec.crypt = Some(Crypt::Unknown("RAR5 encryption version".into()));
                    return Ok(());
                }
                let flags = f.vint()?;
                let lg2 = f.u8()?;
                let salt: [u8; 16] = f.arr()?;
                let iv: [u8; 16] = f.arr()?;
                let check: Option<[u8; 12]> = if flags & 1 != 0 { Some(f.arr()?) } else { None };
                let check = check.filter(crypto::check_value_valid).map(|c| {
                    let mut a = [0u8; 8];
                    a.copy_from_slice(&c[..8]);
                    a
                });
                rec.crypt = Some(Crypt::V5 { lg2, salt, iv, check, mac: flags & 2 != 0 });
            }
            2 => {
                if f.vint()? == 0 {
                    rec.blake2 = Some(f.arr()?);
                }
            }
            3 => {
                let flags = f.vint()?;
                let unix = flags & 1 != 0;
                let read = |f: &mut Rd| -> Result<u64> { if unix { f.u32().map(u64::from) } else { f.u64() } };
                let m = if flags & 2 != 0 { Some(read(f)?) } else { None };
                if flags & 4 != 0 {
                    read(f)?;
                }
                if flags & 8 != 0 {
                    read(f)?;
                }
                let ns = if unix && flags & 0x10 != 0 && flags & 2 != 0 { f.u32().ok() } else { None };
                if let Some(m) = m {
                    rec.mtime = Some(if unix { (m as i64, ns.unwrap_or(0).min(999_999_999)) } else { crate::util::filetime_to_unix(m) });
                }
            }
            5 => {
                let t = f.vint()?;
                let _flags = f.vint()?;
                let n = f.vint()?;
                if n > 64 * 1024 {
                    return Err(bad("link target too long"));
                }
                let target = String::from_utf8_lossy(f.take(n)?).into_owned();
                rec.link = match t {
                    1 => Link::Symlink(target),
                    2 | 3 => Link::Symlink(windows_link_target(&target)),
                    4 => Link::Hardlink(target),
                    5 => Link::Copy(target),
                    _ => Link::None,
                };
            }
            _ => {}
        }
    }
    Ok(())
}

/// Windows link targets use backslashes and `\??\` prefixes for absolute
/// paths; keep relative ones usable, absolute ones stay absolute (and are
/// refused on extraction as escaping links).
fn windows_link_target(t: &str) -> String {
    let t = t.strip_prefix("\\??\\").map(|s| format!("/{s}")).unwrap_or_else(|| t.to_string());
    t.replace('\\', "/")
}
