//! Headers of RAR 1.5 to 4.x archives: 7-byte block headers with a 16-bit
//! CRC, file headers with 32-bit sizes (and high halves for large files),
//! RAR's compact Unicode name encoding, extended times, and the optional
//! encryption of all headers.

use std::io::SeekFrom;

use super::{Crypt, FileRec, Link, Version, VolumeHeaders};
use crate::cipher::AesKey;
use crate::error::{Error, Result};
use crate::io::ReadSeek;
use crate::password::Password;
use crate::util::Bytes;

pub const SIGNATURE: &[u8; 7] = b"Rar!\x1a\x07\x00";

fn bad(msg: &str) -> Error {
    Error::corrupt(format!("RAR header: {msg}"))
}

/// Decodes RAR's Unicode file name encoding: a high byte and 2-bit opcodes
/// that copy ASCII bytes from the plain name or give full UTF-16 units.
fn decode_unicode(plain: &[u8], enc: &[u8]) -> String {
    let mut out: Vec<u16> = Vec::with_capacity(plain.len());
    let mut p = 0usize;
    let Some(&high) = enc.first() else {
        return String::from_utf8_lossy(plain).into_owned();
    };
    p += 1;
    let high = u16::from(high);
    let mut flags = 0u8;
    let mut flag_bits = 0;
    let plain_at = |i: usize| u16::from(plain.get(i).copied().unwrap_or(0));
    while p < enc.len() && out.len() < 0x10000 {
        if flag_bits == 0 {
            flags = enc[p];
            p += 1;
            flag_bits = 8;
        }
        match flags >> 6 {
            0 => {
                let Some(&b) = enc.get(p) else { break };
                out.push(u16::from(b));
                p += 1;
            }
            1 => {
                let Some(&b) = enc.get(p) else { break };
                out.push(u16::from(b) | (high << 8));
                p += 1;
            }
            2 => {
                if p + 1 >= enc.len() {
                    break;
                }
                out.push(u16::from(enc[p]) | (u16::from(enc[p + 1]) << 8));
                p += 2;
            }
            _ => {
                let Some(&l) = enc.get(p) else { break };
                p += 1;
                if l & 0x80 != 0 {
                    let Some(&corr) = enc.get(p) else { break };
                    p += 1;
                    for _ in 0..(l & 0x7f) + 2 {
                        let i = out.len();
                        out.push(((plain_at(i) + u16::from(corr)) & 0xff) | (high << 8));
                    }
                } else {
                    for _ in 0..l + 2 {
                        let i = out.len();
                        out.push(plain_at(i));
                    }
                }
            }
        }
        flags <<= 2;
        flag_bits -= 2;
    }
    String::from_utf16_lossy(&out)
}

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
    let mut encrypted = false;
    let mut count = 0u64;
    while pos + 7 <= size {
        count += 1;
        if count > max_entries.saturating_add(1000) {
            return Err(Error::limit("too many RAR headers"));
        }
        src.seek(SeekFrom::Start(pos))?;
        let (raw, used) = if encrypted {
            let Some(pw) = password else {
                return Err(Error::PasswordRequired);
            };
            match read_encrypted(src, size - pos, pw, keys) {
                Ok(v) => v,
                // Nothing decrypted sensibly yet: RAR 4 has no password check
                // value, so this is how a wrong password shows.
                Err(_) if vh.files.is_empty() => return Err(Error::WrongPassword),
                Err(e) => {
                    vh.warnings.push(e.to_string());
                    vh.truncated = true;
                    break;
                }
            }
        } else {
            match read_plain(src, size - pos) {
                Ok(v) => v,
                Err(e) if count > 1 => {
                    vh.warnings.push(e.to_string());
                    vh.truncated = true;
                    break;
                }
                Err(e) => return Err(e),
            }
        };
        let crc = u16::from_le_bytes([raw[0], raw[1]]);
        let htype = raw[2];
        let flags = u16::from_le_bytes([raw[3], raw[4]]);
        let crc_ok = crate::crc::crc32(&raw[2..]) as u16 == crc;
        let mut add = 0u64;
        if flags & 0x8000 != 0 || htype == 0x74 || htype == 0x7a {
            if raw.len() < 11 {
                return Err(bad("block too short"));
            }
            add = u64::from(u32::from_le_bytes([raw[7], raw[8], raw[9], raw[10]]));
        }
        let data_pos = pos + used;
        let mut next = data_pos + add;
        match htype {
            0x73 => {
                // RAR 2.x keeps the archive comment inside the main header,
                // outside the part its CRC covers.
                let has_comment = flags & 0x0002 != 0 && raw.len() > 13;
                if !crc_ok && !(has_comment && crate::crc::crc32(&raw[2..13]) as u16 == crc) {
                    vh.warnings.push("RAR main header checksum mismatch".into());
                }
                if has_comment {
                    vh.old_comment = old_comment(&raw[13..]);
                }
                vh.volume = flags & 0x0001 != 0;
                vh.solid = flags & 0x0008 != 0;
                vh.locked = flags & 0x0004 != 0;
                if flags & 0x0080 != 0 {
                    encrypted = true;
                    vh.encrypted_headers = true;
                }
            }
            0x74 | 0x7a => {
                let parsed = parse_file(&raw, flags);
                // RAR 2.x file comments follow the fields the CRC covers.
                let crc_ok = crc_ok
                    || flags & 0x0008 != 0
                        && parsed
                            .as_ref()
                            .is_ok_and(|(_, used)| crate::crc::crc32(&raw[2..*used]) as u16 == crc);
                if !crc_ok {
                    if encrypted && vh.files.is_empty() {
                        return Err(Error::WrongPassword);
                    }
                    vh.warnings.push(
                        "a RAR file header is damaged; the files after it were not read".into(),
                    );
                    vh.truncated = true;
                    break;
                }
                let mut rec = match parsed {
                    Ok((r, _)) => r,
                    Err(e) => {
                        vh.warnings
                            .push(format!("{e}; the files after it were not read"));
                        vh.truncated = true;
                        break;
                    }
                };
                if raw.len() >= 36 && flags & 0x0100 != 0 {
                    // Large file: the high half of the packed size.
                    let hi = u64::from(u32::from_le_bytes([raw[32], raw[33], raw[34], raw[35]]));
                    next = data_pos + (hi << 32 | add);
                    add |= hi << 32;
                }
                rec.data_offset = data_pos;
                rec.data_len = add;
                if next > size {
                    rec.data_len = size.saturating_sub(data_pos);
                    rec.truncated = true;
                    vh.truncated = true;
                }
                if htype == 0x74 {
                    vh.files.push(rec);
                } else if rec.name == "CMT" {
                    // Before any file it is the archive comment, after one
                    // it belongs to that file.
                    match vh.files.last_mut() {
                        Some(f) => f.comment_rec = Some(Box::new(rec)),
                        None => vh.comment = Some(rec),
                    }
                }
            }
            0x7b => {
                vh.more_volumes = flags & 0x0001 != 0;
                vh.ended = true;
                break;
            }
            _ => {}
        }
        if next <= pos {
            return Err(bad("block size"));
        }
        if next > size {
            vh.truncated = true;
            break;
        }
        pos = next;
    }
    Ok(vh)
}

/// The whole header block (from the CRC field) and the bytes it occupies.
fn read_plain(src: &mut dyn ReadSeek, left: u64) -> Result<(Vec<u8>, u64)> {
    let mut base = [0u8; 7];
    src.read_exact(&mut base)
        .map_err(|_| bad("archive ends inside a header (incomplete download?)"))?;
    let hsize = u64::from(u16::from_le_bytes([base[5], base[6]]));
    if hsize < 7 {
        return Err(bad("bad header size"));
    }
    if hsize > left {
        return Err(bad("archive ends inside a header (incomplete download?)"));
    }
    let mut raw = vec![0u8; hsize as usize];
    raw[..7].copy_from_slice(&base);
    src.read_exact(&mut raw[7..])?;
    Ok((raw, hsize))
}

/// Encrypted headers: an 8-byte salt, then the header in AES-128-CBC,
/// padded to 16 bytes.
fn read_encrypted(
    src: &mut dyn ReadSeek,
    left: u64,
    pw: &Password,
    keys: &mut super::KeyCache,
) -> Result<(Vec<u8>, u64)> {
    if left < 8 + 16 {
        return Err(bad("archive ends inside a header (incomplete download?)"));
    }
    let mut salt = [0u8; 8];
    src.read_exact(&mut salt)?;
    let (key, iv) = keys.rar3(pw, Some(&salt));
    let aes = AesKey::new(&key[..])?;
    let mut first = [0u8; 16];
    src.read_exact(&mut first)?;
    let dec = super::rar5::cbc_decrypt(&aes, &iv, &first);
    let hsize = u64::from(u16::from_le_bytes([dec[5], dec[6]]));
    if hsize < 7 {
        return Err(Error::Checksum("RAR header".into()));
    }
    let total = hsize.div_ceil(16) * 16;
    if 8 + total > left {
        return Err(bad("archive ends inside a header (incomplete download?)"));
    }
    let mut ct = first.to_vec();
    ct.resize(total as usize, 0);
    src.read_exact(&mut ct[16..])?;
    let mut dec = super::rar5::cbc_decrypt(&aes, &iv, &ct);
    dec.truncate(hsize as usize);
    let crc = u16::from_le_bytes([dec[0], dec[1]]);
    if crate::crc::crc32(&dec[2..]) as u16 != crc && dec[2] != 0x7b {
        return Err(Error::Checksum("RAR header".into()));
    }
    Ok((dec, 8 + total))
}

/// A RAR 2.x comment block embedded in a header (stored, or compressed
/// with the RAR 2.0 or 2.9 method).
fn old_comment(b: &[u8]) -> Option<String> {
    if b.len() < 13 || b[2] != 0x75 {
        return None;
    }
    let size = usize::from(u16::from_le_bytes([b[5], b[6]]));
    let unp = usize::from(u16::from_le_bytes([b[7], b[8]]));
    let (unp_ver, method) = (b[9], b[10]);
    let data = b.get(13..size.min(b.len()))?;
    let bytes = if method == 0x30 {
        data.get(..unp)?.to_vec()
    } else {
        let codec = match unp_ver {
            20 | 26 => super::unpack::Codec::Rar20,
            29 => super::unpack::Codec::Rar29,
            _ => return None,
        };
        let mut up = super::unpack::Unpacker::new(codec, 64 << 20);
        up.begin(false, 1 << 20, Some(unp as u64)).ok()?;
        let mut out = Vec::new();
        let src: Box<dyn std::io::Read + Send> = Box::new(std::io::Cursor::new(data.to_vec()));
        std::io::Read::read_to_end(
            &mut super::unpack::FileDecoder::new(&mut up, src, Some(unp as u64)),
            &mut out,
        )
        .ok()?;
        out
    };
    super::comment_text(&bytes)
}

/// The parsed header and how many of its bytes were fields (the rest can
/// be an embedded comment).
fn parse_file(raw: &[u8], flags: u16) -> Result<(FileRec, usize)> {
    let mut b = Bytes::new(&raw[7..], "RAR file header");
    let pack_lo = b.u32()?;
    let unp_lo = b.u32()?;
    let host = b.u8()?;
    let crc = b.u32()?;
    let ftime = b.u32()?;
    let unp_ver = b.u8()?;
    let method = b.u8()?;
    let nsize = b.u16()?;
    let attr = b.u32()?;
    let _ = pack_lo;
    let (unp_size, known) = if flags & 0x0100 != 0 {
        let _pack_hi = b.u32()?;
        let hi = b.u32()?;
        (
            u64::from(hi) << 32 | u64::from(unp_lo),
            !(unp_lo == u32::MAX && hi == u32::MAX),
        )
    } else {
        (u64::from(unp_lo), unp_lo != u32::MAX)
    };
    let name_raw = b.take(usize::from(nsize))?;
    let name = if flags & 0x0200 != 0 {
        match name_raw.iter().position(|&c| c == 0) {
            Some(z) => decode_unicode(&name_raw[..z], &name_raw[z + 1..]),
            None => String::from_utf8_lossy(name_raw).into_owned(),
        }
    } else {
        crate::util::decode_name(name_raw)
    };
    let name = name.replace('\\', "/");
    let salt: Option<[u8; 8]> = if flags & 0x0400 != 0 {
        let s = b.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        Some(a)
    } else {
        None
    };
    let mut mtime = crate::util::dos_to_unix((ftime >> 16) as u16, ftime as u16).map(|s| (s, 0u32));
    if flags & 0x1000 != 0
        && let Ok(xf) = b.u16()
    {
        for i in 0..4 {
            let rmode = (xf >> ((3 - i) * 4)) & 0xf;
            if rmode & 8 == 0 {
                continue;
            }
            if i != 0 && b.u32().is_err() {
                break;
            }
            let count = usize::from(rmode & 3);
            let mut rem = 0u32;
            for j in 0..count {
                let Ok(byte) = b.u8() else { break };
                rem |= u32::from(byte) << ((j + 3 - count) * 8);
            }
            if i == 0
                && let Some((s, ns)) = mtime.as_mut()
            {
                if rmode & 4 != 0 {
                    *s += 1;
                }
                *ns = rem.min(9_999_999) * 100;
            }
        }
    }
    let unix = host == 3 || host == 5;
    let dir = flags & 0x00e0 == 0x00e0
        || (!unix && attr & 0x10 != 0)
        || (unix && attr & 0o170000 == 0o040000);
    let crypt = if flags & 0x0004 != 0 {
        Some(if unp_ver >= 29 {
            Crypt::V3 { salt }
        } else {
            Crypt::Unknown(format!(
                "encryption of RAR {}.{} archives",
                unp_ver / 10,
                unp_ver % 10
            ))
        })
    } else {
        None
    };
    let link = if unix && attr & 0o170000 == 0o120000 {
        Link::InData
    } else {
        Link::None
    };
    let used = 7 + b.pos();
    let comment = if flags & 0x0008 != 0 {
        old_comment(&raw[used..])
    } else {
        None
    };
    let rec = FileRec {
        name,
        dir,
        size: if dir { 0 } else { unp_size },
        size_known: known,
        mtime,
        attr: u64::from(attr),
        unix,
        crc: Some(crc),
        method: method.wrapping_sub(0x30),
        dict: if dir {
            0
        } else {
            (64u64 << 10) << ((flags >> 5) & 7)
        },
        version: Version::V3 { unp_ver },
        solid: flags & 0x0010 != 0,
        crypt,
        link,
        split_before: flags & 0x0001 != 0,
        split_after: flags & 0x0002 != 0,
        comment,
        ..Default::default()
    };
    Ok((rec, used))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unicode_names() {
        // Opcode 0 for every unit: plain UTF-16 low bytes.
        assert_eq!(decode_unicode(b"ab", &[0, 0b0000_0000, b'a', b'b']), "ab");
        // Opcode 2: full 16-bit unit (U+00E9).
        assert_eq!(decode_unicode(b"_", &[0, 0b1000_0000, 0xe9, 0x00]), "é");
        // Opcode 3: copy 2+1 ASCII bytes from the plain name.
        assert_eq!(decode_unicode(b"abc", &[0, 0b1100_0000, 1]), "abc");
    }
}
