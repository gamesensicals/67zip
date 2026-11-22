//! CRC helpers that the fast `crc32fast` crate does not offer: the raw
//! per-byte CRC-32 update (needed by ZipCrypto) and CRC-64 (as used by xz).

const fn make_crc32_table() -> [u32; 256] {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
}

static CRC32_TABLE: [u32; 256] = make_crc32_table();

/// One step of the CRC-32 register without pre/post inversion.
#[inline]
pub fn crc32_byte(crc: u32, b: u8) -> u32 {
    CRC32_TABLE[((crc ^ u32::from(b)) & 0xff) as usize] ^ (crc >> 8)
}

/// Standard CRC-32 of a whole buffer (same result as zlib's `crc32`).
pub fn crc32(data: &[u8]) -> u32 {
    let mut h = crc32fast::Hasher::new();
    h.update(data);
    h.finalize()
}

const fn make_crc64_tables() -> [[u64; 256]; 8] {
    const POLY: u64 = 0xC96C_5795_D787_0F42; // ECMA-182, reflected (CRC-64/XZ)
    let mut t = [[0u64; 256]; 8];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u64;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { POLY ^ (c >> 1) } else { c >> 1 };
            k += 1;
        }
        t[0][i] = c;
        i += 1;
    }
    let mut s = 1;
    while s < 8 {
        let mut i = 0;
        while i < 256 {
            let prev = t[s - 1][i];
            t[s][i] = (prev >> 8) ^ t[0][(prev & 0xff) as usize];
            i += 1;
        }
        s += 1;
    }
    t
}

static CRC64_TABLES: [[u64; 256]; 8] = make_crc64_tables();

/// Incremental CRC-64/XZ (slice-by-8, safe code).
#[derive(Clone)]
pub struct Crc64 {
    state: u64,
}

impl Default for Crc64 {
    fn default() -> Self {
        Self::new()
    }
}

impl Crc64 {
    pub fn new() -> Self {
        Crc64 { state: !0 }
    }
    pub fn update(&mut self, mut data: &[u8]) {
        let t = &CRC64_TABLES;
        let mut c = self.state;
        while data.len() >= 8 {
            let mut w = [0u8; 8];
            w.copy_from_slice(&data[..8]);
            let v = c ^ u64::from_le_bytes(w);
            c = t[7][(v & 0xff) as usize]
                ^ t[6][((v >> 8) & 0xff) as usize]
                ^ t[5][((v >> 16) & 0xff) as usize]
                ^ t[4][((v >> 24) & 0xff) as usize]
                ^ t[3][((v >> 32) & 0xff) as usize]
                ^ t[2][((v >> 40) & 0xff) as usize]
                ^ t[1][((v >> 48) & 0xff) as usize]
                ^ t[0][(v >> 56) as usize];
            data = &data[8..];
        }
        for &b in data {
            c = t[0][((c ^ u64::from(b)) & 0xff) as usize] ^ (c >> 8);
        }
        self.state = c;
    }
    pub fn finalize(&self) -> u64 {
        !self.state
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc64_check_value() {
        let mut c = Crc64::new();
        c.update(b"123456789");
        assert_eq!(c.finalize(), 0x995D_C9BB_DF19_39FA);
    }

    #[test]
    fn crc32_byte_matches() {
        let mut c = !0u32;
        for &b in b"123456789" {
            c = crc32_byte(c, b);
        }
        assert_eq!(!c, 0xCBF4_3926);
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }
}
