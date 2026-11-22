//! BLAKE2sp, the optional file checksum of RAR5: eight BLAKE2s leaves
//! hashing interleaved 64-byte blocks, and a root hashing their digests.

const IV: [u32; 8] = [
    0x6A09_E667,
    0xBB67_AE85,
    0x3C6E_F372,
    0xA54F_F53A,
    0x510E_527F,
    0x9B05_688C,
    0x1F83_D9AB,
    0x5BE0_CD19,
];
const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

#[derive(Clone)]
struct Blake2s {
    h: [u32; 8],
    t: u64,
    buf: [u8; 64],
    len: usize,
    last_node: bool,
}

impl Blake2s {
    fn new(node_offset: u32, node_depth: u8, last_node: bool) -> Self {
        // Parameter block: digest 32, no key, fanout 8, depth 2, inner 32.
        let p = [
            0x0208_0020u32,
            0,
            node_offset,
            (u32::from(node_depth) << 16) | (32 << 24),
            0,
            0,
            0,
            0,
        ];
        let mut h = IV;
        for i in 0..8 {
            h[i] ^= p[i];
        }
        Blake2s {
            h,
            t: 0,
            buf: [0; 64],
            len: 0,
            last_node,
        }
    }

    fn compress(&mut self, block: &[u8; 64], last: bool) {
        let mut m = [0u32; 16];
        for (i, w) in m.iter_mut().enumerate() {
            *w = u32::from_le_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        let mut v = [0u32; 16];
        v[..8].copy_from_slice(&self.h);
        v[8..].copy_from_slice(&IV);
        v[12] ^= self.t as u32;
        v[13] ^= (self.t >> 32) as u32;
        if last {
            v[14] = !v[14];
            if self.last_node {
                v[15] = !v[15];
            }
        }
        #[inline(always)]
        fn g(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
            v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
            v[d] = (v[d] ^ v[a]).rotate_right(16);
            v[c] = v[c].wrapping_add(v[d]);
            v[b] = (v[b] ^ v[c]).rotate_right(12);
            v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
            v[d] = (v[d] ^ v[a]).rotate_right(8);
            v[c] = v[c].wrapping_add(v[d]);
            v[b] = (v[b] ^ v[c]).rotate_right(7);
        }
        for s in &SIGMA {
            g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
            g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
            g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
            g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
            g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
            g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }
        for i in 0..8 {
            self.h[i] ^= v[i] ^ v[i + 8];
        }
    }

    /// Adds one block; the previous one is compressed first, so the last
    /// block is always kept for `finish`.
    fn push_block(&mut self, data: &[u8]) {
        if self.len == 64 {
            self.t += 64;
            let b = self.buf;
            self.compress(&b, false);
            self.len = 0;
        }
        self.buf[..data.len()].copy_from_slice(data);
        self.len = data.len();
    }

    fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            if self.len == 64 {
                self.t += 64;
                let b = self.buf;
                self.compress(&b, false);
                self.len = 0;
            }
            let n = (64 - self.len).min(data.len());
            self.buf[self.len..self.len + n].copy_from_slice(&data[..n]);
            self.len += n;
            data = &data[n..];
        }
    }

    fn finish(mut self) -> [u8; 32] {
        self.t += self.len as u64;
        let mut b = [0u8; 64];
        b[..self.len].copy_from_slice(&self.buf[..self.len]);
        self.compress(&b, true);
        let mut out = [0u8; 32];
        for (i, w) in self.h.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
        }
        out
    }
}

/// Incremental BLAKE2sp.
#[derive(Clone)]
pub struct Blake2sp {
    leaves: Vec<Blake2s>,
    /// Bytes of the current 64-byte block not yet given to a leaf.
    pending: [u8; 64],
    pending_len: usize,
    next_leaf: usize,
}

impl Default for Blake2sp {
    fn default() -> Self {
        Self::new()
    }
}

impl Blake2sp {
    pub fn new() -> Self {
        Blake2sp {
            leaves: (0..8).map(|i| Blake2s::new(i, 0, i == 7)).collect(),
            pending: [0; 64],
            pending_len: 0,
            next_leaf: 0,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        if self.pending_len > 0 {
            let n = (64 - self.pending_len).min(data.len());
            self.pending[self.pending_len..self.pending_len + n].copy_from_slice(&data[..n]);
            self.pending_len += n;
            data = &data[n..];
            if self.pending_len < 64 {
                return;
            }
            let b = self.pending;
            self.leaves[self.next_leaf].push_block(&b);
            self.next_leaf = (self.next_leaf + 1) % 8;
            self.pending_len = 0;
        }
        while data.len() >= 64 {
            self.leaves[self.next_leaf].push_block(&data[..64]);
            self.next_leaf = (self.next_leaf + 1) % 8;
            data = &data[64..];
        }
        self.pending[..data.len()].copy_from_slice(data);
        self.pending_len = data.len();
    }

    pub fn finalize(mut self) -> [u8; 32] {
        if self.pending_len > 0 {
            let b = self.pending;
            self.leaves[self.next_leaf].update(&b[..self.pending_len]);
        }
        let mut root = Blake2s::new(0, 1, true);
        for leaf in self.leaves {
            root.update(&leaf.finish());
        }
        root.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(d: &[u8]) -> String {
        d.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn known_digests() {
        // Reference values from the BLAKE2 test vectors (blake2sp, no key).
        assert_eq!(
            hex(&Blake2sp::new().finalize()),
            "dd0e891776933f43c7d032b08a917e25741f8aa9a12c12e1cac8801500f2ca4f"
        );
        let data: Vec<u8> = (0..=255u8).collect();
        let mut h = Blake2sp::new();
        h.update(&data);
        let one = h.finalize();
        let mut h = Blake2sp::new();
        for c in data.chunks(7) {
            h.update(c);
        }
        assert_eq!(one, h.finalize());
    }
}
