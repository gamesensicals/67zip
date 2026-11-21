//! Password handling: the secret is wiped from memory when dropped.

use std::fmt;
use zeroize::Zeroizing;

/// A password. Its memory is overwritten with zeros when it is dropped, and
/// it never shows up in debug output or logs.
#[derive(Clone)]
pub struct Password(Zeroizing<String>);

impl Password {
    pub fn new(s: impl Into<String>) -> Self {
        Password(Zeroizing::new(s.into()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    /// UTF-16LE bytes, as used by the 7z AES key derivation.
    pub fn utf16le(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(self.0.len() * 2));
        for u in self.0.encode_utf16() {
            out.extend_from_slice(&u.to_le_bytes());
        }
        out
    }
}

impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Password(<hidden>)")
    }
}
