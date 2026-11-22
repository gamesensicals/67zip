//! The zip format (our own implementation).

pub mod crypto;
mod read;
mod write;

pub use read::{find_eocd, method_name, ZipReader};
pub use write::ZipWriter;
