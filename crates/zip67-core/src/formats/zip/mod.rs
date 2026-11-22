//! The zip format (our own implementation).

pub mod crypto;
mod read;
mod write;

pub use read::{ZipReader, find_eocd, method_name};
pub use write::ZipWriter;
