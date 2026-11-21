//! The 7z format (our own implementation of the container; codecs come
//! from vetted pure-Rust crates).

pub mod coders;
pub mod header;
mod reader;
mod writer;

pub use reader::SevenZReader;
pub use writer::SevenZWriter;
