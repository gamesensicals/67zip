//! The 7z format (our own implementation). Filled in by the 7z stage.

use crate::archive::{ArchiveInfo, ArchiveReader, EntryVisitor, OpenOptions};
use crate::create::{ArchiveWriter, CreateOptions, Item};
use crate::detect::ArchiveType;
use crate::entry::Entry;
use crate::error::{Error, Result};
use crate::io::ReadSeek;
use crate::progress::Progress;

pub struct SevenZReader {
    entries: Vec<Entry>,
}

impl SevenZReader {
    pub fn open(_src: Box<dyn ReadSeek>, _size: u64, _opts: &OpenOptions) -> Result<Self> {
        Err(Error::unsupported("7z (in progress)"))
    }
}

impl ArchiveReader for SevenZReader {
    fn archive_type(&self) -> ArchiveType {
        ArchiveType::SEVEN_Z
    }
    fn entries(&self) -> &[Entry] {
        &self.entries
    }
    fn info(&self) -> ArchiveInfo {
        ArchiveInfo::default()
    }
    fn extract(&mut self, _s: &dyn Fn(&Entry) -> bool, _v: &mut dyn EntryVisitor, _p: &Progress) -> Result<()> {
        Err(Error::unsupported("7z"))
    }
}

pub struct SevenZWriter;

impl SevenZWriter {
    pub fn new(_file: std::fs::File, _opts: &CreateOptions) -> Result<Self> {
        Err(Error::unsupported("7z writing (in progress)"))
    }
}

impl ArchiveWriter for SevenZWriter {
    fn add(&mut self, _item: &Item, _data: Option<&mut dyn std::io::Read>, _p: &Progress) -> Result<()> {
        Err(Error::unsupported("7z"))
    }
    fn finish(self: Box<Self>, _p: &Progress) -> Result<()> {
        Err(Error::unsupported("7z"))
    }
}
