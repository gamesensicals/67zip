//! ISO 9660 images (read only). Implemented in a later stage.

use crate::archive::{ArchiveInfo, ArchiveReader, EntryVisitor, OpenOptions};
use crate::detect::ArchiveType;
use crate::entry::Entry;
use crate::error::{Error, Result};
use crate::io::ReadSeek;
use crate::progress::Progress;

pub struct IsoReader {
    entries: Vec<Entry>,
}

impl IsoReader {
    pub fn open(_src: Box<dyn ReadSeek>, _size: u64, _opts: &OpenOptions) -> Result<Self> {
        Err(Error::unsupported("ISO images (coming soon)"))
    }
}

impl ArchiveReader for IsoReader {
    fn archive_type(&self) -> ArchiveType {
        ArchiveType::ISO
    }
    fn entries(&self) -> &[Entry] {
        &self.entries
    }
    fn info(&self) -> ArchiveInfo {
        ArchiveInfo::default()
    }
    fn extract(&mut self, _s: &dyn Fn(&Entry) -> bool, _v: &mut dyn EntryVisitor, _p: &Progress) -> Result<()> {
        Err(Error::unsupported("ISO images"))
    }
}
