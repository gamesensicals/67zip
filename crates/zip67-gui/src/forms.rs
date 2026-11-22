//! Dialog forms and the choices they offer.

use std::fmt;
use std::path::PathBuf;

use zip67_core::create::Method;
use zip67_core::extract::{Overwrite, PathMode, Selection};
use zip67_core::hash::HashKind;
use zip67_worker::protocol::{HashResult, Question, Request};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Format(pub &'static str);

pub const FORMATS: [Format; 11] = [
    Format("7z"),
    Format("zip"),
    Format("tar"),
    Format("tar.gz"),
    Format("tar.xz"),
    Format("tar.bz2"),
    Format("tar.zst"),
    Format("gz"),
    Format("xz"),
    Format("bz2"),
    Format("zst"),
];

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let t = zip67_core::ArchiveType::from_id(self.0).map(|t| t.display_name()).unwrap_or_default();
        write!(f, "{t}  (.{})", self.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Level(pub u32);
pub const LEVELS: [Level; 6] = [Level(0), Level(1), Level(3), Level(5), Level(7), Level(9)];
impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let n = match self.0 {
            0 => "Store (no compression)",
            1 => "Fastest",
            3 => "Fast",
            5 => "Normal",
            7 => "Maximum",
            _ => "Ultra",
        };
        f.write_str(n)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MethodChoice(pub Option<Method>);
impl fmt::Display for MethodChoice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            None => f.write_str("Default"),
            Some(m) => f.write_str(m.name()),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Volume(pub Option<u64>, pub &'static str);
pub const VOLUMES: [Volume; 6] = [
    Volume(None, "Don't split"),
    Volume(Some(10 << 20), "10 MB"),
    Volume(Some(100 << 20), "100 MB"),
    Volume(Some(700 << 20), "700 MB (CD)"),
    Volume(Some(4092 << 20), "4 GB (FAT32)"),
    Volume(Some(4480 << 20), "4.4 GB (DVD)"),
];
impl fmt::Display for Volume {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.1)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PathChoice(pub PathMode);
pub const PATH_MODES: [PathChoice; 2] = [PathChoice(PathMode::Full), PathChoice(PathMode::Flat)];
impl fmt::Display for PathChoice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.0 {
            PathMode::Full | PathMode::Relative => "Keep folders",
            PathMode::Flat => "All files into one folder",
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OverwriteChoice(pub Overwrite);
pub const OVERWRITES: [OverwriteChoice; 5] = [
    OverwriteChoice(Overwrite::Ask),
    OverwriteChoice(Overwrite::Always),
    OverwriteChoice(Overwrite::Skip),
    OverwriteChoice(Overwrite::RenameNew),
    OverwriteChoice(Overwrite::RenameExisting),
];
impl fmt::Display for OverwriteChoice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.0 {
            Overwrite::Ask => "Ask me",
            Overwrite::Always => "Overwrite",
            Overwrite::Skip => "Skip existing files",
            Overwrite::RenameNew => "Rename new files",
            Overwrite::RenameExisting => "Rename existing files",
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Choice<T: Copy + 'static>(pub T, pub &'static str);
impl<T: Copy> fmt::Display for Choice<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.1)
    }
}

/// Where new files go when adding.
#[derive(Clone, Debug)]
pub struct AddInto {
    pub archive: PathBuf,
    pub folder: String,
    pub password: Option<String>,
}

#[derive(Clone, Debug)]
pub struct AddForm {
    pub sources: Vec<PathBuf>,
    pub into: Option<AddInto>,
    pub archive: String,
    pub format: Format,
    pub level: Level,
    pub method: MethodChoice,
    pub password: String,
    pub password2: String,
    pub show_password: bool,
    pub encrypt_names: bool,
    pub solid: bool,
    pub volume: Volume,
    pub delete_after: bool,
    pub shred: bool,
    pub exclude: String,
    pub error: Option<String>,
}

impl AddForm {
    pub fn methods(&self) -> Vec<MethodChoice> {
        let t = zip67_core::ArchiveType::from_id(self.format.0).unwrap_or(zip67_core::ArchiveType::SEVEN_Z);
        let mut v = vec![MethodChoice(None)];
        v.extend(Method::for_type(t).iter().map(|m| MethodChoice(Some(*m))));
        v
    }
    pub fn encryptable(&self) -> bool {
        matches!(self.format.0, "7z" | "zip")
    }
}

#[derive(Clone, Debug)]
pub struct ExtractForm {
    /// Archives on disk to extract (file-system view) ...
    pub archives: Vec<PathBuf>,
    /// ... or the open archive with a selection.
    pub selection: Option<(PathBuf, Selection, String)>,
    pub dest: String,
    pub subfolder: bool,
    pub path_mode: PathChoice,
    pub overwrite: OverwriteChoice,
    pub password: String,
    pub show_password: bool,
    pub error: Option<String>,
}

#[derive(Clone, Debug)]
pub enum PendingAction {
    DeleteFs(Vec<PathBuf>, bool),
    DeleteInArchive(Vec<String>),
    UpdateModified { temp: PathBuf, archive: PathBuf, folder: String },
    AddDropped(Vec<PathBuf>),
}

#[derive(Clone, Debug)]
pub enum InputAction {
    RenameFs(PathBuf),
    RenameInArchive(String),
    NewFolderFs,
    NewFolderInArchive,
    CopyTo(Vec<PathBuf>),
    MoveTo(Vec<PathBuf>),
    ArchiveCopyTo,
}

#[derive(Clone, Debug)]
pub struct ReportView {
    pub title: String,
    pub summary: String,
    pub lines: Vec<String>,
    pub ok: bool,
}

#[derive(Clone, Debug)]
pub enum Modal {
    Add(AddForm),
    Extract(ExtractForm),
    Password { prompt: String, value: String, show: bool, retry: Box<Request>, purpose: Box<crate::app::Purpose>, title: String },
    Overwrite(Question),
    Confirm { title: String, text: String, ok: String, danger: bool, action: PendingAction },
    Input { title: String, label: String, value: String, action: InputAction, error: Option<String> },
    Report(ReportView),
    Properties { title: String, lines: Vec<(String, String)>, warning: Option<String> },
    Hashes(Vec<HashResult>, Vec<HashKind>),
    Bench(Option<Vec<zip67_core::bench::BenchResult>>),
    Settings,
    About,
}
