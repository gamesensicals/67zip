//! Messages between the GUI (client) and the worker, as JSON lines.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use zip67_core::archive::ArchiveInfo;
use zip67_core::create::{CreateReport, Method};
use zip67_core::extract::{Answer, ExtractOptions, ExtractReport, Selection};
use zip67_core::hash::HashKind;
use zip67_core::progress::Snapshot;
use zip67_core::Entry;

use crate::sandbox::SandboxStatus;

/// How to create an archive (serialisable mirror of `CreateOptions`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateSpec {
    pub archive_type: String,
    pub level: u32,
    pub method: Option<Method>,
    pub dict_size: Option<u32>,
    pub threads: usize,
    pub password: Option<String>,
    pub encrypt_names: bool,
    pub solid: bool,
    pub volume_size: Option<u64>,
    pub follow_symlinks: bool,
    pub delete_after: bool,
    /// With `delete_after`: overwrite the files with random data first.
    #[serde(default)]
    pub shred: bool,
    pub exclude: Vec<String>,
}

impl Default for CreateSpec {
    fn default() -> Self {
        CreateSpec {
            archive_type: "7z".into(),
            level: 5,
            method: None,
            dict_size: None,
            threads: 0,
            password: None,
            encrypt_names: false,
            solid: true,
            volume_size: None,
            follow_symlinks: false,
            delete_after: false,
            shred: false,
            exclude: Vec::new(),
        }
    }
}

impl CreateSpec {
    pub fn to_options(&self) -> zip67_core::Result<zip67_core::create::CreateOptions> {
        let t = zip67_core::ArchiveType::from_id(&self.archive_type)
            .ok_or_else(|| zip67_core::Error::invalid(format!("unknown archive type {}", self.archive_type)))?;
        Ok(zip67_core::create::CreateOptions {
            archive_type: t,
            level: self.level.min(9),
            method: self.method,
            dict_size: self.dict_size,
            threads: if self.threads == 0 { zip67_core::util::default_threads() } else { self.threads },
            password: self.password.clone().filter(|p| !p.is_empty()).map(zip67_core::Password::new),
            encrypt_names: self.encrypt_names,
            solid: self.solid,
            volume_size: self.volume_size,
            follow_symlinks: self.follow_symlinks,
            delete_after: self.delete_after,
            shred: self.shred,
            exclude: self.exclude.clone(),
            size_hint: None,
            out_dir: None,
        })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ChangesSpec {
    pub add: Vec<(PathBuf, String)>,
    pub delete: Vec<String>,
    pub rename: Vec<(String, String)>,
    pub new_dirs: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Request {
    List { archive: PathBuf, password: Option<String> },
    Extract { archive: PathBuf, password: Option<String>, dest: PathBuf, selection: Selection, options: ExtractOptions },
    Test { archive: PathBuf, password: Option<String>, selection: Selection },
    Create { output: PathBuf, inputs: Vec<PathBuf>, spec: CreateSpec },
    AddFiles { archive: PathBuf, inputs: Vec<PathBuf>, arc_dir: String, spec: CreateSpec },
    Update { archive: PathBuf, password: Option<String>, changes: ChangesSpec, level: Option<u32>, threads: usize },
    Hash { paths: Vec<PathBuf>, kinds: Vec<HashKind> },
    Benchmark { seconds: u32, threads: usize, dict_size: u32 },
}

/// What the client sends first: the request, and for requests that write
/// an archive, the private staging folder the worker may write into (the
/// client moves the result into place after checking it).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Job {
    pub request: Request,
    #[serde(default)]
    pub stage: Option<PathBuf>,
}

/// Messages from the client after the request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Control {
    Cancel,
    Pause,
    Resume,
    Answer(Answer),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Question {
    pub path: String,
    pub existing_size: u64,
    pub existing_mtime: Option<i64>,
    pub new_size: u64,
    pub new_mtime: Option<i64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HashResult {
    pub path: PathBuf,
    pub size: u64,
    pub values: Vec<(HashKind, String)>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Reply {
    Listing { archive_type: String, entries: Vec<Entry>, info: ArchiveInfo },
    Extracted(ExtractReport),
    Tested(ExtractReport),
    Created(CreateReport),
    Hashes(Vec<HashResult>),
    Benchmark(Vec<zip67_core::bench::BenchResult>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FailKind {
    PasswordRequired,
    WrongPassword,
    Cancelled,
    Unsupported,
    Corrupt,
    Limit,
    UnsafePath,
    Io,
    Invalid,
    WorkerCrashed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Failure {
    pub kind: FailKind,
    pub message: String,
}

impl From<&zip67_core::Error> for Failure {
    fn from(e: &zip67_core::Error) -> Self {
        use zip67_core::Error as E;
        let kind = match e {
            E::PasswordRequired => FailKind::PasswordRequired,
            E::WrongPassword => FailKind::WrongPassword,
            E::Cancelled => FailKind::Cancelled,
            E::Unsupported(_) | E::UnsupportedFormat => FailKind::Unsupported,
            E::Corrupt(_) | E::Checksum(_) => FailKind::Corrupt,
            E::LimitExceeded(_) => FailKind::Limit,
            E::UnsafePath(_) => FailKind::UnsafePath,
            E::Io(_) => FailKind::Io,
            E::InvalidInput(_) => FailKind::Invalid,
        };
        Failure { kind, message: e.to_string() }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Event {
    Hello { version: String, sandbox: SandboxStatus },
    Progress(Snapshot),
    Ask(Question),
    Done(Reply),
    Failed(Failure),
}
