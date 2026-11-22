//! Safe extraction to a folder.
//!
//! Defences, in order:
//! 1. Entry paths are normalised; absolute paths and `..` are refused.
//! 2. Every file system call goes through a `cap_std::fs::Dir` handle for
//!    the destination, which resolves paths *beneath* that folder only, so
//!    symlinks (planted earlier by the same archive, or racing processes)
//!    cannot redirect writes outside of it.
//! 3. Symlinks whose target would point outside are not created.
//! 4. Device files, FIFOs, setuid/setgid bits are never created.
//! 5. Total size and expansion ratio are limited (decompression bombs).
//! 6. Partly written files are removed when an entry fails.

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cap_std::fs::{Dir, OpenOptions, PermissionsExt};
use serde::{Deserialize, Serialize};

use crate::archive::{ArchiveReader, EntryVisitor};
use crate::entry::{Entry, EntryKind};
use crate::error::{Error, Result};
use crate::limits::Limits;
use crate::progress::Progress;

/// How entry paths map to the destination.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PathMode {
    /// Keep the full folder structure.
    Full,
    /// Keep structure below `base` (the folder the user is looking at).
    Relative,
    /// Drop all folders; files land directly in the destination.
    Flat,
}

/// What to do when a file already exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Overwrite {
    Ask,
    Always,
    Skip,
    RenameNew,
    RenameExisting,
}

/// Answer to an overwrite question.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Answer {
    Yes,
    YesToAll,
    No,
    NoToAll,
    Rename,
    RenameAll,
    Cancel,
}

/// Asks the user about conflicts (GUI dialog, CLI prompt).
pub trait Prompt: Send {
    fn overwrite(&mut self, relative_path: &str, existing_size: u64, existing_mtime: Option<i64>, entry: &Entry) -> Answer;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExtractOptions {
    pub path_mode: PathMode,
    /// For [`PathMode::Relative`]: archive folder whose contents are extracted.
    pub base: String,
    pub overwrite: Overwrite,
    pub preserve_permissions: bool,
    pub preserve_mtime: bool,
    /// Keep files that failed their checksum (renamed `name.broken`).
    pub keep_broken: bool,
    pub limits: Limits,
}

impl Default for ExtractOptions {
    fn default() -> Self {
        ExtractOptions {
            path_mode: PathMode::Full,
            base: String::new(),
            overwrite: Overwrite::Ask,
            preserve_permissions: true,
            preserve_mtime: true,
            keep_broken: false,
            limits: Limits::default(),
        }
    }
}

/// Which entries to process.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub enum Selection {
    #[default]
    All,
    /// Entry indices.
    Indices(Vec<usize>),
    /// Archive paths; a folder path selects everything below it.
    Paths(Vec<String>),
    /// Wildcard patterns (`*`, `?`) matched against the full path or the name.
    Patterns(Vec<String>),
}

impl Selection {
    pub fn matcher(&self) -> Box<dyn Fn(&Entry) -> bool + Send + Sync> {
        match self {
            Selection::All => Box::new(|_| true),
            Selection::Indices(v) => {
                let set: HashSet<usize> = v.iter().copied().collect();
                Box::new(move |e| set.contains(&e.index))
            }
            Selection::Paths(p) => {
                let paths: Vec<String> = p.iter().map(|s| s.trim_matches('/').to_string()).collect();
                Box::new(move |e| {
                    paths.iter().any(|p| p.is_empty() || e.path == *p || (e.path.starts_with(p.as_str()) && e.path.as_bytes().get(p.len()) == Some(&b'/')))
                })
            }
            Selection::Patterns(p) => {
                let pats: Vec<String> = p.iter().map(|s| s.trim_matches('/').to_string()).collect();
                Box::new(move |e| {
                    pats.iter().any(|p| {
                        crate::create::wildcard_match(p, &e.path)
                            || crate::create::wildcard_match(p, e.name())
                            || (e.path.starts_with(p.as_str()) && e.path.as_bytes().get(p.len()) == Some(&b'/'))
                    })
                })
            }
        }
    }
}

/// Outcome of an extraction.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ExtractReport {
    pub files: u64,
    pub dirs: u64,
    pub links: u64,
    pub bytes: u64,
    pub skipped: u64,
    /// (entry path, problem)
    pub errors: Vec<(String, String)>,
    pub warnings: Vec<String>,
}

/// Splits a normalised entry path into safe components, or explains why
/// the path must not be used.
pub fn safe_components(path: &str) -> std::result::Result<Vec<&str>, String> {
    let mut out = Vec::new();
    for c in path.split('/') {
        match c {
            "" | "." => {}
            ".." => return Err("path contains '..'".into()),
            c if c.contains('\0') => return Err("path contains a NUL byte".into()),
            c => out.push(c),
        }
    }
    if out.is_empty() {
        return Err("empty path".into());
    }
    Ok(out)
}

/// Would a symlink at `link_rel` with this target stay inside the root?
pub fn symlink_stays_inside(link_rel: &[&str], target: &str) -> bool {
    if target.is_empty() || target.starts_with('/') || target.contains('\0') {
        return false;
    }
    let mut stack: Vec<&str> = link_rel[..link_rel.len().saturating_sub(1)].to_vec();
    for c in target.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                if stack.pop().is_none() {
                    return false;
                }
            }
            c => stack.push(c),
        }
    }
    true
}

/// Writes entries into a destination folder.
pub struct FsVisitor<'a> {
    root: Dir,
    opts: ExtractOptions,
    prompt: Option<&'a mut dyn Prompt>,
    report: ExtractReport,
    /// Overwrite policy after a "... to all" answer.
    sticky: Option<Overwrite>,
    /// Directories to stamp with their mtime at the end (deepest last).
    dir_times: Vec<(PathBuf, i64, u32, Option<u32>)>,
    /// archive path -> destination path, for hard links.
    written: HashMap<String, PathBuf>,
    archive_size: u64,
    total_written: u64,
    cancelled: bool,
    /// The user's umask: permissions from an archive never exceed what new
    /// files would get anyway (no world-writable files from a crafted
    /// archive), like tar and 7-Zip do for normal users.
    umask: u32,
    /// Destination on disk, for free-space checks while writing.
    dest: PathBuf,
    next_space_check: u64,
}

/// Extraction stops when less than this is left on the destination disk
/// (archives whose sizes are unknown, such as a bare .gz, could otherwise
/// fill it completely).
const MIN_FREE_SPACE: u64 = 256 << 20;

/// The process umask (read by setting and restoring it).
fn current_umask() -> u32 {
    use rustix::fs::Mode;
    let old = rustix::process::umask(Mode::from_raw_mode(0o022));
    rustix::process::umask(old);
    old.as_raw_mode() & 0o777
}

impl<'a> FsVisitor<'a> {
    pub fn new(dest: &Path, opts: ExtractOptions, prompt: Option<&'a mut dyn Prompt>, archive_size: u64) -> Result<Self> {
        std::fs::create_dir_all(dest)?;
        let root = Dir::open_ambient_dir(dest, cap_std::ambient_authority())?;
        Ok(FsVisitor {
            root,
            opts,
            prompt,
            report: ExtractReport::default(),
            sticky: None,
            dir_times: Vec::new(),
            written: HashMap::new(),
            archive_size,
            total_written: 0,
            cancelled: false,
            umask: current_umask(),
            dest: dest.to_path_buf(),
            next_space_check: 0,
        })
    }

    pub fn into_report(mut self) -> ExtractReport {
        self.apply_dir_times();
        self.report
    }

    /// Destination path (relative to the root) for an entry, or None to skip.
    fn target(&mut self, entry: &Entry) -> Result<Option<PathBuf>> {
        if entry.unsafe_path {
            return Err(Error::UnsafePath(entry.path.clone()));
        }
        let rel: &str = match self.opts.path_mode {
            PathMode::Full => &entry.path,
            PathMode::Flat => entry.name(),
            PathMode::Relative => {
                let base = self.opts.base.trim_matches('/');
                if base.is_empty() {
                    &entry.path
                } else if let Some(r) = entry.path.strip_prefix(base).and_then(|r| r.strip_prefix('/')) {
                    r
                } else {
                    return Ok(None);
                }
            }
        };
        let comps = safe_components(rel).map_err(|why| Error::UnsafePath(format!("{}: {why}", entry.path)))?;
        Ok(Some(comps.iter().collect()))
    }

    fn ensure_parent(&self, rel: &Path) -> Result<()> {
        if let Some(parent) = rel.parent() {
            if !parent.as_os_str().is_empty() {
                self.root.create_dir_all(parent)?;
            }
        }
        Ok(())
    }

    fn free_name(&self, rel: &Path) -> PathBuf {
        let parent = rel.parent().map(Path::to_path_buf).unwrap_or_default();
        let name = rel.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let (stem, ext) = match name.rfind('.') {
            Some(i) if i > 0 => (name[..i].to_string(), name[i..].to_string()),
            _ => (name.clone(), String::new()),
        };
        for i in 1..100_000 {
            let cand = parent.join(format!("{stem} ({i}){ext}"));
            if self.root.symlink_metadata(&cand).is_err() {
                return cand;
            }
        }
        parent.join(format!("{stem} (new){ext}"))
    }

    /// Resolves a name clash. Returns the path to write to, or None to skip.
    fn resolve_conflict(&mut self, rel: PathBuf, entry: &Entry) -> Result<Option<PathBuf>> {
        let Ok(md) = self.root.symlink_metadata(&rel) else { return Ok(Some(rel)) };
        if md.is_dir() {
            if entry.kind == EntryKind::Dir {
                return Ok(Some(rel));
            }
            return Err(Error::invalid(format!("a folder named {} already exists", rel.display())));
        }
        let mut policy = self.sticky.unwrap_or(self.opts.overwrite);
        if policy == Overwrite::Ask {
            let answer = match self.prompt.as_mut() {
                Some(p) => {
                    let mtime = md.modified().ok().and_then(|t| t.into_std().duration_since(UNIX_EPOCH).ok()).map(|d| d.as_secs() as i64);
                    p.overwrite(&rel.to_string_lossy(), md.len(), mtime, entry)
                }
                None => Answer::No,
            };
            policy = match answer {
                Answer::Yes => Overwrite::Always,
                Answer::YesToAll => {
                    self.sticky = Some(Overwrite::Always);
                    Overwrite::Always
                }
                Answer::No => Overwrite::Skip,
                Answer::NoToAll => {
                    self.sticky = Some(Overwrite::Skip);
                    Overwrite::Skip
                }
                Answer::Rename => Overwrite::RenameNew,
                Answer::RenameAll => {
                    self.sticky = Some(Overwrite::RenameNew);
                    Overwrite::RenameNew
                }
                Answer::Cancel => {
                    self.cancelled = true;
                    return Err(Error::Cancelled);
                }
            };
        }
        match policy {
            Overwrite::Skip | Overwrite::Ask => {
                self.report.skipped += 1;
                Ok(None)
            }
            Overwrite::Always => {
                // Remove the old file or link itself (never follow it).
                self.root.remove_file(&rel)?;
                Ok(Some(rel))
            }
            Overwrite::RenameNew => Ok(Some(self.free_name(&rel))),
            Overwrite::RenameExisting => {
                let old = self.free_name(&rel);
                self.root.rename(&rel, &self.root, &old)?;
                Ok(Some(rel))
            }
        }
    }

    fn check_limits(&mut self, more: u64) -> Result<()> {
        self.total_written += more;
        if self.total_written >= self.next_space_check {
            self.next_space_check = self.total_written + (64 << 20);
            if free_space(&self.dest).is_some_and(|f| f < MIN_FREE_SPACE) {
                return Err(Error::limit("the destination disk is almost full"));
            }
        }
        let l = &self.opts.limits;
        if self.total_written > l.max_total_size {
            return Err(Error::limit("extracted data exceeds the total size limit"));
        }
        if self.total_written > l.ratio_grace && self.archive_size > 0 && self.total_written / self.archive_size.max(1) > l.max_ratio {
            return Err(Error::limit("archive expands far more than real data does (decompression bomb?)"));
        }
        Ok(())
    }

    fn set_times(&self, rel: &Path, secs: i64, nanos: u32, is_dir: bool) {
        if !self.opts.preserve_mtime {
            return;
        }
        let Some(t) = system_time(secs, nanos) else { return };
        let f = if is_dir { self.root.open_dir(rel).map(Dir::into_std_file) } else { self.root.open_with(rel, OpenOptions::new().write(true)).map(cap_std::fs::File::into_std) };
        if let Ok(f) = f {
            let _ = f.set_times(std::fs::FileTimes::new().set_modified(t).set_accessed(t));
        }
    }

    fn apply_dir_times(&mut self) {
        let mut v = std::mem::take(&mut self.dir_times);
        v.sort_by_key(|(p, ..)| std::cmp::Reverse(p.components().count()));
        for (p, s, n, mode) in v {
            if let (Some(m), true) = (mode, self.opts.preserve_permissions) {
                // Always keep the owner able to enter and write the folder.
                let _ = self.root.set_permissions(&p, cap_std::fs::Permissions::from_mode(((m & 0o777) | 0o700) & !self.umask));
            }
            self.set_times(&p, s, n, true);
        }
    }
}

fn system_time(secs: i64, nanos: u32) -> Option<SystemTime> {
    if secs >= 0 {
        UNIX_EPOCH.checked_add(Duration::new(secs as u64, nanos.min(999_999_999)))
    } else {
        UNIX_EPOCH.checked_sub(Duration::from_secs(secs.unsigned_abs()))
    }
}

impl EntryVisitor for FsVisitor<'_> {
    fn file(&mut self, entry: &Entry, data: &mut dyn Read) -> Result<()> {
        let Some(rel) = self.target(entry)? else { return Ok(()) };
        self.ensure_parent(&rel)?;
        let Some(rel) = self.resolve_conflict(rel, entry)? else {
            crate::io::drain(data)?;
            return Ok(());
        };
        let mut f = self.root.open_with(&rel, OpenOptions::new().write(true).create_new(true))?;
        let mut buf = vec![0u8; crate::io::BUF_SIZE];
        let mut written = 0u64;
        let res: Result<()> = (|| {
            loop {
                let n = match data.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e.into()),
                };
                self.check_limits(n as u64)?;
                f.write_all(&buf[..n])?;
                written += n as u64;
            }
            Ok(())
        })();
        if let Err(e) = res {
            drop(f);
            if self.opts.keep_broken && matches!(e, Error::Checksum(_)) {
                let mut broken = rel.clone().into_os_string();
                broken.push(".broken");
                let _ = self.root.rename(&rel, &self.root, Path::new(&broken));
            } else {
                let _ = self.root.remove_file(&rel);
            }
            return Err(e);
        }
        if self.opts.preserve_permissions {
            if let Some(m) = entry.mode {
                // No setuid/setgid/sticky bits from untrusted archives.
                let _ = f.set_permissions(cap_std::fs::Permissions::from_mode(m & 0o777 & !self.umask));
            }
        }
        drop(f);
        if let Some(s) = entry.mtime {
            self.set_times(&rel, s, entry.mtime_nanos, false);
        }
        self.written.insert(entry.path.clone(), rel);
        self.report.files += 1;
        self.report.bytes += written;
        Ok(())
    }

    fn dir(&mut self, entry: &Entry) -> Result<()> {
        if self.opts.path_mode == PathMode::Flat {
            return Ok(());
        }
        let Some(rel) = self.target(entry)? else { return Ok(()) };
        if let Ok(md) = self.root.symlink_metadata(&rel) {
            if !md.is_dir() {
                return Err(Error::invalid(format!("{} exists and is not a folder", rel.display())));
            }
        } else {
            self.root.create_dir_all(&rel)?;
        }
        if let Some(s) = entry.mtime {
            self.dir_times.push((rel, s, entry.mtime_nanos, entry.mode));
        } else if entry.mode.is_some() {
            self.dir_times.push((rel, i64::MIN, 0, entry.mode));
        }
        self.report.dirs += 1;
        Ok(())
    }

    fn symlink(&mut self, entry: &Entry, target: &str) -> Result<()> {
        let Some(rel) = self.target(entry)? else { return Ok(()) };
        let comps: Vec<String> = rel.iter().map(|c| c.to_string_lossy().into_owned()).collect();
        let comp_refs: Vec<&str> = comps.iter().map(String::as_str).collect();
        if !symlink_stays_inside(&comp_refs, target) {
            let msg = format!("{}: symbolic link to '{target}' points outside the destination, not created", entry.path);
            self.report.warnings.push(msg);
            self.report.skipped += 1;
            return Ok(());
        }
        self.ensure_parent(&rel)?;
        let Some(rel) = self.resolve_conflict(rel, entry)? else { return Ok(()) };
        self.root.symlink(target, &rel)?;
        self.report.links += 1;
        Ok(())
    }

    fn hardlink(&mut self, entry: &Entry, target: &str) -> Result<()> {
        let Some(rel) = self.target(entry)? else { return Ok(()) };
        let (norm, unsafe_target) = crate::util::normalize_path(target);
        let Some(src) = self.written.get(&norm).cloned().filter(|_| !unsafe_target) else {
            self.report.warnings.push(format!("{}: hard link target '{target}' was not extracted, skipped", entry.path));
            self.report.skipped += 1;
            return Ok(());
        };
        self.ensure_parent(&rel)?;
        let Some(rel) = self.resolve_conflict(rel, entry)? else { return Ok(()) };
        self.root.hard_link(&src, &self.root, &rel)?;
        self.report.links += 1;
        Ok(())
    }

    fn entry_error(&mut self, entry: &Entry, err: Error) -> Result<()> {
        if matches!(err, Error::Cancelled | Error::LimitExceeded(_)) || self.cancelled {
            return Err(err);
        }
        self.report.errors.push((entry.path.clone(), err.to_string()));
        Ok(())
    }
}

/// Free bytes on the file system holding `path`.
pub fn free_space(path: &Path) -> Option<u64> {
    let st = rustix::fs::statvfs(path).ok()?;
    Some(st.f_bavail.saturating_mul(st.f_frsize))
}

/// Extracts the selected entries of an opened archive into `dest`.
pub fn extract_to(
    reader: &mut dyn ArchiveReader,
    dest: &Path,
    selection: &Selection,
    opts: &ExtractOptions,
    prompt: Option<&mut dyn Prompt>,
    progress: &Progress,
) -> Result<ExtractReport> {
    let matcher = selection.matcher();
    let selected: Vec<&Entry> = reader.entries().iter().filter(|e| matcher(e)).collect();
    let total: u64 = crate::util::total_size(selected.iter().map(|e| e.size));
    progress.set_total(total);
    progress.set_files_total(selected.len() as u64);
    let unsafe_count = selected.iter().filter(|e| e.unsafe_path).count();
    std::fs::create_dir_all(dest)?;
    if let Some(free) = free_space(dest) {
        if total > free {
            return Err(Error::invalid(format!(
                "not enough free space: {} needed, {} available",
                crate::util::human_size(total),
                crate::util::human_size(free)
            )));
        }
    }
    let size = reader.info().physical_size;
    let mut v = FsVisitor::new(dest, opts.clone(), prompt, size)?;
    let result = reader.extract(&*matcher, &mut v, progress);
    let mut report = v.into_report();
    report.warnings.extend(reader.info().problems);
    if unsafe_count > 0 {
        report.warnings.push(format!("{unsafe_count} entries with unsafe paths (absolute or '..') were not extracted"));
    }
    result?;
    Ok(report)
}

/// Checks the integrity of the selected entries without writing anything.
pub fn test(reader: &mut dyn ArchiveReader, selection: &Selection, progress: &Progress) -> Result<ExtractReport> {
    struct Tester {
        report: ExtractReport,
    }
    impl EntryVisitor for Tester {
        fn file(&mut self, _entry: &Entry, data: &mut dyn Read) -> Result<()> {
            let n = crate::io::drain(data)?;
            self.report.files += 1;
            self.report.bytes += n;
            Ok(())
        }
        fn dir(&mut self, _e: &Entry) -> Result<()> {
            self.report.dirs += 1;
            Ok(())
        }
        fn symlink(&mut self, _e: &Entry, _t: &str) -> Result<()> {
            self.report.links += 1;
            Ok(())
        }
        fn entry_error(&mut self, entry: &Entry, err: Error) -> Result<()> {
            if matches!(err, Error::Cancelled) {
                return Err(err);
            }
            self.report.errors.push((entry.path.clone(), err.to_string()));
            Ok(())
        }
    }
    let matcher = selection.matcher();
    let total: u64 = crate::util::total_size(reader.entries().iter().filter(|e| matcher(e)).map(|e| e.size));
    progress.set_total(total);
    let mut t = Tester { report: ExtractReport::default() };
    reader.extract(&*matcher, &mut t, progress)?;
    t.report.warnings.extend(reader.info().problems);
    Ok(t.report)
}

/// Collects one entry's content in memory (small previews only).
pub fn read_entry(reader: &mut dyn ArchiveReader, index: usize, max: u64, progress: &Progress) -> Result<Vec<u8>> {
    struct Grab {
        max: u64,
        out: Option<Vec<u8>>,
    }
    impl EntryVisitor for Grab {
        fn file(&mut self, _e: &Entry, data: &mut dyn Read) -> Result<()> {
            let mut v = Vec::new();
            data.take(self.max + 1).read_to_end(&mut v)?;
            if v.len() as u64 > self.max {
                return Err(Error::limit("file too large to preview"));
            }
            self.out = Some(v);
            Ok(())
        }
    }
    let mut g = Grab { max, out: None };
    reader.extract(&|e: &Entry| e.index == index, &mut g, progress)?;
    g.out.ok_or_else(|| Error::invalid("entry not found or not a file"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn components() {
        assert!(safe_components("a/../b").is_err());
        assert!(safe_components("").is_err());
        assert_eq!(safe_components("a/./b").unwrap(), vec!["a", "b"]);
    }

    #[test]
    fn symlink_escape() {
        assert!(symlink_stays_inside(&["a", "link"], "../b"));
        assert!(!symlink_stays_inside(&["a", "link"], "../../b"));
        assert!(!symlink_stays_inside(&["link"], "/etc/passwd"));
        assert!(symlink_stays_inside(&["link"], "x/y"));
    }
}
