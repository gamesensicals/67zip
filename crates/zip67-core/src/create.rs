//! Creating archives from files on disk.

use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::detect::{ArchiveType, Container};
use crate::entry::EntryKind;
use crate::error::{Error, Result};
use crate::io::Progressed;
use crate::password::Password;
use crate::progress::Progress;

/// One item to put into an archive.
#[derive(Clone, Debug)]
pub struct Item {
    /// Path inside the archive (`/`-separated, relative).
    pub arcname: String,
    pub kind: EntryKind,
    pub size: u64,
    pub mtime: i64,
    pub mtime_nanos: u32,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub link_target: Option<String>,
    /// Where to read the data from (files only).
    pub source: Option<PathBuf>,
}

/// Format-specific writer. Items are added in order, then `finish` writes
/// the index/trailer.
pub trait ArchiveWriter: Send {
    fn add(&mut self, item: &Item, data: Option<&mut dyn Read>, progress: &Progress) -> Result<()>;
    fn finish(self: Box<Self>, progress: &Progress) -> Result<()>;
}

/// Compression method for 7z and zip.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Method {
    Copy,
    Lzma2,
    Lzma,
    Ppmd,
    Bzip2,
    Deflate,
    Zstd,
    Xz,
}

impl Method {
    pub fn name(self) -> &'static str {
        match self {
            Method::Copy => "Store",
            Method::Lzma2 => "LZMA2",
            Method::Lzma => "LZMA",
            Method::Ppmd => "PPMd",
            Method::Bzip2 => "BZip2",
            Method::Deflate => "Deflate",
            Method::Zstd => "Zstandard",
            Method::Xz => "XZ",
        }
    }
    pub fn from_name(s: &str) -> Option<Self> {
        Some(match s.to_ascii_lowercase().as_str() {
            "copy" | "store" => Method::Copy,
            "lzma2" => Method::Lzma2,
            "lzma" => Method::Lzma,
            "ppmd" => Method::Ppmd,
            "bzip2" | "bz2" => Method::Bzip2,
            "deflate" => Method::Deflate,
            "zstd" | "zstandard" => Method::Zstd,
            "xz" => Method::Xz,
            _ => return None,
        })
    }
    /// Methods offered for an archive type, default first.
    pub fn for_type(t: ArchiveType) -> &'static [Method] {
        match t.container {
            Container::SevenZ => &[Method::Lzma2, Method::Lzma, Method::Ppmd, Method::Bzip2, Method::Deflate, Method::Copy],
            Container::Zip => &[Method::Deflate, Method::Bzip2, Method::Lzma, Method::Zstd, Method::Xz, Method::Copy],
            _ => &[],
        }
    }
}

/// Everything that controls how an archive is created.
#[derive(Clone, Debug)]
pub struct CreateOptions {
    pub archive_type: ArchiveType,
    /// 0 (store) ..= 9 (ultra), like 7-Zip.
    pub level: u32,
    pub method: Option<Method>,
    pub dict_size: Option<u32>,
    pub threads: usize,
    pub password: Option<Password>,
    /// 7z only: also encrypt the file list.
    pub encrypt_names: bool,
    pub solid: bool,
    /// Split the result into parts of this size.
    pub volume_size: Option<u64>,
    pub follow_symlinks: bool,
    /// Delete the source files after the archive was written successfully.
    pub delete_after: bool,
    /// With `delete_after`: overwrite the files with random data first
    /// (see [`crate::shred`]).
    pub shred: bool,
    /// Wildcard patterns of names to leave out (`*.o`, `.git`).
    pub exclude: Vec<String>,
    /// Total bytes that will be added, if known; lets multi-threaded
    /// encoders split the work evenly.
    pub size_hint: Option<u64>,
    /// Write the finished archive (and its parts) into this folder instead
    /// of next to the target, and leave `delete_after` to the caller via
    /// [`CreateReport::delete_later`]. The sandboxed worker uses this: it
    /// may only write to a private staging folder.
    pub out_dir: Option<PathBuf>,
}

impl Default for CreateOptions {
    fn default() -> Self {
        CreateOptions {
            archive_type: ArchiveType::SEVEN_Z,
            level: 5,
            method: None,
            dict_size: None,
            threads: crate::util::default_threads(),
            password: None,
            encrypt_names: false,
            solid: true,
            volume_size: None,
            follow_symlinks: false,
            delete_after: false,
            shred: false,
            exclude: Vec::new(),
            size_hint: None,
            out_dir: None,
        }
    }
}

impl CreateOptions {
    pub fn effective_method(&self) -> Method {
        if self.level == 0 {
            return Method::Copy;
        }
        self.method.unwrap_or(match self.archive_type.container {
            Container::Zip => Method::Deflate,
            _ => Method::Lzma2,
        })
    }
}

/// Result of a create/update operation.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CreateReport {
    pub files: u64,
    pub dirs: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub outputs: Vec<PathBuf>,
    pub warnings: Vec<String>,
    /// Sources to delete once the outputs are in place (`delete_after`
    /// with `out_dir`): files first, then folders deepest first.
    #[serde(default)]
    pub delete_later: Vec<PathBuf>,
}

/// Simple `*`/`?` wildcard match.
pub fn wildcard_match(pattern: &str, name: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let n: Vec<char> = name.chars().collect();
    let (mut pi, mut ni, mut star, mut mark) = (0, 0, None, 0);
    while ni < n.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == n[ni]) {
            pi += 1;
            ni += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ni;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ni = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

fn item_from_meta(path: &Path, arcname: String, md: &fs::Metadata, link: Option<String>) -> Item {
    let kind = if link.is_some() {
        EntryKind::Symlink
    } else if md.is_dir() {
        EntryKind::Dir
    } else {
        EntryKind::File
    };
    Item {
        arcname,
        kind,
        size: if kind == EntryKind::File { md.len() } else { 0 },
        mtime: md.mtime(),
        mtime_nanos: md.mtime_nsec().clamp(0, 999_999_999) as u32,
        mode: md.mode() & 0o7777,
        uid: md.uid(),
        gid: md.gid(),
        link_target: link,
        source: Some(path.to_path_buf()),
    }
}

/// Walks the inputs. Each input lands in the archive under its own name
/// (a folder `photos` becomes `photos/...`), prefixed with `arc_dir`.
pub fn collect_items(
    inputs: &[PathBuf],
    arc_dir: &str,
    follow_symlinks: bool,
    exclude: &[String],
    skip: Option<&Path>,
    warnings: &mut Vec<String>,
) -> Result<Vec<Item>> {
    let skip_id = skip.and_then(|p| fs::metadata(p).ok()).map(|m| (m.dev(), m.ino()));
    let mut items = Vec::new();
    let prefix = arc_dir.trim_matches('/');
    for input in inputs {
        let name = input
            .file_name()
            .and_then(|n| n.to_str())
            .map(str::to_string)
            .or_else(|| fs::canonicalize(input).ok().and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned())))
            .ok_or_else(|| Error::invalid(format!("cannot use {} as input", input.display())))?;
        let arc = if prefix.is_empty() { name } else { format!("{prefix}/{name}") };
        walk(input, arc, follow_symlinks, exclude, skip_id, &mut items, warnings, 0)?;
    }
    Ok(items)
}

#[allow(clippy::too_many_arguments)]
fn walk(
    path: &Path,
    arcname: String,
    follow: bool,
    exclude: &[String],
    skip_id: Option<(u64, u64)>,
    items: &mut Vec<Item>,
    warnings: &mut Vec<String>,
    depth: usize,
) -> Result<()> {
    if depth > 512 {
        warnings.push(format!("{}: folder nesting too deep, skipped", path.display()));
        return Ok(());
    }
    let name = arcname.rsplit('/').next().unwrap_or(&arcname);
    if exclude.iter().any(|p| wildcard_match(p, name)) {
        return Ok(());
    }
    let lmd = fs::symlink_metadata(path)?;
    let md = if follow && lmd.file_type().is_symlink() {
        match fs::metadata(path) {
            Ok(m) => m,
            Err(_) => lmd.clone(),
        }
    } else {
        lmd.clone()
    };
    if skip_id == Some((md.dev(), md.ino())) {
        return Ok(()); // never add the archive being written to itself
    }
    let ft = md.file_type();
    if ft.is_symlink() {
        let target = fs::read_link(path)?.to_string_lossy().into_owned();
        items.push(item_from_meta(path, arcname, &md, Some(target)));
    } else if ft.is_dir() {
        items.push(item_from_meta(path, arcname.clone(), &md, None));
        let mut children: Vec<_> = fs::read_dir(path)?.filter_map(|e| e.ok()).collect();
        children.sort_by_key(|e| e.file_name());
        for c in children {
            let cname = c.file_name().to_string_lossy().into_owned();
            walk(&c.path(), format!("{arcname}/{cname}"), follow, exclude, skip_id, items, warnings, depth + 1)?;
        }
    } else if ft.is_file() {
        items.push(item_from_meta(path, arcname, &md, None));
    } else {
        warnings.push(format!("{}: special file skipped", path.display()));
    }
    Ok(())
}

/// Creates the format writer for `opts` writing into `file`.
pub fn new_writer(file: File, opts: &CreateOptions, single_name: Option<&str>) -> Result<Box<dyn ArchiveWriter>> {
    let t = opts.archive_type;
    if opts.password.is_some() && !t.supports_encryption() {
        return Err(Error::invalid(format!("{} archives cannot be encrypted; use 7z or zip", t.display_name())));
    }
    let threads = opts.threads.max(1);
    Ok(match t.container {
        Container::Zip => Box::new(crate::formats::zip::ZipWriter::new(
            std::io::BufWriter::with_capacity(256 * 1024, file),
            opts.effective_method(),
            opts.level,
            threads,
            opts.password.clone(),
        )?),
        Container::Tar => Box::new(crate::formats::tar::TarWriter::new(file, t.compression, opts.level, threads, opts.size_hint)?),
        Container::Raw => Box::new(crate::formats::raw::RawWriter::new(file, t.compression, opts.level, threads, single_name, opts.size_hint)?),
        Container::SevenZ => Box::new(crate::formats::sevenz::SevenZWriter::new(file, opts)?),
        Container::Iso => return Err(Error::invalid("ISO images can only be read")),
        Container::Rar => return Err(Error::invalid("RAR archives can only be read")),
    })
}

/// A temporary file next to `target`, renamed over it on success.
pub struct AtomicOutput {
    pub tmp: PathBuf,
    pub target: PathBuf,
    done: bool,
}

impl AtomicOutput {
    pub fn new(target: &Path) -> Result<(Self, File)> {
        let dir = target.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
        let name = target.file_name().and_then(|n| n.to_str()).unwrap_or("archive");
        let mut rnd = [0u8; 6];
        getrandom::fill(&mut rnd).map_err(|_| Error::invalid("no random source"))?;
        let suffix: String = rnd.iter().map(|b| format!("{b:02x}")).collect();
        let tmp = dir.join(format!(".{name}.{suffix}.67tmp"));
        let f = fs::OpenOptions::new().write(true).read(true).create_new(true).open(&tmp)?;
        Ok((AtomicOutput { tmp, target: target.to_path_buf(), done: false }, f))
    }
    pub fn commit(mut self) -> Result<()> {
        fs::rename(&self.tmp, &self.target)?;
        self.done = true;
        Ok(())
    }
}

impl Drop for AtomicOutput {
    fn drop(&mut self) {
        if !self.done {
            let _ = fs::remove_file(&self.tmp);
        }
    }
}

/// Writes `items` (already collected) with `writer`, reading file data.
pub fn write_items(writer: &mut dyn ArchiveWriter, items: &[Item], progress: &Progress, report: &mut CreateReport) -> Result<()> {
    for item in items {
        progress.check()?;
        progress.set_current(&item.arcname);
        match item.kind {
            EntryKind::File => {
                let src = item.source.as_ref().ok_or_else(|| Error::invalid("missing source"))?;
                let f = match File::open(src) {
                    Ok(f) => f,
                    Err(e) => {
                        let msg = format!("{}: {e}", src.display());
                        progress.warn(msg.clone());
                        report.warnings.push(msg);
                        continue;
                    }
                };
                let mut r = BufReader::with_capacity(256 * 1024, f);
                writer.add(item, Some(&mut r), progress)?;
                report.files += 1;
                report.bytes_in += item.size;
            }
            EntryKind::Dir => {
                writer.add(item, None, progress)?;
                report.dirs += 1;
            }
            _ => {
                writer.add(item, None, progress)?;
                report.files += 1;
            }
        }
        progress.file_done();
    }
    Ok(())
}

/// Creates a new archive at `output` from `inputs`. Fails if `output`
/// exists (use [`crate::update::add_files`] to add to an archive).
pub fn create(output: &Path, inputs: &[PathBuf], opts: &CreateOptions, progress: &Progress) -> Result<CreateReport> {
    if output.exists() {
        return Err(Error::invalid(format!("{} already exists", output.display())));
    }
    let mut report = CreateReport::default();
    let items = collect_items(inputs, "", opts.follow_symlinks, &opts.exclude, Some(output), &mut report.warnings)?;
    if !opts.archive_type.holds_many_files() {
        let files: Vec<&Item> = items.iter().filter(|i| i.kind == EntryKind::File).collect();
        if files.len() != 1 || items.len() != 1 {
            return Err(Error::invalid(format!(
                "{} compresses exactly one file; choose tar.{} to pack several files or folders",
                opts.archive_type.display_name(),
                opts.archive_type.compression.suffix()
            )));
        }
    }
    let total: u64 = items.iter().map(|i| i.size).sum();
    progress.set_total(total);
    progress.set_files_total(items.len() as u64);
    let target = staged_path(output, opts.out_dir.as_deref());
    let (out, file) = AtomicOutput::new(&target)?;
    let single = items.first().map(|i| i.arcname.clone());
    let opts = CreateOptions { size_hint: opts.size_hint.or(Some(total)), ..opts.clone() };
    let mut writer = new_writer(file, &opts, single.as_deref())?;
    write_items(writer.as_mut(), &items, progress, &mut report)?;
    writer.finish(progress)?;
    let tmp_len = fs::metadata(&out.tmp)?.len();
    report.bytes_out = tmp_len;
    out.commit()?;
    report.outputs = vec![target.clone()];
    if let Some(vs) = opts.volume_size {
        if vs > 0 && tmp_len > vs {
            report.outputs = crate::split::split_file(&target, vs, progress)?;
            fs::remove_file(&target)?;
        }
    }
    if opts.delete_after {
        if opts.out_dir.is_some() {
            report.delete_later = sources_to_delete(&items);
        } else {
            delete_sources(&items, opts.shred, &mut report);
        }
    }
    Ok(report)
}

/// Deletes (or securely deletes) one source file. Returns warnings; for
/// secure deletion also one per distinct reason it may not be reliable
/// (`seen` keeps the reasons already reported).
pub fn delete_one(src: &Path, shred: bool, seen: &mut Vec<String>) -> Vec<String> {
    let mut w = Vec::new();
    if !shred {
        if let Err(e) = fs::remove_file(src) {
            w.push(format!("could not delete {}: {e}", src.display()));
        }
        return w;
    }
    let why = src.parent().filter(|p| !p.as_os_str().is_empty()).and_then(crate::shred::reliability);
    match crate::shred::shred_file(src) {
        Ok(crate::shred::Shredded::Kept(reason)) => w.push(format!("{} not deleted: {reason}", src.display())),
        Ok(_) => {}
        Err(e) => w.push(format!("could not securely delete {}: {e}", src.display())),
    }
    if let Some(why) = why
        && !seen.contains(&why)
    {
        w.push(format!("Secure deletion may not be complete for files like {}: {why}. Full-disk encryption protects against this.", src.display()));
        seen.push(why);
    }
    w
}

/// Where the archive for `output` is written: in `out_dir` when given.
pub fn staged_path(output: &Path, out_dir: Option<&Path>) -> PathBuf {
    match (out_dir, output.file_name()) {
        (Some(d), Some(name)) => d.join(name),
        _ => output.to_path_buf(),
    }
}

fn sources_to_delete(items: &[Item]) -> Vec<PathBuf> {
    let files = items.iter().filter(|i| i.kind != EntryKind::Dir).filter_map(|i| i.source.clone());
    let dirs = items.iter().rev().filter(|i| i.kind == EntryKind::Dir).filter_map(|i| i.source.clone());
    files.chain(dirs).collect()
}

fn delete_sources(items: &[Item], shred: bool, report: &mut CreateReport) {
    let mut seen = Vec::new();
    for item in items.iter().filter(|i| i.kind != EntryKind::Dir) {
        if let Some(src) = &item.source {
            report.warnings.extend(delete_one(src, shred, &mut seen));
        }
    }
    // Then empty folders, deepest first.
    for item in items.iter().rev().filter(|i| i.kind == EntryKind::Dir) {
        if let Some(src) = &item.source {
            let _ = fs::remove_dir(src);
        }
    }
}

/// Reads all of `r` through progress accounting into `w` (used by writers).
pub fn pump(r: &mut dyn Read, w: &mut dyn std::io::Write, progress: &Progress) -> Result<u64> {
    let mut p = Progressed::new(r, progress);
    crate::io::copy_checked(&mut p, w, &Progress::new())
}

#[cfg(test)]
mod tests {
    use super::wildcard_match;

    #[test]
    fn wildcards() {
        assert!(wildcard_match("*.o", "main.o"));
        assert!(!wildcard_match("*.o", "main.c"));
        assert!(wildcard_match("a?c*", "abcdef"));
        assert!(wildcard_match(".git", ".git"));
    }
}
