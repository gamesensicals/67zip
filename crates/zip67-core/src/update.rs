//! Changing existing archives: add, delete, rename, new folder.
//!
//! The archive is rewritten into a temporary file next to it, which then
//! replaces the original in one atomic rename, so a failure or a cancel
//! never leaves a half-written archive behind.

use std::collections::HashSet;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::archive::{open, EntryVisitor, OpenOptions};
use crate::create::{collect_items, new_writer, write_items, ArchiveWriter, AtomicOutput, CreateOptions, CreateReport, Item, Method};
use crate::detect::Container;
use crate::entry::{Entry, EntryKind};
use crate::error::{Error, Result};
use crate::limits::Limits;
use crate::password::Password;
use crate::progress::Progress;

#[derive(Clone, Debug)]
pub struct UpdateOptions {
    pub password: Option<Password>,
    /// Level for re-compressed data (default 5).
    pub level: Option<u32>,
    pub method: Option<Method>,
    pub threads: usize,
    pub follow_symlinks: bool,
    pub exclude: Vec<String>,
    pub limits: Limits,
}

impl Default for UpdateOptions {
    fn default() -> Self {
        UpdateOptions {
            password: None,
            level: None,
            method: None,
            threads: crate::util::default_threads(),
            follow_symlinks: false,
            exclude: Vec::new(),
            limits: Limits::default(),
        }
    }
}

/// A change to apply to an archive.
#[derive(Clone, Debug, Default)]
pub struct Changes {
    /// (file or folder on disk, folder inside the archive to put it in)
    pub add: Vec<(PathBuf, String)>,
    /// Archive paths to remove (folders recursively).
    pub delete: Vec<String>,
    /// (old archive path, new archive path); folders move with their content.
    pub rename: Vec<(String, String)>,
    /// Empty folders to create inside the archive.
    pub new_dirs: Vec<String>,
}

fn under(path: &str, dir: &str) -> bool {
    path == dir || (path.starts_with(dir) && path.as_bytes().get(dir.len()) == Some(&b'/'))
}

fn item_from_entry(e: &Entry, arcname: String) -> Item {
    Item {
        arcname,
        kind: e.kind,
        size: e.size,
        mtime: e.mtime.unwrap_or(0),
        mtime_nanos: e.mtime_nanos,
        mode: e.mode.unwrap_or(if e.kind == EntryKind::Dir { 0o755 } else { 0o644 }),
        uid: 0,
        gid: 0,
        link_target: e.link_target.clone(),
        source: None,
    }
}

struct Rewrite<'a> {
    writer: &'a mut dyn ArchiveWriter,
    renames: &'a [(String, String)],
    progress: &'a Progress,
}

impl Rewrite<'_> {
    fn new_name(&self, path: &str) -> String {
        for (old, new) in self.renames {
            let old = old.trim_matches('/');
            let new = new.trim_matches('/');
            if path == old {
                return new.to_string();
            }
            if under(path, old) {
                return format!("{new}{}", &path[old.len()..]);
            }
        }
        path.to_string()
    }
}

impl EntryVisitor for Rewrite<'_> {
    fn file(&mut self, entry: &Entry, data: &mut dyn Read) -> Result<()> {
        let item = item_from_entry(entry, self.new_name(&entry.path));
        self.writer.add(&item, Some(data), self.progress)
    }
    fn dir(&mut self, entry: &Entry) -> Result<()> {
        let item = item_from_entry(entry, self.new_name(&entry.path));
        self.writer.add(&item, None, self.progress)
    }
    fn symlink(&mut self, entry: &Entry, target: &str) -> Result<()> {
        let mut item = item_from_entry(entry, self.new_name(&entry.path));
        item.link_target = Some(target.to_string());
        self.writer.add(&item, None, self.progress)
    }
    fn hardlink(&mut self, entry: &Entry, target: &str) -> Result<()> {
        let mut item = item_from_entry(entry, self.new_name(&entry.path));
        item.link_target = Some(self.new_name(target));
        self.writer.add(&item, None, self.progress)
    }
}

/// Applies `changes` to the archive at `path`.
pub fn modify(path: &Path, changes: &Changes, opts: &UpdateOptions, progress: &Progress) -> Result<CreateReport> {
    let mut reader = open(path, &OpenOptions { password: opts.password.clone(), limits: opts.limits.clone(), ..Default::default() })?;
    let t = reader.archive_type();
    if !t.can_update() {
        return Err(Error::invalid(format!("{} files cannot be changed; extract and re-create them instead", t.display_name())));
    }
    let info = reader.info();
    if info.volumes > 1 {
        return Err(Error::invalid("split (multi-volume) archives cannot be changed"));
    }
    if (info.encrypted_data || info.encrypted_headers) && opts.password.is_none() {
        return Err(Error::PasswordRequired);
    }
    let mut report = CreateReport::default();
    let mut new_items = Vec::new();
    for (src, dir) in &changes.add {
        new_items.extend(collect_items(std::slice::from_ref(src), dir, opts.follow_symlinks, &opts.exclude, Some(path), &mut report.warnings)?);
    }
    for d in &changes.new_dirs {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
        new_items.push(Item {
            arcname: d.trim_matches('/').to_string(),
            kind: EntryKind::Dir,
            size: 0,
            mtime: now,
            mtime_nanos: 0,
            mode: 0o755,
            uid: 0,
            gid: 0,
            link_target: None,
            source: None,
        });
    }
    let replaced: HashSet<String> = new_items.iter().map(|i| i.arcname.clone()).collect();
    let deletes: Vec<String> = changes.delete.iter().map(|d| d.trim_matches('/').to_string()).collect();
    let keep = |e: &Entry| -> bool { !deletes.iter().any(|d| under(&e.path, d)) && !replaced.contains(&e.path) };

    // Same type and compression; old encryption settings are kept.
    let mut copts = CreateOptions {
        archive_type: t,
        level: opts.level.unwrap_or(5),
        method: opts.method,
        threads: opts.threads,
        password: opts.password.clone().filter(|_| info.encrypted_data || info.encrypted_headers || t.supports_encryption()),
        encrypt_names: info.encrypted_headers,
        ..Default::default()
    };
    if !(info.encrypted_data || info.encrypted_headers) {
        // Adding to an unencrypted archive keeps it unencrypted.
        copts.password = None;
    }
    if t.container == Container::SevenZ && copts.method.is_none() {
        if let Some(m) = info.methods.iter().find_map(|m| Method::from_name(m.split(':').next().unwrap_or(""))) {
            copts.method = Some(m);
        }
    }
    let kept_total: u64 = reader.entries().iter().filter(|e| keep(e)).map(|e| e.size).sum();
    progress.set_total(kept_total + new_items.iter().map(|i| i.size).sum::<u64>());

    let orig_perm = fs::metadata(path)?.permissions();
    let (out, file) = AtomicOutput::new(path)?;
    let mut writer = new_writer(file, &copts, None)?;
    {
        let mut rw = Rewrite { writer: writer.as_mut(), renames: &changes.rename, progress };
        reader.extract(&keep, &mut rw, progress)?;
    }
    drop(reader);
    write_items(writer.as_mut(), &new_items, progress, &mut report)?;
    writer.finish(progress)?;
    fs::set_permissions(&out.tmp, orig_perm)?;
    report.bytes_out = fs::metadata(&out.tmp)?.len();
    out.commit()?;
    report.outputs = vec![path.to_path_buf()];
    Ok(report)
}

/// Adds files to an archive, creating it if it does not exist yet.
pub fn add_files(archive: &Path, inputs: &[PathBuf], arc_dir: &str, create_opts: &CreateOptions, progress: &Progress) -> Result<CreateReport> {
    if !archive.exists() {
        if !arc_dir.is_empty() {
            return Err(Error::invalid("cannot add into a folder of an archive that does not exist"));
        }
        return crate::create::create(archive, inputs, create_opts, progress);
    }
    let changes = Changes { add: inputs.iter().map(|p| (p.clone(), arc_dir.to_string())).collect(), ..Default::default() };
    let opts = UpdateOptions {
        password: create_opts.password.clone(),
        level: Some(create_opts.level),
        method: create_opts.method,
        threads: create_opts.threads,
        follow_symlinks: create_opts.follow_symlinks,
        exclude: create_opts.exclude.clone(),
        limits: Limits::default(),
    };
    modify(archive, &changes, &opts, progress)
}
