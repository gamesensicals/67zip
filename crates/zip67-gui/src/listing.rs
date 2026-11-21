//! What the file list shows: folders on disk, or folders inside an archive.

use std::collections::{BTreeMap, HashMap};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use zip67_core::util::{has_hidden_chars, safe_display};
use zip67_core::{Entry, EntryKind};

use crate::icons::Icon;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Folder,
    Archive,
    Image,
    Audio,
    Video,
    Text,
    Code,
    Pdf,
    Exec,
    Link,
    Other,
}

impl Kind {
    pub fn icon(self) -> Icon {
        match self {
            Kind::Folder => Icon::Folder,
            Kind::Archive => Icon::Archive,
            Kind::Image => Icon::Image,
            Kind::Audio => Icon::Audio,
            Kind::Video => Icon::Video,
            Kind::Text => Icon::Text,
            Kind::Code => Icon::Code,
            Kind::Pdf => Icon::Pdf,
            Kind::Exec => Icon::Exec,
            Kind::Link => Icon::Link,
            Kind::Other => Icon::File,
        }
    }
}

pub fn kind_of(name: &str, is_dir: bool, exec: bool) -> Kind {
    if is_dir {
        return Kind::Folder;
    }
    if zip67_core::ArchiveType::from_file_name(name).is_some() {
        return Kind::Archive;
    }
    let ext = name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_default();
    match ext.as_str() {
        "png" | "jpg" | "jpeg" | "gif" | "webp" | "bmp" | "svg" | "tif" | "tiff" | "heic" | "avif" | "ico" => Kind::Image,
        "mp3" | "flac" | "ogg" | "opus" | "wav" | "m4a" | "aac" => Kind::Audio,
        "mp4" | "mkv" | "webm" | "avi" | "mov" | "m4v" => Kind::Video,
        "txt" | "md" | "log" | "csv" | "ini" | "cfg" | "conf" | "toml" | "yaml" | "yml" | "json" | "xml" | "rtf" => Kind::Text,
        "rs" | "c" | "h" | "cpp" | "hpp" | "py" | "js" | "ts" | "go" | "java" | "kt" | "sh" | "rb" | "php" | "html" | "css" | "lua" | "zig" => Kind::Code,
        "pdf" => Kind::Pdf,
        "exe" | "dll" | "so" | "appimage" | "bin" | "run" | "deb" | "rpm" => Kind::Exec,
        _ if exec => Kind::Exec,
        _ => Kind::Other,
    }
}

pub fn type_label(r: &Row) -> String {
    match r.kind {
        Kind::Folder => "Folder".into(),
        Kind::Link => "Link".into(),
        _ => match r.name.rsplit_once('.') {
            Some((stem, e)) if !stem.is_empty() && e.len() <= 8 => format!("{} file", e.to_ascii_uppercase()),
            _ => "File".into(),
        },
    }
}

/// One line of the file list.
#[derive(Clone, Debug)]
pub struct Row {
    pub name: String,
    /// Name made safe for display (control and direction characters escaped).
    pub display: String,
    pub suspicious: bool,
    pub kind: Kind,
    pub is_dir: bool,
    pub size: Option<u64>,
    pub packed: Option<u64>,
    pub mtime: Option<i64>,
    pub encrypted: bool,
    pub method: Option<String>,
    pub crc: Option<u32>,
    pub mode: Option<u32>,
    /// On-disk path (file system view).
    pub path: PathBuf,
    /// Path inside the archive (archive view).
    pub arc_path: String,
    /// Entry index (archive view; None for implicit folders).
    pub entry: Option<usize>,
    pub hidden: bool,
    pub link_target: Option<String>,
}

fn row(name: String) -> Row {
    let display = safe_display(&name);
    let suspicious = has_hidden_chars(&name);
    Row {
        hidden: name.starts_with('.'),
        name,
        display,
        suspicious,
        kind: Kind::Other,
        is_dir: false,
        size: None,
        packed: None,
        mtime: None,
        encrypted: false,
        method: None,
        crc: None,
        mode: None,
        path: PathBuf::new(),
        arc_path: String::new(),
        entry: None,
        link_target: None,
    }
}

pub fn list_dir(dir: &Path, show_hidden: bool) -> std::io::Result<Vec<Row>> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir)? {
        let Ok(e) = e else { continue };
        let name = e.file_name().to_string_lossy().into_owned();
        if !show_hidden && name.starts_with('.') {
            continue;
        }
        let path = e.path();
        let lmd = std::fs::symlink_metadata(&path);
        let md = std::fs::metadata(&path).or_else(|_| std::fs::symlink_metadata(&path));
        let mut r = row(name);
        if let Ok(m) = md {
            r.is_dir = m.is_dir();
            r.size = if m.is_dir() { None } else { Some(m.len()) };
            r.mtime = Some(m.mtime());
            r.mode = Some(m.mode() & 0o7777);
        }
        let is_link = lmd.map(|m| m.file_type().is_symlink()).unwrap_or(false);
        r.kind = kind_of(&r.name, r.is_dir, r.mode.is_some_and(|m| m & 0o111 != 0));
        if is_link {
            r.link_target = std::fs::read_link(&path).ok().map(|p| p.to_string_lossy().into_owned());
            if !r.is_dir {
                r.kind = Kind::Link;
            }
        }
        r.path = path;
        out.push(r);
    }
    Ok(out)
}

/// Folder structure of an archive, built from the flat entry list.
#[derive(Default, Debug)]
pub struct Tree {
    /// folder path ("" = root) -> child names -> (is_dir, entry index)
    pub dirs: HashMap<String, BTreeMap<String, (bool, Option<usize>)>>,
    /// folder path -> (total size, total packed, newest mtime)
    pub totals: HashMap<String, (u64, u64, Option<i64>)>,
    /// explicit folder entries
    pub dir_entries: HashMap<String, usize>,
}

impl Tree {
    pub fn build(entries: &[Entry]) -> Tree {
        let mut t = Tree::default();
        t.dirs.insert(String::new(), BTreeMap::new());
        for e in entries {
            if e.path.is_empty() {
                continue;
            }
            let parts: Vec<&str> = e.path.split('/').collect();
            let mut cur = String::new();
            for (i, p) in parts.iter().enumerate() {
                let last = i == parts.len() - 1;
                let child_path = if cur.is_empty() { (*p).to_string() } else { format!("{cur}/{p}") };
                let is_dir = !last || e.kind == EntryKind::Dir;
                let slot = t.dirs.entry(cur.clone()).or_default().entry((*p).to_string()).or_insert((is_dir, None));
                if last {
                    slot.1 = Some(e.index);
                    slot.0 = is_dir || slot.0;
                }
                if is_dir {
                    t.dirs.entry(child_path.clone()).or_default();
                    if last {
                        t.dir_entries.insert(child_path.clone(), e.index);
                    }
                }
                if !e.is_dir() {
                    let tot = t.totals.entry(cur.clone()).or_insert((0, 0, None));
                    tot.0 += e.size;
                    tot.1 += e.packed_size.unwrap_or(0);
                    tot.2 = tot.2.max(e.mtime);
                }
                cur = child_path;
            }
        }
        t
    }

    pub fn has_dir(&self, path: &str) -> bool {
        self.dirs.contains_key(path)
    }

    /// Rows for one folder of the archive.
    pub fn rows(&self, entries: &[Entry], folder: &str) -> Vec<Row> {
        let Some(children) = self.dirs.get(folder) else { return Vec::new() };
        let mut out = Vec::with_capacity(children.len());
        for (name, &(is_dir, idx)) in children {
            let arc_path = if folder.is_empty() { name.clone() } else { format!("{folder}/{name}") };
            let mut r = row(name.clone());
            r.is_dir = is_dir;
            r.arc_path = arc_path.clone();
            r.entry = idx;
            if let Some(e) = idx.and_then(|i| entries.get(i)) {
                r.mtime = e.mtime;
                r.encrypted = e.encrypted;
                r.method = e.method.clone();
                r.crc = e.crc32;
                r.mode = e.mode;
                r.link_target = e.link_target.clone();
                if !is_dir {
                    r.size = Some(e.size);
                    r.packed = e.packed_size;
                }
            }
            if is_dir {
                if let Some(&(s, p, m)) = self.totals.get(&arc_path) {
                    r.size = Some(s);
                    r.packed = if p > 0 { Some(p) } else { None };
                    if r.mtime.is_none() {
                        r.mtime = m;
                    }
                }
            }
            let link = idx.and_then(|i| entries.get(i)).is_some_and(|e| e.kind == EntryKind::Symlink);
            r.kind = if link { Kind::Link } else { kind_of(&r.name, is_dir, r.mode.is_some_and(|m| m & 0o111 != 0)) };
            out.push(r);
        }
        out
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SortKey {
    Name,
    Size,
    Packed,
    Modified,
    Type,
}

pub fn sort(rows: &mut [Row], key: SortKey, ascending: bool) {
    rows.sort_by(|a, b| {
        let dirs = b.is_dir.cmp(&a.is_dir);
        if dirs != std::cmp::Ordering::Equal {
            return dirs;
        }
        let ord = match key {
            SortKey::Name => natural_cmp(&a.name, &b.name),
            SortKey::Size => a.size.cmp(&b.size),
            SortKey::Packed => a.packed.cmp(&b.packed),
            SortKey::Modified => a.mtime.cmp(&b.mtime),
            SortKey::Type => type_label(a).cmp(&type_label(b)).then_with(|| natural_cmp(&a.name, &b.name)),
        };
        if ascending { ord } else { ord.reverse() }
    });
}

/// Case-insensitive comparison that orders "file2" before "file10".
pub fn natural_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let (mut ai, mut bi) = (a.chars().peekable(), b.chars().peekable());
    loop {
        match (ai.peek(), bi.peek()) {
            (None, None) => return a.cmp(b),
            (None, _) => return std::cmp::Ordering::Less,
            (_, None) => return std::cmp::Ordering::Greater,
            (Some(x), Some(y)) if x.is_ascii_digit() && y.is_ascii_digit() => {
                let mut na = String::new();
                while let Some(c) = ai.peek().filter(|c| c.is_ascii_digit()) {
                    na.push(*c);
                    ai.next();
                }
                let mut nb = String::new();
                while let Some(c) = bi.peek().filter(|c| c.is_ascii_digit()) {
                    nb.push(*c);
                    bi.next();
                }
                let o = na.trim_start_matches('0').len().cmp(&nb.trim_start_matches('0').len()).then_with(|| na.trim_start_matches('0').cmp(nb.trim_start_matches('0')));
                if o != std::cmp::Ordering::Equal {
                    return o;
                }
            }
            (Some(x), Some(y)) => {
                let o = x.to_lowercase().cmp(y.to_lowercase());
                if o != std::cmp::Ordering::Equal {
                    return o;
                }
                ai.next();
                bi.next();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn natural() {
        let mut v = vec!["file10", "File2", "file1", "a"];
        v.sort_by(|a, b| natural_cmp(a, b));
        assert_eq!(v, vec!["a", "file1", "File2", "file10"]);
    }

    #[test]
    fn tree_has_implicit_dirs() {
        let mut e = Entry::new(0, "a/b/c.txt".into(), EntryKind::File);
        e.size = 5;
        let t = Tree::build(&[e]);
        assert!(t.has_dir("a"));
        assert!(t.has_dir("a/b"));
        let rows = t.rows(&[Entry::new(0, "a/b/c.txt".into(), EntryKind::File)], "a");
        assert_eq!(rows[0].name, "b");
        assert!(rows[0].is_dir);
    }
}
