//! Desktop integration: places, opening files with their default app,
//! private temporary folders, and the freedesktop.org Trash.

use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};

use crate::icons::Icon;

pub fn home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
}

/// Reads `XDG_*_DIR` entries from `~/.config/user-dirs.dirs`.
fn user_dir(key: &str, fallback: &str) -> PathBuf {
    let h = home();
    let cfg = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| h.join(".config"));
    if let Ok(s) = std::fs::read_to_string(cfg.join("user-dirs.dirs")) {
        for line in s.lines() {
            if let Some(v) = line.strip_prefix(&format!("{key}=")) {
                let v = v
                    .trim()
                    .trim_matches('"')
                    .replace("$HOME", &h.to_string_lossy());
                return PathBuf::from(v);
            }
        }
    }
    h.join(fallback)
}

pub fn places() -> Vec<(String, PathBuf, Icon)> {
    let mut v = vec![("Home".to_string(), home(), Icon::Home)];
    for (key, fb, name, icon) in [
        ("XDG_DESKTOP_DIR", "Desktop", "Desktop", Icon::Desktop),
        (
            "XDG_DOCUMENTS_DIR",
            "Documents",
            "Documents",
            Icon::Documents,
        ),
        (
            "XDG_DOWNLOAD_DIR",
            "Downloads",
            "Downloads",
            Icon::Downloads,
        ),
        ("XDG_PICTURES_DIR", "Pictures", "Pictures", Icon::Pictures),
        ("XDG_MUSIC_DIR", "Music", "Music", Icon::Music),
    ] {
        let p = user_dir(key, fb);
        if p.is_dir() && p != home() {
            v.push((name.to_string(), p, icon));
        }
    }
    v.push(("File system".to_string(), PathBuf::from("/"), Icon::Drive));
    v
}

/// Desktop launchers: opening one may run any command it names.
pub fn is_launcher(path: &Path) -> bool {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    [".desktop", ".kdelnk", ".directory"]
        .iter()
        .any(|e| name.ends_with(e))
}

/// Opens a file with the desktop's default application.
pub fn open_with_default(path: &Path) -> std::io::Result<()> {
    for cmd in ["xdg-open", "gio"] {
        let mut c = std::process::Command::new(cmd);
        if cmd == "gio" {
            c.arg("open");
        }
        c.arg(path)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        if c.spawn().is_ok() {
            return Ok(());
        }
    }
    Err(std::io::Error::other(
        "no program found to open files (install xdg-utils)",
    ))
}

/// Private temporary folder of this process: `$XDG_RUNTIME_DIR/67zip/<pid>`
/// (or `/tmp/67zip-<uid>/<pid>`), mode 0700. Leftovers of processes that no
/// longer run are removed. A shared folder such as /tmp is only used when
/// the `67zip-<uid>` folder there is really ours: owned by this user, a
/// real directory (not a link) and closed to others; otherwise a fresh
/// folder with an unpredictable name is created.
pub fn temp_base() -> PathBuf {
    let uid = rustix::process::getuid().as_raw();
    let root = match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(r) if private_dir(&PathBuf::from(&r), uid) => PathBuf::from(r).join("67zip"),
        _ => std::env::temp_dir().join(format!("67zip-{uid}")),
    };
    let _ = std::fs::DirBuilder::new().mode(0o700).create(&root);
    let root = if private_dir(&root, uid) {
        root
    } else {
        fresh_private_dir()
    };
    if let Ok(rd) = std::fs::read_dir(&root) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if let Ok(pid) = name.parse::<u32>()
                && !Path::new(&format!("/proc/{pid}")).exists()
            {
                // Files left by a session that ended: overwrite, then delete.
                let _ = zip67_core::shred::shred_tree(&e.path());
            }
        }
    }
    let mine = root.join(std::process::id().to_string());
    let _ = zip67_core::shred::shred_tree(&mine);
    let _ = OWN_TEMP.set(mine.clone());
    let _ = std::fs::DirBuilder::new().mode(0o700).create(&mine);
    mine
}

static OWN_TEMP: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// Overwrites and deletes this session's temporary files (decrypted copies
/// of files opened from archives). Called when the app closes.
pub fn wipe_own_temp() {
    if let Some(t) = OWN_TEMP.get() {
        let _ = zip67_core::shred::shred_tree(t);
    }
}

/// True when temporary copies live in memory (tmpfs) rather than on a disk.
pub fn temp_in_memory() -> bool {
    OWN_TEMP
        .get()
        .is_some_and(|t| zip67_core::shred::in_memory(t))
}

/// A directory owned by `uid`, not a symbolic link, closed to others.
fn private_dir(p: &Path, uid: u32) -> bool {
    std::fs::symlink_metadata(p)
        .is_ok_and(|m| m.is_dir() && m.uid() == uid && m.mode() & 0o077 == 0)
}

/// A new directory with a random name in the system temp folder (created
/// here, so nobody else can own it).
fn fresh_private_dir() -> PathBuf {
    loop {
        let p = std::env::temp_dir().join(format!("67zip-{}", zip67_core::util::random_hex(12)));
        if std::fs::DirBuilder::new().mode(0o700).create(&p).is_ok() {
            return p;
        }
    }
}

pub fn new_temp_dir(base: &Path) -> PathBuf {
    loop {
        let p = base.join(zip67_core::util::random_hex(8));
        if std::fs::DirBuilder::new().mode(0o700).create(&p).is_ok() || !base.is_dir() {
            return p;
        }
    }
}

fn url_encode(p: &str) -> String {
    let mut out = String::new();
    for b in p.bytes() {
        if b.is_ascii_alphanumeric() || b"/-_.~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Moves `path` into the user's Trash (freedesktop.org Trash spec), so a
/// delete can be undone from any file manager.
pub fn move_to_trash(path: &Path) -> std::io::Result<()> {
    let data = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home().join(".local/share"));
    let trash = data.join("Trash");
    let (files, info) = (trash.join("files"), trash.join("info"));
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&files)?;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&info)?;
    // Only on the same file system as the home trash; otherwise refuse
    // rather than copying (the caller then offers a permanent delete).
    let dev_item = std::fs::symlink_metadata(path)?.dev();
    let dev_trash = std::fs::metadata(&files)?.dev();
    if dev_item != dev_trash {
        return Err(std::io::Error::other(
            "the item is on another drive, so it cannot go to the Trash",
        ));
    }
    let abs = std::fs::canonicalize(path.parent().unwrap_or(Path::new("/")))?
        .join(path.file_name().unwrap_or_default());
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "item".into());
    let mut candidate = name.clone();
    let mut i = 1;
    loop {
        let info_path = info.join(format!("{candidate}.trashinfo"));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&info_path)
        {
            Ok(mut f) => {
                use std::io::Write;
                let date = jiff::Timestamp::now()
                    .to_zoned_datetime(jiff::tz::TimeZone::system())
                    .strftime("%Y-%m-%dT%H:%M:%S")
                    .to_string();
                writeln!(
                    f,
                    "[Trash Info]\nPath={}\nDeletionDate={date}",
                    url_encode(&abs.to_string_lossy())
                )?;
                if let Err(e) = std::fs::rename(path, files.join(&candidate)) {
                    let _ = std::fs::remove_file(&info_path);
                    return Err(e);
                }
                return Ok(());
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                i += 1;
                candidate = format!("{name}.{i}");
            }
            Err(e) => return Err(e),
        }
    }
}
