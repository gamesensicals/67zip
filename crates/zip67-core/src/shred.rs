//! Secure deletion: a file's content is overwritten with random data and
//! flushed to the disk, its name is replaced by a random one, then it is
//! deleted. One pass is enough for modern drives.
//!
//! This only destroys the old data where the file system writes in place
//! and the drive does not move data around itself: classic hard disks with
//! ext4, XFS and the like. SSDs (wear levelling) and copy-on-write file
//! systems (btrfs, ZFS, bcachefs, f2fs) keep old blocks around; there
//! [`reliability`] says so. Full-disk encryption is what protects there.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

/// What happened to one file.
#[derive(Debug, PartialEq, Eq)]
pub enum Shredded {
    /// Overwritten and deleted.
    Done,
    /// A symbolic link: only the link was removed.
    LinkRemoved,
    /// Not deleted, with the reason (other hard links share the data, or
    /// it is not a regular file).
    Kept(String),
}

/// Overwrites `path` with random data, then deletes it.
pub fn shred_file(path: &Path) -> io::Result<Shredded> {
    let md = fs::symlink_metadata(path)?;
    if md.file_type().is_symlink() {
        fs::remove_file(path)?;
        return Ok(Shredded::LinkRemoved);
    }
    if !md.is_file() {
        return Ok(Shredded::Kept("not a regular file".into()));
    }
    if md.nlink() > 1 {
        return Ok(Shredded::Kept("other hard links share its data, so it was kept".into()));
    }
    let nofollow = rustix::fs::OFlags::NOFOLLOW.bits() as i32;
    let mut f = OpenOptions::new().write(true).custom_flags(nofollow).open(path)?;
    // Still the same file we looked at (not swapped in the meantime).
    let fmd = f.metadata()?;
    if fmd.dev() != md.dev() || fmd.ino() != md.ino() {
        return Ok(Shredded::Kept("the file changed while it was being deleted".into()));
    }
    overwrite(&mut f, fmd.len())?;
    f.set_len(0)?;
    f.sync_all()?;
    drop(f);
    // Leave no trace of the name either.
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let hidden = dir.join(format!(".{}", crate::util::random_hex(12)));
    let gone = if fs::rename(path, &hidden).is_ok() { hidden } else { path.to_path_buf() };
    fs::remove_file(&gone)?;
    if let Ok(d) = File::open(&dir) {
        let _ = d.sync_all();
    }
    Ok(Shredded::Done)
}

fn overwrite(f: &mut File, len: u64) -> io::Result<()> {
    let mut buf = vec![0u8; 1 << 20];
    let mut left = len;
    while left > 0 {
        let n = left.min(buf.len() as u64) as usize;
        getrandom::fill(&mut buf[..n]).map_err(|_| io::Error::other("no random source"))?;
        f.write_all(&buf[..n])?;
        left -= n as u64;
    }
    f.flush()?;
    f.sync_all()
}

/// Shreds every file under `dir` (links are removed, not followed), then
/// removes the folders. Returns the problems met.
pub fn shred_tree(dir: &Path) -> Vec<String> {
    let mut problems = Vec::new();
    let Ok(md) = fs::symlink_metadata(dir) else { return problems };
    if !md.is_dir() {
        if let Err(e) = shred_file(dir) {
            problems.push(format!("{}: {e}", dir.display()));
        }
        return problems;
    }
    if let Ok(rd) = fs::read_dir(dir) {
        for e in rd.flatten() {
            problems.extend(shred_tree(&e.path()));
        }
    }
    if let Err(e) = fs::remove_dir(dir) {
        problems.push(format!("{}: {e}", dir.display()));
    }
    problems
}

// File system magic numbers (statfs f_type).
const TMPFS: u64 = 0x0102_1994;
const RAMFS: u64 = 0x8584_58f6;
const BTRFS: u64 = 0x9123_683e;
const ZFS: u64 = 0x2fc1_2fc1;
const BCACHEFS: u64 = 0xca45_1a4e;
const F2FS: u64 = 0xf2f5_2010;
const NILFS: u64 = 0x3434;
const OVERLAY: u64 = 0x794c_7630;
const NFS: u64 = 0x6969;
const SMB: u64 = 0xfe53_4d42;
const CIFS: u64 = 0xff53_4d42;
const FUSE: u64 = 0x6573_5546;

fn fs_type(path: &Path) -> Option<u64> {
    rustix::fs::statfs(path).ok().map(|s| (s.f_type as u64) & 0xffff_ffff)
}

/// True when `path` lives in memory (tmpfs/ramfs), not on a disk.
pub fn in_memory(path: &Path) -> bool {
    matches!(fs_type(path), Some(TMPFS | RAMFS))
}

/// Whether overwriting a file at `path` really destroys its old content.
/// `None` means it should; otherwise the reason it may not.
pub fn reliability(path: &Path) -> Option<String> {
    let t = fs_type(path)?;
    let why = match t {
        TMPFS | RAMFS => return None,
        BTRFS | ZFS | BCACHEFS | F2FS | NILFS => "it is on a copy-on-write file system, which writes new data elsewhere and may keep the old blocks (and snapshots)",
        OVERLAY => "it is on an overlay file system, which may keep the original in a lower layer",
        NFS | SMB | CIFS | FUSE => "it is on a network or FUSE file system whose storage 67zip cannot check",
        _ => match disk_kind(path) {
            Disk::Rotational | Disk::Encrypted => return None,
            Disk::Solid => "it is on an SSD, which may keep old data in cells it remaps",
            Disk::Unknown => return None,
        },
    };
    Some(why.to_string())
}

enum Disk {
    Rotational,
    Solid,
    Encrypted,
    Unknown,
}

fn disk_kind(path: &Path) -> Disk {
    let Ok(md) = fs::metadata(path) else { return Disk::Unknown };
    let dev = md.dev();
    let base = PathBuf::from(format!("/sys/dev/block/{}:{}", rustix::fs::major(dev), rustix::fs::minor(dev)));
    // Device-mapper crypt (LUKS): the data at rest is encrypted anyway.
    if fs::read_to_string(base.join("dm/uuid")).is_ok_and(|u| u.starts_with("CRYPT-")) {
        return Disk::Encrypted;
    }
    // Partitions keep the "queue" folder in their parent disk.
    for q in [base.join("queue/rotational"), base.join("../queue/rotational")] {
        if let Ok(v) = fs::read_to_string(&q) {
            return if v.trim() == "1" { Disk::Rotational } else { Disk::Solid };
        }
    }
    Disk::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overwrites_and_deletes() {
        let tmp = std::env::temp_dir().join(format!("67zip-shred-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(tmp.join("sub")).unwrap();
        let f = tmp.join("secret.txt");
        fs::write(&f, b"secret data").unwrap();
        // Keep a second handle to the same inode: the content must be gone.
        let keep = File::open(&f).unwrap();
        assert_eq!(shred_file(&f).unwrap(), Shredded::Done);
        assert!(!f.exists());
        assert_eq!(keep.metadata().unwrap().len(), 0);
        // Hard-linked files are kept.
        fs::write(tmp.join("a"), b"x").unwrap();
        fs::hard_link(tmp.join("a"), tmp.join("b")).unwrap();
        assert!(matches!(shred_file(&tmp.join("a")).unwrap(), Shredded::Kept(_)));
        assert!(tmp.join("a").exists());
        // Links are removed, never followed.
        fs::write(tmp.join("target"), b"keep me").unwrap();
        std::os::unix::fs::symlink(tmp.join("target"), tmp.join("sub/link")).unwrap();
        fs::write(tmp.join("sub/x"), b"y").unwrap();
        assert!(shred_tree(&tmp.join("sub")).is_empty());
        assert!(!tmp.join("sub").exists());
        assert_eq!(fs::read(tmp.join("target")).unwrap(), b"keep me");
        let _ = fs::remove_dir_all(&tmp);
    }
}
