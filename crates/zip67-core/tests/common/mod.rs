#![allow(dead_code)]
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use zip67_core::create::{CreateOptions, Method};
use zip67_core::extract::{extract_to, ExtractOptions, Overwrite, Selection};
use zip67_core::{open, ArchiveType, OpenOptions, Password, Progress};

/// Deterministic pseudo-random bytes.
pub fn noise(n: usize, seed: u64) -> Vec<u8> {
    let mut x = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

pub fn make_tree(root: &Path) -> PathBuf {
    let base = root.join("data");
    fs::create_dir_all(base.join("sub/deeper")).unwrap();
    fs::create_dir_all(base.join("empty dir")).unwrap();
    fs::write(base.join("hello.txt"), b"Hello, 67zip!\n".repeat(1000)).unwrap();
    fs::write(base.join("empty.bin"), b"").unwrap();
    fs::write(base.join("sub/random.bin"), noise(300_000, 7)).unwrap();
    fs::write(base.join("sub/deeper/ünïcödé 名前.txt"), "text ".repeat(5000)).unwrap();
    fs::write(base.join("run.sh"), b"#!/bin/sh\necho hi\n").unwrap();
    fs::set_permissions(base.join("run.sh"), fs::Permissions::from_mode(0o755)).unwrap();
    std::os::unix::fs::symlink("hello.txt", base.join("link-to-hello")).unwrap();
    base
}

/// Compares two trees: names, kinds, contents, symlink targets, exec bits.
pub fn assert_same_tree(a: &Path, b: &Path) {
    let mut ea: Vec<_> = walk(a);
    let mut eb: Vec<_> = walk(b);
    ea.sort();
    eb.sort();
    let names_a: Vec<_> = ea.iter().map(|(p, _)| p.clone()).collect();
    let names_b: Vec<_> = eb.iter().map(|(p, _)| p.clone()).collect();
    assert_eq!(names_a, names_b, "trees differ: {} vs {}", a.display(), b.display());
    for ((p, _), _) in ea.iter().zip(eb.iter()) {
        let (pa, pb) = (a.join(p), b.join(p));
        let ma = fs::symlink_metadata(&pa).unwrap();
        let mb = fs::symlink_metadata(&pb).unwrap();
        assert_eq!(ma.file_type().is_symlink(), mb.file_type().is_symlink(), "{p}");
        if ma.file_type().is_symlink() {
            assert_eq!(fs::read_link(&pa).unwrap(), fs::read_link(&pb).unwrap(), "{p}");
        } else if ma.is_file() {
            assert_eq!(fs::read(&pa).unwrap(), fs::read(&pb).unwrap(), "content of {p}");
            assert_eq!(ma.permissions().mode() & 0o111 != 0, mb.permissions().mode() & 0o111 != 0, "exec bit of {p}");
        }
    }
}

fn walk(root: &Path) -> Vec<(String, bool)> {
    let mut out = Vec::new();
    fn go(root: &Path, dir: &Path, out: &mut Vec<(String, bool)>) {
        for e in fs::read_dir(dir).unwrap() {
            let e = e.unwrap();
            let p = e.path();
            let rel = p.strip_prefix(root).unwrap().to_string_lossy().into_owned();
            let md = fs::symlink_metadata(&p).unwrap();
            out.push((rel, md.is_dir()));
            if md.is_dir() {
                go(root, &p, out);
            }
        }
    }
    go(root, root, &mut out);
    out
}

pub fn opts(t: &str, method: Option<Method>, password: Option<&str>) -> CreateOptions {
    CreateOptions {
        archive_type: ArchiveType::from_id(t).unwrap(),
        method,
        password: password.map(Password::new),
        threads: 2,
        ..Default::default()
    }
}

pub fn extract_all(archive: &Path, dest: &Path, password: Option<&str>) -> zip67_core::extract::ExtractReport {
    let mut r = open(archive, &OpenOptions { password: password.map(Password::new), ..Default::default() }).unwrap();
    let eo = ExtractOptions { overwrite: Overwrite::Always, ..Default::default() };
    extract_to(r.as_mut(), dest, &Selection::All, &eo, None, &Progress::new()).unwrap()
}

pub fn seven_zip() -> Option<&'static str> {
    for c in ["7zz", "7z"] {
        if Command::new(c).arg("i").output().map(|o| o.status.success()).unwrap_or(false) {
            return Some(c);
        }
    }
    None
}
