//! Hostile archives must never write outside the destination.

mod common;

use std::fs;
use std::io::Write;

use common::*;
use zip67_core::extract::{ExtractOptions, Overwrite, Selection, extract_to};
use zip67_core::{OpenOptions, Progress, open};

/// Builds a zip with stored entries; `dup_offset` makes the second central
/// record point at the first local header (overlap bomb).
fn crafted_zip(entries: &[(&str, &[u8], u32)], dup_offset: bool) -> Vec<u8> {
    let mut out = Vec::new();
    let mut cd = Vec::new();
    let mut first_offset = 0u32;
    for (i, (name, data, mode)) in entries.iter().enumerate() {
        let offset = out.len() as u32;
        if i == 0 {
            first_offset = offset;
        }
        let crc = zip67_core::crc::crc32(data);
        let mut lh = Vec::new();
        lh.extend_from_slice(&0x04034b50u32.to_le_bytes());
        lh.extend_from_slice(&10u16.to_le_bytes());
        lh.extend_from_slice(&0u16.to_le_bytes());
        lh.extend_from_slice(&0u16.to_le_bytes());
        lh.extend_from_slice(&0u32.to_le_bytes());
        lh.extend_from_slice(&crc.to_le_bytes());
        lh.extend_from_slice(&(data.len() as u32).to_le_bytes());
        lh.extend_from_slice(&(data.len() as u32).to_le_bytes());
        lh.extend_from_slice(&(name.len() as u16).to_le_bytes());
        lh.extend_from_slice(&0u16.to_le_bytes());
        lh.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&lh);
        out.extend_from_slice(data);
        let off = if dup_offset && i > 0 {
            first_offset
        } else {
            offset
        };
        cd.extend_from_slice(&0x02014b50u32.to_le_bytes());
        cd.extend_from_slice(&((3u16 << 8) | 20).to_le_bytes());
        cd.extend_from_slice(&10u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u32.to_le_bytes());
        cd.extend_from_slice(&crc.to_le_bytes());
        cd.extend_from_slice(&(data.len() as u32).to_le_bytes());
        cd.extend_from_slice(&(data.len() as u32).to_le_bytes());
        cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
        cd.extend_from_slice(&[0u8; 8]);
        cd.extend_from_slice(&(mode << 16).to_le_bytes());
        cd.extend_from_slice(&off.to_le_bytes());
        cd.extend_from_slice(name.as_bytes());
    }
    let cd_off = out.len() as u32;
    out.extend_from_slice(&cd);
    out.extend_from_slice(&0x06054b50u32.to_le_bytes());
    out.extend_from_slice(&[0u8; 4]);
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(cd.len() as u32).to_le_bytes());
    out.extend_from_slice(&cd_off.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

fn extract(
    archive: &std::path::Path,
    dest: &std::path::Path,
) -> zip67_core::Result<zip67_core::extract::ExtractReport> {
    let mut r = open(archive, &OpenOptions::default())?;
    let eo = ExtractOptions {
        overwrite: Overwrite::Always,
        ..Default::default()
    };
    extract_to(
        r.as_mut(),
        dest,
        &Selection::All,
        &eo,
        None,
        &Progress::new(),
    )
}

#[test]
fn zip_slip_is_blocked() {
    let tmp = tempfile::tempdir().unwrap();
    let z = tmp.path().join("evil.zip");
    fs::write(
        &z,
        crafted_zip(
            &[
                ("../escaped.txt", b"pwned", 0o100644),
                ("/abs.txt", b"pwned", 0o100644),
                ("ok.txt", b"fine", 0o100644),
            ],
            false,
        ),
    )
    .unwrap();
    let dest = tmp.path().join("dest");
    let rep = extract(&z, &dest).unwrap();
    assert!(!tmp.path().join("escaped.txt").exists());
    assert!(!dest.join("abs.txt").exists());
    assert_eq!(fs::read(dest.join("ok.txt")).unwrap(), b"fine");
    assert_eq!(rep.errors.len(), 2, "{rep:?}");
}

#[test]
fn symlink_escape_is_blocked() {
    // symlink "link" -> "/" or "..", then a file written "through" it.
    let tmp = tempfile::tempdir().unwrap();
    let outside = tmp.path().join("outside");
    fs::create_dir(&outside).unwrap();
    let target = outside.to_string_lossy().into_owned();
    let z = tmp.path().join("evil2.zip");
    fs::write(
        &z,
        crafted_zip(
            &[
                ("link", target.as_bytes(), 0o120777),
                ("up", b"..", 0o120777),
                ("link/pwned.txt", b"x", 0o100644),
                ("up/pwned2.txt", b"x", 0o100644),
            ],
            false,
        ),
    )
    .unwrap();
    let dest = tmp.path().join("dest");
    let _ = extract(&z, &dest);
    assert!(!outside.join("pwned.txt").exists());
    assert!(!tmp.path().join("pwned2.txt").exists());
    for l in ["link", "up"] {
        // The later file entry may create a plain folder of that name; it
        // must never be a symlink.
        let md = fs::symlink_metadata(dest.join(l));
        assert!(
            md.map(|m| !m.file_type().is_symlink()).unwrap_or(true),
            "{l} must not be a symlink"
        );
    }
}

#[test]
fn overlapping_entries_bomb_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let z = tmp.path().join("bomb.zip");
    fs::write(
        &z,
        crafted_zip(
            &[
                ("a", b"0000000000", 0o100644),
                ("b", b"0000000000", 0o100644),
            ],
            true,
        ),
    )
    .unwrap();
    assert!(open(&z, &OpenOptions::default()).is_err());
}

#[test]
fn tar_absolute_and_dotdot_paths_blocked() {
    let tmp = tempfile::tempdir().unwrap();
    // Hand-made tar with "../evil" and a symlink to /tmp followed by a write.
    let mut tar = Vec::new();
    let mut add = |name: &str, typ: u8, link: &str, data: &[u8]| {
        let mut h = [0u8; 512];
        h[..name.len()].copy_from_slice(name.as_bytes());
        h[100..108].copy_from_slice(b"0000644\0");
        h[108..116].copy_from_slice(b"0000000\0");
        h[116..124].copy_from_slice(b"0000000\0");
        h[124..136].copy_from_slice(format!("{:011o}\0", data.len()).as_bytes());
        h[136..148].copy_from_slice(b"00000000000\0");
        h[156] = typ;
        h[157..157 + link.len()].copy_from_slice(link.as_bytes());
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        h[148..156].copy_from_slice(b"        ");
        let sum: u32 = h.iter().map(|&b| b as u32).sum();
        h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        tar.extend_from_slice(&h);
        tar.extend_from_slice(data);
        tar.resize(tar.len().div_ceil(512) * 512, 0);
    };
    let outside = tmp.path().join("outside");
    fs::create_dir(&outside).unwrap();
    add("../evil.txt", b'0', "", b"pwned");
    add("ln", b'2', &outside.to_string_lossy(), b"");
    add("ln/inside-outside.txt", b'0', "", b"pwned");
    add("good.txt", b'0', "", b"good");
    tar.extend_from_slice(&[0u8; 1024]);
    let t = tmp.path().join("evil.tar");
    fs::File::create(&t).unwrap().write_all(&tar).unwrap();
    let dest = tmp.path().join("dest");
    let rep = extract(&t, &dest).unwrap();
    assert!(!tmp.path().join("evil.txt").exists());
    assert!(!outside.join("inside-outside.txt").exists());
    assert_eq!(fs::read(dest.join("good.txt")).unwrap(), b"good");
    assert!(!rep.warnings.is_empty() || !rep.errors.is_empty());
}

#[test]
fn garbage_never_panics() {
    // Random and truncated inputs must produce errors, never panics/hangs.
    let tmp = tempfile::tempdir().unwrap();
    let src = make_tree(tmp.path());
    let good = tmp.path().join("good.zip");
    zip67_core::create::create(&good, &[src], &opts("zip", None, None), &Progress::new()).unwrap();
    let bytes = fs::read(&good).unwrap();
    for seed in 0..200u64 {
        let mut b = bytes.clone();
        let n = noise(8, seed);
        let pos = (u64::from_le_bytes(n.clone().try_into().unwrap()) as usize) % b.len();
        b[pos] ^= 0x5a;
        if seed % 3 == 0 {
            b.truncate(pos.max(1));
        }
        let p = tmp.path().join(format!("f{seed}.zip"));
        fs::write(&p, &b).unwrap();
        if let Ok(mut r) = open(&p, &OpenOptions::default()) {
            let _ = zip67_core::extract::test(r.as_mut(), &Selection::All, &Progress::new());
        }
    }
    for seed in 0..50u64 {
        let p = tmp.path().join(format!("n{seed}.bin"));
        fs::write(&p, noise(5000, seed)).unwrap();
        let _ = open(&p, &OpenOptions::default());
    }
}

#[test]
fn archive_permissions_respect_the_umask() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    // World-writable, setuid file: neither may survive extraction.
    let zip = crafted_zip(&[("open.sh", b"#!/bin/sh\n", 0o104777)], false);
    let p = tmp.path().join("perm.zip");
    fs::write(&p, zip).unwrap();
    let dest = tmp.path().join("out");
    extract(&p, &dest).unwrap();
    let mode = fs::metadata(dest.join("open.sh"))
        .unwrap()
        .permissions()
        .mode()
        & 0o7777;
    let umask = {
        let old = rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o022));
        rustix::process::umask(old);
        old.as_raw_mode()
    };
    assert_eq!(mode, 0o777 & !umask, "got {mode:o}");
    assert_eq!(mode & 0o7002, 0, "setuid or world-writable: {mode:o}");
}
