//! Split archives in every naming scheme, opened from any part.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use common::*;
use zip67_core::create::{CreateOptions, create};
use zip67_core::{ArchiveType, OpenOptions, Progress, open};

/// Creates `dir/name.7z.001...` and returns the parts in order.
fn make_numbered(dir: &Path, src: &Path, t: &str) -> Vec<PathBuf> {
    let archive = dir.join(format!("orig.{t}"));
    let o = CreateOptions {
        archive_type: ArchiveType::from_id(t).unwrap(),
        volume_size: Some(100_000),
        threads: 2,
        ..Default::default()
    };
    let rep = create(&archive, &[src.to_path_buf()], &o, &Progress::new()).unwrap();
    assert!(
        rep.outputs.len() >= 3,
        "want several parts, got {:?}",
        rep.outputs
    );
    rep.outputs
}

fn check(archive: &Path, src: &Path, label: &str) {
    let r = open(archive, &OpenOptions::default()).unwrap_or_else(|e| panic!("{label}: {e}"));
    assert!(r.info().volumes > 1, "{label}: not seen as split");
    drop(r);
    let out = archive.with_extension("out");
    let _ = fs::remove_dir_all(&out);
    let rep = extract_all(archive, &out, None);
    assert!(rep.errors.is_empty(), "{label}: {:?}", rep.errors);
    assert_same_tree(src, &out.join("data"));
}

fn copy_as(parts: &[PathBuf], dir: &Path, name: impl Fn(usize) -> String) -> Vec<PathBuf> {
    parts
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let to = dir.join(name(i + 1));
            fs::copy(p, &to).unwrap();
            to
        })
        .collect()
}

#[test]
fn every_naming_scheme_opens_from_any_part() {
    let tmp = tempfile::tempdir().unwrap();
    let src = make_tree(tmp.path());
    let d = tmp.path().join("v");
    fs::create_dir(&d).unwrap();
    for t in ["7z", "zip", "tar.gz"] {
        let parts = make_numbered(&d, &src, t);
        check(&parts[1], &src, &format!("{t} numbered, from part 2"));
        let n = parts.len();
        let schemes: Vec<(&str, Box<dyn Fn(usize) -> String>)> = vec![
            (
                "part before ext",
                Box::new(move |i| format!("a-{}.part{i}.{t}", t.replace('.', "-"))),
            ),
            (
                "padded part before ext",
                Box::new(move |i| format!("b-{}.part{i:02}.{t}", t.replace('.', "-"))),
            ),
            (
                "part after ext",
                Box::new(move |i| format!("c.{t}.part{i}")),
            ),
            (
                "letters",
                Box::new(move |i| {
                    format!(
                        "e.{t}.{}",
                        ["aa", "ab", "ac", "ad", "ae", "af", "ag", "ah", "ai", "aj"][i - 1]
                    )
                }),
            ),
        ];
        for (label, f) in schemes {
            let copies = copy_as(&parts, &d, f);
            check(
                &copies[n - 1],
                &src,
                &format!("{t} {label}, from last part"),
            );
            check(&copies[0], &src, &format!("{t} {label}, from first part"));
        }
    }
}

#[test]
fn missing_parts_are_reported() {
    let tmp = tempfile::tempdir().unwrap();
    let src = make_tree(tmp.path());
    let parts = make_numbered(tmp.path(), &src, "7z");
    // Middle part missing.
    fs::remove_file(&parts[1]).unwrap();
    let e = open(&parts[0], &OpenOptions::default())
        .err()
        .expect("must fail")
        .to_string();
    assert!(e.contains("part 2"), "{e}");
    // Last part missing.
    let tmp2 = tempfile::tempdir().unwrap();
    let parts = make_numbered(tmp2.path(), &src, "7z");
    fs::remove_file(parts.last().unwrap()).unwrap();
    let e = open(&parts[0], &OpenOptions::default())
        .err()
        .expect("must fail")
        .to_string();
    assert!(e.contains("split archive"), "{e}");
}

#[test]
fn pkzip_split_archives() {
    if Command::new("zip").arg("-v").output().is_err() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let src = make_tree(tmp.path());
    let st = Command::new("zip")
        .current_dir(tmp.path())
        .args(["-q", "-r", "-y", "-s", "64k", "split.zip", "data"])
        .status()
        .unwrap();
    assert!(st.success());
    assert!(tmp.path().join("split.z01").exists(), "zip did not split");
    check(&tmp.path().join("split.zip"), &src, "split zip via .zip");
    check(&tmp.path().join("split.z02"), &src, "split zip via .z02");
    fs::remove_file(tmp.path().join("split.z02")).unwrap();
    let e = open(&tmp.path().join("split.zip"), &OpenOptions::default())
        .err()
        .expect("must fail")
        .to_string();
    assert!(e.contains("part 2"), "{e}");
}
