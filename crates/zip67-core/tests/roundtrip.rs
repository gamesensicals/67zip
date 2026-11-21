mod common;

use std::fs;
use std::process::Command;

use common::*;
use zip67_core::create::{create, Method};
use zip67_core::extract::{test as test_archive, Selection};
use zip67_core::{open, OpenOptions, Password, Progress};

fn roundtrip(t: &str, method: Option<Method>, password: Option<&str>) {
    let tmp = tempfile::tempdir().unwrap();
    let src = make_tree(tmp.path());
    let archive = tmp.path().join(format!("out.{t}"));
    let report = create(&archive, &[src.clone()], &opts(t, method, password), &Progress::new()).unwrap();
    assert!(report.files >= 6, "{t}: {report:?}");

    // List
    let mut r = open(&archive, &OpenOptions { password: password.map(Password::new), ..Default::default() }).unwrap();
    assert_eq!(r.archive_type().id(), t);
    let names: Vec<String> = r.entries().iter().map(|e| e.path.clone()).collect();
    assert!(names.contains(&"data/sub/random.bin".to_string()), "{t}: {names:?}");
    // Test
    let rep = test_archive(r.as_mut(), &Selection::All, &Progress::new()).unwrap();
    assert!(rep.errors.is_empty(), "{t}: {:?}", rep.errors);
    // Extract and compare
    let out = tmp.path().join("x");
    let rep = extract_all(&archive, &out, password);
    assert!(rep.errors.is_empty(), "{t}: {:?}", rep.errors);
    assert_same_tree(&src, &out.join("data"));

    // Real 7-Zip must accept what we wrote.
    if let Some(sz) = seven_zip() {
        let mut cmd = Command::new(sz);
        cmd.arg("t").arg(&archive);
        if let Some(p) = password {
            cmd.arg(format!("-p{p}"));
        }
        let o = cmd.output().unwrap();
        assert!(o.status.success(), "7-Zip rejected our {t}: {}", String::from_utf8_lossy(&o.stdout));
    }
}

#[test]
fn zip_deflate() {
    roundtrip("zip", None, None);
}
#[test]
fn zip_store() {
    roundtrip("zip", Some(Method::Copy), None);
}
#[test]
fn zip_bzip2() {
    roundtrip("zip", Some(Method::Bzip2), None);
}
#[test]
fn zip_lzma() {
    roundtrip("zip", Some(Method::Lzma), None);
}
#[test]
fn zip_xz() {
    roundtrip("zip", Some(Method::Xz), None);
}
#[test]
fn zip_zstd() {
    // 7-Zip 23 cannot read zstd in zip; only check our own round trip.
    let tmp = tempfile::tempdir().unwrap();
    let src = make_tree(tmp.path());
    let archive = tmp.path().join("z.zip");
    create(&archive, &[src.clone()], &opts("zip", Some(Method::Zstd), None), &Progress::new()).unwrap();
    let out = tmp.path().join("x");
    extract_all(&archive, &out, None);
    assert_same_tree(&src, &out.join("data"));
}
#[test]
fn zip_aes() {
    roundtrip("zip", None, Some("pässwörd 67"));
}
#[test]
fn tar_plain() {
    roundtrip("tar", None, None);
}
#[test]
fn tar_gz() {
    roundtrip("tar.gz", None, None);
}
#[test]
fn tar_bz2() {
    roundtrip("tar.bz2", None, None);
}
#[test]
fn tar_xz() {
    roundtrip("tar.xz", None, None);
}
#[test]
fn tar_zst() {
    let tmp = tempfile::tempdir().unwrap();
    let src = make_tree(tmp.path());
    let archive = tmp.path().join("out.tar.zst");
    create(&archive, &[src.clone()], &opts("tar.zst", None, None), &Progress::new()).unwrap();
    let out = tmp.path().join("x");
    extract_all(&archive, &out, None);
    assert_same_tree(&src, &out.join("data"));
}
#[test]
fn tar_lzip_and_lzma() {
    for t in ["tar.lz", "tar.lzma"] {
        let tmp = tempfile::tempdir().unwrap();
        let src = make_tree(tmp.path());
        let archive = tmp.path().join(format!("out.{t}"));
        create(&archive, &[src.clone()], &opts(t, None, None), &Progress::new()).unwrap();
        let out = tmp.path().join("x");
        extract_all(&archive, &out, None);
        assert_same_tree(&src, &out.join("data"));
    }
}

#[test]
fn single_file_formats() {
    for t in ["gz", "bz2", "xz", "zst", "lzma", "lz"] {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("notes.txt");
        fs::write(&f, b"some text ".repeat(20_000)).unwrap();
        let archive = tmp.path().join(format!("notes.txt.{t}"));
        create(&archive, &[f.clone()], &opts(t, None, None), &Progress::new()).unwrap();
        let r = open(&archive, &OpenOptions::default()).unwrap();
        assert_eq!(r.archive_type().id(), t);
        assert_eq!(r.entries()[0].path, "notes.txt");
        let out = tmp.path().join("x");
        extract_all(&archive, &out, None);
        assert_eq!(fs::read(out.join("notes.txt")).unwrap(), fs::read(&f).unwrap(), "{t}");
        if t != "zst" && t != "lz" {
            if let Some(sz) = seven_zip() {
                let o = Command::new(sz).arg("t").arg(&archive).output().unwrap();
                assert!(o.status.success(), "7-Zip rejected our {t}");
            }
        }
    }
}

#[test]
fn wrong_password_is_detected() {
    let tmp = tempfile::tempdir().unwrap();
    let src = make_tree(tmp.path());
    let archive = tmp.path().join("p.zip");
    create(&archive, &[src], &opts("zip", None, Some("right")), &Progress::new()).unwrap();
    let mut r = open(&archive, &OpenOptions { password: Some(Password::new("wrong")), ..Default::default() }).unwrap();
    let rep = test_archive(r.as_mut(), &Selection::All, &Progress::new()).unwrap();
    assert!(!rep.errors.is_empty());
    assert!(rep.errors.iter().all(|(_, e)| e.contains("wrong password")), "{:?}", rep.errors);
}

/// Archives made by real 7-Zip must open and extract identically.
#[test]
fn reads_archives_made_by_7zip() {
    let Some(sz) = seven_zip() else { return };
    let tmp = tempfile::tempdir().unwrap();
    let src = make_tree(tmp.path());
    let cases: &[(&str, &[&str], Option<&str>)] = &[
        ("a.zip", &["-tzip"], None),
        ("b.zip", &["-tzip", "-mm=BZip2"], None),
        ("c.zip", &["-tzip", "-mm=LZMA"], None),
        ("d.zip", &["-tzip", "-mm=PPMd"], None),
        ("e.zip", &["-tzip", "-mem=AES256", "-psecret"], Some("secret")),
        ("f.zip", &["-tzip", "-mem=ZipCrypto", "-psecret"], Some("secret")),
        ("g.tar", &["-ttar"], None),
        ("h.zip", &["-tzip", "-mx0"], None),
    ];
    for (name, args, pw) in cases {
        let archive = tmp.path().join(name);
        let o = Command::new(sz).current_dir(tmp.path()).arg("a").args(*args).arg("-snl").arg(&archive).arg("data").output().unwrap();
        assert!(o.status.success(), "7z failed for {name}: {}", String::from_utf8_lossy(&o.stdout));
        let out = tmp.path().join(format!("x-{name}"));
        let rep = extract_all(&archive, &out, *pw);
        assert!(rep.errors.is_empty(), "{name}: {:?}", rep.errors);
        assert_same_tree(&src, &out.join("data"));
    }
    // Compressed tar and single files made by 7-Zip.
    let tar = tmp.path().join("g.tar");
    for (t, ext) in [("gzip", "gz"), ("bzip2", "bz2"), ("xz", "xz")] {
        let archive = tmp.path().join(format!("g.tar.{ext}"));
        let o = Command::new(sz).arg("a").arg(format!("-t{t}")).arg(&archive).arg(&tar).output().unwrap();
        assert!(o.status.success());
        let r = open(&archive, &OpenOptions::default()).unwrap();
        assert_eq!(r.archive_type().id(), format!("tar.{ext}"));
        let out = tmp.path().join(format!("x-tar-{ext}"));
        extract_all(&archive, &out, None);
        assert_same_tree(&src, &out.join("data"));
    }
}
