mod common;

use std::fs;
use std::process::Command;

use common::*;
use zip67_core::create::{create, CreateOptions, Method};
use zip67_core::extract::{test as test_archive, Selection};
use zip67_core::{open, ArchiveType, Error, OpenOptions, Password, Progress};

fn ours(method: Method, password: Option<&str>, encrypt_names: bool, solid: bool, threads: usize) {
    let tmp = tempfile::tempdir().unwrap();
    let src = make_tree(tmp.path());
    let archive = tmp.path().join("t.7z");
    let o = CreateOptions {
        archive_type: ArchiveType::SEVEN_Z,
        method: Some(method),
        password: password.map(Password::new),
        encrypt_names,
        solid,
        threads,
        ..Default::default()
    };
    create(&archive, &[src.clone()], &o, &Progress::new()).unwrap();
    let out = tmp.path().join("x");
    let rep = extract_all(&archive, &out, password);
    assert!(rep.errors.is_empty(), "{method:?}: {:?}", rep.errors);
    assert_same_tree(&src, &out.join("data"));
    if let Some(sz) = seven_zip() {
        let mut c = Command::new(sz);
        c.arg("t").arg(&archive);
        c.arg(format!("-p{}", password.unwrap_or("")));
        let o = c.output().unwrap();
        assert!(o.status.success(), "7-Zip rejected our 7z ({method:?}): {}", String::from_utf8_lossy(&o.stdout));
        // And 7-Zip's extraction must match the source too.
        let out7 = tmp.path().join("x7");
        let mut c = Command::new(sz);
        c.arg("x").arg(&archive).arg(format!("-o{}", out7.display())).arg("-y").arg("-snl");
        c.arg(format!("-p{}", password.unwrap_or("")));
        assert!(c.output().unwrap().status.success());
        assert_same_tree(&src, &out7.join("data"));
    }
}

#[test]
fn lzma2_multithreaded() {
    ours(Method::Lzma2, None, false, true, 4);
}
#[test]
fn lzma2_single_thread() {
    ours(Method::Lzma2, None, false, true, 1);
}
#[test]
fn lzma() {
    ours(Method::Lzma, None, false, true, 1);
}
#[test]
fn ppmd() {
    ours(Method::Ppmd, None, false, true, 1);
}
#[test]
fn bzip2() {
    ours(Method::Bzip2, None, false, true, 2);
}
#[test]
fn deflate() {
    ours(Method::Deflate, None, false, true, 1);
}
#[test]
fn copy() {
    ours(Method::Copy, None, false, true, 1);
}
#[test]
fn non_solid() {
    ours(Method::Lzma2, None, false, false, 2);
}
#[test]
fn aes_data_only() {
    ours(Method::Lzma2, Some("pässwörd"), false, true, 2);
}
#[test]
fn aes_with_encrypted_names() {
    ours(Method::Lzma2, Some("secret"), true, true, 2);
}

#[test]
fn encrypted_names_need_password() {
    let tmp = tempfile::tempdir().unwrap();
    let src = make_tree(tmp.path());
    let archive = tmp.path().join("h.7z");
    let o = CreateOptions { archive_type: ArchiveType::SEVEN_Z, password: Some(Password::new("pw")), encrypt_names: true, ..Default::default() };
    create(&archive, &[src], &o, &Progress::new()).unwrap();
    assert!(matches!(open(&archive, &OpenOptions::default()), Err(Error::PasswordRequired)));
    assert!(matches!(open(&archive, &OpenOptions { password: Some(Password::new("nope")), ..Default::default() }), Err(Error::WrongPassword)));
    assert!(open(&archive, &OpenOptions { password: Some(Password::new("pw")), ..Default::default() }).is_ok());
}

#[test]
fn wrong_password_on_data() {
    let tmp = tempfile::tempdir().unwrap();
    let src = make_tree(tmp.path());
    let archive = tmp.path().join("d.7z");
    let o = CreateOptions { archive_type: ArchiveType::SEVEN_Z, password: Some(Password::new("pw")), ..Default::default() };
    create(&archive, &[src], &o, &Progress::new()).unwrap();
    let mut r = open(&archive, &OpenOptions { password: Some(Password::new("bad")), ..Default::default() }).unwrap();
    let rep = test_archive(r.as_mut(), &Selection::All, &Progress::new()).unwrap();
    assert!(!rep.errors.is_empty());
    assert!(rep.errors.iter().all(|(_, e)| e.contains("wrong password")), "{:?}", rep.errors);
}

#[test]
fn reads_7zip_archives() {
    let Some(sz) = seven_zip() else { return };
    let tmp = tempfile::tempdir().unwrap();
    let src = make_tree(tmp.path());
    // An ELF binary to exercise the executable filters.
    fs::copy("/bin/ls", src.join("sub/ls-binary")).unwrap();
    let cases: &[(&str, &[&str], Option<&str>)] = &[
        ("lzma2.7z", &["-m0=lzma2", "-mx5"], None),
        ("lzma2mt.7z", &["-m0=lzma2", "-mx5", "-mmt4"], None),
        ("lzma.7z", &["-m0=lzma"], None),
        ("ppmd.7z", &["-m0=ppmd"], None),
        ("bzip2.7z", &["-m0=bzip2"], None),
        ("deflate.7z", &["-m0=deflate"], None),
        ("copy.7z", &["-m0=copy"], None),
        ("bcj.7z", &["-mf=BCJ"], None),
        ("bcj2.7z", &["-m0=BCJ2", "-m1=LZMA", "-m2=LZMA", "-m3=LZMA", "-mb0:1", "-mb0s1:2", "-mb0s2:3"], None),
        ("arm64.7z", &["-mf=ARM64"], None),
        ("delta.7z", &["-mf=Delta:4"], None),
        ("nonsolid.7z", &["-ms=off"], None),
        ("ultra.7z", &["-mx9"], None),
        ("aes.7z", &["-psecret"], Some("secret")),
        ("aes-hdr.7z", &["-psecret", "-mhe=on"], Some("secret")),
        ("store-hdr.7z", &["-mhc=off"], None),
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
}

#[test]
fn update_7z_keeps_everything() {
    let tmp = tempfile::tempdir().unwrap();
    let src = make_tree(tmp.path());
    let archive = tmp.path().join("u.7z");
    create(&archive, &[src.clone()], &CreateOptions::default(), &Progress::new()).unwrap();
    // Add a file, delete one, rename one.
    let extra = tmp.path().join("extra.txt");
    fs::write(&extra, b"new file").unwrap();
    let changes = zip67_core::update::Changes {
        add: vec![(extra.clone(), "data".into())],
        delete: vec!["data/empty.bin".into()],
        rename: vec![("data/run.sh".into(), "data/start.sh".into())],
        new_dirs: vec!["data/new folder".into()],
    };
    zip67_core::update::modify(&archive, &changes, &Default::default(), &Progress::new()).unwrap();
    let r = open(&archive, &OpenOptions::default()).unwrap();
    let names: Vec<&str> = r.entries().iter().map(|e| e.path.as_str()).collect();
    assert!(names.contains(&"data/extra.txt"));
    assert!(names.contains(&"data/start.sh"));
    assert!(names.contains(&"data/new folder"));
    assert!(!names.contains(&"data/empty.bin"));
    assert!(!names.contains(&"data/run.sh"));
    let out = tmp.path().join("x");
    extract_all(&archive, &out, None);
    assert_eq!(fs::read(out.join("data/sub/random.bin")).unwrap(), fs::read(src.join("sub/random.bin")).unwrap());
    assert_eq!(fs::read(out.join("data/extra.txt")).unwrap(), b"new file");
}
