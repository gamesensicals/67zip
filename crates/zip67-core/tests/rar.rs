//! RAR reading against sample archives from libarchive's test suite (see
//! tests/data/rar/README.md). Set RAR_UPDATE_EXPECTED=1 to rewrite
//! expected.txt after checking the output against another RAR reader.

use std::io::Read;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use zip67_core::{open, Entry, EntryVisitor, Error, OpenOptions, Password, Progress, Result};

fn data() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/rar")
}

#[derive(Default)]
struct Collect {
    lines: Vec<String>,
}

impl EntryVisitor for Collect {
    fn file(&mut self, e: &Entry, data: &mut dyn Read) -> Result<()> {
        let mut v = Vec::new();
        data.read_to_end(&mut v)?;
        let h: String = Sha256::digest(&v)[..8].iter().map(|b| format!("{b:02x}")).collect();
        self.lines.push(format!("F {} {} {h}", e.path, v.len()));
        Ok(())
    }
    fn dir(&mut self, e: &Entry) -> Result<()> {
        self.lines.push(format!("D {}", e.path));
        Ok(())
    }
    fn symlink(&mut self, e: &Entry, t: &str) -> Result<()> {
        self.lines.push(format!("L {} -> {t}", e.path));
        Ok(())
    }
    fn hardlink(&mut self, e: &Entry, t: &str) -> Result<()> {
        self.lines.push(format!("H {} -> {t}", e.path));
        Ok(())
    }
    fn entry_error(&mut self, e: &Entry, err: Error) -> Result<()> {
        self.lines.push(format!("E {}: {err}", e.path));
        Ok(())
    }
}

fn password_for(name: &str) -> Option<&'static str> {
    if name.starts_with("rar_encryption") {
        Some("12345678")
    } else if name.contains("encrypted") {
        Some("password")
    } else {
        None
    }
}

/// What 67zip makes of one archive, as text.
fn describe(name: &str) -> String {
    let opts = OpenOptions { password: password_for(name).map(Password::new), ..Default::default() };
    let mut out = format!("== {name}\n");
    match open(&data().join(name), &opts) {
        Ok(mut r) => {
            let info = r.info();
            out += &format!("format {} volumes {} solid {} entries {}\n", info.format, info.volumes, info.solid, r.entries().len());
            for p in &info.problems {
                out += &format!("problem {p}\n");
            }
            let mut c = Collect::default();
            if let Err(e) = r.extract(&|_| true, &mut c, &Progress::new()) {
                c.lines.push(format!("fatal {e}"));
            }
            for l in c.lines {
                out += &l;
                out.push('\n');
            }
        }
        Err(e) => out += &format!("open error: {e}\n"),
    }
    out
}

fn archives() -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(data())
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|n| (n.ends_with(".rar") || n.ends_with(".exe")) && !n.contains(".part") || n.ends_with(".part1.rar") || n.ends_with(".part01.rar"))
        .collect();
    v.sort();
    v
}

#[test]
fn samples_match_expected() {
    let got: String = archives().iter().map(|n| describe(n)).collect();
    let path = data().join("expected.txt");
    if std::env::var_os("RAR_UPDATE_EXPECTED").is_some() {
        std::fs::write(&path, &got).unwrap();
        return;
    }
    let want = std::fs::read_to_string(&path).unwrap();
    if got != want {
        for (g, w) in got.lines().zip(want.lines()) {
            if g != w {
                panic!("first difference:\n got: {g}\nwant: {w}");
            }
        }
        panic!("output length differs ({} vs {} lines)", got.lines().count(), want.lines().count());
    }
}

#[test]
fn wrong_and_missing_passwords() {
    for (name, wrong_err) in [("rar5_encrypted_filenames.rar", true), ("rar_encryption_header.rar", true)] {
        let p = data().join(name);
        assert!(matches!(open(&p, &OpenOptions::default()), Err(Error::PasswordRequired)), "{name}");
        let opts = OpenOptions { password: Some(Password::new("not it")), ..Default::default() };
        assert_eq!(matches!(open(&p, &opts), Err(Error::WrongPassword)), wrong_err, "{name}");
    }
    // Encrypted data with plain headers: listed, then refused per file.
    let opts = OpenOptions { password: Some(Password::new("not it")), ..Default::default() };
    for name in ["rar5_solid_encrypted.rar", "rar_encryption_data.rar", "rar4_solid_encrypted.rar"] {
        let mut r = open(&data().join(name), &opts).unwrap();
        let mut c = Collect::default();
        r.extract(&|_| true, &mut c, &Progress::new()).unwrap();
        assert!(c.lines.iter().any(|l| l.starts_with('E') && l.contains("wrong password")), "{name}: {:?}", c.lines);
        assert!(!c.lines.iter().any(|l| l.starts_with('F')), "{name}: {:?}", c.lines);
    }
}

#[test]
fn self_extracting_and_truncated() {
    let tmp = tempfile::tempdir().unwrap();
    let rar = std::fs::read(data().join("rar5_compressed.rar")).unwrap();
    // A fake program in front: the archive is found after it.
    let mut sfx = b"MZ".to_vec();
    sfx.extend(std::iter::repeat_n(0x90u8, 70_000));
    sfx.extend_from_slice(&rar);
    let p = tmp.path().join("setup.exe");
    std::fs::write(&p, &sfx).unwrap();
    let mut r = open(&p, &OpenOptions::default()).unwrap();
    assert_eq!(r.info().offset, 70_002);
    let mut c = Collect::default();
    r.extract(&|_| true, &mut c, &Progress::new()).unwrap();
    assert!(c.lines.iter().any(|l| l.starts_with("F test.bin 1200 ")), "{:?}", c.lines);

    // Cut off in the middle of the data: the file fails, the cut is reported.
    let p = tmp.path().join("cut.rar");
    std::fs::write(&p, &rar[..rar.len() - 200]).unwrap();
    let mut r = open(&p, &OpenOptions::default()).unwrap();
    assert!(!r.info().problems.is_empty());
    let mut c = Collect::default();
    r.extract(&|_| true, &mut c, &Progress::new()).unwrap();
    assert!(c.lines.iter().all(|l| !l.starts_with('F')), "{:?}", c.lines);
}

#[test]
fn volumes_found_from_any_part() {
    let a = describe("rar5_multiarchive_solid.part01.rar");
    let b = describe("rar5_multiarchive_solid.part03.rar").replace("part03", "part01");
    assert_eq!(a, b);
    assert!(a.contains("volumes 4"));
}

mod rar5enc;

#[test]
fn files_from_test_encoder() {
    // Several blocks, repeat distances, long and short matches, an empty
    // file; checked through the CRC and by comparing the content.
    let mut text = Vec::new();
    for i in 0..60_000u32 {
        text.extend_from_slice(format!("line {i}: the quick brown fox {} jumps\n", i % 97).as_bytes());
    }
    let mut bin = Vec::new();
    let mut x = 0x1234_5678u32;
    for i in 0..1_500_000u32 {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        bin.push(if i % 3 == 0 { (x >> 24) as u8 } else { (i / 1000) as u8 });
    }
    let files: Vec<(&str, &[u8])> = vec![("text.txt", &text), ("empty", &[]), ("bin.dat", &bin)];
    let arc = rar5enc::archive(&files);
    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path().join("enc.rar");
    std::fs::write(&p, &arc).unwrap();
    let mut r = open(&p, &OpenOptions::default()).unwrap();
    struct Grab(Vec<(String, Vec<u8>)>);
    impl EntryVisitor for Grab {
        fn file(&mut self, e: &Entry, data: &mut dyn Read) -> Result<()> {
            let mut v = Vec::new();
            data.read_to_end(&mut v)?;
            self.0.push((e.path.clone(), v));
            Ok(())
        }
    }
    let mut g = Grab(Vec::new());
    r.extract(&|_| true, &mut g, &Progress::new()).unwrap();
    assert_eq!(g.0.len(), 3);
    for ((name, want), (got_name, got)) in files.iter().zip(&g.0) {
        assert_eq!(name, got_name);
        assert!(got == want, "{name} differs");
    }
}

#[test]
fn fuzz_finds_fail_cleanly() {
    for f in std::fs::read_dir(data().join("fuzz")).unwrap() {
        let p = f.unwrap().path();
        let opts = OpenOptions { password: Some(Password::new("fuzz")), ..Default::default() };
        if let Ok(mut r) = open(&p, &opts) {
            let _ = r.extract(&|_| true, &mut Collect::default(), &Progress::new());
        }
    }
}
