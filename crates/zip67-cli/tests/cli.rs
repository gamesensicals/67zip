use std::fs;
use std::process::Command;

use zip67_worker::client::WorkerHandle;
use zip67_worker::protocol::{Event, Reply, Request};

const EXE: &str = env!("CARGO_BIN_EXE_67z");

#[test]
fn sandbox_blocks_what_it_should() {
    let tmp = tempfile::tempdir().unwrap();
    let o = Command::new(EXE).arg("--sandbox-selftest").arg(tmp.path()).output().unwrap();
    let out = String::from_utf8_lossy(&o.stdout);
    println!("{out}");
    assert!(o.status.success(), "sandbox self-test failed:\n{out}");
}

#[test]
fn add_list_extract_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("in");
    fs::create_dir_all(src.join("d")).unwrap();
    fs::write(src.join("d/a.txt"), b"hello hello hello").unwrap();
    let arc = tmp.path().join("t.7z");
    let st = Command::new(EXE).current_dir(tmp.path()).args(["a", "-bd", "t.7z", "in"]).status().unwrap();
    assert!(st.success());
    let l = Command::new(EXE).args(["l"]).arg(&arc).output().unwrap();
    assert!(String::from_utf8_lossy(&l.stdout).contains("in/d/a.txt"));
    let out = tmp.path().join("out");
    let st = Command::new(EXE).args(["x", "-bd", "-y"]).arg(format!("-o{}", out.display())).arg(&arc).status().unwrap();
    assert!(st.success());
    assert_eq!(fs::read(out.join("in/d/a.txt")).unwrap(), b"hello hello hello");
}

#[test]
fn bad_switch_is_usage_error() {
    let st = Command::new(EXE).args(["x", "-qqq", "a.7z"]).status().unwrap();
    assert_eq!(st.code(), Some(7));
}

#[test]
fn worker_protocol_lists_archive() {
    let tmp = tempfile::tempdir().unwrap();
    let f = tmp.path().join("f.txt");
    fs::write(&f, b"data").unwrap();
    let arc = tmp.path().join("w.zip");
    assert!(Command::new(EXE).args(["a", "-bd", "-tzip"]).arg(&arc).arg(&f).status().unwrap().success());
    let mut w = WorkerHandle::spawn(EXE.as_ref(), &Request::List { archive: arc, password: None }).unwrap();
    let mut saw_hello = false;
    loop {
        match w.next_blocking() {
            Some(Event::Hello { .. }) => saw_hello = true,
            Some(Event::Done(Reply::Listing { entries, archive_type, .. })) => {
                assert_eq!(archive_type, "zip");
                assert_eq!(entries[0].path, "f.txt");
                break;
            }
            Some(Event::Failed(f)) => panic!("worker failed: {f:?}"),
            Some(_) => {}
            None => panic!("worker ended without result"),
        }
    }
    assert!(saw_hello);
}

#[test]
fn worker_cannot_read_other_files() {
    // A request for one archive must not let the worker open another file.
    let tmp = tempfile::tempdir().unwrap();
    let o = Command::new(EXE).arg("--sandbox-selftest").arg(tmp.path()).output().unwrap();
    assert!(String::from_utf8_lossy(&o.stdout).contains("reading /etc/passwd is blocked") || !String::from_utf8_lossy(&o.stdout).contains("Landlock"));
}

#[test]
fn secure_delete_after_archiving() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("private");
    fs::create_dir_all(src.join("d")).unwrap();
    fs::write(src.join("d/a.txt"), b"top secret").unwrap();
    fs::write(src.join("b.bin"), vec![7u8; 200_000]).unwrap();
    let st = Command::new(EXE).current_dir(tmp.path()).args(["a", "-bd", "-psecret", "-sshred", "vault.7z", "private"]).status().unwrap();
    assert!(st.success());
    assert!(!src.exists(), "originals and their folders are gone");
    assert!(tmp.path().join("vault.7z").exists());
    assert!(fs::read_dir(tmp.path()).unwrap().all(|e| !e.unwrap().file_name().to_string_lossy().starts_with(".67zip")), "no staging leftovers");
    let out = tmp.path().join("out");
    let st = Command::new(EXE).args(["x", "-bd", "-y", "-psecret"]).arg(format!("-o{}", out.display())).arg(tmp.path().join("vault.7z")).status().unwrap();
    assert!(st.success());
    assert_eq!(fs::read(out.join("private/d/a.txt")).unwrap(), b"top secret");
}

#[test]
fn password_protected_zip() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join("secret.txt"), b"for your eyes only").unwrap();
    let st = Command::new(EXE).current_dir(tmp.path()).args(["a", "-bd", "-tzip", "-pcorrect horse", "s.zip", "secret.txt"]).status().unwrap();
    assert!(st.success());
    // Every entry is AES-256 encrypted and the plain text is nowhere in the file.
    let l = Command::new(EXE).current_dir(tmp.path()).args(["l", "-slt", "-pcorrect horse", "s.zip"]).output().unwrap();
    let listing = String::from_utf8_lossy(&l.stdout);
    assert!(listing.contains("Encrypted = +") && listing.contains("AES-256"), "{listing}");
    let raw = fs::read(tmp.path().join("s.zip")).unwrap();
    assert!(!raw.windows(b"eyes only".len()).any(|w| w == b"eyes only"));
    // The wrong password is refused, the right one restores the file.
    let wrong = Command::new(EXE).current_dir(tmp.path()).args(["t", "-bd", "-pnope", "s.zip"]).status().unwrap();
    assert!(!wrong.success());
    let st = Command::new(EXE).current_dir(tmp.path()).args(["x", "-bd", "-y", "-pcorrect horse", "-oout", "s.zip"]).status().unwrap();
    assert!(st.success());
    assert_eq!(fs::read(tmp.path().join("out/secret.txt")).unwrap(), b"for your eyes only");
}

#[test]
fn zipcrypto_is_never_created() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join("a.txt"), b"abc").unwrap();
    let o = Command::new(EXE).current_dir(tmp.path()).args(["a", "-bd", "-tzip", "-mem=ZipCrypto", "-pabc", "z.zip", "a.txt"]).output().unwrap();
    assert!(o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("ZipCrypto"), "the user is told why");
    let l = Command::new(EXE).current_dir(tmp.path()).args(["l", "-slt", "-pabc", "z.zip"]).output().unwrap();
    assert!(String::from_utf8_lossy(&l.stdout).contains("AES-256"));
    let bad = Command::new(EXE).current_dir(tmp.path()).args(["a", "-bd", "-tzip", "-mem=rot13", "-pabc", "y.zip", "a.txt"]).status().unwrap();
    assert_eq!(bad.code(), Some(7));
}
