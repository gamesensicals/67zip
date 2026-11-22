mod common;

use std::process::Command;

use common::*;
use zip67_core::{OpenOptions, open};

#[test]
fn reads_iso_images() {
    if Command::new("genisoimage")
        .arg("--version")
        .output()
        .is_err()
    {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let src = make_tree(tmp.path());
    for (name, flags) in [
        ("rr.iso", vec!["-R"]),
        ("joliet.iso", vec!["-J"]),
        ("plain.iso", vec![]),
    ] {
        let iso = tmp.path().join(name);
        let mut c = Command::new("genisoimage");
        c.args(&flags)
            .arg("-quiet")
            .arg("-o")
            .arg(&iso)
            .arg(tmp.path().join("data"));
        assert!(c.status().unwrap().success());
        let r = open(&iso, &OpenOptions::default()).unwrap();
        assert_eq!(r.archive_type().id(), "iso");
        let out = tmp.path().join(format!("x-{name}"));
        let rep = extract_all(&iso, &out, None);
        assert!(rep.errors.is_empty(), "{name}: {:?}", rep.errors);
        if name == "rr.iso" {
            // Rock Ridge keeps names, permissions and symlinks exactly.
            assert_same_tree(&src, &out);
        } else {
            // Without Rock Ridge, at least the file contents must survive.
            let n = std::fs::read(out.join(if name == "joliet.iso" {
                "hello.txt"
            } else {
                "HELLO.TXT"
            }))
            .unwrap();
            assert_eq!(n, std::fs::read(src.join("hello.txt")).unwrap(), "{name}");
        }
    }
}
