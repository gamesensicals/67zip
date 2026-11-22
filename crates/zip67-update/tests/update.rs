//! The update client against a local stand-in for GitHub, with a throwaway
//! key generated here (never the real release key).

use std::collections::HashMap;
use std::io::{Cursor, Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};
use zip67_update::{install_appimage, keep_download, verify_manifest, Check, Client, UpdateError, Version};

struct Keys {
    pair: minisign::KeyPair,
}

impl Keys {
    fn new() -> Keys {
        Keys { pair: minisign::KeyPair::generate_unencrypted_keypair().unwrap() }
    }
    fn public(&self) -> minisign_verify::PublicKey {
        minisign_verify::PublicKey::decode(&self.pair.pk.to_box().unwrap().into_string()).unwrap()
    }
    fn sign(&self, data: &[u8]) -> String {
        minisign::sign(Some(&self.pair.pk), &self.pair.sk, Cursor::new(data), None, None).unwrap().into_string()
    }
}

/// A tiny HTTP server: path -> (status, extra headers, body).
type Routes = Arc<Mutex<HashMap<String, (u16, Vec<(String, String)>, Vec<u8>)>>>;

fn server() -> (String, Routes) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let routes: Routes = Arc::default();
    let r = routes.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let mut req = Vec::new();
            let mut byte = [0u8; 1];
            while !req.ends_with(b"\r\n\r\n") && s.read(&mut byte).map(|n| n == 1).unwrap_or(false) {
                req.push(byte[0]);
            }
            let line = String::from_utf8_lossy(&req).lines().next().unwrap_or("").to_string();
            let path = line.split(' ').nth(1).unwrap_or("/").to_string();
            let (status, headers, body) = r.lock().unwrap().get(&path).cloned().unwrap_or((404, vec![], b"no".to_vec()));
            let mut head = format!("HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n", body.len());
            for (k, v) in headers {
                head.push_str(&format!("{k}: {v}\r\n"));
            }
            head.push_str("\r\n");
            let _ = s.write_all(head.as_bytes());
            let _ = s.write_all(&body);
        }
    });
    (base, routes)
}

fn manifest(version: &str, package: &[u8], url_file: &str) -> Vec<u8> {
    let sha = Sha256::digest(package);
    let hex: String = sha.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        r#"{{"product":"67zip","version":"{version}","date":"2030-01-01","notes":"Faster and safer.","packages":{{"appimage-x86_64":{{"url":"https://github.com/gamesensicals/67zip/releases/download/v{version}/{url_file}","size":{},"sha256":"{hex}"}}}}}}"#,
        package.len()
    )
    .into_bytes()
}

fn publish(routes: &Routes, keys: &Keys, manifest: &[u8], version: &str, file: &str, package: &[u8]) {
    let mut r = routes.lock().unwrap();
    r.insert("/latest.json".into(), (200, vec![], manifest.to_vec()));
    r.insert("/latest.json.minisig".into(), (200, vec![], keys.sign(manifest).into_bytes()));
    r.insert(format!("/gamesensicals/67zip/releases/download/v{version}/{file}"), (200, vec![], package.to_vec()));
}

#[test]
fn finds_downloads_and_verifies_an_update() {
    let keys = Keys::new();
    let (base, routes) = server();
    let package = b"#!/bin/sh\necho new 67zip\n".repeat(5000);
    let m = manifest("9.9.9", &package, "67zip-x86_64.AppImage");
    publish(&routes, &keys, &m, "9.9.9", "67zip-x86_64.AppImage", &package);
    let client = Client::for_tests(&base, keys.public());

    let Check::Available(found) = client.check(Version(0, 1, 1)).unwrap() else { panic!("no update found") };
    assert_eq!(found.version, Version(9, 9, 9));
    assert_eq!(found.notes, "Faster and safer.");
    // The same or a newer version installed: nothing to offer.
    assert_eq!(client.check(Version(9, 9, 9)).unwrap(), Check::UpToDate(Version(9, 9, 9)));
    assert_eq!(client.check(Version(10, 0, 0)).unwrap(), Check::UpToDate(Version(9, 9, 9)));

    let dir = tempfile::tempdir().unwrap();
    let pkg = found.package("appimage-x86_64").unwrap();
    let seen = Mutex::new(0u64);
    let tmp = client.download(pkg, dir.path(), &|done, _| *seen.lock().unwrap() = done, &AtomicBool::new(false)).unwrap();
    assert_eq!(std::fs::read(&tmp).unwrap(), package);
    assert_eq!(*seen.lock().unwrap(), package.len() as u64);
    assert_eq!(std::fs::metadata(&tmp).unwrap().permissions().mode() & 0o777, 0o600);

    // AppImage: replaced in place and made executable.
    let target = dir.path().join("67zip.AppImage");
    std::fs::write(&target, b"old").unwrap();
    install_appimage(&tmp, &target).unwrap();
    assert_eq!(std::fs::read(&target).unwrap(), package);
    assert_eq!(std::fs::metadata(&target).unwrap().permissions().mode() & 0o777, 0o755);
}

#[test]
fn tampering_is_caught() {
    let keys = Keys::new();
    let other = Keys::new();
    let (base, routes) = server();
    let package = vec![7u8; 100_000];
    let good = manifest("2.0.0", &package, "a.AppImage");
    let client = Client::for_tests(&base, keys.public());
    let set = |body: &[u8], sig: String| {
        let mut r = routes.lock().unwrap();
        r.insert("/latest.json".into(), (200, vec![], body.to_vec()));
        r.insert("/latest.json.minisig".into(), (200, vec![], sig.into_bytes()));
    };

    // Changed after signing.
    let mut changed = good.clone();
    let at = changed.windows(5).position(|w| w == b"2.0.0").unwrap();
    changed[at] = b'3';
    set(&changed, keys.sign(&good));
    assert!(matches!(client.check(Version(0, 1, 1)), Err(UpdateError::BadSignature(_))));
    // Signed by someone else.
    set(&good, other.sign(&good));
    assert!(matches!(client.check(Version(0, 1, 1)), Err(UpdateError::BadSignature(_))));
    // No signature at all.
    routes.lock().unwrap().remove("/latest.json.minisig");
    assert!(client.check(Version(0, 1, 1)).is_err());
    // Garbage instead of a signature.
    set(&good, "untrusted comment: x\nnot base64 at all\n".into());
    assert!(matches!(client.check(Version(0, 1, 1)), Err(UpdateError::BadSignature(_))));
    // A huge manifest is cut off before parsing.
    let huge = vec![b' '; 1 << 20];
    set(&huge, keys.sign(&huge));
    assert!(matches!(client.check(Version(0, 1, 1)), Err(UpdateError::TooLarge)));

    // The package: same size, other bytes -> rejected and removed.
    set(&good, keys.sign(&good));
    let mut evil = package.clone();
    evil[500] ^= 1;
    routes.lock().unwrap().insert("/gamesensicals/67zip/releases/download/v2.0.0/a.AppImage".into(), (200, vec![], evil));
    let Check::Available(m) = client.check(Version(0, 1, 1)).unwrap() else { panic!() };
    let dir = tempfile::tempdir().unwrap();
    let r = client.download(&m.packages[0], dir.path(), &|_, _| {}, &AtomicBool::new(false));
    assert!(matches!(r, Err(UpdateError::Mismatch(_))), "{r:?}");
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0, "nothing is left behind");
    // Longer than signed.
    let mut longer = package.clone();
    longer.push(0);
    routes.lock().unwrap().insert("/gamesensicals/67zip/releases/download/v2.0.0/a.AppImage".into(), (200, vec![], longer));
    assert!(matches!(client.download(&m.packages[0], dir.path(), &|_, _| {}, &AtomicBool::new(false)), Err(UpdateError::Mismatch(_))));
    // Cancelled.
    routes.lock().unwrap().insert("/gamesensicals/67zip/releases/download/v2.0.0/a.AppImage".into(), (200, vec![], package.clone()));
    assert!(matches!(client.download(&m.packages[0], dir.path(), &|_, _| {}, &AtomicBool::new(true)), Err(UpdateError::Cancelled)));
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn redirects_stay_on_allowed_hosts() {
    let keys = Keys::new();
    let (base, routes) = server();
    let m = manifest("2.0.0", b"x", "a");
    {
        let mut r = routes.lock().unwrap();
        r.insert("/latest.json".into(), (302, vec![("Location".into(), "/moved.json".into())], vec![]));
        r.insert("/moved.json".into(), (200, vec![], m.clone()));
        r.insert("/latest.json.minisig".into(), (302, vec![("Location".into(), "http://127.0.0.1:9/evil".into())], vec![]));
    }
    let client = Client::for_tests(&base, keys.public());
    match client.check(Version(0, 1, 1)) {
        Err(UpdateError::Network(e)) => assert!(e.contains("refusing"), "{e}"),
        other => panic!("{other:?}"),
    }
    // A redirect loop ends.
    routes.lock().unwrap().insert("/latest.json".into(), (302, vec![("Location".into(), "/latest.json".into())], vec![]));
    assert!(matches!(client.check(Version(0, 1, 1)), Err(UpdateError::Network(_))));
}

#[test]
fn signed_but_invalid_manifests() {
    let keys = Keys::new();
    let key = keys.public();
    let good = String::from_utf8(manifest("1.2.3", b"abc", "f.AppImage")).unwrap();
    assert!(verify_manifest(good.as_bytes(), &keys.sign(good.as_bytes()), &key).is_ok());
    let cases = [
        good.replace("\"67zip\"", "\"other\""),
        good.replace("1.2.3\",\"date", "1.2\",\"date"),
        good.replace("https://github.com/gamesensicals/67zip/releases/download/", "https://evil.example/gamesensicals/67zip/releases/download/"),
        good.replace("https://github.com/gamesensicals/67zip/", "https://github.com/someone/67zip/"),
        good.replace("v1.2.3/f.AppImage", "v1.2.3/../../evil"),
        good.replace("v1.2.3/f.AppImage", "v1.2.3/a/b"),
        good.replace("\"size\":3", "\"size\":0"),
        good.replace("\"size\":3", "\"size\":99999999999"),
        good.replace("\"sha256\":\"", "\"sha256\":\"zz"),
        good.replace("\"notes\"", "\"extra\":1,\"notes\""),
        good.replace("appimage-x86_64", "app image"),
        "not json".to_string(),
    ];
    for bad in cases {
        let r = verify_manifest(bad.as_bytes(), &keys.sign(bad.as_bytes()), &key);
        assert!(matches!(r, Err(UpdateError::BadManifest(_))), "accepted: {bad}");
    }
}

#[test]
fn downloads_never_overwrite() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("67zip-1.0.0-x86_64.AppImage"), b"mine").unwrap();
    let tmp = dir.path().join(".part");
    std::fs::write(&tmp, b"new").unwrap();
    let kept = keep_download(&tmp, dir.path(), "67zip-1.0.0-x86_64.AppImage").unwrap();
    assert_eq!(kept.file_name().unwrap(), "67zip-1.0.0-x86_64 (2).AppImage");
    assert_eq!(std::fs::read(dir.path().join("67zip-1.0.0-x86_64.AppImage")).unwrap(), b"mine");
    assert!(!tmp.exists());
}

/// Writes a throwaway password-protected secret key to `$KEY_OUT`, for
/// trying the release tool by hand: `KEY_OUT=/tmp/k cargo test -- --ignored`.
#[test]
#[ignore]
fn write_throwaway_secret_key() {
    let out = std::env::var("KEY_OUT").unwrap();
    let kp = minisign::KeyPair::generate_encrypted_keypair(Some("pw".into())).unwrap();
    std::fs::write(out, kp.sk.to_box(None).unwrap().into_string()).unwrap();
}
