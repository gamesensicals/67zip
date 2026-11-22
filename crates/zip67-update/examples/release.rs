//! Release tooling, used by `.github/workflows/release.yml`:
//!
//!     release manifest <version> <tag> <CHANGELOG.md> <file>=<kind>...  > latest.json
//!     release notes <version> <CHANGELOG.md>                            > notes.md
//!     release sign <secret key file> <file>...
//!
//! `sign` reads the key's password from `MINISIGN_PASSWORD`, writes
//! `<file>.minisig` next to each file and then checks every signature
//! against the release key built into 67zip, so a wrong key fails the
//! release instead of shipping updates nobody can verify.

use std::io::Cursor;
use std::path::Path;
use std::process::exit;

use sha2::{Digest, Sha256};

fn fail(msg: impl std::fmt::Display) -> ! {
    eprintln!("release: {msg}");
    exit(1)
}

/// The CHANGELOG section of `version`, without its heading.
fn changelog_section(path: &str, version: &str) -> String {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| fail(format!("{path}: {e}")));
    let mut out = Vec::new();
    let mut found = false;
    let mut inside = false;
    for line in text.lines() {
        if let Some(h) = line.strip_prefix("## ") {
            if inside {
                break;
            }
            inside = h.split_whitespace().next() == Some(version);
            found |= inside;
            continue;
        }
        if inside {
            out.push(line);
        }
    }
    if !found {
        fail(format!("no \"## {version}\" section in {path}"));
    }
    out.join("\n").trim().to_string()
}

fn today() -> String {
    std::process::Command::new("date").args(["-u", "+%Y-%m-%d"]).output().map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_default()
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("manifest") if args.len() >= 5 => {
            let (version, tag, changelog) = (&args[1], &args[2], &args[3]);
            if zip67_update::Version::parse(version).is_none() || *tag != format!("v{version}") {
                fail("version must be MAJOR.MINOR.PATCH and the tag v<version>");
            }
            // Plain text for the app: no Markdown emphasis or code marks.
            let notes = changelog_section(changelog, version).replace("**", "").replace('`', "");
            let mut packages = serde_json::Map::new();
            for spec in &args[4..] {
                let (file, kind) = spec.split_once('=').unwrap_or_else(|| fail(format!("expected <file>=<kind>, got {spec}")));
                let data = std::fs::read(file).unwrap_or_else(|e| fail(format!("{file}: {e}")));
                let name = Path::new(file).file_name().and_then(|n| n.to_str()).unwrap_or_else(|| fail("bad file name"));
                let sha: String = Sha256::digest(&data).iter().map(|b| format!("{b:02x}")).collect();
                packages.insert(
                    kind.to_string(),
                    serde_json::json!({
                        "url": format!("https://github.com/gamesensicals/67zip/releases/download/{tag}/{name}"),
                        "size": data.len(),
                        "sha256": sha,
                    }),
                );
            }
            let m = serde_json::json!({ "product": "67zip", "version": version, "date": today(), "notes": notes, "packages": packages });
            let bytes = serde_json::to_vec_pretty(&m).unwrap_or_else(|e| fail(e));
            // Exactly the checks the app makes, minus the signature.
            zip67_update::parse_manifest(&bytes).unwrap_or_else(|e| fail(e));
            println!("{}", String::from_utf8_lossy(&bytes));
        }
        Some("notes") if args.len() == 3 => println!("{}", changelog_section(&args[2], &args[1])),
        Some("sign") if args.len() >= 3 => {
            let password = std::env::var("MINISIGN_PASSWORD").ok().filter(|p| !p.is_empty());
            let boxed = std::fs::read_to_string(&args[1]).unwrap_or_else(|e| fail(format!("secret key: {e}")));
            let sk = minisign::SecretKeyBox::from_string(&boxed)
                .and_then(|b| b.into_secret_key(password))
                .unwrap_or_else(|e| fail(format!("can't open the secret key (wrong MINISIGN_PASSWORD?): {e}")));
            let key = zip67_update::release_key();
            for file in &args[2..] {
                let data = std::fs::read(file).unwrap_or_else(|e| fail(format!("{file}: {e}")));
                let name = Path::new(file).file_name().and_then(|n| n.to_str()).unwrap_or("file");
                let sig = minisign::sign(None, &sk, Cursor::new(&data), Some(&format!("67zip release file: {name}")), None)
                    .unwrap_or_else(|e| fail(format!("signing {file}: {e}")))
                    .into_string();
                let parsed = minisign_verify::Signature::decode(&sig).unwrap_or_else(|e| fail(e));
                if let Err(e) = key.verify(&data, &parsed, false) {
                    fail(format!(
                        "the signature of {file} doesn't match the release key built into 67zip ({}): {e}. Is MINISIGN_SECRET_KEY the right key?",
                        zip67_update::KEY_ID
                    ));
                }
                std::fs::write(format!("{file}.minisig"), sig).unwrap_or_else(|e| fail(e));
                eprintln!("signed and verified {name}");
            }
        }
        _ => fail("usage: release manifest <version> <tag> <CHANGELOG.md> <file>=<kind>... | notes <version> <CHANGELOG.md> | sign <key> <file>..."),
    }
}
