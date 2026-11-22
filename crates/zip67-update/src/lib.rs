//! Update checks and downloads for 67zip.
//!
//! Every release carries `latest.json`, a small manifest with the version,
//! release notes and, for each package, its download address, size and
//! SHA-256 hash. The manifest is signed with the 67zip release key
//! (minisign, Ed25519, key ID [`KEY_ID`]); the public key is built into
//! the program. Nothing in the manifest is used before its signature
//! checks out, and a download is used only if its size and hash match the
//! signed manifest. So a hijacked website, mirror or network can at worst
//! make the check fail; it cannot deliver a different program.
//!
//! Further rules:
//! - HTTPS only, to GitHub's own hosts, with timeouts and size caps on
//!   everything read; redirects are followed by hand and checked too.
//! - Older or equal versions are never offered (no downgrades).
//! - Nothing is sent but a request with a `67zip/<version>` user agent.
//! - Nothing downloaded is ever run. An AppImage is replaced in one atomic
//!   rename after verification; other installs get the verified file in
//!   their Downloads folder plus instructions.
//!
//! This code runs in the app's own process, never in the sandboxed worker,
//! which has no network access.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use minisign_verify::{PublicKey, Signature};
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// The 67zip release key (minisign public key file).
pub const PUBLIC_KEY: &str = include_str!("../../../data/67zip-update.pub");
/// Its key ID, as minisign prints it.
pub const KEY_ID: &str = "269FF0C6C87BEF0F";
/// Where the newest release's manifest lives.
pub const MANIFEST_URL: &str = "https://github.com/gamesensicals/67zip/releases/latest/download/latest.json";
/// The release page, for people who update by hand.
pub const RELEASES_PAGE: &str = "https://github.com/gamesensicals/67zip/releases/latest";

/// Hosts the client may talk to: GitHub and its release download hosts.
const ALLOWED_HOSTS: &[&str] = &["github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"];
/// Package addresses in the manifest must point into this project's releases.
const ASSET_PREFIX: &str = "https://github.com/gamesensicals/67zip/releases/download/";

const MAX_MANIFEST: u64 = 64 << 10;
const MAX_SIGNATURE: u64 = 4 << 10;
/// No 67zip package comes anywhere near this.
pub const MAX_PACKAGE: u64 = 512 << 20;
const MAX_NOTES: usize = 16 << 10;
const MAX_REDIRECTS: usize = 5;

/// What can go wrong; every case leaves the installed program untouched.
#[derive(Debug)]
pub enum UpdateError {
    /// Network, TLS or HTTP failure.
    Network(String),
    /// Nothing has been released yet.
    NoRelease,
    /// The manifest's signature is missing, malformed or not by the release key.
    BadSignature(String),
    /// The signed manifest is malformed or breaks a rule.
    BadManifest(String),
    /// A response was bigger than allowed.
    TooLarge,
    /// The download doesn't match the signed size or hash.
    Mismatch(String),
    /// No package for this kind of installation.
    NoPackage,
    Cancelled,
    Io(io::Error),
}

impl fmt::Display for UpdateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UpdateError::Network(e) => write!(f, "couldn't reach the update server: {e}"),
            UpdateError::NoRelease => write!(f, "no 67zip release has been published yet"),
            UpdateError::BadSignature(e) => write!(f, "the update information isn't signed by the 67zip release key ({e})"),
            UpdateError::BadManifest(e) => write!(f, "the update information is invalid: {e}"),
            UpdateError::TooLarge => write!(f, "the server sent more data than allowed"),
            UpdateError::Mismatch(e) => write!(f, "the download doesn't match the signed release ({e}); nothing was changed"),
            UpdateError::NoPackage => write!(f, "this release has no package for this kind of installation"),
            UpdateError::Cancelled => write!(f, "cancelled"),
            UpdateError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for UpdateError {}

impl From<io::Error> for UpdateError {
    fn from(e: io::Error) -> Self {
        UpdateError::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, UpdateError>;

/// A release version: `MAJOR.MINOR.PATCH`, digits only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version(pub u32, pub u32, pub u32);

impl Version {
    pub fn parse(s: &str) -> Option<Version> {
        let mut it = s.split('.');
        let mut part = || {
            let p = it.next()?;
            if p.is_empty() || p.len() > 9 || !p.bytes().all(|b| b.is_ascii_digit()) || (p.len() > 1 && p.starts_with('0')) {
                return None;
            }
            p.parse().ok()
        };
        let v = Version(part()?, part()?, part()?);
        it.next().is_none().then_some(v)
    }

    /// The version of this program.
    pub fn current() -> Version {
        Version::parse(env!("CARGO_PKG_VERSION")).expect("the crate version is MAJOR.MINOR.PATCH")
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}

/// One downloadable package of a release.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Package {
    /// e.g. `appimage-x86_64`, `deb-x86_64`.
    pub kind: String,
    pub url: String,
    pub size: u64,
    pub sha256: [u8; 32],
}

impl Package {
    /// The file name at the end of the address.
    pub fn file_name(&self) -> &str {
        self.url.rsplit('/').next().unwrap_or("67zip-update")
    }
}

/// A verified release manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub version: Version,
    pub date: String,
    pub notes: String,
    pub packages: Vec<Package>,
}

impl Manifest {
    pub fn package(&self, kind: &str) -> Option<&Package> {
        self.packages.iter().find(|p| p.kind == kind)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManifest {
    product: String,
    version: String,
    date: String,
    #[serde(default)]
    notes: String,
    packages: BTreeMap<String, RawPackage>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPackage {
    url: String,
    size: u64,
    sha256: String,
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, pair) in s.as_bytes().chunks(2).enumerate() {
        let hex = |c: u8| match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        };
        out[i] = hex(pair[0])? << 4 | hex(pair[1])?;
    }
    Some(out)
}

/// The built-in release key.
pub fn release_key() -> PublicKey {
    PublicKey::decode(PUBLIC_KEY).expect("the built-in release key is valid")
}

/// Checks the signature of `manifest` and only then parses it.
pub fn verify_manifest(manifest: &[u8], signature: &str, key: &PublicKey) -> Result<Manifest> {
    let sig = Signature::decode(signature).map_err(|e| UpdateError::BadSignature(e.to_string()))?;
    key.verify(manifest, &sig, false).map_err(|e| UpdateError::BadSignature(e.to_string()))?;
    parse_manifest(manifest)
}

/// Parses and checks a manifest whose signature was already verified
/// (public for the release tooling and fuzzing).
#[doc(hidden)]
pub fn parse_manifest(manifest: &[u8]) -> Result<Manifest> {
    let bad = |m: &str| UpdateError::BadManifest(m.to_string());
    let raw: RawManifest = serde_json::from_slice(manifest).map_err(|e| UpdateError::BadManifest(e.to_string()))?;
    if raw.product != "67zip" {
        return Err(bad("it is for another program"));
    }
    let version = Version::parse(&raw.version).ok_or_else(|| bad("bad version"))?;
    if raw.notes.len() > MAX_NOTES || raw.date.len() > 32 {
        return Err(bad("text too long"));
    }
    if raw.packages.len() > 32 {
        return Err(bad("too many packages"));
    }
    let mut packages = Vec::new();
    for (kind, p) in raw.packages {
        if kind.is_empty() || kind.len() > 64 || !kind.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
            return Err(bad("bad package name"));
        }
        let rest = p.url.strip_prefix(ASSET_PREFIX).ok_or_else(|| bad("a package is not on the 67zip release page"))?;
        // "<tag>/<file>": plain names only, no way to climb out of the release.
        let mut parts = rest.split('/');
        let (tag, file) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
        let plain = |s: &str| !s.is_empty() && s != "." && s != ".." && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b));
        if parts.next().is_some() || !plain(tag) || !plain(file) {
            return Err(bad("bad package address"));
        }
        if p.size == 0 || p.size > MAX_PACKAGE {
            return Err(bad("bad package size"));
        }
        let sha256 = hex32(&p.sha256).ok_or_else(|| bad("bad package hash"))?;
        packages.push(Package { kind, url: p.url, size: p.size, sha256 });
    }
    Ok(Manifest { version, date: raw.date, notes: raw.notes, packages })
}

/// How this copy of 67zip was installed, which decides how it updates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Install {
    /// An AppImage: it can replace itself.
    AppImage(PathBuf),
    /// Flatpak updates come from Flathub / `flatpak update`; no checks.
    Flatpak,
    /// A distribution package (deb/rpm) under /usr: the package manager updates it.
    Package,
    /// Built from source with `install.sh` (or run from a build folder).
    Source,
}

impl Install {
    pub fn detect() -> Install {
        if std::env::var_os("FLATPAK_ID").is_some() || Path::new("/.flatpak-info").exists() {
            return Install::Flatpak;
        }
        if let Some(p) = std::env::var_os("APPIMAGE").map(PathBuf::from)
            && p.is_absolute()
            && p.is_file()
        {
            return Install::AppImage(p);
        }
        match std::env::current_exe() {
            Ok(exe) if exe.starts_with("/usr/bin") || exe.starts_with("/usr/lib") || exe.starts_with("/bin") => Install::Package,
            _ => Install::Source,
        }
    }

    /// Whether to look for updates at all.
    pub fn checks_for_updates(&self) -> bool {
        !matches!(self, Install::Flatpak)
    }

    /// The package this installation wants, if any.
    pub fn package_kind(&self) -> Option<String> {
        let arch = std::env::consts::ARCH;
        match self {
            Install::AppImage(_) | Install::Source => Some(format!("appimage-{arch}")),
            Install::Package if Path::new("/usr/bin/dpkg").exists() => Some(format!("deb-{arch}")),
            Install::Package | Install::Flatpak => None,
        }
    }

    /// What to tell people whose installation can't update itself.
    pub fn how_to_update(&self, file: Option<&Path>) -> String {
        match (self, file) {
            (Install::AppImage(_), _) => "The new version replaces this AppImage. Restart 67zip to use it.".into(),
            (Install::Flatpak, _) => "Update 67zip from your software centre, or run: flatpak update".into(),
            (Install::Package, Some(f)) => format!("Install it with your package manager, e.g.: sudo apt install {}", shell_quote(f)),
            (Install::Package, None) => "Update 67zip with your package manager.".into(),
            (Install::Source, Some(f)) => format!(
                "Saved a ready-to-run AppImage: {}. Or update your own build: git pull && ./install.sh",
                f.display()
            ),
            (Install::Source, None) => "Update your build: git pull && ./install.sh".into(),
        }
    }
}

fn shell_quote(p: &Path) -> String {
    let s = p.to_string_lossy();
    if s.bytes().all(|b| b.is_ascii_alphanumeric() || b"/._-+".contains(&b)) {
        s.into_owned()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

/// Result of a check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Check {
    UpToDate(Version),
    Available(Manifest),
}

/// The update client.
pub struct Client {
    agent: ureq::Agent,
    manifest_url: String,
    /// Tests only: a plain-HTTP server on the loopback address that stands
    /// in for GitHub.
    test_base: Option<String>,
    key: PublicKey,
}

impl Client {
    /// The real client: HTTPS to GitHub, verified with the release key.
    pub fn new() -> Client {
        Self::build(MANIFEST_URL.to_string(), None, release_key())
    }

    /// A client for tests: a local plain-HTTP server and a test key.
    #[doc(hidden)]
    pub fn for_tests(base: &str, key: PublicKey) -> Client {
        assert!(base.starts_with("http://127.0.0.1:") && !base[17..].contains('/'), "test clients only talk to the loopback address");
        Self::build(format!("{base}/latest.json"), Some(base.to_string()), key)
    }

    fn build(manifest_url: String, test_base: Option<String>, key: PublicKey) -> Client {
        let tls = ureq::tls::TlsConfig::builder().root_certs(ureq::tls::RootCerts::PlatformVerifier).build();
        let config = ureq::Agent::config_builder()
            .https_only(test_base.is_none())
            .max_redirects(0)
            .http_status_as_error(false)
            .timeout_connect(Some(Duration::from_secs(15)))
            .timeout_per_read(Some(Duration::from_secs(30)))
            .timeout_global(Some(Duration::from_secs(30 * 60)))
            .user_agent(format!("67zip/{}", env!("CARGO_PKG_VERSION")))
            .tls_config(tls)
            .build();
        Client { agent: ureq::Agent::new_with_config(config), manifest_url, test_base, key }
    }

    fn allowed(&self, url: &str) -> bool {
        if let Some(base) = &self.test_base {
            return url.strip_prefix(base.as_str()).is_some_and(|rest| rest.starts_with('/'));
        }
        let Some(rest) = url.strip_prefix("https://") else { return false };
        let host = rest.split(['/', '?', '#']).next().unwrap_or("");
        ALLOWED_HOSTS.contains(&host)
    }

    /// GET with hand-checked redirects. Returns the response and its size if known.
    fn get(&self, url: &str) -> Result<(ureq::http::Response<ureq::Body>, Option<u64>)> {
        let mut url = url.to_string();
        for _ in 0..=MAX_REDIRECTS {
            if !self.allowed(&url) {
                return Err(UpdateError::Network(format!("refusing to connect to {}", url.split('?').next().unwrap_or(""))));
            }
            let resp = self.agent.get(&url).call().map_err(|e| UpdateError::Network(e.to_string()))?;
            let status = resp.status().as_u16();
            if (300..400).contains(&status) {
                let loc = resp.headers().get("location").and_then(|v| v.to_str().ok()).ok_or_else(|| UpdateError::Network("redirect without a target".into()))?;
                url = if loc.starts_with('/') {
                    let origin_end = url.find("://").map(|i| i + 3).and_then(|s| url[s..].find('/').map(|e| s + e)).unwrap_or(url.len());
                    format!("{}{loc}", &url[..origin_end])
                } else {
                    loc.to_string()
                };
                continue;
            }
            if status == 404 {
                return Err(UpdateError::NoRelease);
            }
            if status != 200 {
                return Err(UpdateError::Network(format!("server answered {status}")));
            }
            let len = resp.body().content_length();
            return Ok((resp, len));
        }
        Err(UpdateError::Network("too many redirects".into()))
    }

    fn get_small(&self, url: &str, limit: u64) -> Result<Vec<u8>> {
        let (mut resp, len) = self.get(url)?;
        if len.is_some_and(|l| l > limit) {
            return Err(UpdateError::TooLarge);
        }
        let mut out = Vec::new();
        resp.body_mut().as_reader().take(limit + 1).read_to_end(&mut out).map_err(|e| UpdateError::Network(e.to_string()))?;
        if out.len() as u64 > limit {
            return Err(UpdateError::TooLarge);
        }
        Ok(out)
    }

    /// Downloads and verifies the newest manifest.
    pub fn latest(&self) -> Result<Manifest> {
        let manifest = self.get_small(&self.manifest_url, MAX_MANIFEST)?;
        let sig = self.get_small(&format!("{}.minisig", self.manifest_url), MAX_SIGNATURE)?;
        let sig = String::from_utf8(sig).map_err(|_| UpdateError::BadSignature("not text".into()))?;
        verify_manifest(&manifest, &sig, &self.key)
    }

    /// Is there a version newer than `current`?
    pub fn check(&self, current: Version) -> Result<Check> {
        let m = self.latest()?;
        Ok(if m.version > current { Check::Available(m) } else { Check::UpToDate(m.version) })
    }

    /// Downloads `pkg` into a new private file in `dir` and verifies it.
    /// Returns the file; on any failure nothing is left behind.
    pub fn download(&self, pkg: &Package, dir: &Path, progress: &dyn Fn(u64, u64), cancel: &AtomicBool) -> Result<PathBuf> {
        let tmp = dir.join(format!(".67zip-update-{}.part", zip67_core::util::random_hex(8)));
        let res = self.download_to(pkg, &tmp, progress, cancel);
        if res.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        res.map(|()| tmp)
    }

    fn download_to(&self, pkg: &Package, tmp: &Path, progress: &dyn Fn(u64, u64), cancel: &AtomicBool) -> Result<()> {
        let url = match &self.test_base {
            Some(base) => pkg.url.replacen("https://github.com", base, 1),
            None => pkg.url.clone(),
        };
        let (mut resp, len) = self.get(&url)?;
        if len.is_some_and(|l| l != pkg.size) {
            return Err(UpdateError::Mismatch("wrong size".into()));
        }
        let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(tmp)?;
        let mut reader = resp.body_mut().as_reader();
        let mut hasher = Sha256::new();
        let mut done = 0u64;
        let mut buf = vec![0u8; 256 << 10];
        loop {
            if cancel.load(Ordering::Relaxed) {
                return Err(UpdateError::Cancelled);
            }
            let n = reader.read(&mut buf).map_err(|e| UpdateError::Network(e.to_string()))?;
            if n == 0 {
                break;
            }
            done += n as u64;
            if done > pkg.size {
                return Err(UpdateError::Mismatch("too big".into()));
            }
            hasher.update(&buf[..n]);
            file.write_all(&buf[..n])?;
            progress(done, pkg.size);
        }
        if done != pkg.size {
            return Err(UpdateError::Mismatch("download ended early".into()));
        }
        if hasher.finalize().as_slice() != pkg.sha256 {
            return Err(UpdateError::Mismatch("wrong SHA-256".into()));
        }
        file.sync_all()?;
        Ok(())
    }
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

/// Replaces the AppImage at `target` with the verified download `new`
/// (which must be in the same folder) in one atomic rename. The running
/// program keeps using the old file until it exits.
pub fn install_appimage(new: &Path, target: &Path) -> Result<()> {
    if new.parent() != target.parent() {
        return Err(UpdateError::Io(io::Error::other("the download must be next to the AppImage")));
    }
    let meta = fs::symlink_metadata(target)?;
    if !meta.file_type().is_file() {
        return Err(UpdateError::Io(io::Error::other("the AppImage is not a regular file")));
    }
    fs::set_permissions(new, fs::Permissions::from_mode(0o755))?;
    fs::rename(new, target)?;
    if let Some(dir) = target.parent() {
        File::open(dir).and_then(|d| d.sync_all()).ok();
    }
    Ok(())
}

/// The user's Downloads folder (`XDG_DOWNLOAD_DIR`), or the home folder.
pub fn downloads_dir() -> PathBuf {
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/"));
    let cfg = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from).unwrap_or_else(|| home.join(".config"));
    let mut dir = home.join("Downloads");
    if let Ok(s) = fs::read_to_string(cfg.join("user-dirs.dirs")) {
        for line in s.lines() {
            if let Some(v) = line.strip_prefix("XDG_DOWNLOAD_DIR=") {
                dir = PathBuf::from(v.trim().trim_matches('"').replace("$HOME", &home.to_string_lossy()));
            }
        }
    }
    if dir.is_dir() { dir } else { home }
}

/// Where to put the download for this installation: next to an AppImage
/// (so it can be renamed over it), else the Downloads folder.
pub fn download_folder(install: &Install) -> PathBuf {
    match install {
        Install::AppImage(p) => p.parent().map(Path::to_path_buf).unwrap_or_else(downloads_dir),
        _ => downloads_dir(),
    }
}

/// Moves a verified download into `dir` under `name`, never replacing an
/// existing file (adds " (2)", " (3)", ...). Returns the final path.
pub fn keep_download(tmp: &Path, dir: &Path, name: &str) -> Result<PathBuf> {
    let ext_at = [".tar.gz", ".tar.xz", ".tar.zst"].iter().find_map(|e| name.strip_suffix(e).map(str::len)).or_else(|| name.rfind('.')).unwrap_or(name.len());
    let (stem, ext) = name.split_at(ext_at);
    for n in 1..100 {
        let candidate = dir.join(if n == 1 { name.to_string() } else { format!("{stem} ({n}){ext}") });
        // A hard link fails if the name exists, so nothing is overwritten.
        // File systems without hard links get a checked rename instead.
        let linked = match fs::hard_link(tmp, &candidate) {
            Ok(()) => fs::remove_file(tmp),
            Err(e) if e.kind() != io::ErrorKind::AlreadyExists && !candidate.exists() => fs::rename(tmp, &candidate),
            Err(e) => Err(e),
        };
        match linked {
            Ok(()) => {
                let mode = if name.ends_with(".AppImage") { 0o755 } else { 0o644 };
                fs::set_permissions(&candidate, fs::Permissions::from_mode(mode))?;
                return Ok(candidate);
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Err(UpdateError::Io(io::Error::other("too many files with the same name")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        assert_eq!(Version::parse("0.1.10"), Some(Version(0, 1, 10)));
        assert!(Version(0, 1, 10) > Version(0, 1, 9));
        for bad in ["", "1", "1.2", "1.2.3.4", "01.2.3", "1.2.x", "1.2.-3", "+1.2.3", "1.2.3 ", "99999999999.0.0"] {
            assert_eq!(Version::parse(bad), None, "{bad}");
        }
        assert_eq!(Version::current().to_string(), env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn built_in_key() {
        assert!(PUBLIC_KEY.contains(KEY_ID));
        let _ = release_key();
    }

    #[test]
    fn only_github_hosts() {
        let c = Client::new();
        assert!(c.allowed("https://github.com/gamesensicals/67zip/releases/latest/download/latest.json"));
        assert!(c.allowed("https://objects.githubusercontent.com/x"));
        assert!(!c.allowed("http://github.com/x"));
        assert!(!c.allowed("https://github.com.evil.example/x"));
        assert!(!c.allowed("https://evil.example/?https://github.com/"));
        assert!(!c.allowed("https://user@github.com/x"));
        assert!(!c.allowed("https://github.com@evil.example/"));
        assert!(!c.allowed("https://github.com:8443/x"));
    }
}
