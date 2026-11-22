//! 7-Zip style command line: `67z <command> [switches] <archive> [files]`.

use std::path::PathBuf;

use zip67_core::extract::Overwrite;

#[derive(Debug, Default)]
pub struct Args {
    /// Things worth telling the user about the switches they gave (printed to stderr).
    pub notes: Vec<String>,
    pub command: String,
    pub archive: Option<PathBuf>,
    pub files: Vec<String>,
    pub archive_type: Option<String>,
    pub level: Option<u32>,
    pub method: Option<String>,
    pub dict: Option<u32>,
    pub threads: Option<usize>,
    pub solid: Option<bool>,
    pub encrypt_names: bool,
    /// Some(None): ask for it.
    pub password: Option<Option<String>>,
    pub output: Option<PathBuf>,
    pub yes: bool,
    pub overwrite: Option<Overwrite>,
    pub volume: Option<u64>,
    pub exclude: Vec<String>,
    pub hashes: Vec<String>,
    pub delete_after: bool,
    pub shred: bool,
    pub follow_links: bool,
    pub technical: bool,
    pub no_progress: bool,
    pub no_sandbox: bool,
    pub help: bool,
    pub version: bool,
}

fn on_off(v: &str) -> Result<bool, String> {
    match v.to_ascii_lowercase().as_str() {
        "on" | "+" | "" => Ok(true),
        "off" | "-" => Ok(false),
        other => Err(format!("expected on or off, got '{other}'")),
    }
}

fn size(v: &str) -> Result<u64, String> {
    zip67_core::split::parse_size(v).ok_or_else(|| format!("bad size '{v}'"))
}

fn method_switch(a: &mut Args, s: &str) -> Result<(), String> {
    // s is what follows "-m"
    let (k, v) = match s.split_once('=') {
        Some((k, v)) => (k.to_ascii_lowercase(), v.to_string()),
        None => {
            let lower = s.to_ascii_lowercase();
            if let Some(n) = lower.strip_prefix("mt") {
                ("mt".to_string(), n.to_string())
            } else if let Some(n) = lower.strip_prefix('x') {
                ("x".to_string(), n.to_string())
            } else {
                (lower, String::new())
            }
        }
    };
    match k.as_str() {
        "x" => a.level = Some(if v.is_empty() { 9 } else { v.parse().map_err(|_| format!("bad level '{v}'"))? }),
        "0" | "m" => a.method = Some(v),
        "d" => a.dict = Some(size(&v)?.min(u64::from(u32::MAX)) as u32),
        "mt" => {
            a.threads = Some(match v.to_ascii_lowercase().as_str() {
                "on" | "" => 0,
                "off" => 1,
                n => n.parse().map_err(|_| format!("bad thread count '{n}'"))?,
            })
        }
        "s" => a.solid = Some(on_off(&v)?),
        "he" => a.encrypt_names = on_off(&v)?,
        "em" => match v.to_ascii_lowercase().replace('-', "").as_str() {
            "aes256" => {}
            "aes128" | "aes192" => a.notes.push(format!("-mem={v}: zips are always encrypted with AES-256, the strongest option.")),
            "zipcrypto" => a.notes.push(
                "-mem=ZipCrypto: 67z doesn't create ZipCrypto zips because that old encryption is easy to break; using AES-256 (7-Zip and 67zip open it, Windows Explorer can't).".into(),
            ),
            other => return Err(format!("unknown encryption method '-mem={other}' (zips use AES256)")),
        },
        "hc" | "f" | "tc" | "ta" | "tm" | "qs" | "fb" | "pass" | "mf" | "cu" | "cl" => {} // accepted, defaults used
        other => return Err(format!("unknown -m switch '-m{other}'")),
    }
    Ok(())
}

pub fn parse(raw: Vec<String>) -> Result<Args, String> {
    let mut a = Args::default();
    let mut positional = Vec::new();
    let mut switches_done = false;
    for arg in raw {
        if !switches_done && arg == "--" {
            switches_done = true;
            continue;
        }
        if switches_done || !arg.starts_with('-') || arg == "-" {
            positional.push(arg);
            continue;
        }
        match arg.as_str() {
            "-h" | "--help" | "-?" => {
                a.help = true;
                continue;
            }
            "--version" => {
                a.version = true;
                continue;
            }
            "--no-sandbox" => {
                a.no_sandbox = true;
                continue;
            }
            _ => {}
        }
        let s = &arg[1..];
        let lower = s.to_ascii_lowercase();
        if let Some(t) = s.strip_prefix('t') {
            a.archive_type = Some(t.to_ascii_lowercase());
        } else if let Some(m) = s.strip_prefix('m') {
            method_switch(&mut a, m)?;
        } else if let Some(p) = s.strip_prefix('p') {
            a.password = Some(if p.is_empty() { None } else { Some(p.to_string()) });
        } else if let Some(o) = s.strip_prefix('o') {
            if o.is_empty() {
                return Err("-o needs a folder, written without a space: -o/path/to/folder".into());
            }
            a.output = Some(PathBuf::from(o));
        } else if lower == "y" {
            a.yes = true;
        } else if let Some(m) = lower.strip_prefix("ao") {
            a.overwrite = Some(match m {
                "a" => Overwrite::Always,
                "s" => Overwrite::Skip,
                "u" => Overwrite::RenameNew,
                "t" => Overwrite::RenameExisting,
                _ => return Err(format!("unknown overwrite mode '-ao{m}'")),
            });
        } else if let Some(v) = lower.strip_prefix('v') {
            a.volume = Some(size(v)?);
        } else if let Some(x) = s.strip_prefix("xr!").or_else(|| s.strip_prefix("x!")) {
            a.exclude.push(x.to_string());
        } else if let Some(h) = lower.strip_prefix("scrc") {
            a.hashes.push(if h.is_empty() { "crc32".into() } else { h.to_string() });
        } else if lower == "sdel" {
            a.delete_after = true;
        } else if lower == "sshred" {
            a.delete_after = true;
            a.shred = true;
        } else if lower == "l" {
            a.follow_links = true;
        } else if lower == "snl" || lower == "r" || lower == "spf" || lower == "ssc" || lower == "ssc-" {
            // Symlinks are stored as links by default; recursion is always on.
        } else if lower == "slt" {
            a.technical = true;
        } else if lower == "bd" {
            a.no_progress = true;
        } else if lower.starts_with("bb") || lower.starts_with("bs") || lower.starts_with("bt") || lower.starts_with("sc") {
            // output tuning switches of 7z: accepted and ignored
        } else {
            return Err(format!("unknown switch '{arg}'"));
        }
    }
    let mut it = positional.into_iter();
    a.command = it.next().unwrap_or_default().to_ascii_lowercase();
    let needs_archive = !matches!(a.command.as_str(), "h" | "b" | "i" | "");
    if needs_archive {
        a.archive = it.next().map(PathBuf::from);
    }
    a.files = it.collect();
    Ok(a)
}

pub const HELP: &str = "\
Usage: 67z <command> [<switches>...] <archive> [<files>...]

Commands
  a  Add files to an archive (creates it if needed)
  d  Delete files from an archive
  e  Extract files, all into one folder (no paths)
  x  eXtract files with full paths
  l  List contents
  t  Test integrity
  u  Update (same as a)
  rn Rename: 67z rn archive old-name new-name [old new ...]
  h  Calculate hashes of files: 67z h [-scrcSHA256] files...
  b  Benchmark
  i  Show supported formats
  update [--check]  Look for a newer 67zip (an AppImage also installs it)

Switches
  -t{type}      Archive type: 7z, zip, tar, tar.gz, tar.bz2, tar.xz, tar.zst,
                gz, bz2, xz, zst, lzma, lz
  -mx{0-9}      Compression level (0 = store, 5 = normal, 9 = ultra)
  -m0={method}  Method: LZMA2, LZMA, PPMd, BZip2, Deflate, Copy (7z);
                Deflate, BZip2, LZMA, XZ, Zstd, Copy (zip)
  -md={size}    Dictionary size, e.g. 64m
  -mmt={N|on|off} Threads
  -ms={on|off}  Solid archive (7z)
  -mhe=on       Encrypt file names too (7z)
  -p{password}  Password (just -p to type it hidden)
  -o{folder}    Output folder (no space after -o)
  -y            Answer yes to all questions (overwrite)
  -ao{a|s|u|t}  Overwrite all / skip / rename new / rename existing
  -v{size}      Split into volumes, e.g. -v100m
  -x!{pattern}  Exclude names matching a wildcard pattern
  -scrc{type}   Hash type for h: CRC32, CRC64, SHA256, SHA1, SHA512, BLAKE3,
                MD5, or * for all
  -sdel         Delete files after adding them
  -sshred       Delete them securely: overwrite with random data first
                (reliable on hard disks; not on SSDs or btrfs/ZFS)
  -l            Follow symbolic links instead of storing them
  -slt          Technical listing
  -bd           No progress display
  --no-sandbox  Do not restrict this process (troubleshooting only)

Exit codes: 0 ok, 1 warning, 2 fatal error, 7 bad command line, 255 stopped.
";
