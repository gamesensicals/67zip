//! Command implementations.

use std::path::{Path, PathBuf};

use zip67_core::extract::{ExtractOptions, Overwrite, PathMode, Selection};
use zip67_core::hash::HashKind;
use zip67_core::util::{format_local_time, human_size, safe_display};
use zip67_core::{ArchiveType, Entry, EntryKind, Error, Progress};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use zip67_core::progress::Snapshot;
use zip67_worker::client::WorkerHandle;
use zip67_worker::protocol::{ChangesSpec, CreateSpec, Event, FailKind, Reply, Request};
use zip67_worker::sandbox::SandboxStatus;
use zip67_worker::server::execute;

use crate::args::{self, Args, HELP};
use crate::term::{self, ProgressLine, TtyPrompt};

const EXIT_WARNING: i32 = 1;
const EXIT_FATAL: i32 = 2;
const EXIT_USAGE: i32 = 7;
const EXIT_STOPPED: i32 = 255;

fn banner() {
    println!("\n67zip {} : MIT license : https://github.com/gamesensicals/67zip\n", zip67_core::VERSION);
}

pub fn main(raw: Vec<String>) -> i32 {
    let a = match args::parse(raw) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("67z: {e}\nRun '67z --help' for usage.");
            return EXIT_USAGE;
        }
    };
    if a.version {
        println!("67z {}", zip67_core::VERSION);
        return 0;
    }
    for note in &a.notes {
        eprintln!("67z: note: {note}");
    }
    banner();
    if a.help || a.command.is_empty() {
        print!("{HELP}");
        return if a.help { 0 } else { EXIT_USAGE };
    }
    match a.command.as_str() {
        "i" => {
            info();
            0
        }
        "a" | "u" => add(&a),
        "d" => update(&a, ChangesSpec { delete: a.files.clone(), ..Default::default() }),
        "rn" => {
            if a.files.len() % 2 != 0 || a.files.is_empty() {
                eprintln!("67z: rn needs pairs of names: old new [old new ...]");
                return EXIT_USAGE;
            }
            let pairs = a.files.chunks(2).map(|c| (c[0].clone(), c[1].clone())).collect();
            update(&a, ChangesSpec { rename: pairs, ..Default::default() })
        }
        "x" | "e" => extract(&a),
        "l" => list(&a),
        "t" => test(&a),
        "h" => hash(&a),
        "b" => bench(&a),
        other => {
            eprintln!("67z: unknown command '{other}'\nRun '67z --help' for usage.");
            EXIT_USAGE
        }
    }
}

/// Runs a request in a sandboxed worker process (or here, with
/// `--no-sandbox`), asking for a password when needed.
fn run(a: &Args, mut make: impl FnMut(Option<String>) -> Request) -> Result<Reply, Error> {
    let mut password = match &a.password {
        Some(Some(p)) => Some(p.clone()),
        Some(None) => term::read_password("Enter password: "),
        None => None,
    };
    let cancel = Arc::new(AtomicBool::new(false));
    let progress = Progress::new();
    {
        let (p, c) = (progress.clone(), cancel.clone());
        let _ = ctrlc::set_handler(move || {
            p.cancel();
            c.store(true, Ordering::Relaxed);
        });
    }
    for _ in 0..3 {
        let req = make(password.clone());
        let res = if a.no_sandbox {
            let line = ProgressLine::start(&progress, !a.no_progress);
            let r = execute(req, &progress, &mut TtyPrompt);
            line.finish();
            r
        } else {
            in_worker(&req, a, &cancel)
        };
        match res {
            Err(e @ (Error::PasswordRequired | Error::WrongPassword)) if term::interactive() => {
                if matches!(e, Error::WrongPassword) {
                    eprintln!("Wrong password.");
                }
                password = term::read_password("Enter password: ");
                if password.is_none() {
                    return Err(e);
                }
            }
            other => return other,
        }
    }
    Err(Error::WrongPassword)
}

/// The archive work happens in a separate `67z --worker` process that
/// locks itself down and has no terminal; this process only shows
/// progress, answers questions and moves finished archives into place.
fn in_worker(req: &Request, a: &Args, cancel: &AtomicBool) -> Result<Reply, Error> {
    let exe = std::env::current_exe().map_err(Error::Io)?;
    let mut h = WorkerHandle::spawn(&exe, req).map_err(Error::Io)?;
    let snap: Arc<Mutex<Snapshot>> = Arc::default();
    let line = {
        let s = snap.clone();
        ProgressLine::start_with(move || s.lock().map(|x| x.clone()).unwrap_or_default(), !a.no_progress)
    };
    let mut cancel_sent = false;
    let result = loop {
        if cancel.load(Ordering::Relaxed) && !cancel_sent {
            h.cancel();
            cancel_sent = true;
        }
        match h.try_next() {
            Some(Event::Hello { sandbox, .. }) => report_sandbox(&sandbox),
            Some(Event::Progress(s)) => {
                if let Ok(mut x) = snap.lock() {
                    *x = s;
                }
            }
            Some(Event::Ask(q)) => h.answer(term::ask_overwrite(&q.path, q.existing_size, q.existing_mtime, q.new_size, q.new_mtime)),
            Some(Event::Done(r)) => break Ok(r),
            Some(Event::Failed(f)) => {
                break Err(match f.kind {
                    FailKind::PasswordRequired => Error::PasswordRequired,
                    FailKind::WrongPassword => Error::WrongPassword,
                    FailKind::Cancelled => Error::Cancelled,
                    _ => Error::InvalidInput(f.message),
                });
            }
            None if h.is_finished() => break Err(Error::invalid("the worker process stopped unexpectedly")),
            None => std::thread::sleep(Duration::from_millis(15)),
        }
    };
    line.finish();
    result
}

fn report_sandbox(s: &SandboxStatus) {
    if !s.is_strong() {
        eprintln!("Note: {}", s.describe());
    }
}

fn fail(e: &Error) -> i32 {
    term::clear_line();
    eprintln!("\nERROR: {}", safe_display(&e.to_string()));
    if matches!(e, Error::Cancelled) {
        EXIT_STOPPED
    } else {
        EXIT_FATAL
    }
}

fn archive_arg(a: &Args) -> Option<PathBuf> {
    if a.archive.is_none() {
        eprintln!("67z: the archive name is missing");
    }
    a.archive.clone()
}

fn add(a: &Args) -> i32 {
    let Some(mut archive) = archive_arg(a) else { return EXIT_USAGE };
    let t = match &a.archive_type {
        Some(t) => match ArchiveType::from_id(t) {
            Some(t) => t,
            None => {
                eprintln!("67z: unknown archive type '{t}'");
                return EXIT_USAGE;
            }
        },
        None => ArchiveType::from_file_name(&archive.to_string_lossy()).unwrap_or(ArchiveType::SEVEN_Z),
    };
    if archive.extension().is_none() {
        archive.set_extension(t.id());
    }
    let inputs: Vec<PathBuf> = if a.files.is_empty() {
        match std::fs::read_dir(".") {
            Ok(rd) => rd.filter_map(|e| e.ok()).map(|e| e.path()).filter(|p| p.file_name() != archive.file_name()).collect(),
            Err(e) => return fail(&e.into()),
        }
    } else {
        a.files.iter().map(PathBuf::from).collect()
    };
    let mut password = a.password.clone();
    if let Some(None) = password {
        let p1 = term::read_password("Enter password: ").unwrap_or_default();
        let p2 = term::read_password("Verify password: ").unwrap_or_default();
        if p1 != p2 {
            eprintln!("67z: the passwords do not match");
            return EXIT_USAGE;
        }
        password = Some(Some(p1));
    }
    let method = match a.method.as_deref().map(|m| zip67_core::create::Method::from_name(m).ok_or(m)) {
        Some(Err(m)) => {
            eprintln!("67z: unknown method '{m}'");
            return EXIT_USAGE;
        }
        Some(Ok(m)) => Some(m),
        None => None,
    };
    let spec = CreateSpec {
        archive_type: t.id(),
        level: a.level.unwrap_or(5),
        method,
        dict_size: a.dict,
        threads: a.threads.unwrap_or(0),
        password: password.clone().flatten(),
        encrypt_names: a.encrypt_names,
        solid: a.solid.unwrap_or(true),
        volume_size: a.volume,
        follow_symlinks: a.follow_links,
        delete_after: a.delete_after,
        shred: a.shred,
        exclude: a.exclude.clone(),
    };
    println!("Archive: {}", safe_display(&archive.to_string_lossy()));
    let a2 = Args { password: None, ..clone_args(a) };
    let res = run(&a2, |_| Request::AddFiles { archive: archive.clone(), inputs: inputs.clone(), arc_dir: String::new(), spec: spec.clone() });
    match res {
        Ok(Reply::Created(r)) => {
            for w in &r.warnings {
                eprintln!("WARNING: {}", safe_display(w));
            }
            let ratio = if r.bytes_in > 0 { 100.0 * r.bytes_out as f64 / r.bytes_in as f64 } else { 0.0 };
            println!("Files: {}  Folders: {}  Size: {}  Archive: {} ({ratio:.1}%)", r.files, r.dirs, human_size(r.bytes_in), human_size(r.bytes_out));
            for o in &r.outputs {
                println!("Written: {}", safe_display(&o.to_string_lossy()));
            }
            println!("Everything is Ok");
            if r.warnings.is_empty() { 0 } else { EXIT_WARNING }
        }
        Ok(_) => EXIT_FATAL,
        Err(e) => fail(&e),
    }
}

fn clone_args(a: &Args) -> Args {
    Args {
        command: a.command.clone(),
        archive: a.archive.clone(),
        files: a.files.clone(),
        password: a.password.clone(),
        output: a.output.clone(),
        no_progress: a.no_progress,
        no_sandbox: a.no_sandbox,
        yes: a.yes,
        ..Default::default()
    }
}

fn update(a: &Args, changes: ChangesSpec) -> i32 {
    let Some(archive) = archive_arg(a) else { return EXIT_USAGE };
    let res = run(a, |pw| Request::Update { archive: archive.clone(), password: pw, changes: changes.clone(), level: a.level, threads: a.threads.unwrap_or(0) });
    match res {
        Ok(Reply::Created(_)) => {
            println!("Everything is Ok");
            0
        }
        Ok(_) => EXIT_FATAL,
        Err(e) => fail(&e),
    }
}

fn selection(files: &[String]) -> Selection {
    if files.is_empty() {
        Selection::All
    } else {
        Selection::Patterns(files.to_vec())
    }
}

fn extract(a: &Args) -> i32 {
    let Some(archive) = archive_arg(a) else { return EXIT_USAGE };
    let dest = a.output.clone().unwrap_or_else(|| PathBuf::from("."));
    let overwrite = if a.yes { Overwrite::Always } else { a.overwrite.unwrap_or(Overwrite::Ask) };
    let options = ExtractOptions { path_mode: if a.command == "e" { PathMode::Flat } else { PathMode::Full }, overwrite, ..Default::default() };
    let sel = selection(&a.files);
    let res = run(a, |pw| Request::Extract { archive: archive.clone(), password: pw, dest: dest.clone(), selection: sel.clone(), options: options.clone() });
    match res {
        Ok(Reply::Extracted(r)) => report_extract(&r, "Extracted"),
        Ok(_) => EXIT_FATAL,
        Err(e) => fail(&e),
    }
}

fn report_extract(r: &zip67_core::extract::ExtractReport, verb: &str) -> i32 {
    for w in &r.warnings {
        eprintln!("WARNING: {}", safe_display(w));
    }
    for (p, e) in &r.errors {
        eprintln!("ERROR: {} : {}", safe_display(p), safe_display(e));
    }
    println!("{verb}: {} files, {} folders, {} links, {}", r.files, r.dirs, r.links, human_size(r.bytes));
    if r.skipped > 0 {
        println!("Skipped: {}", r.skipped);
    }
    if r.errors.is_empty() {
        println!("Everything is Ok");
        if r.warnings.is_empty() { 0 } else { EXIT_WARNING }
    } else {
        println!("Errors: {}", r.errors.len());
        EXIT_FATAL
    }
}

fn test(a: &Args) -> i32 {
    let Some(archive) = archive_arg(a) else { return EXIT_USAGE };
    let sel = selection(&a.files);
    match run(a, |pw| Request::Test { archive: archive.clone(), password: pw, selection: sel.clone() }) {
        Ok(Reply::Tested(r)) => report_extract(&r, "Tested"),
        Ok(_) => EXIT_FATAL,
        Err(e) => fail(&e),
    }
}

fn attr(e: &Entry) -> &'static str {
    match e.kind {
        EntryKind::Dir => "D....",
        EntryKind::Symlink => "L....",
        EntryKind::Hardlink => "H....",
        EntryKind::Special => "S....",
        EntryKind::File => {
            if e.mode.is_some_and(|m| m & 0o222 == 0) {
                "R...A"
            } else {
                "....A"
            }
        }
    }
}

fn list(a: &Args) -> i32 {
    let Some(archive) = archive_arg(a) else { return EXIT_USAGE };
    let res = run(&Args { no_progress: true, ..clone_args(a) }, |pw| Request::List { archive: archive.clone(), password: pw });
    let (t, entries, info) = match res {
        Ok(Reply::Listing { archive_type, entries, info }) => (archive_type, entries, info),
        Ok(_) => return EXIT_FATAL,
        Err(e) => return fail(&e),
    };
    let matcher = selection(&a.files).matcher();
    let entries: Vec<&Entry> = entries.iter().filter(|e| matcher(e)).collect();
    println!("Listing archive: {}\n", safe_display(&archive.to_string_lossy()));
    println!("--");
    println!("Path = {}", safe_display(&archive.to_string_lossy()));
    println!("Type = {t}");
    println!("Physical Size = {}", info.physical_size);
    if !info.methods.is_empty() {
        println!("Method = {}", info.methods.join(" "));
    }
    if t == "7z" {
        println!("Solid = {}", if info.solid { "+" } else { "-" });
        println!("Blocks = {}", info.blocks);
    }
    if info.encrypted_headers {
        println!("Encrypted names = +");
    }
    if let Some(c) = &info.comment {
        println!("Comment = {}", safe_display(c));
    }
    for w in &info.warnings {
        println!("Warning = {}", safe_display(w));
    }
    for w in &info.problems {
        println!("Warning = {}", safe_display(w));
    }
    println!();
    if a.technical {
        println!("----------");
        for e in &entries {
            println!("Path = {}", safe_display(&e.path));
            println!("Folder = {}", if e.is_dir() { "+" } else { "-" });
            println!("Size = {}", e.size);
            if let Some(p) = e.packed_size {
                println!("Packed Size = {p}");
            }
            if let Some(m) = e.mtime {
                println!("Modified = {}", format_local_time(m));
            }
            if let Some(m) = e.mode {
                println!("Mode = {m:04o}");
            }
            if let Some(c) = e.crc32 {
                println!("CRC = {c:08X}");
            }
            println!("Encrypted = {}", if e.encrypted { "+" } else { "-" });
            if let Some(m) = &e.method {
                println!("Method = {m}");
            }
            if let Some(b) = e.block {
                println!("Block = {b}");
            }
            if let Some(l) = &e.link_target {
                println!("Link = {}", safe_display(l));
            }
            if let Some(c) = &e.comment {
                println!("Comment = {}", safe_display(c));
            }
            println!();
        }
        return 0;
    }
    println!("   Date      Time    Attr         Size   Compressed  Name");
    println!("------------------- ----- ------------ ------------  ------------------------");
    let (mut files, mut dirs, mut size, mut packed) = (0u64, 0u64, 0u64, 0u64);
    let mut newest = None::<i64>;
    for e in &entries {
        let date = e.mtime.map(format_local_time).unwrap_or_else(|| " ".repeat(19));
        let p = e.packed_size.map(|p| p.to_string()).unwrap_or_default();
        println!("{date} {} {:>12} {:>12}  {}", attr(e), if e.size_known { e.size.to_string() } else { String::new() }, p, safe_display(&e.path));
        if e.is_dir() {
            dirs += 1;
        } else {
            files += 1;
        }
        size = size.saturating_add(e.size);
        packed = packed.saturating_add(e.packed_size.unwrap_or(0));
        newest = newest.max(e.mtime);
    }
    println!("------------------- ----- ------------ ------------  ------------------------");
    let date = newest.map(format_local_time).unwrap_or_else(|| " ".repeat(19));
    println!("{date}       {size:>12} {packed:>12}  {files} files, {dirs} folders");
    0
}

fn collect_files(paths: &[String]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    fn walk(p: &Path, out: &mut Vec<PathBuf>) {
        match std::fs::symlink_metadata(p) {
            Ok(m) if m.is_dir() => {
                if let Ok(rd) = std::fs::read_dir(p) {
                    let mut v: Vec<_> = rd.filter_map(|e| e.ok()).map(|e| e.path()).collect();
                    v.sort();
                    for c in v {
                        walk(&c, out);
                    }
                }
            }
            Ok(m) if m.is_file() => out.push(p.to_path_buf()),
            _ => {}
        }
    }
    for p in paths {
        walk(Path::new(p), &mut out);
    }
    out
}

fn hash(a: &Args) -> i32 {
    let mut names = a.files.clone();
    if let Some(arch) = &a.archive {
        names.insert(0, arch.to_string_lossy().into_owned());
    }
    if names.is_empty() {
        eprintln!("67z: give the files to hash");
        return EXIT_USAGE;
    }
    let kinds: Vec<HashKind> = if a.hashes.is_empty() {
        vec![HashKind::Crc32]
    } else if a.hashes.iter().any(|h| h == "*") {
        HashKind::ALL.to_vec()
    } else {
        let mut v = Vec::new();
        for h in &a.hashes {
            match HashKind::from_name(h) {
                Some(k) => v.push(k),
                None => {
                    eprintln!("67z: unknown hash '{h}'");
                    return EXIT_USAGE;
                }
            }
        }
        v
    };
    let files = collect_files(&names);
    let res = run(a, |_| Request::Hash { paths: files.clone(), kinds: kinds.clone() });
    match res {
        Ok(Reply::Hashes(v)) => {
            let mut bad = 0;
            let mut total = 0u64;
            for r in &v {
                if let Some(e) = &r.error {
                    eprintln!("ERROR: {} : {}", safe_display(&r.path.to_string_lossy()), safe_display(e));
                    bad += 1;
                    continue;
                }
                total = total.saturating_add(r.size);
                let vals: Vec<String> = r.values.iter().map(|(_, h)| h.clone()).collect();
                println!("{}  {:>12}  {}", vals.join("  "), r.size, safe_display(&r.path.to_string_lossy()));
            }
            println!("\nFiles: {}  Size: {}  ({})", v.len() - bad, total, kinds.iter().map(|k| k.name()).collect::<Vec<_>>().join(", "));
            if bad == 0 { 0 } else { EXIT_FATAL }
        }
        Ok(_) => EXIT_FATAL,
        Err(e) => fail(&e),
    }
}

fn bench(a: &Args) -> i32 {
    let threads = a.threads.filter(|&t| t > 0).unwrap_or_else(zip67_core::util::default_threads);
    println!("Benchmark with {threads} threads on 64 MB of sample data...\n");
    match run(a, |_| Request::Benchmark { seconds: 8, threads, dict_size: 0 }) {
        Ok(Reply::Benchmark(v)) => {
            println!("{:<18} {:>7} {:>14} {:>16} {:>8}", "Method", "Threads", "Compress MB/s", "Decompress MB/s", "Ratio");
            for r in v {
                println!("{:<18} {:>7} {:>14.1} {:>16.1} {:>7.1}%", r.method, r.threads, r.compress_mbps, r.decompress_mbps, r.ratio);
            }
            0
        }
        Ok(_) => EXIT_FATAL,
        Err(e) => fail(&e),
    }
}

fn info() {
    println!("Formats:");
    println!("  {:<9} {:<6} {:<10} Notes", "Type", "Read", "Write");
    let rows: &[(&str, &str, &str, &str)] = &[
        ("7z", "yes", "yes", "LZMA2/LZMA/PPMd/BZip2/Deflate/Copy, BCJ/BCJ2/ARM64/Delta, AES-256"),
        ("zip", "yes", "yes", "Deflate/BZip2/LZMA/XZ/Zstd/PPMd(read)/Store, Zip64, AES-256; ZipCrypto read-only"),
        ("tar", "yes", "yes", "ustar, PAX, GNU long names"),
        ("tar.gz", "yes", "yes", "also .tgz"),
        ("tar.bz2", "yes", "yes", "also .tbz2"),
        ("tar.xz", "yes", "yes", "also .txz"),
        ("tar.zst", "yes", "yes", "Zstandard (fast level only for writing)"),
        ("tar.lz", "yes", "yes", "lzip"),
        ("gz bz2", "yes", "yes", "single files"),
        ("xz zst", "yes", "yes", "single files"),
        ("lzma lz", "yes", "yes", "single files"),
        ("iso", "yes", "no", "ISO 9660, Rock Ridge, Joliet"),
        ("rar", "yes", "no", "RAR5 and RAR 2.0-4.x: solid, volumes, AES, self-extracting; not RAR 1.5 or RAR 2.0 encryption"),
        ("split", "yes", "yes", "any format split into parts: .001, .part1.7z, .7z.part1, .z01 ... .zip, .part1.rar, .r00, .aa"),
    ];
    for (t, r, w, n) in rows {
        println!("  {t:<9} {r:<6} {w:<10} {n}");
    }
    println!("\nHashes: {}", HashKind::ALL.iter().map(|k| k.name()).collect::<Vec<_>>().join(", "));
}
