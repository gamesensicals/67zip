//! Terminal helpers: hidden password input, questions, progress line.

use std::io::{self, BufRead, IsTerminal, Write};
use std::os::fd::AsFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use zip67_core::extract::{Answer, Prompt};
use zip67_core::progress::Snapshot;
use zip67_core::util::{format_local_time, human_size, safe_display};
use zip67_core::{Entry, Progress};

pub fn read_line() -> Option<String> {
    let mut s = String::new();
    match io::stdin().lock().read_line(&mut s) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(s.trim_end_matches(['\n', '\r']).to_string()),
    }
}

/// Reads a line without echo when stdin is a terminal.
pub fn read_password(prompt: &str) -> Option<String> {
    eprint!("{prompt}");
    let _ = io::stderr().flush();
    let stdin = io::stdin();
    let fd = stdin.as_fd();
    let saved = rustix::termios::tcgetattr(fd).ok();
    if let Some(t) = &saved {
        let mut quiet = t.clone();
        quiet.local_modes.remove(rustix::termios::LocalModes::ECHO);
        let _ = rustix::termios::tcsetattr(fd, rustix::termios::OptionalActions::Now, &quiet);
    }
    let line = read_line();
    if let Some(t) = &saved {
        let _ = rustix::termios::tcsetattr(fd, rustix::termios::OptionalActions::Now, t);
        eprintln!();
    }
    line
}

pub fn interactive() -> bool {
    io::stdin().is_terminal()
}

pub struct TtyPrompt;

impl Prompt for TtyPrompt {
    fn overwrite(
        &mut self,
        path: &str,
        existing_size: u64,
        existing_mtime: Option<i64>,
        entry: &Entry,
    ) -> Answer {
        ask_overwrite(path, existing_size, existing_mtime, entry.size, entry.mtime)
    }
}

/// Asks whether to overwrite an existing file.
pub fn ask_overwrite(
    path: &str,
    existing_size: u64,
    existing_mtime: Option<i64>,
    new_size: u64,
    new_mtime: Option<i64>,
) -> Answer {
    {
        if !interactive() {
            return Answer::No;
        }
        clear_line();
        eprintln!("\nFile already exists: {}", safe_display(path));
        eprintln!(
            "  existing: {:>12}  {}",
            human_size(existing_size),
            existing_mtime.map(format_local_time).unwrap_or_default()
        );
        eprintln!(
            "  new:      {:>12}  {}",
            human_size(new_size),
            new_mtime.map(format_local_time).unwrap_or_default()
        );
        loop {
            eprint!("Overwrite? (Y)es / (N)o / (A)lways / (S)kip all / A(u)to rename / (Q)uit? ");
            let _ = io::stderr().flush();
            let Some(l) = read_line() else {
                return Answer::Cancel;
            };
            match l.trim().to_ascii_lowercase().as_str() {
                "y" | "yes" => return Answer::Yes,
                "n" | "no" => return Answer::No,
                "a" | "always" => return Answer::YesToAll,
                "s" => return Answer::NoToAll,
                "u" => return Answer::RenameAll,
                "q" | "quit" => return Answer::Cancel,
                _ => {}
            }
        }
    }
}

pub fn clear_line() {
    if io::stderr().is_terminal() {
        eprint!("\r\x1b[K");
    }
}

pub struct ProgressLine {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl ProgressLine {
    pub fn start(progress: &Progress, enabled: bool) -> Self {
        let p = progress.clone();
        Self::start_with(move || p.snapshot(), enabled)
    }

    /// Shows snapshots from `get` (e.g. the last one a worker sent).
    pub fn start_with(get: impl Fn() -> Snapshot + Send + 'static, enabled: bool) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let handle = if enabled && io::stderr().is_terminal() {
            let s = stop.clone();
            Some(std::thread::spawn(move || {
                while !s.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(200));
                    let snap = get();
                    let pct = snap
                        .done
                        .min(snap.total)
                        .saturating_mul(100)
                        .checked_div(snap.total)
                        .unwrap_or(0);
                    let mut name = safe_display(&snap.current);
                    if name.chars().count() > 50 {
                        name = format!(
                            "…{}",
                            name.chars()
                                .rev()
                                .take(49)
                                .collect::<Vec<_>>()
                                .into_iter()
                                .rev()
                                .collect::<String>()
                        );
                    }
                    eprint!("\r\x1b[K{pct:3}% {:>10}  {name}", human_size(snap.done));
                    let _ = io::stderr().flush();
                }
            }))
        } else {
            None
        };
        ProgressLine { stop, handle }
    }
    pub fn finish(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
            clear_line();
        }
    }
}
