//! Starting a worker and talking to it (used by the GUI).

use std::ffi::OsString;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, TryRecvError};

use crate::protocol::{Control, Event, FailKind, Failure, Job, Reply, Request};

pub struct WorkerHandle {
    child: Child,
    stdin: Option<ChildStdin>,
    events: Receiver<Event>,
    finished: bool,
    stage: Option<Staging>,
}

/// A private folder next to an archive being written. The sandboxed worker
/// may write only there; afterwards this (unsandboxed) side checks what it
/// produced and renames it into place.
struct Staging {
    dir: PathBuf,
    target_dir: PathBuf,
    name: OsString,
    /// Replace an existing archive (update) instead of creating new files.
    replace: bool,
    /// For "delete files after archiving": only these and what is inside
    /// them may be deleted.
    delete_roots: Vec<PathBuf>,
    /// Overwrite them with random data first.
    shred: bool,
}

fn parent_dir(p: &Path) -> PathBuf {
    match p.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

impl Staging {
    fn for_request(req: &Request) -> std::io::Result<Option<Staging>> {
        let (target, replace, delete_roots, shred) = match req {
            Request::Create {
                output,
                inputs,
                spec,
            } => (
                output,
                false,
                if spec.delete_after {
                    inputs.clone()
                } else {
                    vec![]
                },
                spec.shred,
            ),
            Request::AddFiles {
                archive,
                inputs,
                spec,
                ..
            } => {
                let exists = archive.exists();
                (
                    archive,
                    exists,
                    if spec.delete_after && !exists {
                        inputs.clone()
                    } else {
                        vec![]
                    },
                    spec.shred,
                )
            }
            Request::Update { archive, .. } => (archive, true, vec![], false),
            _ => return Ok(None),
        };
        let Some(name) = target.file_name().map(|n| n.to_os_string()) else {
            return Ok(None);
        };
        let target_dir = parent_dir(target);
        let dir = target_dir.join(format!(".67zip-{}", zip67_core::util::random_hex(8)));
        std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
        Ok(Some(Staging {
            dir,
            target_dir,
            name,
            replace,
            delete_roots,
            shred,
        }))
    }

    /// Checks the worker's outputs and moves them into place. Paths the
    /// worker reports are never trusted beyond the staging folder.
    fn finish(&self, report: &mut zip67_core::create::CreateReport) -> Result<(), String> {
        if report.outputs.is_empty() || self.replace && report.outputs.len() != 1 {
            return Err("the worker reported unexpected output files".into());
        }
        let base = self.name.to_string_lossy().into_owned();
        let mut moves = Vec::new();
        for out in &report.outputs {
            let name = out
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let named_ok = name == base
                || !self.replace
                    && name
                        .strip_prefix(&base)
                        .and_then(|r| r.strip_prefix('.'))
                        .is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()));
            let inside = out.parent() == Some(self.dir.as_path());
            let regular = std::fs::symlink_metadata(out).is_ok_and(|m| m.file_type().is_file());
            if !(named_ok && inside && regular) {
                return Err(format!(
                    "the worker reported an unexpected output file: {}",
                    out.display()
                ));
            }
            // Keep the caller's form of the path ("x.7z", not "./x.7z").
            let dst = if self.target_dir == Path::new(".") {
                PathBuf::from(&name)
            } else {
                self.target_dir.join(&name)
            };
            moves.push((out.clone(), dst));
        }
        let mut done = Vec::new();
        for (from, to) in moves {
            let res = if self.replace {
                std::fs::rename(&from, &to)
            } else {
                rename_no_replace(&from, &to)
            };
            if let Err(e) = res {
                // Do not leave half a set of volumes behind.
                for d in &done {
                    let _ = std::fs::remove_file(d);
                }
                return Err(format!("{}: {e}", to.display()));
            }
            done.push(to);
        }
        report.outputs = done;
        let roots: Vec<PathBuf> = self.delete_roots.iter().map(|r| lexical(r)).collect();
        let mut seen = Vec::new();
        for p in std::mem::take(&mut report.delete_later) {
            let clean = lexical(&p);
            if p.components().any(|c| c == Component::ParentDir)
                || !roots.iter().any(|r| clean.starts_with(r))
            {
                report.warnings.push(format!(
                    "not deleted (outside the archived files): {}",
                    p.display()
                ));
                continue;
            }
            if std::fs::symlink_metadata(&p).is_ok_and(|m| m.is_dir()) {
                let _ = std::fs::remove_dir(&p);
            } else {
                report
                    .warnings
                    .extend(zip67_core::create::delete_one(&p, self.shred, &mut seen));
            }
        }
        Ok(())
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// `p` made absolute (from the current folder) without following links.
fn lexical(p: &Path) -> PathBuf {
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(p)
    };
    let mut out = PathBuf::new();
    for c in abs.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

fn rename_no_replace(from: &Path, to: &Path) -> std::io::Result<()> {
    use rustix::fs::{CWD, RenameFlags, renameat_with};
    match renameat_with(CWD, from, CWD, to, RenameFlags::NOREPLACE) {
        Ok(()) => Ok(()),
        // File systems without RENAME_NOREPLACE.
        Err(rustix::io::Errno::INVAL) | Err(rustix::io::Errno::NOSYS) => {
            if to.symlink_metadata().is_ok() {
                return Err(std::io::Error::from(std::io::ErrorKind::AlreadyExists));
            }
            std::fs::rename(from, to)
        }
        Err(e) => Err(e.into()),
    }
}

impl WorkerHandle {
    /// Starts `exe --worker` and sends the request.
    pub fn spawn(exe: &Path, req: &Request) -> std::io::Result<Self> {
        let stage = Staging::for_request(req)?;
        let job = Job {
            request: req.clone(),
            stage: stage.as_ref().map(|s| s.dir.clone()),
        };
        let mut child = Command::new(exe)
            .arg("--worker")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .env_remove("LD_PRELOAD")
            .spawn()?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| std::io::Error::other("no stdin"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| std::io::Error::other("no stdout"))?;
        let line = serde_json::to_string(&job).map_err(std::io::Error::other)?;
        writeln!(stdin, "{line}")?;
        stdin.flush()?;
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let reader = BufReader::with_capacity(1 << 20, stdout);
            for line in reader.lines() {
                let Ok(line) = line else { break };
                // Messages from the worker are parsed strictly; anything
                // malformed is dropped.
                if let Ok(ev) = serde_json::from_str::<Event>(&line) {
                    let last = matches!(ev, Event::Done(_) | Event::Failed(_));
                    if tx.send(ev).is_err() || last {
                        break;
                    }
                }
            }
        });
        Ok(WorkerHandle {
            child,
            stdin: Some(stdin),
            events: rx,
            finished: false,
            stage,
        })
    }

    fn control(&mut self, c: &Control) {
        if let (Some(s), Ok(line)) = (self.stdin.as_mut(), serde_json::to_string(c)) {
            let _ = writeln!(s, "{line}");
            let _ = s.flush();
        }
    }
    pub fn cancel(&mut self) {
        self.control(&Control::Cancel);
    }
    pub fn pause(&mut self) {
        self.control(&Control::Pause);
    }
    pub fn resume(&mut self) {
        self.control(&Control::Resume);
    }
    pub fn answer(&mut self, a: zip67_core::extract::Answer) {
        self.control(&Control::Answer(a));
    }

    /// Next event if one is ready. A crashed worker yields a failure.
    pub fn try_next(&mut self) -> Option<Event> {
        if self.finished {
            return None;
        }
        match self.events.try_recv() {
            Ok(ev) => {
                if matches!(ev, Event::Done(_) | Event::Failed(_)) {
                    self.finished = true;
                }
                Some(self.settle(ev))
            }
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => {
                self.finished = true;
                let status = self
                    .child
                    .wait()
                    .ok()
                    .map(|s| s.to_string())
                    .unwrap_or_default();
                Some(Event::Failed(Failure {
                    kind: FailKind::WorkerCrashed,
                    message: format!("the worker process stopped unexpectedly ({status})"),
                }))
            }
        }
    }

    /// Blocks until the next event.
    pub fn next_blocking(&mut self) -> Option<Event> {
        if self.finished {
            return None;
        }
        match self.events.recv() {
            Ok(ev) => {
                if matches!(ev, Event::Done(_) | Event::Failed(_)) {
                    self.finished = true;
                }
                Some(self.settle(ev))
            }
            Err(_) => {
                self.finished = true;
                Some(Event::Failed(Failure {
                    kind: FailKind::WorkerCrashed,
                    message: "the worker process stopped unexpectedly".into(),
                }))
            }
        }
    }

    /// Moves a staged archive into place when the worker is done.
    fn settle(&mut self, ev: Event) -> Event {
        let Some(stage) = self.stage.take() else {
            return ev;
        };
        match ev {
            Event::Done(Reply::Created(mut rep)) => match stage.finish(&mut rep) {
                Ok(()) => Event::Done(Reply::Created(rep)),
                Err(message) => Event::Failed(Failure {
                    kind: FailKind::Io,
                    message,
                }),
            },
            Event::Done(_) | Event::Failed(_) => ev,
            other => {
                self.stage = Some(stage);
                other
            }
        }
    }

    pub fn is_finished(&self) -> bool {
        self.finished
    }
}

impl Drop for WorkerHandle {
    fn drop(&mut self) {
        self.stdin = None;
        if !self.finished {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zip67_core::create::CreateReport;

    fn stage(root: &Path, replace: bool, delete_roots: Vec<PathBuf>) -> Staging {
        let dir = root.join(".67zip-test");
        std::fs::create_dir(&dir).unwrap();
        Staging {
            dir,
            target_dir: root.to_path_buf(),
            name: "a.7z".into(),
            replace,
            delete_roots,
            shred: false,
        }
    }

    #[test]
    fn outputs_must_stay_in_the_staging_folder() {
        let tmp = std::env::temp_dir().join(format!("67zip-stage-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        // Reported file outside the staging folder.
        let s = stage(&tmp, false, vec![]);
        std::fs::write(tmp.join("a.7z.evil"), b"x").unwrap();
        let mut r = CreateReport {
            outputs: vec![tmp.join("a.7z.evil")],
            ..Default::default()
        };
        assert!(s.finish(&mut r).is_err());
        drop(s);
        // A symlink in the staging folder, and a wrong name.
        let s = stage(&tmp, false, vec![]);
        std::os::unix::fs::symlink("/etc/passwd", s.dir.join("a.7z")).unwrap();
        let mut r = CreateReport {
            outputs: vec![s.dir.join("a.7z")],
            ..Default::default()
        };
        assert!(s.finish(&mut r).is_err());
        std::fs::write(s.dir.join("b.7z"), b"x").unwrap();
        let mut r = CreateReport {
            outputs: vec![s.dir.join("b.7z")],
            ..Default::default()
        };
        assert!(s.finish(&mut r).is_err());
        drop(s);
        // An update must produce exactly one file.
        let s = stage(&tmp, true, vec![]);
        std::fs::write(s.dir.join("a.7z"), b"x").unwrap();
        std::fs::write(s.dir.join("a.7z.001"), b"x").unwrap();
        let mut r = CreateReport {
            outputs: vec![s.dir.join("a.7z"), s.dir.join("a.7z.001")],
            ..Default::default()
        };
        assert!(s.finish(&mut r).is_err());
        drop(s);
        // Never over an existing file when creating.
        std::fs::write(tmp.join("a.7z"), b"old").unwrap();
        let s = stage(&tmp, false, vec![]);
        std::fs::write(s.dir.join("a.7z"), b"new").unwrap();
        let mut r = CreateReport {
            outputs: vec![s.dir.join("a.7z")],
            ..Default::default()
        };
        assert!(s.finish(&mut r).is_err());
        assert_eq!(std::fs::read(tmp.join("a.7z")).unwrap(), b"old");
        drop(s);
        assert!(!tmp.join(".67zip-test").exists(), "staging folder removed");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn deletes_only_inside_the_inputs() {
        let tmp = std::env::temp_dir().join(format!("67zip-stage-del-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("in")).unwrap();
        std::fs::write(tmp.join("in/f"), b"x").unwrap();
        std::fs::write(tmp.join("precious"), b"x").unwrap();
        let s = stage(&tmp, false, vec![tmp.join("in")]);
        std::fs::write(s.dir.join("a.7z"), b"x").unwrap();
        let mut r = CreateReport {
            outputs: vec![s.dir.join("a.7z")],
            delete_later: vec![
                tmp.join("in/f"),
                tmp.join("precious"),
                tmp.join("in/../precious"),
            ],
            ..Default::default()
        };
        s.finish(&mut r).unwrap();
        assert!(!tmp.join("in/f").exists());
        assert!(tmp.join("precious").exists());
        assert_eq!(r.warnings.len(), 2);
        assert!(tmp.join("a.7z").exists());
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
