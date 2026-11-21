//! Starting a worker and talking to it (used by the GUI).

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, TryRecvError};

use crate::protocol::{Control, Event, FailKind, Failure, Request};

pub struct WorkerHandle {
    child: Child,
    stdin: Option<ChildStdin>,
    events: Receiver<Event>,
    finished: bool,
}

impl WorkerHandle {
    /// Starts `exe --worker` and sends the request.
    pub fn spawn(exe: &Path, req: &Request) -> std::io::Result<Self> {
        let mut child = Command::new(exe)
            .arg("--worker")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .env_remove("LD_PRELOAD")
            .spawn()?;
        let mut stdin = child.stdin.take().ok_or_else(|| std::io::Error::other("no stdin"))?;
        let stdout = child.stdout.take().ok_or_else(|| std::io::Error::other("no stdout"))?;
        let line = serde_json::to_string(req).map_err(std::io::Error::other)?;
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
        Ok(WorkerHandle { child, stdin: Some(stdin), events: rx, finished: false })
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
                Some(ev)
            }
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => {
                self.finished = true;
                let status = self.child.wait().ok().map(|s| s.to_string()).unwrap_or_default();
                Some(Event::Failed(Failure { kind: FailKind::WorkerCrashed, message: format!("the worker process stopped unexpectedly ({status})") }))
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
                Some(ev)
            }
            Err(_) => {
                self.finished = true;
                Some(Event::Failed(Failure { kind: FailKind::WorkerCrashed, message: "the worker process stopped unexpectedly".into() }))
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
