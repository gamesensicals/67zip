//! Shared progress counters with cancel and pause support.
//!
//! A [`Progress`] is cheap to clone; all clones share the same counters, so a
//! GUI thread can read them while a worker thread updates them.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::error::{Error, Result};

#[derive(Default)]
struct Inner {
    total: AtomicU64,
    done: AtomicU64,
    files_total: AtomicU64,
    files_done: AtomicU64,
    /// Compressed bytes read or written, for the ratio display.
    packed: AtomicU64,
    cancelled: AtomicBool,
    paused: Mutex<bool>,
    resume: Condvar,
    current: Mutex<String>,
    warnings: Mutex<Vec<String>>,
}

/// Progress of one long-running operation.
#[derive(Clone)]
pub struct Progress {
    inner: Arc<Inner>,
    started: Instant,
}

/// A consistent copy of the counters, for display.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct Snapshot {
    pub total: u64,
    pub done: u64,
    pub files_total: u64,
    pub files_done: u64,
    pub packed: u64,
    pub current: String,
    pub elapsed_ms: u64,
    pub paused: bool,
}

impl Default for Progress {
    fn default() -> Self {
        Self::new()
    }
}

impl Progress {
    pub fn new() -> Self {
        Progress { inner: Arc::new(Inner::default()), started: Instant::now() }
    }

    pub fn set_total(&self, bytes: u64) {
        self.inner.total.store(bytes, Ordering::Relaxed);
    }
    pub fn add_total(&self, bytes: u64) {
        self.inner.total.fetch_add(bytes, Ordering::Relaxed);
    }
    pub fn set_files_total(&self, n: u64) {
        self.inner.files_total.store(n, Ordering::Relaxed);
    }
    pub fn file_done(&self) {
        self.inner.files_done.fetch_add(1, Ordering::Relaxed);
    }
    pub fn add_done(&self, bytes: u64) {
        self.inner.done.fetch_add(bytes, Ordering::Relaxed);
    }
    pub fn add_packed(&self, bytes: u64) {
        self.inner.packed.fetch_add(bytes, Ordering::Relaxed);
    }
    pub fn set_current(&self, name: &str) {
        if let Ok(mut c) = self.inner.current.lock() {
            c.clear();
            c.push_str(name);
        }
    }
    pub fn warn(&self, msg: impl Into<String>) {
        if let Ok(mut w) = self.inner.warnings.lock() {
            if w.len() < 10_000 {
                w.push(msg.into());
            }
        }
    }
    pub fn warnings(&self) -> Vec<String> {
        self.inner.warnings.lock().map(|w| w.clone()).unwrap_or_default()
    }

    pub fn cancel(&self) {
        self.inner.cancelled.store(true, Ordering::SeqCst);
        self.resume();
    }
    pub fn is_cancelled(&self) -> bool {
        self.inner.cancelled.load(Ordering::Relaxed)
    }
    pub fn pause(&self) {
        if let Ok(mut p) = self.inner.paused.lock() {
            *p = true;
        }
    }
    pub fn resume(&self) {
        if let Ok(mut p) = self.inner.paused.lock() {
            *p = false;
        }
        self.inner.resume.notify_all();
    }
    pub fn is_paused(&self) -> bool {
        self.inner.paused.lock().map(|p| *p).unwrap_or(false)
    }

    /// Called often by workers: blocks while paused, fails when cancelled.
    pub fn check(&self) -> Result<()> {
        if self.is_cancelled() {
            return Err(Error::Cancelled);
        }
        if let Ok(mut paused) = self.inner.paused.lock() {
            while *paused && !self.is_cancelled() {
                match self.inner.resume.wait_timeout(paused, Duration::from_millis(200)) {
                    Ok((guard, _)) => paused = guard,
                    Err(_) => break,
                }
            }
        }
        if self.is_cancelled() {
            return Err(Error::Cancelled);
        }
        Ok(())
    }

    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            total: self.inner.total.load(Ordering::Relaxed),
            done: self.inner.done.load(Ordering::Relaxed),
            files_total: self.inner.files_total.load(Ordering::Relaxed),
            files_done: self.inner.files_done.load(Ordering::Relaxed),
            packed: self.inner.packed.load(Ordering::Relaxed),
            current: self.inner.current.lock().map(|c| c.clone()).unwrap_or_default(),
            elapsed_ms: self.started.elapsed().as_millis() as u64,
            paused: self.is_paused(),
        }
    }
}
