//! Compresses fixed-size chunks on several threads and writes the results
//! in order. Works for formats where concatenated streams are valid
//! (gzip members, bzip2 streams, zstd frames).

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;

use crate::error::{Error, Result};

type Job = (u64, Vec<u8>);
type CompressFn = Arc<dyn Fn(&[u8]) -> Result<Vec<u8>> + Send + Sync>;

pub struct ParallelWriter<W: Write> {
    inner: Option<W>,
    chunk: usize,
    buf: Vec<u8>,
    next_id: u64,
    next_write: u64,
    pending: BTreeMap<u64, Result<Vec<u8>>>,
    job_tx: Option<mpsc::SyncSender<Job>>,
    res_rx: mpsc::Receiver<(u64, Result<Vec<u8>>)>,
    workers: Vec<thread::JoinHandle<()>>,
    in_flight: usize,
    max_in_flight: usize,
}

impl<W: Write> ParallelWriter<W> {
    pub fn new(inner: W, chunk: usize, threads: usize, f: CompressFn) -> Self {
        let threads = threads.max(1);
        let (job_tx, job_rx) = mpsc::sync_channel::<Job>(threads * 2);
        let (res_tx, res_rx) = mpsc::channel();
        let job_rx = Arc::new(std::sync::Mutex::new(job_rx));
        let mut workers = Vec::new();
        for _ in 0..threads {
            let rx = Arc::clone(&job_rx);
            let tx = res_tx.clone();
            let f = Arc::clone(&f);
            workers.push(thread::spawn(move || {
                loop {
                    let job = match rx.lock() {
                        Ok(guard) => guard.recv(),
                        Err(_) => return,
                    };
                    let Ok((id, data)) = job else { return };
                    if tx.send((id, f(&data))).is_err() {
                        return;
                    }
                }
            }));
        }
        ParallelWriter {
            inner: Some(inner),
            chunk: chunk.max(64 * 1024),
            buf: Vec::new(),
            next_id: 0,
            next_write: 0,
            pending: BTreeMap::new(),
            job_tx: Some(job_tx),
            res_rx,
            workers,
            in_flight: 0,
            max_in_flight: threads * 3,
        }
    }

    fn dispatch(&mut self) -> Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let data = std::mem::replace(&mut self.buf, Vec::with_capacity(self.chunk));
        while self.in_flight >= self.max_in_flight {
            self.collect_one()?;
        }
        let tx = self
            .job_tx
            .as_ref()
            .ok_or_else(|| Error::invalid("writer finished"))?;
        tx.send((self.next_id, data))
            .map_err(|_| Error::invalid("compression thread stopped"))?;
        self.next_id += 1;
        self.in_flight += 1;
        Ok(())
    }

    fn collect_one(&mut self) -> Result<()> {
        let (id, res) = self
            .res_rx
            .recv()
            .map_err(|_| Error::invalid("compression thread stopped"))?;
        self.in_flight -= 1;
        self.pending.insert(id, res);
        while let Some(res) = self.pending.remove(&self.next_write) {
            self.inner
                .as_mut()
                .ok_or_else(|| Error::invalid("writer finished"))?
                .write_all(&res?)?;
            self.next_write += 1;
        }
        Ok(())
    }

    pub fn finish(mut self) -> Result<W> {
        self.dispatch()?;
        while self.in_flight > 0 {
            self.collect_one()?;
        }
        self.job_tx = None;
        for w in self.workers.drain(..) {
            let _ = w.join();
        }
        self.inner
            .take()
            .ok_or_else(|| Error::invalid("writer finished"))
    }
}

impl<W: Write> Write for ParallelWriter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let room = self.chunk - self.buf.len();
        let n = room.min(data.len());
        self.buf.extend_from_slice(&data[..n]);
        if self.buf.len() >= self.chunk {
            self.dispatch()?;
        }
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<W: Write> Drop for ParallelWriter<W> {
    fn drop(&mut self) {
        self.job_tx = None;
        for w in self.workers.drain(..) {
            let _ = w.join();
        }
    }
}
