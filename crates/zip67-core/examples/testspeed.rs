//! Times an integrity test of an archive with a given thread count.
//! Usage: cargo run --release --example testspeed -- <archive> [threads]
use std::time::Instant;
use zip67_core::extract::{test, Selection};
use zip67_core::{open, OpenOptions, Progress};

fn main() {
    let mut a = std::env::args().skip(1);
    let path = a.next().expect("archive");
    let threads: usize = a.next().map(|t| t.parse().unwrap()).unwrap_or(0);
    let t = Instant::now();
    let mut r = open(path.as_ref(), &OpenOptions { threads, ..Default::default() }).unwrap();
    let rep = test(r.as_mut(), &Selection::All, &Progress::new()).unwrap();
    println!("{path}: {} files, {} bytes, threads {threads}: {:.2}s, errors {}", rep.files, rep.bytes, t.elapsed().as_secs_f64(), rep.errors.len());
}
