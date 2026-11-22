//! Decodes a .bz2 file with N threads and prints the time.
use std::io::Read;
use std::time::Instant;
fn main() {
    let mut a = std::env::args().skip(1);
    let path = a.next().expect("file");
    let threads: usize = a.next().map(|t| t.parse().unwrap()).unwrap_or(1);
    let data = std::fs::read(&path).unwrap();
    let t = Instant::now();
    let mut d = zip67_core::codecs::bz2::BzDecoder::new(&data[..], threads);
    let mut n = 0u64;
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let k = d.read(&mut buf).unwrap();
        if k == 0 { break }
        n += k as u64;
    }
    println!("{path}: {n} bytes, {threads} threads: {:.2}s", t.elapsed().as_secs_f64());
}
