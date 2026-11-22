//! Writes a RAR5 archive with the test encoder, for speed checks against
//! other RAR readers (67zip itself does not create RAR archives):
//!
//! cargo run --release --example rar5enc -- out.rar file...

#[path = "../tests/rar5enc/mod.rs"]
mod rar5enc;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (out, inputs) = args.split_first().expect("usage: rar5enc out.rar file...");
    let data: Vec<(String, Vec<u8>)> = inputs
        .iter()
        .map(|p| {
            let name = std::path::Path::new(p).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            (name, std::fs::read(p).expect("read input"))
        })
        .collect();
    let files: Vec<(&str, &[u8])> = data.iter().map(|(n, d)| (n.as_str(), d.as_slice())).collect();
    std::fs::write(out, rar5enc::archive(&files)).expect("write output");
}
