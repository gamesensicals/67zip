#![no_main]
// First byte picks the stream format; the rest is the stream.
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    use zip67_core::{ArchiveType, Compression, Container};
    let Some((&k, rest)) = data.split_first() else { return };
    let c = Compression::ALL[k as usize % Compression::ALL.len()];
    let container = if k & 0x80 != 0 { Container::Tar } else { Container::Raw };
    zip67_fuzz::run(rest, Some(ArchiveType::new(container, c)), "fuzz.dat");
});
