#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| zip67_fuzz::run(data, Some(zip67_core::ArchiveType::ISO), "fuzz.iso"));
