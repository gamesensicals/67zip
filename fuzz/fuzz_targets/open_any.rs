#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| zip67_fuzz::run(data, None, "fuzz.bin"));
