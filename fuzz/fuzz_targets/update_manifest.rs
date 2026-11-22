#![no_main]
// The update manifest parser and the signature decoder get untrusted bytes
// from the network (the parser only after a signature check, but it must
// never panic either way).
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = zip67_update::parse_manifest(data);
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = zip67_update::verify_manifest(data, text, &zip67_update::release_key());
    }
});
