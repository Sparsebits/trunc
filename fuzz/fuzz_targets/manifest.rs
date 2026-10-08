#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(opened) = trunc_core::SignedManifest::open(data) {
        // Anything that validates must have a self-consistent layout.
        let m = &opened.manifest;
        let fbo = 4096;
        for k in 0..=m.blocks.len() {
            assert_eq!(m.consumed_blocks(fbo, m.len_after_consuming(fbo, k)), Some(k));
        }
    }
});
