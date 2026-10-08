#![no_main]
use libfuzzer_sys::fuzz_target;
use trunc_core::{FOOTER_LEN, Footer};

fuzz_target!(|data: &[u8]| {
    let _ = Footer::decode(data);

    // As in the header target: repair magic and CRC so the field checks are exercised, and
    // require that anything accepted encodes back to the same bytes.
    let mut b = [0u8; FOOTER_LEN];
    let n = data.len().min(FOOTER_LEN);
    b[..n].copy_from_slice(&data[..n]);
    b[0..8].copy_from_slice(b"TRNCBLK\0");
    let crc = trunc_hash::crc32c(&b[0..124]);
    b[124..128].copy_from_slice(&crc.to_le_bytes());
    if let Ok(f) = Footer::decode(&b) {
        assert_eq!(f.encode(), b);
    }
});
