#![no_main]
use libfuzzer_sys::fuzz_target;
use trunc_core::{HEADER_LEN, Header};

fuzz_target!(|data: &[u8]| {
    let _ = Header::decode(data);

    // Random bytes almost never pass the magic and CRC checks, so also decode a copy with both
    // repaired. That reaches the field validation. Decoding is canonical: anything accepted must
    // encode back to the same bytes.
    let mut b = [0u8; HEADER_LEN];
    let n = data.len().min(HEADER_LEN);
    b[..n].copy_from_slice(&data[..n]);
    b[0..6].copy_from_slice(b"TRNC\0\x01");
    let crc = trunc_hash::crc32c(&b[0..92]);
    b[92..96].copy_from_slice(&crc.to_le_bytes());
    if let Ok(h) = Header::decode(&b) {
        assert_eq!(h.encode(), b);
    }
});
