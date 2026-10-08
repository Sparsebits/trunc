#![no_main]
use libfuzzer_sys::fuzz_target;
use trunc_legacy::tar::{self, Reader};

fuzz_target!(|data: &[u8]| {
    // The first byte picks how the stream is split into pieces, so chunk boundaries that fall
    // inside headers and PAX records are exercised.
    let Some((&split, body)) = data.split_first() else {
        return;
    };
    let chunk = usize::from(split).max(1);
    let mut r = Reader::new();
    let mut content = 0u64;
    for piece in body.chunks(chunk) {
        if r.feed_data(piece, &mut |d| content += d.len() as u64).is_err() {
            return;
        }
    }
    let end = r.position();
    if let Ok(entries) = r.finish() {
        // Accepted entries: content lies inside the stream, in order, and adds up to what the
        // reader reported as file data.
        let mut prev = 0u64;
        let mut total = 0u64;
        for e in &entries {
            assert!(e.data_offset >= prev && e.data_offset + e.size <= end);
            assert!(e.kind == tar::Kind::File || e.size == 0);
            prev = e.data_offset + e.size;
            total += e.size;
        }
        assert_eq!(total, content);
        let b = tar::entries_to_bytes(&entries);
        assert_eq!(tar::entries_from_bytes(&b), Some((entries, b.len())));
    }
});
