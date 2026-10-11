//! The JSON reader for container image metadata (`manifest.json`, `index.json`, configs).
//!
//! It must not panic or recurse without bound on any input. Whatever it accepts is valid
//! UTF-8 (strings are checked, everything else is ASCII), and writing the parsed value back
//! gives text that is accepted again and written back identically (so the writer and reader
//! agree on escapes, nesting and member order).

#![no_main]
use libfuzzer_sys::fuzz_target;
use trunc_engine::fuzz::json_canonical;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = json_canonical(data) else {
        return;
    };
    assert!(
        std::str::from_utf8(data).is_ok(),
        "accepted input that is not UTF-8"
    );
    let again = json_canonical(text.as_bytes())
        .unwrap_or_else(|e| panic!("written text {text:?} is refused: {e}"));
    assert_eq!(again, text, "writing is not stable");
    assert!(text.len() <= data.len() * 6 + 2, "written text grew too much");
});
