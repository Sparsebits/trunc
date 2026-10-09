#![no_main]
use libfuzzer_sys::fuzz_target;
use trunc_legacy::stream::Codec;

#[path = "common/stream.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    common::run(
        Codec::Zstd,
        data,
        |d, l| {
            let level = i32::from(l % 20) - 1;
            trunc_testkit::tarbuild::zstd_with(d, level, l & 0x20 != 0, None)
        },
        |c| zstd::stream::decode_all(c).ok(),
    );
});
