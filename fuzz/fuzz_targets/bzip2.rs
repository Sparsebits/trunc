#![no_main]
use std::io::Read;

use libfuzzer_sys::fuzz_target;
use trunc_legacy::stream::Codec;

#[path = "common/stream.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    common::run(
        Codec::Bzip2,
        data,
        |d, l| trunc_testkit::tarbuild::bzip2(d, u32::from(l % 9) + 1),
        |c| {
            let mut out = Vec::new();
            bzip2::read::MultiBzDecoder::new(c).read_to_end(&mut out).ok()?;
            Some(out)
        },
    );
});
