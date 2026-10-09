#![no_main]
use std::io::Read;

use libfuzzer_sys::fuzz_target;
use trunc_legacy::stream::Codec;
use trunc_testkit::tarbuild::{self, XzCheck};

#[path = "common/stream.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    common::run(
        Codec::Xz,
        data,
        |d, l| {
            let check = [XzCheck::None, XzCheck::Crc32, XzCheck::Crc64, XzCheck::Sha256]
                [usize::from(l % 4)];
            let block = (l & 0x10 != 0).then_some(4096);
            tarbuild::xz_with(d, u32::from(l % 4), check, block)
        },
        |c| {
            let mut out = Vec::new();
            liblzma::read::XzDecoder::new_multi_decoder(c)
                .read_to_end(&mut out)
                .ok()?;
            Some(out)
        },
    );
});
