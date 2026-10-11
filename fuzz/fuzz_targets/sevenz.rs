#![no_main]
//! 7z parsing and folder decoding. The first byte picks the input: odd means "build an archive
//! from the rest with the test writer (and maybe damage one byte)", which gets past the header
//! CRCs into the decoders; even means "parse the rest as it is". Nothing may panic, and decoded
//! output never exceeds what the header declares.

use std::cell::Cell;
use std::path::Path;

use libfuzzer_sys::fuzz_target;
use trunc_fs::{FsBackend, OpenMode, Share};
use trunc_legacy::sevenz;
use trunc_testkit::sevenzbuild::{Codec7, Item7, Opts7, build};
use trunc_testkit::{CrashModel, FaultFs};

/// Folders declaring more output than this are parsed but not decoded (keeps runs fast).
const MAX_FOLDER: u64 = 16 << 20;

fn archive(data: &[u8]) -> Vec<u8> {
    let Some((&first, rest)) = data.split_first() else {
        return Vec::new();
    };
    if first & 1 == 0 {
        return rest.to_vec();
    }
    let codec = match (first >> 1) % 6 {
        0 => Codec7::Copy,
        1 => Codec7::Lzma,
        2 => Codec7::Lzma2,
        3 => Codec7::BcjLzma2,
        4 => Codec7::BcjLzma,
        _ => Codec7::DeltaLzma2(1 + (first >> 4)),
    };
    let items: Vec<Item7> = rest
        .chunks(97)
        .enumerate()
        .map(|(i, c)| Item7::file(&format!("d{}/f{i}", i % 3), c))
        .collect();
    let mut a = build(
        &items,
        &Opts7 {
            codec,
            solid: first & 0x40 != 0,
            encode_header: first & 0x80 != 0,
            ..Opts7::default()
        },
    );
    if let Some(&b) = rest.first() {
        if b & 1 == 1 && !a.is_empty() {
            let i = usize::from(b) * 7919 % a.len();
            a[i] ^= b | 1;
        }
    }
    a
}

fuzz_target!(|data: &[u8]| {
    let bytes = archive(data);
    let fs = FaultFs::new(CrashModel::WriteThrough);
    fs.put_file(Path::new("/a.7z"), &bytes);
    let h = fs.open(Path::new("/a.7z"), OpenMode::Read, Share::Shared).unwrap();
    let Ok(layout) = sevenz::parse(h.as_ref(), 16 << 20) else {
        return;
    };
    for (i, f) in layout.folders.iter().enumerate() {
        assert!(f.pack_offset + f.pack_size <= layout.header_offset);
        if f.unpack_size > MAX_FOLDER {
            continue;
        }
        let got: Vec<Cell<u64>> = vec![Cell::new(0); layout.entries.len()];
        let _ = sevenz::decode_folder(
            h.as_ref(),
            &layout,
            i,
            &mut |_| Ok(()),
            &mut |e, b| {
                got[e].set(got[e].get() + b.len() as u64);
                assert!(got[e].get() <= layout.entries[e].size);
                Ok(())
            },
            &mut |e| {
                assert_eq!(got[e].get(), layout.entries[e].size);
                Ok(())
            },
        );
    }
});
