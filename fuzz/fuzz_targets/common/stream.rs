//! Shared body of the stream decoder targets.
//!
//! The first byte picks the input: odd means "compress the rest with the reference encoder
//! (and maybe damage one byte)", which reaches deep decoder paths; even means "decode the
//! rest as it is". Then:
//! - the decoder must not panic, and its output stays within the limit;
//! - whatever it accepts, the reference decoder accepts with the same output;
//! - resuming from every safe point, with the input before it zeroed and the window read back
//!   from the output, gives exactly the rest of the output.

use std::path::Path;

use trunc_fs::{FileHandle, FsBackend, OpenMode, Share};
use trunc_legacy::stream::{self, Codec, History, Input, Limits, NoHistory};
use trunc_testkit::{CrashModel, FaultFs};

const MAX_OUT: u64 = 8 << 20;

struct VecHistory<'a>(&'a [u8]);

impl History for VecHistory<'_> {
    fn read(&mut self, at: u64, buf: &mut [u8]) -> stream::Result<()> {
        let at = at as usize;
        buf.copy_from_slice(&self.0[at..at + buf.len()]);
        Ok(())
    }
}

fn host(bytes: &[u8]) -> (FaultFs, Box<dyn FileHandle>) {
    let fs = FaultFs::new(CrashModel::WriteThrough);
    fs.put_file(Path::new("/d"), bytes);
    let h = fs.open(Path::new("/d"), OpenMode::Read, Share::Shared).unwrap();
    (fs, h)
}

type Points = Vec<(Vec<u8>, u64, u64)>;

fn decode(
    codec: Codec,
    h: &dyn FileHandle,
    start: Option<&[u8]>,
    history: &mut dyn History,
) -> Result<(Vec<u8>, Points), stream::StreamError> {
    let mut out = Vec::new();
    let mut points = Vec::new();
    let len = h.size().unwrap();
    stream::decode(
        codec,
        Input { src: h, len },
        start,
        history,
        Limits {
            max_out: MAX_OUT,
            max_window: 16 << 20,
        },
        2048,
        &mut |b| {
            out.extend_from_slice(b);
            Ok(())
        },
        &mut |p| {
            points.push((p.cursor.to_vec(), p.out, p.free_below));
            Ok(())
        },
    )?;
    Ok((out, points))
}

pub fn run(
    codec: Codec,
    data: &[u8],
    encode: fn(&[u8], u8) -> Vec<u8>,
    reference: fn(&[u8]) -> Option<Vec<u8>>,
) {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let input = if mode & 1 == 1 {
        let mut c = encode(rest, mode >> 1);
        if mode & 0x80 != 0 && !c.is_empty() {
            let at = (usize::from(mode) * 7919 + rest.len()) % c.len();
            c[at] ^= 1 << (mode % 8);
        }
        c
    } else {
        rest.to_vec()
    };
    let (_fs, h) = host(&input);
    let Ok((out, points)) = decode(codec, h.as_ref(), None, &mut NoHistory) else {
        return;
    };
    assert!(out.len() as u64 <= MAX_OUT);
    if let Some(r) = reference(&input) {
        assert!(r == out, "{codec:?}: output differs from the reference decoder");
    } else {
        panic!("{codec:?}: accepted input the reference decoder rejects");
    }
    for (cursor, at, free_below) in &points {
        let mut punched = input.clone();
        punched[..*free_below as usize].fill(0);
        let (_fs, h) = host(&punched);
        let (rest, _) = decode(codec, h.as_ref(), Some(cursor), &mut VecHistory(&out))
            .unwrap_or_else(|e| panic!("{codec:?}: resume at {at} failed: {e}"));
        assert!(rest == out[*at as usize..], "{codec:?}: resume at {at} differs");
    }
}
