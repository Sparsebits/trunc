//! Time a decoder alone: `cargo run --release -p trunc-legacy --example decode -- <file>`.
//! Detects the codec, decodes the whole file, discards the output. `TRUNC_THREADS=1` decodes
//! on one thread.

use std::path::Path;
use std::time::Instant;

use trunc_fs::{FsBackend, OpenMode, OsFs, Share};
use trunc_legacy::stream::{self, Codec, Input, Limits, NoHistory};

fn main() {
    let path = std::env::args().nth(1).expect("usage: decode <file>");
    let fs = OsFs::new();
    let h = fs
        .open(Path::new(&path), OpenMode::Read, Share::Shared)
        .expect("open");
    let len = h.size().expect("size");
    let mut head = [0u8; 16];
    h.read_exact_at(&mut head, 0).expect("read");
    let codec = Codec::sniff(&head).expect("not a known compressed file");
    let mut best = f64::MAX;
    let mut out = 0u64;
    for _ in 0..3 {
        let t = Instant::now();
        out = 0;
        stream::decode(
            codec,
            Input {
                src: h.as_ref(),
                len,
            },
            None,
            &mut NoHistory,
            Limits {
                threads: std::env::var("TRUNC_THREADS")
                    .ok()
                    .and_then(|t| t.parse().ok())
                    .unwrap_or(0),
                ..Limits::new(u64::MAX)
            },
            0,
            &mut |b| {
                out += b.len() as u64;
                Ok(())
            },
            &mut |_| Ok(()),
        )
        .expect("decode");
        best = best.min(t.elapsed().as_secs_f64());
    }
    #[allow(clippy::cast_precision_loss)]
    let mbs = out as f64 / best / 1e6;
    println!("{codec:?}: {out} bytes in {best:.3}s ({mbs:.0} MB/s)");
}
