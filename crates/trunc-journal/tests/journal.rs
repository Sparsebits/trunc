#![allow(clippy::unwrap_used)]

use std::path::Path;

use trunc_fs::FsError;
use trunc_journal::{Journal, JournalError};
use trunc_testkit::{CrashModel, Fault, FaultFs};

const J: &str = "/a.zip.trncj";

#[test]
fn round_trip_and_alternation() {
    let fs = FaultFs::new(CrashModel::LoseUnflushed);
    let mut j = Journal::create(&fs, Path::new(J), b"preamble bytes", 64).unwrap();
    j.write(b"one").unwrap();
    j.write(b"two").unwrap();
    j.write(b"three").unwrap();
    drop(j);
    fs.recover(); // everything above was flushed
    let (j, pre, latest) = Journal::open(&fs, Path::new(J)).unwrap();
    assert_eq!(pre, b"preamble bytes");
    assert_eq!(latest.unwrap(), b"three");
    assert!(matches!(
        {
            let mut j = j;
            j.write(&[0u8; 65])
        },
        Err(JournalError::TooLarge { .. })
    ));
}

#[test]
fn empty_journal_has_no_checkpoint() {
    let fs = FaultFs::new(CrashModel::LoseUnflushed);
    drop(Journal::create(&fs, Path::new(J), b"", 16).unwrap());
    fs.recover();
    let (_, pre, latest) = Journal::open(&fs, Path::new(J)).unwrap();
    assert!(pre.is_empty() && latest.is_none());
}

/// Crash (or tear) every operation of a write sequence: the newest committed checkpoint is
/// always either the last fully written one or the one before it, never garbage.
#[test]
fn crash_sweep_never_loses_the_previous_checkpoint() {
    for model in [
        CrashModel::LoseUnflushed,
        CrashModel::RandomSubset { seed: 3 },
        CrashModel::WriteThrough,
    ] {
        let count = {
            let fs = FaultFs::new(CrashModel::WriteThrough);
            let mut j = Journal::create(&fs, Path::new(J), b"pre", 32).unwrap();
            let start = fs.op_count();
            for i in 0..6u8 {
                j.write(&[i; 20]).unwrap();
            }
            fs.op_count() - start
        };
        for k in 1..=count {
            for torn in [false, true] {
                let fs = FaultFs::new(model);
                let mut j = Journal::create(&fs, Path::new(J), b"pre", 32).unwrap();
                let base = fs.op_count();
                fs.inject(if torn {
                    Fault::TornWrite {
                        op: base + k,
                        keep: 9,
                    }
                } else {
                    Fault::CrashAt(base + k)
                });
                let mut committed: Option<u8> = None;
                for i in 0..6u8 {
                    match j.write(&[i; 20]) {
                        Ok(()) => committed = Some(i),
                        Err(JournalError::Fs(FsError::Crashed)) => break,
                        Err(e) => panic!("{e}"),
                    }
                }
                fs.recover();
                let (_, pre, latest) = Journal::open(&fs, Path::new(J)).unwrap();
                assert_eq!(pre, b"pre");
                let got = latest.map(|p| {
                    assert!(
                        p.iter().all(|&b| b == p[0]) && p.len() == 20,
                        "garbage checkpoint"
                    );
                    p[0]
                });
                match committed {
                    // The write in flight may or may not have landed.
                    Some(c) => assert!(
                        got == Some(c) || got == Some(c + 1),
                        "{model:?} op {k}: {got:?} vs {c}"
                    ),
                    None => assert!(got.is_none() || got == Some(0), "{model:?} op {k}: {got:?}"),
                }
            }
        }
    }
}

#[test]
fn corrupt_header_or_preamble_is_rejected() {
    let fs = FaultFs::new(CrashModel::WriteThrough);
    drop(Journal::create(&fs, Path::new(J), b"important layout", 16).unwrap());
    let mut bytes = fs.get_file(Path::new(J)).unwrap();
    bytes[70] ^= 1; // inside the preamble
    fs.put_file(Path::new("/b"), &bytes);
    assert!(matches!(
        Journal::open(&fs, Path::new("/b")),
        Err(JournalError::BadPreamble)
    ));
    bytes[70] ^= 1;
    bytes[3] ^= 1; // header magic
    fs.put_file(Path::new("/c"), &bytes);
    assert!(matches!(
        Journal::open(&fs, Path::new("/c")),
        Err(JournalError::BadHeader)
    ));
}
