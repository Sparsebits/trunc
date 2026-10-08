#![no_main]
use std::path::Path;

use libfuzzer_sys::fuzz_target;
use trunc_fs::{FsBackend, OpenMode, Share};
use trunc_legacy::inflate::{Checkpoint, Inflater};
use trunc_testkit::{CrashModel, FaultFs};

fuzz_target!(|data: &[u8]| {
    let fs = FaultFs::new(CrashModel::WriteThrough);
    fs.put_file(Path::new("/d"), data);
    let h = fs.open(Path::new("/d"), OpenMode::Read, Share::Shared).unwrap();
    let mut total = 0u64;
    let _ = Inflater::new(&Checkpoint::start(), 1 << 22).run(
        h.as_ref(),
        0,
        data.len() as u64,
        &mut |b| {
            total += b.len() as u64;
            Ok(())
        },
        4096,
        &mut |ck| {
            assert!(Checkpoint::from_bytes(&ck.to_bytes()).is_some());
            Ok(())
        },
    );
    assert!(total <= 1 << 22);
});
