#![no_main]
use std::path::Path;

use libfuzzer_sys::fuzz_target;
use trunc_fs::{FsBackend, OpenMode, Share};
use trunc_testkit::{CrashModel, FaultFs};

fuzz_target!(|data: &[u8]| {
    let fs = FaultFs::new(CrashModel::WriteThrough);
    fs.put_file(Path::new("/z"), data);
    let h = fs.open(Path::new("/z"), OpenMode::Read, Share::Shared).unwrap();
    if let Ok(layout) = trunc_legacy::zip::parse(h.as_ref()) {
        for e in &layout.entries {
            assert!(e.region_start < e.data_offset && e.data_offset + e.compressed_size <= e.region_end);
            assert!(e.region_end <= layout.cd_start);
        }
        assert_eq!(trunc_legacy::zip::Layout::from_bytes(&layout.to_bytes()), Some(layout));
    }
});
