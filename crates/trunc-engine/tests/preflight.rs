#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};

use trunc_engine::preflight::{self, Finding, Severity};
use trunc_engine::producer::{self, CreateOptions};
use trunc_engine::{Archive, SpaceParams};
use trunc_fs::{
    FileHandle, FsBackend, FsKind, Meta, OpenMode, Result, Share, SnapshotHint, SyncHint,
    VolumeInfo,
};
use trunc_testkit::{CrashModel, FaultFs, fixtures};

fn archive() -> (tempfile::TempDir, PathBuf) {
    let d = tempfile::tempdir().unwrap();
    let src = d.path().join("src");
    fixtures::large_file(&src, 2 << 20, 1);
    let arc = d.path().join("a.trnc");
    let o = CreateOptions {
        block_size: 256 << 10,
        ..CreateOptions::default()
    };
    producer::create(&arc, &[src], &o).unwrap();
    (d, arc)
}

fn params() -> SpaceParams {
    SpaceParams {
        margin_fixed: 0,
        margin_ppm: 0,
        batch_max_u: 256 << 10,
        ..SpaceParams::default()
    }
}

#[test]
fn fit_verdicts_follow_free_space() {
    let (_d, arc) = archive();
    let a = Archive::open(&arc).unwrap();
    let fs = FaultFs::new(CrashModel::WriteThrough);

    fs.set_capacity(Some(1 << 40));
    let p = preflight::assess(&fs, &a, Path::new("/out"), params()).unwrap();
    assert!(p.same_volume);
    assert_eq!((p.extract_fits, p.consume_fits), (Some(true), Some(true)));
    assert!(
        p.consume_needs < p.bound.extract_extra,
        "consume needs less than extract"
    );
    assert!(p.blockers().next().is_none());

    // Enough for consume, not for extract.
    fs.set_capacity(Some(p.consume_needs + 1));
    let p = preflight::assess(&fs, &a, Path::new("/out"), params()).unwrap();
    assert_eq!((p.extract_fits, p.consume_fits), (Some(false), Some(true)));

    fs.set_capacity(Some(1));
    let p = preflight::assess(&fs, &a, Path::new("/out"), params()).unwrap();
    assert_eq!((p.extract_fits, p.consume_fits), (Some(false), Some(false)));
}

/// Wraps a backend but reports a chosen volume for every path.
#[derive(Debug)]
struct FakeVolume<B> {
    inner: B,
    archive_vol: VolumeInfo,
    dest_vol: VolumeInfo,
    archive_path: PathBuf,
}

impl<B: FsBackend> FsBackend for FakeVolume<B> {
    fn open(&self, p: &Path, m: OpenMode, s: Share) -> Result<Box<dyn FileHandle>> {
        self.inner.open(p, m, s)
    }
    fn create_dir(&self, p: &Path) -> Result<()> {
        self.inner.create_dir(p)
    }
    fn flush_dir(&self, p: &Path) -> Result<()> {
        self.inner.flush_dir(p)
    }
    fn rename(&self, a: &Path, b: &Path) -> Result<()> {
        self.inner.rename(a, b)
    }
    fn hard_link(&self, a: &Path, b: &Path) -> Result<()> {
        self.inner.hard_link(a, b)
    }
    fn remove_file(&self, p: &Path) -> Result<()> {
        self.inner.remove_file(p)
    }
    fn remove_dir(&self, p: &Path) -> Result<()> {
        self.inner.remove_dir(p)
    }
    fn metadata(&self, p: &Path) -> Result<Option<Meta>> {
        self.inner.metadata(p)
    }
    fn read_dir(&self, p: &Path) -> Result<Vec<String>> {
        self.inner.read_dir(p)
    }
    fn set_mode(&self, p: &Path, mode: u32) -> Result<()> {
        self.inner.set_mode(p, mode)
    }
    fn probe_volume(&self, p: &Path) -> Result<VolumeInfo> {
        Ok(if p == self.archive_path {
            self.archive_vol.clone()
        } else {
            self.dest_vol.clone()
        })
    }
}

fn vol(fs: FsKind, name: &str, id: u64, sync: SyncHint) -> VolumeInfo {
    VolumeInfo {
        fs,
        fs_name: name.into(),
        root: None,
        volume_id: Some(id),
        cluster_size: 32 * 1024,
        free_bytes: Some(1 << 40),
        total_bytes: Some(1 << 41),
        supports_sparse: false,
        sparse_granularity: 0,
        max_file_size: if fs == FsKind::Fat32 {
            (4 << 30) - 1
        } else {
            u64::MAX
        },
        sync,
        snapshots: SnapshotHint::None,
    }
}

#[test]
fn blockers_for_unjournaled_and_synced_archives() {
    let (_d, arc) = archive();
    let a = Archive::open(&arc).unwrap();
    let mk = |archive_vol, dest_vol| FakeVolume {
        inner: FaultFs::new(CrashModel::WriteThrough),
        archive_vol,
        dest_vol,
        archive_path: arc.clone(),
    };

    let fat = vol(FsKind::Fat32, "FAT32", 1, SyncHint::None);
    let p = preflight::assess(&mk(fat.clone(), fat), &a, Path::new("/o"), params()).unwrap();
    assert!(
        p.findings.contains(&Finding::NotJournaled("FAT32".into())),
        "{:?}",
        p.findings
    );
    assert_eq!(
        p.findings[0].severity(),
        Severity::Blocker,
        "blockers sort first"
    );
    // The destination's cluster size (32 KiB here) feeds the slack estimate.
    let m = a.manifest();
    let rounding: u64 = m
        .entries
        .iter()
        .map(|e| e.size.div_ceil(32 * 1024) * 32 * 1024 - e.size)
        .sum();
    assert_eq!(
        p.bound.slack,
        rounding + m.entries.len() as u64 * params().per_entry_overhead
    );

    let synced = vol(FsKind::Ntfs, "NTFS", 1, SyncHint::OneDrive);
    let ntfs = vol(FsKind::Ntfs, "NTFS", 1, SyncHint::None);
    let p = preflight::assess(&mk(synced, ntfs.clone()), &a, Path::new("/o"), params()).unwrap();
    assert!(
        p.findings
            .contains(&Finding::ArchiveSynced(SyncHint::OneDrive))
    );
    assert_eq!(p.blockers().count(), 1);

    let other = vol(FsKind::Ntfs, "NTFS", 2, SyncHint::None);
    let p = preflight::assess(&mk(ntfs, other), &a, Path::new("/o"), params()).unwrap();
    assert!(!p.same_volume);
    assert!(p.findings.contains(&Finding::DifferentVolumes));
    assert_eq!(
        p.consume_needs, p.bound.extract_extra,
        "different volume: consume saves nothing"
    );
    assert!(p.blockers().next().is_none());
}
