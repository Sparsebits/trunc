//! Preflight: will extraction or consumption fit, and is consumption safe here?
//!
//! Combines the conservative [`SpaceBound`] with live facts about the destination and archive
//! volumes. The consumer (phase 3) refuses to start when any [`Severity::Blocker`] is present.

use std::fmt;
use std::path::Path;

use trunc_core::space::{self, SpaceBound, SpaceParams};
use trunc_fs::{FsBackend, SnapshotHint, SyncHint, VolumeInfo};

use crate::archive::Archive;
use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Note,
    Warning,
    /// Destructive mode refuses to run (some can be overridden by an explicit flag).
    Blocker,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    /// Archive and destination are on different volumes: consuming frees space on the wrong
    /// volume, so it saves nothing at the destination.
    DifferentVolumes,
    /// The archive sits in a folder a sync client manages; every truncation could be uploaded,
    /// destroying the cloud copy.
    ArchiveSynced(SyncHint),
    /// The destination is synced: outputs will be uploaded (not unsafe, but slow and noisy).
    DestinationSynced(SyncHint),
    /// The archive's filesystem does not journal metadata (FAT32, exFAT): a crash during
    /// truncation can corrupt it. Overridable with `--allow-unjournaled`.
    NotJournaled(String),
    /// The filesystem could not be identified, so whether it journals metadata is unknown.
    JournalingUnknown,
    SnapshotsPresent(String),
    SnapshotsUnknown(String),
    /// A file is larger than the destination filesystem allows.
    FileTooLarge {
        path: String,
        size: u64,
        max: u64,
    },
    FreeSpaceUnknown,
    /// The archive carries no signature, so its origin cannot be checked.
    Unsigned,
    /// Some blocks were already consumed; this is a resume.
    PartiallyConsumed {
        consumed: usize,
        total: usize,
    },
}

impl Finding {
    pub fn severity(&self) -> Severity {
        match self {
            Finding::ArchiveSynced(_)
            | Finding::NotJournaled(_)
            | Finding::JournalingUnknown
            | Finding::FileTooLarge { .. } => Severity::Blocker,
            Finding::DifferentVolumes
            | Finding::DestinationSynced(_)
            | Finding::SnapshotsPresent(_)
            | Finding::FreeSpaceUnknown => Severity::Warning,
            Finding::SnapshotsUnknown(_)
            | Finding::PartiallyConsumed { .. }
            | Finding::Unsigned => Severity::Note,
        }
    }
}

fn sync_name(h: &SyncHint) -> &'static str {
    match h {
        SyncHint::None => "no sync client",
        SyncHint::OneDrive => "OneDrive",
        SyncHint::Dropbox => "Dropbox",
        SyncHint::GoogleDrive => "Google Drive",
        SyncHint::ICloud => "iCloud Drive",
        SyncHint::CloudFiles => "a cloud sync client (placeholder files)",
    }
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Finding::DifferentVolumes => write!(
                f,
                "archive and destination are on different volumes; --consume frees space on the \
                 archive's volume only, so it needs as much free space at the destination as a \
                 normal extract"
            ),
            Finding::ArchiveSynced(h) => write!(
                f,
                "the archive is in a folder managed by {}; --consume would upload every \
                 truncation and could destroy the cloud copy. Move it out of the synced folder",
                sync_name(h)
            ),
            Finding::DestinationSynced(h) => write!(
                f,
                "the destination is managed by {}; extracted files will be uploaded",
                sync_name(h)
            ),
            Finding::NotJournaled(fs) => write!(
                f,
                "the archive's filesystem ({fs}) does not journal metadata; a crash during \
                 --consume can corrupt it (override with --allow-unjournaled)"
            ),
            Finding::JournalingUnknown => write!(
                f,
                "the archive's filesystem could not be identified, so crash safety of --consume depends on it journaling metadata (most modern filesystems do)"
            ),
            Finding::SnapshotsPresent(why) => write!(
                f,
                "snapshots keep truncated data allocated ({why}); --consume may free nothing"
            ),
            Finding::SnapshotsUnknown(why) => write!(f, "snapshots not checked: {why}"),
            Finding::FileTooLarge { path, size, max } => {
                write!(
                    f,
                    "{path} is {size} bytes; the destination allows at most {max}"
                )
            }
            Finding::FreeSpaceUnknown => {
                write!(f, "free space at the destination could not be determined")
            }
            Finding::Unsigned => write!(
                f,
                "the archive is unsigned: its integrity is checked, but not who made it (--require-signed to insist)"
            ),
            Finding::PartiallyConsumed { consumed, total } => {
                write!(
                    f,
                    "{consumed} of {total} blocks already consumed; this would resume"
                )
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct Preflight {
    pub bound: SpaceBound,
    pub destination: VolumeInfo,
    pub archive_volume: VolumeInfo,
    pub same_volume: bool,
    /// Free space consumption actually needs at the destination (equals the extract figure when
    /// the volumes differ).
    pub consume_needs: u64,
    pub extract_fits: Option<bool>,
    pub consume_fits: Option<bool>,
    pub findings: Vec<Finding>,
}

impl Preflight {
    pub fn blockers(&self) -> impl Iterator<Item = &Finding> {
        self.findings
            .iter()
            .filter(|f| f.severity() == Severity::Blocker)
    }
}

/// Facts about the archive's and destination's volumes, with the findings they imply.
#[derive(Debug, Clone)]
pub struct VolumeCheck {
    pub destination: VolumeInfo,
    pub archive_volume: VolumeInfo,
    pub same_volume: bool,
    pub findings: Vec<Finding>,
}

/// Probe both volumes and collect the format-independent findings. `largest_file` is the size
/// of the biggest entry (checked against the destination's file-size limit).
pub fn check_volumes(
    fs: &dyn FsBackend,
    archive_path: &Path,
    dest: &Path,
    largest_file: Option<(&str, u64)>,
) -> Result<VolumeCheck> {
    let fsr = |e: trunc_fs::FsError| Error::Input(e.to_string());
    let destination = fs.probe_volume(dest).map_err(fsr)?;
    let archive_volume = fs.probe_volume(archive_path).map_err(fsr)?;
    let same_volume = match (destination.volume_id, archive_volume.volume_id) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    };
    let mut findings = Vec::new();
    if !same_volume {
        findings.push(Finding::DifferentVolumes);
    }
    if archive_volume.sync != SyncHint::None {
        findings.push(Finding::ArchiveSynced(archive_volume.sync.clone()));
    }
    if destination.sync != SyncHint::None {
        findings.push(Finding::DestinationSynced(destination.sync.clone()));
    }
    if archive_volume.fs == trunc_fs::FsKind::Unknown {
        findings.push(Finding::JournalingUnknown);
    } else if !archive_volume.journaled() {
        findings.push(Finding::NotJournaled(archive_volume.fs_name.clone()));
    }
    match &archive_volume.snapshots {
        SnapshotHint::None => {}
        SnapshotHint::Present(why) => findings.push(Finding::SnapshotsPresent(why.clone())),
        SnapshotHint::Unknown(why) => findings.push(Finding::SnapshotsUnknown(why.clone())),
    }
    if let Some((path, size)) = largest_file.filter(|(_, s)| *s > destination.max_file_size) {
        findings.push(Finding::FileTooLarge {
            path: path.to_owned(),
            size,
            max: destination.max_file_size,
        });
    }
    if destination.free_bytes.is_none() {
        findings.push(Finding::FreeSpaceUnknown);
    }
    Ok(VolumeCheck {
        destination,
        archive_volume,
        same_volume,
        findings,
    })
}

/// Assess extracting or consuming `archive` into `dest`.
/// `batch_max_u` and other allowances come from `params`; the cluster size is taken from the
/// destination volume.
pub fn assess(
    fs: &dyn FsBackend,
    archive: &Archive,
    dest: &Path,
    params: SpaceParams,
) -> Result<Preflight> {
    let m = archive.manifest();
    let largest = m
        .entries
        .iter()
        .max_by_key(|e| e.size)
        .map(|e| (e.path.as_str(), e.size));
    let VolumeCheck {
        destination,
        archive_volume,
        same_volume,
        mut findings,
    } = check_volumes(fs, archive.path(), dest, largest)?;
    let params = SpaceParams {
        cluster_size: u64::from(destination.cluster_size.max(1)),
        ..params
    };
    let bound = space::bound(
        m,
        archive.header().first_block_off(),
        archive.consumed(),
        &params,
    );
    let consume_needs = if same_volume {
        bound.consume_extra
    } else {
        bound.extract_extra
    };
    if archive.signer().is_none() {
        findings.push(Finding::Unsigned);
    }
    if archive.consumed() > 0 {
        findings.push(Finding::PartiallyConsumed {
            consumed: archive.consumed(),
            total: m.blocks.len(),
        });
    }
    findings.sort_by_key(|f| std::cmp::Reverse(f.severity()));

    let extract_fits = destination.free_bytes.map(|f| f >= bound.extract_extra);
    let consume_fits = destination.free_bytes.map(|f| f >= consume_needs);
    Ok(Preflight {
        bound,
        destination,
        archive_volume,
        same_volume,
        consume_needs,
        extract_fits: if archive.is_complete() {
            extract_fits
        } else {
            Some(false)
        },
        consume_fits,
        findings,
    })
}
