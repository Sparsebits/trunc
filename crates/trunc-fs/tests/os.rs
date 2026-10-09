//! OsFs against the real filesystem (NTFS on the Windows dev machine and CI, ext4 on Linux CI).

#![allow(clippy::unwrap_used)]

use std::path::Path;

use trunc_fs::{Dealloc, FsBackend, FsError, FsKind, NodeKind, OpenMode, OsFs, Share};

fn fs() -> OsFs {
    OsFs::new()
}

fn write_file(p: &Path, data: &[u8]) {
    let f = fs().open(p, OpenMode::CreateNew, Share::Shared).unwrap();
    f.write_all_at(data, 0).unwrap();
    f.flush_data().unwrap();
}

#[test]
fn create_read_write_resize() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("f");
    write_file(&p, b"hello world");
    let f = fs()
        .open(&p, OpenMode::ReadWrite, Share::Exclusive)
        .unwrap();
    let mut buf = [0u8; 5];
    f.read_exact_at(&mut buf, 6).unwrap();
    assert_eq!(&buf, b"world");
    assert!(
        matches!(f.read_exact_at(&mut buf, 8), Err(FsError::Io { .. })),
        "short read is an error"
    );
    f.set_len(5).unwrap();
    assert_eq!(f.size().unwrap(), 5);
    f.preallocate(100).unwrap();
    assert_eq!(f.size().unwrap(), 100);
    f.preallocate(10).unwrap();
    assert_eq!(f.size().unwrap(), 100, "preallocate never shrinks");
}

#[test]
fn create_new_refuses_existing() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("f");
    write_file(&p, b"x");
    assert!(matches!(
        fs().open(&p, OpenMode::CreateNew, Share::Shared),
        Err(FsError::AlreadyExists { .. })
    ));
    assert!(matches!(
        fs().open(&d.path().join("missing"), OpenMode::Read, Share::Shared),
        Err(FsError::NotFound { .. })
    ));
}

#[test]
fn rename_never_replaces() {
    let d = tempfile::tempdir().unwrap();
    let (a, b) = (d.path().join("a"), d.path().join("b"));
    write_file(&a, b"a");
    write_file(&b, b"b");
    assert!(matches!(
        fs().rename(&a, &b),
        Err(FsError::AlreadyExists { .. })
    ));
    assert_eq!(std::fs::read(&b).unwrap(), b"b");
    let c = d.path().join("c");
    fs().rename(&a, &c).unwrap();
    assert_eq!(std::fs::read(&c).unwrap(), b"a");
}

#[test]
fn file_ids_follow_files_not_names() {
    let d = tempfile::tempdir().unwrap();
    let (a, b) = (d.path().join("a"), d.path().join("b"));
    write_file(&a, b"a");
    write_file(&b, b"b");
    let ida = fs()
        .open(&a, OpenMode::Read, Share::Shared)
        .unwrap()
        .file_id()
        .unwrap();
    let idb = fs()
        .open(&b, OpenMode::Read, Share::Shared)
        .unwrap()
        .file_id()
        .unwrap();
    assert_ne!(ida, idb);
    let moved = d.path().join("moved");
    fs().rename(&a, &moved).unwrap();
    let again = fs()
        .open(&moved, OpenMode::Read, Share::Shared)
        .unwrap()
        .file_id()
        .unwrap();
    assert_eq!(ida, again);
}

#[test]
fn directories_metadata_and_flush() {
    let d = tempfile::tempdir().unwrap();
    let sub = d.path().join("sub");
    fs().create_dir(&sub).unwrap();
    assert!(matches!(
        fs().create_dir(&sub),
        Err(FsError::AlreadyExists { .. })
    ));
    write_file(&sub.join("x"), b"1");
    write_file(&sub.join("a"), b"22");
    fs().flush_dir(&sub).unwrap();
    fs().flush_dir(d.path()).unwrap();
    assert_eq!(fs().read_dir(&sub).unwrap(), vec!["a", "x"]);
    assert_eq!(fs().metadata(&sub).unwrap().unwrap().kind, NodeKind::Dir);
    let m = fs().metadata(&sub.join("a")).unwrap().unwrap();
    assert_eq!((m.kind, m.len), (NodeKind::File, 2));
    assert!(fs().metadata(&sub.join("nope")).unwrap().is_none());
    fs().remove_file(&sub.join("a")).unwrap();
    fs().remove_file(&sub.join("x")).unwrap();
    fs().remove_dir(&sub).unwrap();
    assert!(fs().metadata(&sub).unwrap().is_none());
}

#[test]
fn probe_reports_a_sane_volume() {
    let d = tempfile::tempdir().unwrap();
    let v = fs()
        .probe_volume(&d.path().join("not/yet/created"))
        .unwrap();
    assert!(
        v.cluster_size.is_power_of_two() && v.cluster_size >= 512,
        "{v:?}"
    );
    if cfg!(any(windows, target_os = "linux")) {
        assert!(v.free_bytes.unwrap() > 0, "free space is probed: {v:?}");
        assert!(v.volume_id.is_some());
    }
    if cfg!(windows) {
        assert_ne!(v.fs, FsKind::Unknown, "{v:?}");
        assert!(v.free_bytes.unwrap() > 0 && v.total_bytes.unwrap() >= v.free_bytes.unwrap());
        assert!(v.root.is_some() && v.volume_id.is_some());
    }
}

#[test]
fn dealloc_zeroes_and_reports() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("sparse");
    let mib = 1u64 << 20;
    let data: Vec<u8> = (0..4 * mib).map(|i| (i % 251) as u8 + 1).collect();
    write_file(&p, &data);
    let f = fs()
        .open(&p, OpenMode::ReadWrite, Share::Exclusive)
        .unwrap();
    match f.deallocate(mib, 3 * mib).unwrap() {
        Dealloc::Unsupported => {
            assert!(!cfg!(windows) || fs().probe_volume(&p).unwrap().fs != FsKind::Ntfs);
        }
        Dealloc::Freed { freed } => {
            assert!(freed.start >= mib && freed.end <= 3 * mib, "{freed:?}");
            assert!(
                freed.end - freed.start >= mib,
                "most of a 2 MiB range should be freed: {freed:?}"
            );
            let mut back = vec![0u8; usize::try_from(4 * mib).unwrap()];
            f.read_exact_at(&mut back, 0).unwrap();
            let (m, m3) = (
                usize::try_from(mib).unwrap(),
                usize::try_from(3 * mib).unwrap(),
            );
            assert_eq!(&back[..m], &data[..m]);
            assert!(back[m..m3].iter().all(|&b| b == 0));
            assert_eq!(&back[m3..], &data[m3..]);
            let alloc = f.allocated_ranges().unwrap();
            assert!(
                alloc
                    .iter()
                    .all(|r| r.end <= freed.start || r.start >= freed.end),
                "freed range still allocated: {alloc:?} vs {freed:?}"
            );
        }
    }
}

/// The probe's `sparse_granularity` must be at least the real unit, so planned frees never
/// overestimate what is released.
#[cfg(any(windows, target_os = "linux"))]
#[test]
fn sparse_granularity_matches_probe() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("gran");
    write_file(&p, &vec![7u8; 1 << 20]);
    let v = fs().probe_volume(&p).unwrap();
    if !v.supports_sparse {
        return;
    }
    let f = fs()
        .open(&p, OpenMode::ReadWrite, Share::Exclusive)
        .unwrap();
    // An unaligned request: what gets freed is aligned to the real unit.
    let Dealloc::Freed { freed } = f.deallocate(100_000, 700_000).unwrap() else {
        panic!("the probe said {} can free ranges", v.fs_name);
    };
    let unit = u64::from(v.sparse_granularity);
    eprintln!(
        "cluster {} probe granularity {unit} freed {freed:?}",
        v.cluster_size
    );
    assert!(
        freed.start % u64::from(v.cluster_size) == 0 && freed.end % u64::from(v.cluster_size) == 0
    );
    // Everything the probe promises (request aligned inward to `unit`) was freed.
    let promised = 100_000u64.div_ceil(unit) * unit..(700_000 / unit) * unit;
    assert!(
        freed.start <= promised.start && freed.end >= promised.end,
        "{freed:?} vs {promised:?}"
    );
}

#[cfg(windows)]
#[test]
fn exclusive_open_blocks_other_handles() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("x");
    write_file(&p, b"x");
    let held = fs()
        .open(&p, OpenMode::ReadWrite, Share::Exclusive)
        .unwrap();
    // Readers may coexist (scanners, our own verification); writers may not.
    drop(fs().open(&p, OpenMode::Read, Share::Shared).unwrap());
    assert!(matches!(
        fs().open(&p, OpenMode::ReadWrite, Share::Shared),
        Err(FsError::Busy { .. })
    ));
    held.write_all_at(b"still writable", 0).unwrap();
}

#[cfg(windows)]
#[test]
fn junctions_are_never_followed() {
    let d = tempfile::tempdir().unwrap();
    let target = d.path().join("target");
    std::fs::create_dir(&target).unwrap();
    write_file(&target.join("f"), b"secret");
    let j = d.path().join("j");
    let ok = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&j)
        .arg(&target)
        .output()
        .unwrap()
        .status
        .success();
    assert!(ok, "mklink /J needs no privileges");
    assert_eq!(fs().metadata(&j).unwrap().unwrap().kind, NodeKind::Link);
    assert!(matches!(
        fs().open(&j, OpenMode::Read, Share::Shared),
        Err(FsError::Link { .. })
    ));
    assert!(matches!(
        fs().create_dir(&j),
        Err(FsError::AlreadyExists { .. })
    ));
}

/// Another process maps the file; shrinking must fail with the retryable `Mapped` error.
/// Spawns PowerShell, so it is ignored by default: `cargo test -p trunc-fs -- --ignored`.
#[cfg(windows)]
#[test]
#[ignore]
fn truncating_a_mapped_file_is_retryable() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("mapped");
    write_file(&p, &vec![1u8; 1 << 20]);
    let script = format!(
        // Open with sharing, as indexers and scanners do, so only the mapping blocks truncation.
        // [NullString]::Value: PowerShell would pass $null as "" and the map call would fail.
        "$ErrorActionPreference='Stop';\
         $f=[System.IO.File]::Open('{}','Open','ReadWrite','ReadWrite,Delete');\
         $m=[System.IO.MemoryMappedFiles.MemoryMappedFile]::CreateFromFile($f,[NullString]::Value,0,'ReadWrite',$null,'None',$true);\
         $v=$m.CreateViewAccessor(); [Console]::Out.WriteLine('mapped'); [Console]::Out.Flush();\
         Start-Sleep -Seconds 20",
        p.display()
    );
    let mut child = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &script])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    std::io::BufRead::read_line(
        &mut std::io::BufReader::new(child.stdout.take().unwrap()),
        &mut line,
    )
    .unwrap();
    assert_eq!(line.trim(), "mapped");
    let f = fs().open(&p, OpenMode::ReadWrite, Share::Shared).unwrap();
    let e = f.set_len(1000).unwrap_err();
    child.kill().unwrap();
    let _ = child.wait();
    assert!(matches!(e, FsError::Mapped { .. }), "{e}");
    assert!(e.is_retryable());
}

/// Shrinking must return space to the volume immediately, while the handle stays open. (Setting
/// only the end-of-file marker leaves the allocation in place until the handle closes, which would
/// make --consume hold the whole archive until the end.)
#[cfg(any(windows, target_os = "linux"))]
#[test]
fn shrinking_frees_space_while_open() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("big");
    let mib = 1usize << 20;
    let f = fs()
        .open(&p, OpenMode::CreateNew, Share::Exclusive)
        .unwrap();
    let chunk = vec![0xA5u8; 16 * mib];
    for i in 0..32u64 {
        f.write_all_at(&chunk, i * 16 * mib as u64).unwrap();
    }
    f.flush_data().unwrap();
    let free = || fs().probe_volume(d.path()).unwrap().free_bytes.unwrap();
    let before = free();
    f.set_len(0).unwrap();
    f.flush_data().unwrap();
    let after = free();
    let freed = after.saturating_sub(before);
    eprintln!("freed {} MiB while open", freed >> 20);
    assert!(
        freed >= 400 << 20,
        "only {} MiB returned after shrinking 512 MiB",
        freed >> 20
    );
}

#[test]
fn read_back_sees_flushed_bytes_at_unaligned_offsets() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("rb");
    let f = fs()
        .open(&p, OpenMode::CreateNew, Share::Exclusive)
        .unwrap();
    let data: Vec<u8> = (0..300_000u32).map(|i| (i % 253) as u8).collect();
    f.write_all_at(&data, 0).unwrap();
    f.flush_data().unwrap();
    for (off, len) in [
        (0usize, 10usize),
        (4095, 2),
        (12_345, 100_000),
        (299_990, 10),
    ] {
        let mut buf = vec![0u8; len];
        f.read_back(&mut buf, off as u64).unwrap();
        assert_eq!(buf, &data[off..off + len], "offset {off}");
    }
    let mut past = [0u8; 20];
    assert!(
        f.read_back(&mut past, 299_990).is_err(),
        "reading past the end is an error"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn linux_probe_names_the_mount() {
    let d = tempfile::tempdir().unwrap();
    let v = fs().probe_volume(d.path()).unwrap();
    eprintln!("{v:?}");
    assert!(v.root.is_some(), "mount point found: {v:?}");
    assert_ne!(v.fs_name, "unknown", "named by magic or mount table: {v:?}");
    if v.fs == FsKind::Ext4 {
        assert!(v.supports_sparse && v.sparse_granularity >= 512, "{v:?}");
    }
}

/// `Share::Exclusive` is an advisory lock on Linux: a second trunc is turned away, other programs
/// are not (that limit is documented).
#[cfg(target_os = "linux")]
#[test]
fn exclusive_open_stops_a_second_exclusive_open() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("x");
    write_file(&p, b"x");
    let held = fs()
        .open(&p, OpenMode::ReadWrite, Share::Exclusive)
        .unwrap();
    for mode in [OpenMode::ReadWrite, OpenMode::Read] {
        assert!(matches!(
            fs().open(&p, mode, Share::Exclusive),
            Err(FsError::Busy { .. })
        ));
    }
    drop(fs().open(&p, OpenMode::ReadWrite, Share::Shared).unwrap());
    held.write_all_at(b"still writable", 0).unwrap();
    drop(held);
    // Readers share.
    let r1 = fs().open(&p, OpenMode::Read, Share::Exclusive).unwrap();
    let r2 = fs().open(&p, OpenMode::Read, Share::Exclusive).unwrap();
    drop((r1, r2));
}

#[cfg(unix)]
#[test]
fn symlinks_are_never_followed() {
    use std::os::unix::fs::symlink;
    let d = tempfile::tempdir().unwrap();
    let root = d.path().join("stage");
    let outside = d.path().join("outside");
    std::fs::create_dir(&root).unwrap();
    std::fs::create_dir(&outside).unwrap();
    write_file(&outside.join("victim"), b"keep");
    symlink(outside.join("victim"), root.join("file-link")).unwrap();
    symlink(&outside, root.join("dir-link")).unwrap();

    // A link as the final component, through plain open and the confined variants.
    for mode in [
        OpenMode::Read,
        OpenMode::ReadWrite,
        OpenMode::CreateOrTruncate,
    ] {
        let e = fs()
            .open(&root.join("file-link"), mode, Share::Shared)
            .unwrap_err();
        assert!(matches!(e, FsError::Link { .. }), "{mode:?}: {e}");
        let e = fs()
            .open_beneath(&root, &root.join("file-link"), mode, Share::Shared)
            .unwrap_err();
        assert!(matches!(e, FsError::Link { .. }), "{mode:?}: {e}");
    }
    // A link in the middle of the path.
    let through = root.join("dir-link").join("victim");
    let e = fs()
        .open_beneath(&root, &through, OpenMode::ReadWrite, Share::Shared)
        .unwrap_err();
    assert!(matches!(e, FsError::Link { .. }), "{e}");
    let e = fs()
        .create_dir_beneath(&root, &root.join("dir-link").join("new"))
        .unwrap_err();
    assert!(matches!(e, FsError::Link { .. }), "{e}");
    assert!(!outside.join("new").exists());
    // Leaving the root.
    assert!(
        fs().open_beneath(
            &root,
            &outside.join("victim"),
            OpenMode::Read,
            Share::Shared
        )
        .is_err()
    );
    assert!(
        fs().open_beneath(
            &root,
            &root.join("..").join("outside").join("victim"),
            OpenMode::Read,
            Share::Shared
        )
        .is_err()
    );
    assert_eq!(std::fs::read(outside.join("victim")).unwrap(), b"keep");

    // Ordinary nested paths work.
    fs().create_dir_beneath(&root, &root.join("a")).unwrap();
    fs().create_dir_beneath(&root, &root.join("a").join("b"))
        .unwrap();
    let f = fs()
        .open_beneath(
            &root,
            &root.join("a").join("b").join("c"),
            OpenMode::CreateNew,
            Share::Exclusive,
        )
        .unwrap();
    f.write_all_at(b"ok", 0).unwrap();
    drop(f);
    let f = fs()
        .open_beneath(
            &root,
            &root.join("a").join("b").join("c"),
            OpenMode::ReadWrite,
            Share::Exclusive,
        )
        .unwrap();
    assert_eq!(f.size().unwrap(), 2);
}

#[cfg(target_os = "linux")]
#[test]
fn preallocate_reserves_blocks() {
    use std::os::unix::fs::MetadataExt;
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("pre");
    let f = fs()
        .open(&p, OpenMode::CreateNew, Share::Exclusive)
        .unwrap();
    let len = 64u64 << 20;
    f.preallocate(len).unwrap();
    assert_eq!(f.size().unwrap(), len);
    let md = std::fs::metadata(&p).unwrap();
    if fs().probe_volume(&p).unwrap().fs == FsKind::Ext4 {
        assert!(
            md.blocks() * 512 >= len,
            "{} bytes reserved",
            md.blocks() * 512
        );
    }
    // Never shrinks.
    f.preallocate(1).unwrap();
    assert_eq!(f.size().unwrap(), len);
}

/// Confined opens and directory creation through a junction in the middle of the path: refused,
/// and anything created through it is taken back.
#[cfg(windows)]
#[test]
fn confined_opens_refuse_junctions_on_the_way() {
    let d = tempfile::tempdir().unwrap();
    let root = d.path().join("stage");
    let outside = d.path().join("outside");
    std::fs::create_dir(&root).unwrap();
    std::fs::create_dir(&outside).unwrap();
    write_file(&outside.join("victim"), b"keep");
    let ok = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(root.join("j"))
        .arg(&outside)
        .output()
        .unwrap()
        .status
        .success();
    assert!(ok, "mklink /J needs no privileges");
    let through = root.join("j").join("victim");
    for mode in [OpenMode::Read, OpenMode::ReadWrite] {
        let e = fs()
            .open_beneath(&root, &through, mode, Share::Shared)
            .unwrap_err();
        assert!(matches!(e, FsError::Link { .. }), "{mode:?}: {e}");
    }
    let e = fs()
        .open_beneath(
            &root,
            &root.join("j").join("new"),
            OpenMode::CreateNew,
            Share::Exclusive,
        )
        .unwrap_err();
    assert!(matches!(e, FsError::Link { .. }), "{e}");
    assert!(
        !outside.join("new").exists(),
        "the file created through the junction was removed"
    );
    let e = fs()
        .create_dir_beneath(&root, &root.join("j").join("newdir"))
        .unwrap_err();
    assert!(matches!(e, FsError::Link { .. }), "{e}");
    assert!(!outside.join("newdir").exists());
    assert_eq!(std::fs::read(outside.join("victim")).unwrap(), b"keep");

    // Ordinary nested paths work, and opening the root's children stays allowed.
    fs().create_dir_beneath(&root, &root.join("a")).unwrap();
    let f = fs()
        .open_beneath(
            &root,
            &root.join("a").join("f"),
            OpenMode::CreateNew,
            Share::Exclusive,
        )
        .unwrap();
    f.write_all_at(b"ok", 0).unwrap();
    drop(f);
    let f = fs()
        .open_beneath(
            &root,
            &root.join("a").join("f"),
            OpenMode::ReadWrite,
            Share::Exclusive,
        )
        .unwrap();
    assert_eq!(f.size().unwrap(), 2);
}
