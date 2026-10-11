//! ISO 9660 parsing (`trunc_legacy::iso::parse`).
//!
//! The first byte picks the input: even means "parse the rest as it is"; odd means "build a
//! valid image from the parameters that follow (Joliet, Rock Ridge, continuation areas,
//! nested directories, multi-extent files, symlinks), check it parses back to what was built,
//! then damage it", with the damage aimed at descriptors and directory records most of the
//! time. Either way the parser must not panic, and whatever it accepts must be consistent:
//! file data inside the image, empty regions for everything else, unique names, `cd_start` at
//! the end of the last file's data and overlaps that match the regions.

#![no_main]
use std::collections::{BTreeMap, HashSet};

use libfuzzer_sys::fuzz_target;
use trunc_legacy::iso::{self, Image};
use trunc_legacy::zip::{Kind, Method};
use trunc_testkit::isobuild::{IsoBuilder, Spec, SpecKind, Tree};

#[path = "common/mutate.rs"]
mod mutate;

use mutate::Params;

fn check(bytes: &[u8], img: &Image) {
    let l = &img.layout;
    assert_eq!(l.file_len, bytes.len() as u64);
    let mut names = HashSet::new();
    let mut end = 0;
    for e in &l.entries {
        assert!(names.insert(e.name.as_str()), "duplicate name {:?}", e.name);
        assert!(!e.name.is_empty() && !e.name.starts_with('/') && !e.name.ends_with('/'));
        assert_eq!(e.method, Method::Stored);
        assert_eq!(e.compressed_size, e.size);
        if e.kind == Kind::File && e.size > 0 {
            assert_eq!(e.region_start, e.data_offset);
            assert_eq!(e.region_end, e.data_offset + e.size);
            assert!(e.region_end <= l.file_len, "{:?} past the end", e.name);
            end = end.max(e.region_end);
        } else {
            assert_eq!(
                (e.size, e.region_start, e.data_offset, e.region_end),
                (0, 0, 0, 0)
            );
        }
    }
    assert_eq!(l.cd_start, end);
    for &(a, b) in &l.overlaps {
        let (a, b) = (&l.entries[a], &l.entries[b]);
        assert!(a.region_start < b.region_end && b.region_start < a.region_end);
    }
}

/// name -> Some(content) for files, None for directories (symlinks left out).
fn contents(bytes: &[u8], img: &Image) -> BTreeMap<String, Option<Vec<u8>>> {
    img.layout
        .entries
        .iter()
        .filter(|e| e.kind != Kind::Symlink)
        .map(|e| {
            let v = (e.kind == Kind::File)
                .then(|| bytes[e.data_offset as usize..(e.data_offset + e.size) as usize].to_vec());
            (e.name.clone(), v)
        })
        .collect()
}

fn want(specs: &[Spec]) -> BTreeMap<String, Option<Vec<u8>>> {
    let mut m = BTreeMap::new();
    for s in specs {
        let mut p = s.path.as_str();
        while let Some((parent, _)) = p.rsplit_once('/') {
            m.insert(parent.to_owned(), None);
            p = parent;
        }
        match &s.kind {
            SpecKind::File(d) => {
                m.insert(s.path.clone(), Some(d.clone()));
            }
            SpecKind::Dir => {
                m.insert(s.path.clone(), None);
            }
            SpecKind::Symlink(_) => {}
        }
    }
    m
}

fn parse(bytes: &[u8]) -> Option<Image> {
    let (_fs, h) = mutate::host(bytes);
    let img = iso::parse(h.as_ref()).ok()?;
    check(bytes, &img);
    Some(img)
}

fn structured(p: &mut Params<'_>) {
    let flags = p.byte();
    let joliet = flags & 1 != 0;
    let rr = flags & 2 != 0;
    let mut b = IsoBuilder::new()
        .joliet(joliet)
        .rock_ridge(rr)
        .ce_names(rr && flags & 4 != 0)
        .pad(usize::from(flags >> 5));
    let mut specs = Vec::new();
    let n = 1 + usize::from(p.byte() % 6);
    for i in 0..n {
        let k = p.byte();
        // Uppercase names without extensions read back unchanged from every name source.
        let dir = ["", "A/", "A/B/", "C/"][usize::from(k % 4)];
        let path = format!("{dir}F{i}");
        let mut s = match (k >> 2) % 4 {
            0 => Spec::dir(&path),
            1 if rr => Spec::symlink(&path, "F0"),
            _ => {
                let len = usize::from(p.byte()) * 41;
                let data: Vec<u8> = (0..len).map(|j| (i * 31 + j) as u8).collect();
                let s = Spec::file(&path, &data);
                if k & 0x40 != 0 && len > 2048 {
                    s.sections(2048)
                } else {
                    s
                }
            }
        };
        if k & 0x80 != 0 {
            s = s.hidden();
        }
        b.add(s.clone());
        specs.push(s);
    }
    let built = b.build();
    let img = parse(&built.bytes).expect("a built image parses");
    assert_eq!(contents(&built.bytes, &img), want(&specs));
    assert!(img.layout.overlaps.is_empty());

    // Descriptors, both roots and every directory record.
    let mut hot = vec![16 * 2048, 16 * 2048 + 128, 16 * 2048 + 156, 17 * 2048 + 156];
    hot.push(built.root(Tree::Primary) as usize * 2048);
    if joliet {
        hot.push(built.root(Tree::Joliet) as usize * 2048);
    }
    hot.extend(built.records.values().flatten().copied());
    let mut bytes = built.bytes;
    mutate::damage(&mut bytes, p, &hot);
    let _ = parse(&bytes);
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    if mode & 1 == 0 {
        let _ = parse(rest);
    } else {
        structured(&mut Params(rest));
    }
});
