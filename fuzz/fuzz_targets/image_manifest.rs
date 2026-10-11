//! Container image metadata: detection (`image::detect`) and the metadata walk
//! (`image::inspect_image`: outer tar index, `manifest.json`, `index.json` and nested indexes,
//! configs, layer descriptors), on an in-memory file system. Layers are not decoded.
//!
//! The first byte picks the input (`mode % 6`):
//! - 0: the rest as the outer file, as it is;
//! - 1, 2: a valid `docker save` / OCI archive built from the parameters, then damaged (aimed
//!   at tar headers and metadata files most of the time);
//! - 3: an OCI layout whose `index.json` is the rest of the input;
//! - 4: an OCI layout whose index points (by a correct digest) at the rest of the input, as a
//!   nested image manifest or index;
//! - 5: a Docker archive whose `manifest.json`, or whose config, is the rest of the input.
//!
//! Bit 7 gzips the outer tar (decompressed into a temporary file under `/t`). Nothing must
//! panic, the file system must be left exactly as it was (the temporary copy removed, nothing
//! written anywhere else) and an accepted image must be consistent with its archive.

#![no_main]
use std::path::Path;

use libfuzzer_sys::fuzz_target;
use trunc_engine::image::{self, ImageFormat, ImageOptions};
use trunc_fs::FsBackend;
use trunc_testkit::imagebuild::{self, Compression, INDEX, Layer, MANIFEST, Outer};
use trunc_testkit::tarbuild::{self, Spec};

#[path = "common/mutate.rs"]
mod mutate;

use mutate::Params;

const PLATFORMS: [&str; 3] = ["linux/amd64", "linux/arm64/v8", "windows/amd64"];

fn layers(p: &mut Params<'_>) -> Vec<Layer> {
    let n = 1 + usize::from(p.byte() % 2);
    (0..n)
        .map(|i| {
            let k = p.byte();
            let mut specs = vec![
                Spec::dir("etc"),
                Spec::file(&format!("etc/f{i}"), &vec![k; usize::from(k)]),
            ];
            if k & 1 != 0 {
                specs.push(Spec::file("etc/.wh.f0", b""));
            }
            let c = [Compression::None, Compression::Gzip, Compression::Zstd][usize::from(k >> 6) % 3];
            imagebuild::layer(&specs, c)
        })
        .collect()
}

/// Offsets of the headers and contents of the files in a tar.
fn hot_spots(tar_bytes: &[u8]) -> Vec<usize> {
    let mut r = trunc_legacy::tar::Reader::new();
    let _ = r.feed(tar_bytes);
    r.entries()
        .iter()
        .flat_map(|e| [e.data_offset.saturating_sub(512) as usize, e.data_offset as usize])
        .collect()
}

/// Layer files of a Docker archive (classic layout) under their usual names.
fn docker_layers(o: &mut Outer, ls: &[Layer]) -> Vec<String> {
    ls.iter()
        .map(|l| {
            let path = format!("{}/layer.tar", &l.digest[7..]);
            o.add(&path, &l.blob);
            imagebuild::js(&path)
        })
        .collect()
}

/// The outer tar, and whether it must be accepted.
fn build(mode: u8, p: &mut Params<'_>) -> (Vec<u8>, bool) {
    let platform = PLATFORMS[usize::from(p.byte()) % PLATFORMS.len()];
    let ls = layers(p);
    match mode % 6 {
        1 | 2 => {
            // With two platforms, which one is picked depends on the host (or none is).
            let two = mode % 6 == 2 && p.byte() & 1 != 0;
            let mut tar = if mode % 6 == 1 {
                imagebuild::docker_archive(&[(&["x:1", "y:2"], platform, ls)])
            } else if two {
                let second = layers(p);
                imagebuild::oci_archive(&[(platform, ls), ("linux/riscv64", second)])
            } else {
                imagebuild::oci_archive(&[(platform, ls)])
            };
            let hot = hot_spots(&tar);
            let before = tar.clone();
            mutate::damage(&mut tar, p, &hot);
            let intact = tar == before && !two;
            (tar, intact)
        }
        3 | 4 => {
            let mut o = Outer::default();
            o.add("oci-layout", br#"{"imageLayoutVersion":"1.0.0"}"#);
            let m = o.image(platform, &ls);
            let flags = p.byte();
            let text = p.rest();
            let index = if mode % 6 == 3 {
                text.to_vec()
            } else {
                o.blob(text);
                let mt = if flags & 1 != 0 { INDEX } else { MANIFEST };
                let extra = if flags & 2 != 0 {
                    imagebuild::platform(platform)
                } else {
                    String::new()
                };
                imagebuild::index(&[
                    imagebuild::descriptor(mt, text, &extra),
                    imagebuild::descriptor(MANIFEST, &m, ""),
                ])
            };
            o.add("index.json", &index);
            (o.tar(), false)
        }
        _ => {
            let mut o = Outer::default();
            let paths = docker_layers(&mut o, &ls);
            let flags = p.byte();
            let text = p.rest();
            if flags & 1 != 0 {
                let ids: Vec<&str> = ls.iter().map(|l| l.diff_id.as_str()).collect();
                o.add("config.json", &imagebuild::config(platform, &ids));
                o.add("manifest.json", text);
            } else {
                o.add("config.json", text);
                let m = format!(
                    "[{{\"Config\":\"config.json\",\"RepoTags\":[\"x:1\"],\"Layers\":[{}]}}]",
                    paths.join(",")
                );
                o.add("manifest.json", m.as_bytes());
            }
            (o.tar(), false)
        }
    }
}

fn run(outer: &[u8], opts: &ImageOptions, must_accept: bool) {
    let fs = mutate::fs_with("/img.tar", outer);
    fs.create_dir(Path::new("/t")).unwrap();
    // A decompressed copy larger than this fails with "no space" rather than filling memory.
    fs.set_capacity(Some(outer.len() as u64 + (64 << 20)));
    let before = fs.snapshot();
    let arc = Path::new("/img.tar");
    let _ = image::detect(&fs, arc);
    let r = image::inspect_image(&fs, arc, Path::new("/t"), opts);
    assert!(fs.snapshot() == before, "the file system was changed");
    let info = match r {
        Ok(info) => info,
        Err(e) => {
            assert!(!must_accept, "a valid image is refused: {e}");
            return;
        }
    };
    assert_eq!(info.file_len, outer.len() as u64);
    if info.outer_codec.is_none() {
        assert!(info.layers.iter().all(|l| l.size <= info.file_len));
        assert!(info.blob_bytes() <= info.file_len);
    }
    assert!(info.layers.iter().all(|l| l.diff_id.starts_with("sha256:")));
    if must_accept {
        assert!(image::detect(&fs, arc), "a valid image is not detected");
        if let Some(p) = &opts.platform {
            assert!(info.platform.starts_with(p.as_str()));
        }
        assert!(matches!(info.format, ImageFormat::Docker | ImageFormat::Oci));
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let mut p = Params(rest);
    let mut opts = ImageOptions {
        max_window: 8 << 20,
        threads: 1,
        ..ImageOptions::default()
    };
    let (mut outer, mut must_accept) = if mode % 6 == 0 {
        (rest.to_vec(), false)
    } else {
        let sel = p.byte();
        if sel & 1 != 0 {
            opts.platform = Some(PLATFORMS[usize::from(sel >> 1) % PLATFORMS.len()].into());
        }
        if sel & 0x10 != 0 {
            opts.image = Some("x:1".into());
        }
        build(mode, &mut p)
    };
    // The platform or image asked for may not be the one built.
    if opts.platform.is_some() || opts.image.is_some() {
        must_accept = false;
    }
    if mode & 0x80 != 0 {
        outer = tarbuild::gzip(&outer, 1);
    }
    run(&outer, &opts, must_accept);
});
