//! Container image tarballs for tests: layers built from tar [`Spec`]s (plain, gzip or zstd),
//! packed as `docker save` output (`manifest.json`, `<id>/layer.tar`) or as an OCI image layout
//! (`oci-layout`, `index.json`, `blobs/sha256/<hex>`), with the pieces exposed so tests can
//! build broken or hostile images.

use crate::tarbuild::{self, Spec};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    None,
    Gzip,
    Zstd,
}

/// A layer blob and what an image says about it.
#[derive(Debug, Clone)]
pub struct Layer {
    pub blob: Vec<u8>,
    /// `sha256:<hex>` of the blob.
    pub digest: String,
    /// `sha256:<hex>` of the uncompressed tar.
    pub diff_id: String,
    pub media_type: String,
}

pub fn digest(data: &[u8]) -> String {
    format!("sha256:{}", hex(&trunc_hash::sha256(data)))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|c| format!("{c:02x}")).collect()
}

/// A JSON string literal.
pub fn js(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if u32::from(c) < 0x20 => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A layer from tar entries.
pub fn layer(entries: &[Spec], c: Compression) -> Layer {
    let tar = tarbuild::tar(entries);
    let (blob, media_type) = match c {
        Compression::None => (tar.clone(), "application/vnd.oci.image.layer.v1.tar"),
        Compression::Gzip => (
            tarbuild::gzip(&tar, 6),
            "application/vnd.oci.image.layer.v1.tar+gzip",
        ),
        Compression::Zstd => (
            tarbuild::zstd(&tar, 3),
            "application/vnd.oci.image.layer.v1.tar+zstd",
        ),
    };
    Layer {
        digest: digest(&blob),
        diff_id: digest(&tar),
        blob,
        media_type: media_type.into(),
    }
}

/// An image config for `platform` (`os/arch[/variant]`) with these diff_ids.
pub fn config(platform: &str, diff_ids: &[&str]) -> Vec<u8> {
    let mut p = platform.split('/');
    let (os, arch, variant) = (p.next().unwrap(), p.next().unwrap(), p.next());
    let variant = variant.map_or(String::new(), |v| format!(",\"variant\":{}", js(v)));
    let ids: Vec<String> = diff_ids.iter().map(|d| js(d)).collect();
    format!(
        "{{\"architecture\":{},\"os\":{}{variant},\"config\":{{}},\"rootfs\":{{\"type\":\"layers\",\"diff_ids\":[{}]}}}}",
        js(arch),
        js(os),
        ids.join(",")
    )
    .into_bytes()
}

/// A descriptor object.
pub fn descriptor(media_type: &str, data: &[u8], extra: &str) -> String {
    format!(
        "{{\"mediaType\":{},\"digest\":{},\"size\":{}{extra}}}",
        js(media_type),
        js(&digest(data)),
        data.len()
    )
}

pub const MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
pub const INDEX: &str = "application/vnd.oci.image.index.v1+json";
pub const CONFIG: &str = "application/vnd.oci.image.config.v1+json";

/// An OCI image manifest.
pub fn manifest(config: &[u8], layers: &[Layer]) -> Vec<u8> {
    let ls: Vec<String> = layers
        .iter()
        .map(|l| {
            format!(
                "{{\"mediaType\":{},\"digest\":{},\"size\":{}}}",
                js(&l.media_type),
                js(&l.digest),
                l.blob.len()
            )
        })
        .collect();
    format!(
        "{{\"schemaVersion\":2,\"mediaType\":{},\"config\":{},\"layers\":[{}]}}",
        js(MANIFEST),
        descriptor(CONFIG, config, ""),
        ls.join(",")
    )
    .into_bytes()
}

/// An OCI index listing `manifests` (descriptor objects).
pub fn index(manifests: &[String]) -> Vec<u8> {
    format!(
        "{{\"schemaVersion\":2,\"mediaType\":{},\"manifests\":[{}]}}",
        js(INDEX),
        manifests.join(",")
    )
    .into_bytes()
}

/// `,"platform":{...}` for a descriptor.
pub fn platform(p: &str) -> String {
    let mut it = p.split('/');
    let (os, arch, variant) = (it.next().unwrap(), it.next().unwrap(), it.next());
    let variant = variant.map_or(String::new(), |v| format!(",\"variant\":{}", js(v)));
    format!(
        ",\"platform\":{{\"architecture\":{},\"os\":{}{variant}}}",
        js(arch),
        js(os)
    )
}

/// The files of an outer tar, in order.
#[derive(Debug, Clone, Default)]
pub struct Outer {
    pub files: Vec<(String, Vec<u8>)>,
}

impl Outer {
    pub fn add(&mut self, name: &str, data: &[u8]) {
        self.files.push((name.to_owned(), data.to_vec()));
    }

    /// Add a blob under `blobs/sha256/` (once) and return its digest.
    pub fn blob(&mut self, data: &[u8]) -> String {
        let d = digest(data);
        let name = format!("blobs/sha256/{}", &d[7..]);
        if !self.files.iter().any(|(n, _)| *n == name) {
            self.add(&name, data);
        }
        d
    }

    /// Add an image's config, layers and manifest as blobs; returns the manifest bytes.
    pub fn image(&mut self, platform: &str, layers: &[Layer]) -> Vec<u8> {
        let ids: Vec<&str> = layers.iter().map(|l| l.diff_id.as_str()).collect();
        let cfg = config(platform, &ids);
        self.blob(&cfg);
        for l in layers {
            self.blob(&l.blob);
        }
        let m = manifest(&cfg, layers);
        self.blob(&m);
        m
    }

    pub fn tar(&self) -> Vec<u8> {
        let specs: Vec<Spec> = self.files.iter().map(|(n, d)| Spec::file(n, d)).collect();
        tarbuild::tar(&specs)
    }
}

/// An OCI image layout with one image per `(platform, layers)`, all listed in `index.json`.
pub fn oci_archive(images: &[(&str, Vec<Layer>)]) -> Vec<u8> {
    let mut o = Outer::default();
    o.add("oci-layout", br#"{"imageLayoutVersion":"1.0.0"}"#);
    let mut ds = Vec::new();
    for (p, layers) in images {
        let m = o.image(p, layers);
        ds.push(descriptor(MANIFEST, &m, &platform(p)));
    }
    o.add("index.json", &index(&ds));
    o.tar()
}

/// `docker save` output (the classic layout: `<id>/layer.tar`, `<config>.json`,
/// `manifest.json`) for one image per `(tags, platform, layers)`. Layers are stored as given.
pub fn docker_archive(images: &[(&[&str], &str, Vec<Layer>)]) -> Vec<u8> {
    let mut o = Outer::default();
    let mut entries = Vec::new();
    for (tags, p, layers) in images {
        let mut paths = Vec::new();
        for l in layers {
            let path = format!("{}/layer.tar", &l.digest[7..]);
            if !o.files.iter().any(|(n, _)| *n == path) {
                o.add(&format!("{}/VERSION", &l.digest[7..]), b"1.0");
                o.add(&path, &l.blob);
            }
            paths.push(js(&path));
        }
        let ids: Vec<&str> = layers.iter().map(|l| l.diff_id.as_str()).collect();
        let cfg = config(p, &ids);
        let cfg_name = format!("{}.json", &digest(&cfg)[7..]);
        o.add(&cfg_name, &cfg);
        let tags: Vec<String> = tags.iter().map(|t| js(t)).collect();
        entries.push(format!(
            "{{\"Config\":{},\"RepoTags\":[{}],\"Layers\":[{}]}}",
            js(&cfg_name),
            tags.join(","),
            paths.join(",")
        ));
    }
    o.add(
        "manifest.json",
        format!("[{}]", entries.join(",")).as_bytes(),
    );
    o.tar()
}
