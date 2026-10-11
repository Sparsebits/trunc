//! Registry manifests: image indexes (manifest lists), image manifests and image configs, and
//! choosing a platform.

use anyhow::{Context, Result, bail};
use trunc_engine::json::Json;

use crate::reference::valid_digest;

pub const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
pub const DOCKER_LIST: &str = "application/vnd.docker.distribution.manifest.list.v2+json";
pub const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
pub const DOCKER_MANIFEST: &str = "application/vnd.docker.distribution.manifest.v2+json";

/// The `Accept` header for manifest requests.
pub const ACCEPT: &str = "application/vnd.oci.image.index.v1+json, \
     application/vnd.docker.distribution.manifest.list.v2+json, \
     application/vnd.oci.image.manifest.v1+json, \
     application/vnd.docker.distribution.manifest.v2+json";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Descriptor {
    pub media_type: String,
    pub digest: String,
    pub size: u64,
}

/// One manifest of an index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformEntry {
    pub descriptor: Descriptor,
    /// `os/arch[/variant]`, or `unknown/unknown`.
    pub platform: String,
    /// An attestation or signature manifest rather than an image.
    pub attestation: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageManifest {
    pub media_type: String,
    pub config: Descriptor,
    pub layers: Vec<Descriptor>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Manifest {
    Index(Vec<PlatformEntry>),
    Image(ImageManifest),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageConfig {
    pub platform: String,
    pub diff_ids: Vec<String>,
}

fn descriptor(j: &Json, what: &str) -> Result<Descriptor> {
    let digest = j
        .get_str("digest")
        .with_context(|| format!("{what}: no digest"))?;
    if !valid_digest(digest) {
        bail!("{what}: {digest:?} is not a sha256 digest");
    }
    Ok(Descriptor {
        media_type: j.get_str("mediaType").unwrap_or_default().to_owned(),
        digest: digest.to_owned(),
        size: j
            .get("size")
            .and_then(Json::u64)
            .with_context(|| format!("{what}: no size"))?,
    })
}

fn platform_of(j: &Json) -> String {
    let os = j.get_str("os").unwrap_or("unknown");
    let arch = j.get_str("architecture").unwrap_or("unknown");
    match j.get_str("variant") {
        Some(v) if !v.is_empty() => format!("{os}/{arch}/{v}"),
        _ => format!("{os}/{arch}"),
    }
}

/// Parse a manifest; `content_type` is the response's `Content-Type`, used when the document
/// does not say what it is.
pub fn parse(bytes: &[u8], content_type: Option<&str>) -> Result<Manifest> {
    let j = Json::parse(bytes).map_err(|e| anyhow::anyhow!("manifest: invalid JSON: {e}"))?;
    if j.get("schemaVersion").and_then(Json::u64) == Some(1) {
        bail!(
            "this image uses the long-deprecated Docker schema 1 manifest, which is not supported"
        );
    }
    let ct = content_type.map(|c| c.split(';').next().unwrap_or(c).trim());
    let media_type = j.get_str("mediaType").or(ct).unwrap_or_default().to_owned();
    let is_index = match media_type.as_str() {
        OCI_INDEX | DOCKER_LIST => true,
        OCI_MANIFEST | DOCKER_MANIFEST => false,
        _ if j.get("manifests").is_some() => true,
        _ if j.get("layers").is_some() => false,
        m => bail!("unsupported manifest media type {m:?}"),
    };
    if is_index {
        let ms = j
            .get("manifests")
            .and_then(Json::arr)
            .context("index: no manifests")?;
        let mut out = Vec::with_capacity(ms.len());
        for (i, m) in ms.iter().enumerate() {
            let d = descriptor(m, &format!("index entry {}", i + 1))?;
            let platform = m
                .get("platform")
                .map_or("unknown/unknown".into(), platform_of);
            let attestation = platform == "unknown/unknown"
                || m.get("annotations")
                    .and_then(|a| a.get_str("vnd.docker.reference.type"))
                    .is_some();
            out.push(PlatformEntry {
                descriptor: d,
                platform,
                attestation,
            });
        }
        Ok(Manifest::Index(out))
    } else {
        let config = descriptor(j.get("config").context("manifest: no config")?, "config")?;
        let layers = j
            .get("layers")
            .and_then(Json::arr)
            .context("manifest: no layers")?
            .iter()
            .enumerate()
            .map(|(i, l)| descriptor(l, &format!("layer {}", i + 1)))
            .collect::<Result<Vec<_>>>()?;
        Ok(Manifest::Image(ImageManifest {
            media_type,
            config,
            layers,
        }))
    }
}

pub fn parse_config(bytes: &[u8]) -> Result<ImageConfig> {
    let j = Json::parse(bytes).map_err(|e| anyhow::anyhow!("image config: invalid JSON: {e}"))?;
    let ids = j
        .get("rootfs")
        .and_then(|r| r.get("diff_ids"))
        .and_then(Json::arr)
        .context("image config: no rootfs.diff_ids")?;
    let diff_ids = ids
        .iter()
        .map(|d| match d.str() {
            Some(s) if valid_digest(s) => Ok(s.to_owned()),
            _ => bail!("image config: invalid diff_id"),
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(ImageConfig {
        platform: platform_of(&j),
        diff_ids,
    })
}

/// The platform pulled by default: Linux on this computer's architecture (container images are
/// almost always Linux, whatever the host).
pub fn default_platform() -> String {
    let (_, arch) = trunc_engine::image::host_platform();
    format!("linux/{arch}")
}

/// Pick the manifest for `want` (`os/arch[/variant]`; without a variant, any variant).
/// Attestation manifests are never picked.
pub fn select_platform<'a>(entries: &'a [PlatformEntry], want: &str) -> Result<&'a PlatformEntry> {
    let images: Vec<&PlatformEntry> = entries.iter().filter(|e| !e.attestation).collect();
    if let Some(e) = images
        .iter()
        .find(|e| trunc_engine::image::platform_matches(&e.platform, want))
    {
        return Ok(e);
    }
    let have: Vec<&str> = images.iter().map(|e| e.platform.as_str()).collect();
    bail!(
        "the image has no {want} variant; it has: {} (choose one with --platform)",
        if have.is_empty() {
            "none".to_owned()
        } else {
            have.join(", ")
        }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(platform: &str, attestation: bool) -> PlatformEntry {
        PlatformEntry {
            descriptor: Descriptor {
                media_type: OCI_MANIFEST.into(),
                digest: format!("sha256:{}", "0".repeat(64)),
                size: 1,
            },
            platform: platform.into(),
            attestation,
        }
    }

    #[test]
    fn platform_selection() {
        let es = vec![
            entry("linux/amd64", false),
            entry("linux/arm/v6", false),
            entry("linux/arm/v7", false),
            entry("linux/arm64/v8", false),
            entry("unknown/unknown", true),
        ];
        assert_eq!(
            select_platform(&es, "linux/amd64").expect("x").platform,
            "linux/amd64"
        );
        assert_eq!(
            select_platform(&es, "linux/arm64").expect("x").platform,
            "linux/arm64/v8"
        );
        assert_eq!(
            select_platform(&es, "linux/arm/v7").expect("x").platform,
            "linux/arm/v7"
        );
        assert_eq!(
            select_platform(&es, "linux/arm").expect("x").platform,
            "linux/arm/v6"
        );
        let e = select_platform(&es, "linux/s390x").expect_err("absent");
        assert!(e.to_string().contains("linux/amd64, linux/arm/v6"), "{e}");
        assert!(!e.to_string().contains("unknown"), "{e}");
        assert!(select_platform(&es, "unknown/unknown").is_err());
        assert!(default_platform().starts_with("linux/"));
    }

    #[test]
    fn parses_index_and_manifest() {
        let d = format!("sha256:{}", "a".repeat(64));
        let idx = format!(
            r#"{{"schemaVersion":2,"manifests":[
              {{"mediaType":"{OCI_MANIFEST}","digest":"{d}","size":10,"platform":{{"os":"linux","architecture":"arm64","variant":"v8"}}}},
              {{"mediaType":"{OCI_MANIFEST}","digest":"{d}","size":10,"platform":{{"os":"unknown","architecture":"unknown"}},
                "annotations":{{"vnd.docker.reference.type":"attestation-manifest"}}}}]}}"#
        );
        let Manifest::Index(es) = parse(idx.as_bytes(), Some(OCI_INDEX)).expect("index") else {
            panic!("not an index");
        };
        assert_eq!(es.len(), 2);
        assert_eq!(es[0].platform, "linux/arm64/v8");
        assert!(es[1].attestation);
        let m = format!(
            r#"{{"schemaVersion":2,"mediaType":"{DOCKER_MANIFEST}","config":{{"digest":"{d}","size":5}},
               "layers":[{{"mediaType":"application/vnd.docker.image.rootfs.diff.tar.gzip","digest":"{d}","size":7}}]}}"#
        );
        let Manifest::Image(im) = parse(m.as_bytes(), None).expect("manifest") else {
            panic!("not a manifest");
        };
        assert_eq!(im.layers.len(), 1);
        assert_eq!(im.layers[0].size, 7);
        assert!(parse(br#"{"schemaVersion":1}"#, None).is_err());
        assert!(parse(br#"{"mediaType":"text/plain"}"#, None).is_err());
        let cfg = format!(
            r#"{{"os":"linux","architecture":"amd64","rootfs":{{"type":"layers","diff_ids":["{d}"]}}}}"#
        );
        let c = parse_config(cfg.as_bytes()).expect("config");
        assert_eq!(c.platform, "linux/amd64");
        assert_eq!(c.diff_ids, vec![d]);
    }
}
