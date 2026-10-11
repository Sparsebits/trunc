//! layerless: pull a container image straight to a root filesystem, with no tarball, no daemon
//! and no second copy on disk. Layers stream from the registry through trunc's decoders and tar
//! reader into a staging directory, verified as they arrive (blob digest and diff_id), and the
//! merged tree is renamed into place only once everything checks out.

pub mod auth;
pub mod manifest;
pub mod reference;
pub mod registry;

use std::path::Path;

use anyhow::{Context, Result, bail};
use trunc_engine::image::ImageSummary;
use trunc_engine::layerstream::{self, LayerSpec, StreamOptions};
use trunc_fs::OsFs;

use crate::manifest::{ImageConfig, ImageManifest, Manifest, PlatformEntry};
use crate::reference::Reference;
use crate::registry::Client;

/// An image resolved down to one platform's manifest and config.
#[derive(Debug, Clone)]
pub struct Resolved {
    pub reference: Reference,
    /// The index (manifest list) the tag pointed at, if any: its digest and entries.
    pub index: Option<(String, Vec<PlatformEntry>)>,
    pub manifest_digest: String,
    pub manifest: ImageManifest,
    pub config: ImageConfig,
}

impl Resolved {
    pub fn layers(&self) -> Vec<LayerSpec> {
        self.manifest
            .layers
            .iter()
            .zip(&self.config.diff_ids)
            .map(|(l, d)| LayerSpec {
                media_type: l.media_type.clone(),
                digest: l.digest.clone(),
                size: l.size,
                diff_id: d.clone(),
            })
            .collect()
    }

    pub fn download_bytes(&self) -> u64 {
        self.manifest.layers.iter().map(|l| l.size).sum()
    }
}

/// Resolve `reference` to one platform's manifest and config (default platform: Linux on this
/// computer's architecture), without downloading any layer.
pub fn resolve(client: &mut Client, platform: Option<&str>) -> Result<Resolved> {
    let reference = client.reference().clone();
    let want = platform.map_or_else(manifest::default_platform, str::to_owned);
    let (body, ct, digest) = client.manifest(reference.target())?;
    let (index, manifest_digest, manifest) = match manifest::parse(&body, ct.as_deref())? {
        Manifest::Image(m) => (None, digest, m),
        Manifest::Index(entries) => {
            let pick = manifest::select_platform(&entries, &want)?
                .descriptor
                .clone();
            let (body, ct, d) = client.manifest(&pick.digest)?;
            match manifest::parse(&body, ct.as_deref())? {
                Manifest::Image(m) => (Some((digest, entries)), d, m),
                Manifest::Index(_) => bail!("index entry {} is itself an index", pick.digest),
            }
        }
    };
    let cfg = client.blob_bytes(&manifest.config.digest, manifest.config.size)?;
    let config = manifest::parse_config(&cfg)?;
    if config.diff_ids.len() != manifest.layers.len() {
        bail!(
            "the manifest lists {} layers but the config {} diff_ids",
            manifest.layers.len(),
            config.diff_ids.len()
        );
    }
    if index.is_none()
        && platform.is_some()
        && !trunc_engine::image::platform_matches(&config.platform, &want)
    {
        bail!(
            "{reference} is a single-platform image for {}, not {want}",
            config.platform
        );
    }
    Ok(Resolved {
        reference,
        index,
        manifest_digest,
        manifest,
        config,
    })
}

/// Pull `reference` into `dest` as a merged root filesystem. `on_layer` is told when each layer
/// has been streamed and verified.
pub fn pull(
    reference: &str,
    dest: &Path,
    platform: Option<&str>,
    on_resolved: &mut dyn FnMut(&Resolved),
    on_layer: &mut dyn FnMut(usize, &LayerSpec),
) -> Result<ImageSummary> {
    let r = Reference::parse(reference)?;
    let mut client = Client::new(r);
    let resolved = resolve(&mut client, platform)?;
    on_resolved(&resolved);
    let layers = resolved.layers();
    let summary = layerstream::extract_layer_streams(
        &OsFs::new(),
        dest,
        &layers,
        &StreamOptions::default(),
        &mut |_, spec| {
            client
                .open_blob(&spec.digest)
                .map_err(|e| trunc_engine::Error::Input(format!("{e:#}")))
        },
        on_layer,
    )
    .with_context(|| format!("pulling {} into {}", resolved.reference, dest.display()))?;
    Ok(summary)
}
