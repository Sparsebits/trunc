//! A minimal OCI distribution client: anonymous bearer tokens, manifests and blobs.

use std::io::Read;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use trunc_engine::json::Json;

use crate::auth::Challenge;
use crate::reference::Reference;

/// Largest manifest, index or config accepted.
const MAX_DOCUMENT: u64 = 16 << 20;

#[derive(Debug)]
pub struct Client {
    agent: ureq::Agent,
    reference: Reference,
    token: Option<String>,
}

type Response = ureq::http::Response<ureq::Body>;

fn hex_sha256(b: &[u8]) -> String {
    format!("sha256:{}", hex::encode(trunc_hash::sha256(b)))
}

impl Client {
    pub fn new(reference: Reference) -> Self {
        let agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .user_agent(concat!("layerless/", env!("CARGO_PKG_VERSION")))
            .timeout_connect(Some(Duration::from_secs(30)))
            .timeout_recv_response(Some(Duration::from_secs(60)))
            .build()
            .into();
        Self {
            agent,
            reference,
            token: None,
        }
    }

    pub fn reference(&self) -> &Reference {
        &self.reference
    }

    fn url(&self, kind: &str, target: &str) -> String {
        format!(
            "{}/v2/{}/{kind}/{target}",
            self.reference.base_url(),
            self.reference.repository
        )
    }

    fn send(&self, url: &str, accept: Option<&str>) -> Result<Response> {
        let mut req = self.agent.get(url);
        if let Some(a) = accept {
            req = req.header("Accept", a);
        }
        if let Some(t) = &self.token {
            req = req.header("Authorization", format!("Bearer {t}"));
        }
        req.call().with_context(|| format!("GET {url}"))
    }

    /// GET `url`, fetching an anonymous token once if the registry asks for one.
    fn get(&mut self, url: &str, accept: Option<&str>) -> Result<Response> {
        let resp = self.send(url, accept)?;
        if resp.status().as_u16() != 401 || self.token.is_some() {
            return check(url, resp);
        }
        let header = resp
            .headers()
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok())
            .with_context(|| format!("GET {url}: 401 without a WWW-Authenticate challenge"))?
            .to_owned();
        let challenge = Challenge::parse(&header)?;
        let token_url = challenge.token_url(&self.reference.repository)?;
        let mut tr = self
            .agent
            .get(&token_url)
            .call()
            .with_context(|| format!("GET {token_url}"))?;
        if !tr.status().is_success() {
            bail!(
                "the registry refused an anonymous token for {} ({}); is the image public?",
                self.reference.repository,
                tr.status()
            );
        }
        let body = tr
            .body_mut()
            .with_config()
            .limit(MAX_DOCUMENT)
            .read_to_vec()
            .context("reading the token response")?;
        let j = Json::parse(&body).map_err(|e| anyhow::anyhow!("token response: {e}"))?;
        let token = j
            .get_str("token")
            .or_else(|| j.get_str("access_token"))
            .context("token response: no token")?;
        self.token = Some(token.to_owned());
        check(url, self.send(url, accept)?)
    }

    fn read_document(&mut self, url: &str, accept: Option<&str>) -> Result<(Vec<u8>, Response)> {
        let mut resp = self.get(url, accept)?;
        let body = resp
            .body_mut()
            .with_config()
            .limit(MAX_DOCUMENT)
            .read_to_vec()
            .with_context(|| format!("reading {url}"))?;
        Ok((body, resp))
    }

    /// The manifest (or index) for `target` (a tag or digest): its bytes, `Content-Type` and
    /// digest. A digest asked for is checked.
    pub fn manifest(&mut self, target: &str) -> Result<(Vec<u8>, Option<String>, String)> {
        let url = self.url("manifests", target);
        let (body, resp) = self.read_document(&url, Some(crate::manifest::ACCEPT))?;
        let got = hex_sha256(&body);
        if target.starts_with("sha256:") && got != target {
            bail!("manifest {target}: the registry sent a document whose sha256 is {got}");
        }
        let ct = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        Ok((body, ct, got))
    }

    /// A small blob (a config), checked against its digest.
    pub fn blob_bytes(&mut self, digest: &str, size: u64) -> Result<Vec<u8>> {
        if size > MAX_DOCUMENT {
            bail!("blob {digest} is {size} bytes, too large for a config");
        }
        let url = self.url("blobs", digest);
        let (body, _) = self.read_document(&url, None)?;
        let got = hex_sha256(&body);
        if got != digest {
            bail!("blob {digest}: the registry sent data whose sha256 is {got}");
        }
        Ok(body)
    }

    /// A reader of a blob (redirects to a CDN are followed; the token is not sent there).
    pub fn open_blob(&mut self, digest: &str) -> Result<Box<dyn Read + Send>> {
        let url = self.url("blobs", digest);
        let resp = self.get(&url, None)?;
        Ok(Box::new(resp.into_body().into_reader()))
    }
}

fn check(url: &str, resp: Response) -> Result<Response> {
    let s = resp.status();
    if s.is_success() {
        return Ok(resp);
    }
    match s.as_u16() {
        401 | 403 => bail!("GET {url}: {s}; the image may be private or not exist"),
        404 => bail!("GET {url}: not found (check the image name and tag)"),
        429 => bail!("GET {url}: rate limited by the registry ({s}); try again later"),
        _ => bail!("GET {url}: {s}"),
    }
}
