//! Image references: `[registry[:port]/]repository[:tag][@sha256:<hex>]`, with Docker Hub's
//! shorthands (`alpine` is `docker.io/library/alpine:latest`).

use anyhow::{Result, bail};

/// Where Docker Hub's registry API actually lives.
pub const DOCKER_HUB_API: &str = "registry-1.docker.io";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    /// Registry host (and port) as written, `docker.io` for Docker Hub.
    pub registry: String,
    pub repository: String,
    pub tag: Option<String>,
    pub digest: Option<String>,
}

fn valid_repo(r: &str) -> bool {
    !r.is_empty()
        && r.split('/').all(|c| {
            !c.is_empty()
                && c.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
                })
                && c.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
        })
}

fn valid_tag(t: &str) -> bool {
    !t.is_empty()
        && t.len() <= 128
        && t.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        && !t.starts_with(['.', '-'])
}

/// `sha256:<64 lowercase hex>`.
pub fn valid_digest(d: &str) -> bool {
    d.strip_prefix("sha256:")
        .is_some_and(|h| h.len() == 64 && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}

impl Reference {
    pub fn parse(s: &str) -> Result<Self> {
        let (rest, digest) = match s.rsplit_once('@') {
            Some((r, d)) => {
                if !valid_digest(d) {
                    bail!("{s:?}: {d:?} is not a sha256 digest");
                }
                (r, Some(d.to_owned()))
            }
            None => (s, None),
        };
        let (registry, path) = match rest.split_once('/') {
            Some((first, path))
                if first.contains('.') || first.contains(':') || first == "localhost" =>
            {
                (first.to_owned(), path)
            }
            _ => ("docker.io".to_owned(), rest),
        };
        let (repo, tag) = match path.rsplit_once(':') {
            Some((r, t)) if !t.contains('/') => (r, Some(t.to_owned())),
            _ => (path, None),
        };
        let registry = match registry.as_str() {
            "index.docker.io" | "registry-1.docker.io" | "registry.hub.docker.com" => {
                "docker.io".to_owned()
            }
            _ => registry,
        };
        let repository = if registry == "docker.io" && !repo.contains('/') {
            format!("library/{repo}")
        } else {
            repo.to_owned()
        };
        if !valid_repo(&repository) {
            bail!(
                "{s:?}: {repo:?} is not a valid repository name (lowercase letters, digits, '.', '_', '-' and '/')"
            );
        }
        if let Some(t) = &tag {
            if !valid_tag(t) {
                bail!("{s:?}: {t:?} is not a valid tag");
            }
        }
        if registry.is_empty() {
            bail!("{s:?}: no registry");
        }
        Ok(Self {
            registry,
            repository,
            tag,
            digest,
        })
    }

    /// What to ask the registry for: the digest if given, else the tag (default `latest`).
    pub fn target(&self) -> &str {
        self.digest
            .as_deref()
            .or(self.tag.as_deref())
            .unwrap_or("latest")
    }

    /// Host (and port) of the registry API.
    pub fn api_host(&self) -> &str {
        if self.registry == "docker.io" {
            DOCKER_HUB_API
        } else {
            &self.registry
        }
    }

    /// `scheme://host`: plain HTTP for loopback registries (as Docker allows), HTTPS otherwise.
    pub fn base_url(&self) -> String {
        let host = self.api_host();
        let name = match host.rsplit_once(':') {
            Some((h, p)) if p.bytes().all(|b| b.is_ascii_digit()) => h,
            _ => host,
        };
        let scheme = if matches!(name, "localhost" | "127.0.0.1" | "[::1]") {
            "http"
        } else {
            "https"
        };
        format!("{scheme}://{host}")
    }
}

impl std::fmt::Display for Reference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.registry, self.repository)?;
        if let Some(t) = &self.tag {
            write!(f, ":{t}")?;
        } else if self.digest.is_none() {
            write!(f, ":latest")?;
        }
        if let Some(d) = &self.digest {
            write!(f, "@{d}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Reference {
        Reference::parse(s).unwrap_or_else(|e| panic!("{s}: {e}"))
    }

    #[test]
    fn docker_hub_shorthands() {
        let r = p("alpine");
        assert_eq!(r.registry, "docker.io");
        assert_eq!(r.repository, "library/alpine");
        assert_eq!(r.target(), "latest");
        assert_eq!(r.base_url(), "https://registry-1.docker.io");
        assert_eq!(r.to_string(), "docker.io/library/alpine:latest");
        let r = p("alpine:3.20");
        assert_eq!(
            (r.repository.as_str(), r.target()),
            ("library/alpine", "3.20")
        );
        let r = p("bitnami/redis:7");
        assert_eq!(r.repository, "bitnami/redis");
        assert_eq!(p("docker.io/alpine").repository, "library/alpine");
        assert_eq!(p("index.docker.io/library/alpine").registry, "docker.io");
    }

    #[test]
    fn other_registries() {
        let r = p("ghcr.io/owner/tool:v1.2");
        assert_eq!(r.registry, "ghcr.io");
        assert_eq!(r.repository, "owner/tool");
        assert_eq!(r.target(), "v1.2");
        assert_eq!(r.base_url(), "https://ghcr.io");
        let r = p("localhost:5000/img");
        assert_eq!(r.registry, "localhost:5000");
        assert_eq!(r.repository, "img");
        assert_eq!(r.base_url(), "http://localhost:5000");
        let r = p("127.0.0.1:8080/a/b:t");
        assert_eq!(r.base_url(), "http://127.0.0.1:8080");
        assert_eq!(p("quay.io/x/y").base_url(), "https://quay.io");
    }

    #[test]
    fn digests() {
        let d = format!("sha256:{}", "ab".repeat(32));
        let r = p(&format!("alpine@{d}"));
        assert_eq!(r.digest.as_deref(), Some(d.as_str()));
        assert_eq!(r.target(), d);
        let r = p(&format!("ghcr.io/o/r:tag@{d}"));
        assert_eq!(r.tag.as_deref(), Some("tag"));
        assert_eq!(r.target(), d);
        assert!(Reference::parse("alpine@sha256:xyz").is_err());
        assert!(Reference::parse("alpine@md5:00").is_err());
    }

    #[test]
    fn invalid() {
        for s in [
            "",
            "Alpine",
            "alpine:",
            "alpine:-x",
            "a//b",
            "ghcr.io/",
            "/x",
        ] {
            assert!(Reference::parse(s).is_err(), "{s:?} should be refused");
        }
    }
}
