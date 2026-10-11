//! Anonymous registry authentication: the `WWW-Authenticate` challenge of a 401 and the token
//! request it describes (the Docker registry token protocol, also used by GHCR, Quay, ECR
//! Public and most others).

use anyhow::{Result, bail};

/// A parsed `WWW-Authenticate` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    /// `bearer`, `basic`, ... (lowercase).
    pub scheme: String,
    /// Parameters in order, names lowercase.
    pub params: Vec<(String, String)>,
}

impl Challenge {
    pub fn param(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// Parse one challenge: `Scheme k=v, k="quoted, \"value\"", ...`.
    pub fn parse(header: &str) -> Result<Self> {
        let h = header.trim();
        let (scheme, mut rest) = match h.find(char::is_whitespace) {
            Some(i) => (&h[..i], h[i..].trim_start()),
            None => (h, ""),
        };
        if scheme.is_empty()
            || !scheme
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            bail!("unrecognised WWW-Authenticate header {header:?}");
        }
        let mut params = Vec::new();
        while !rest.is_empty() {
            let eq = rest
                .find('=')
                .ok_or_else(|| anyhow::anyhow!("WWW-Authenticate {header:?}: expected k=v"))?;
            let key = rest[..eq].trim().to_ascii_lowercase();
            if key.is_empty() {
                bail!("WWW-Authenticate {header:?}: empty parameter name");
            }
            rest = rest[eq + 1..].trim_start();
            let value;
            if let Some(q) = rest.strip_prefix('"') {
                let mut v = String::new();
                let mut chars = q.char_indices();
                let mut end = None;
                while let Some((i, c)) = chars.next() {
                    match c {
                        '\\' => {
                            if let Some((_, n)) = chars.next() {
                                v.push(n);
                            }
                        }
                        '"' => {
                            end = Some(i + 1);
                            break;
                        }
                        c => v.push(c),
                    }
                }
                let end = end.ok_or_else(|| {
                    anyhow::anyhow!("WWW-Authenticate {header:?}: unterminated quoted value")
                })?;
                value = v;
                rest = q[end..].trim_start();
            } else {
                let end = rest.find(',').unwrap_or(rest.len());
                value = rest[..end].trim().to_owned();
                rest = &rest[end..];
            }
            params.push((key, value));
            rest = rest.trim_start();
            if let Some(r) = rest.strip_prefix(',') {
                rest = r.trim_start();
            } else if !rest.is_empty() {
                bail!("WWW-Authenticate {header:?}: expected ',' between parameters");
            }
        }
        Ok(Self {
            scheme: scheme.to_ascii_lowercase(),
            params,
        })
    }

    /// The URL to ask for an anonymous pull token for `repository`.
    pub fn token_url(&self, repository: &str) -> Result<String> {
        if self.scheme != "bearer" {
            bail!(
                "the registry asks for {} authentication; layerless only pulls anonymously \
                 (public images)",
                self.scheme
            );
        }
        let realm = self
            .param("realm")
            .ok_or_else(|| anyhow::anyhow!("the registry's bearer challenge has no realm"))?;
        if !(realm.starts_with("https://") || realm.starts_with("http://")) {
            bail!("the registry's token realm {realm:?} is not an http(s) URL");
        }
        let fallback = format!("repository:{repository}:pull");
        let scope = self.param("scope").unwrap_or(&fallback);
        let mut url = realm.to_owned();
        let mut sep = if realm.contains('?') { '&' } else { '?' };
        if let Some(service) = self.param("service") {
            url.push(sep);
            url.push_str("service=");
            url.push_str(&encode(service));
            sep = '&';
        }
        url.push(sep);
        url.push_str("scope=");
        url.push_str(&encode(scope));
        Ok(url)
    }
}

/// Percent-encode a query value.
fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~' | b':' | b'/') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docker_hub_challenge() {
        let c = Challenge::parse(
            r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/alpine:pull""#,
        )
        .expect("parses");
        assert_eq!(c.scheme, "bearer");
        assert_eq!(c.param("realm"), Some("https://auth.docker.io/token"));
        assert_eq!(c.param("service"), Some("registry.docker.io"));
        assert_eq!(
            c.token_url("library/alpine").expect("url"),
            "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/alpine:pull"
        );
    }

    #[test]
    fn quoting_spacing_and_case() {
        let c = Challenge::parse(
            r#"bearer  Realm = "https://x/t?a=1" , scope="a \"b\", c",error=insufficient_scope"#,
        )
        .expect("parses");
        assert_eq!(c.param("realm"), Some("https://x/t?a=1"));
        assert_eq!(c.param("scope"), Some("a \"b\", c"));
        assert_eq!(c.param("error"), Some("insufficient_scope"));
        assert_eq!(
            c.token_url("r").expect("url"),
            "https://x/t?a=1&scope=a%20%22b%22%2C%20c"
        );
    }

    #[test]
    fn missing_scope_falls_back_to_pull() {
        let c = Challenge::parse(r#"Bearer realm="https://ghcr.io/token",service="ghcr.io""#)
            .expect("parses");
        assert_eq!(
            c.token_url("o/r").expect("url"),
            "https://ghcr.io/token?service=ghcr.io&scope=repository:o/r:pull"
        );
    }

    #[test]
    fn refusals() {
        let basic = Challenge::parse(r#"Basic realm="Registry""#).expect("parses");
        assert!(basic.token_url("r").is_err());
        assert!(Challenge::parse(r#"Bearer realm="unterminated"#).is_err());
        assert!(Challenge::parse("Bearer realm").is_err());
        assert!(Challenge::parse("").is_err());
        let file = Challenge::parse(r#"Bearer realm="file:///etc/passwd""#).expect("parses");
        assert!(file.token_url("r").is_err());
        let none = Challenge::parse("Bearer").expect("parses");
        assert!(none.token_url("r").is_err());
    }
}
