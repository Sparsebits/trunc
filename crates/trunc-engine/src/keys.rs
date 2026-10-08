//! Ed25519 signing keys stored as hex text files.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use ed25519_dalek::SigningKey;

use crate::error::{Error, IoContext, Result, at};

/// Generate a new random signing key.
pub fn generate() -> Result<SigningKey> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed)
        .map_err(|e| Error::Input(format!("OS random source failed: {e}")))?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Write the secret key as hex. Refuses to overwrite an existing file.
pub fn save_secret(path: &Path, key: &SigningKey) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .ctx(at("creating key file", path))?;
    writeln!(f, "{}", hex::encode(key.to_bytes())).ctx(at("writing key file", path))?;
    f.sync_all().ctx(at("flushing key file", path))?;
    Ok(())
}

/// Load a secret key written by [`save_secret`].
pub fn load_secret(path: &Path) -> Result<SigningKey> {
    let text = std::fs::read_to_string(path).ctx(at("reading key file", path))?;
    let bytes: [u8; 32] = hex::decode(text.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| Error::Input(format!("{} is not a trunc secret key", path.display())))?;
    Ok(SigningKey::from_bytes(&bytes))
}

/// Hex form of a public key.
pub fn public_hex(key: &[u8; 32]) -> String {
    hex::encode(key)
}

/// Parse a hex public key.
pub fn parse_public(s: &str) -> Result<[u8; 32]> {
    hex::decode(s.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| Error::Input(format!("{s:?} is not a 64-character hex public key")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("k");
        let k = generate().unwrap();
        save_secret(&p, &k).unwrap();
        assert_eq!(load_secret(&p).unwrap().to_bytes(), k.to_bytes());
        assert!(save_secret(&p, &k).is_err(), "must not overwrite");
        let pk = k.verifying_key().to_bytes();
        assert_eq!(parse_public(&public_hex(&pk)).unwrap(), pk);
        assert!(parse_public("abc").is_err());
    }
}
