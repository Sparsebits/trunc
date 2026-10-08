//! The fixed 96-byte header at offset 0.
//!
//! ```text
//!  0..6   magic            b"TRNC\0\x01"
//!  6..8   version          u16
//!  8..12  flags            u32 (must be 0 in v1)
//! 12..20  manifest_off     u64 (== 96)
//! 20..28  manifest_len     u64
//! 28..36  dict_off         u64 (== manifest_off + manifest_len)
//! 36..44  dict_len         u64 (0 = no dictionary)
//! 44..52  first_block_off  u64 (== dict_off + dict_len)
//! 52..84  manifest_blake3  BLAKE3 of the manifest region bytes
//! 84..92  reserved         zero
//! 92..96  crc32c           over bytes 0..92
//! ```
//!
//! `manifest_blake3` makes corruption of an unsigned manifest detectable. Authenticity (as
//! opposed to integrity) comes only from the optional signature inside the manifest.

use crate::{FORMAT_VERSION, FormatError, MAX_DICT_LEN, MAX_MANIFEST_LEN};

pub const HEADER_LEN: usize = 96;
pub const HEADER_MAGIC: [u8; 6] = *b"TRNC\0\x01";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub manifest_len: u64,
    pub dict_len: u64,
    pub manifest_blake3: [u8; 32],
}

impl Header {
    /// Header for a manifest region and dictionary length.
    pub fn for_manifest(region: &[u8], dict_len: u64) -> Self {
        Self {
            manifest_len: region.len() as u64,
            dict_len,
            manifest_blake3: trunc_hash::blake3(region),
        }
    }

    pub fn manifest_off(&self) -> u64 {
        HEADER_LEN as u64
    }

    pub fn dict_off(&self) -> u64 {
        self.manifest_off() + self.manifest_len
    }

    pub fn first_block_off(&self) -> u64 {
        self.dict_off() + self.dict_len
    }

    /// Check manifest region bytes read from disk against `manifest_blake3`.
    pub fn check_manifest(&self, region: &[u8]) -> Result<(), FormatError> {
        if region.len() as u64 != self.manifest_len {
            return Err(FormatError::Length {
                what: "manifest region",
                expected: usize::try_from(self.manifest_len).unwrap_or(usize::MAX),
                got: region.len(),
            });
        }
        if trunc_hash::blake3(region) != self.manifest_blake3 {
            return Err(FormatError::Checksum("manifest"));
        }
        Ok(())
    }

    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut b = [0u8; HEADER_LEN];
        b[0..6].copy_from_slice(&HEADER_MAGIC);
        b[6..8].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        b[8..12].copy_from_slice(&0u32.to_le_bytes());
        b[12..20].copy_from_slice(&self.manifest_off().to_le_bytes());
        b[20..28].copy_from_slice(&self.manifest_len.to_le_bytes());
        b[28..36].copy_from_slice(&self.dict_off().to_le_bytes());
        b[36..44].copy_from_slice(&self.dict_len.to_le_bytes());
        b[44..52].copy_from_slice(&self.first_block_off().to_le_bytes());
        b[52..84].copy_from_slice(&self.manifest_blake3);
        let crc = trunc_hash::crc32c(&b[0..92]);
        b[92..96].copy_from_slice(&crc.to_le_bytes());
        b
    }

    pub fn decode(b: &[u8]) -> Result<Self, FormatError> {
        if b.len() != HEADER_LEN {
            return Err(FormatError::Length {
                what: "header",
                expected: HEADER_LEN,
                got: b.len(),
            });
        }
        if b[0..6] != HEADER_MAGIC {
            return Err(FormatError::BadMagic("header"));
        }
        if trunc_hash::crc32c(&b[0..92]) != le_u32(&b[92..96]) {
            return Err(FormatError::Checksum("header"));
        }
        let version = le_u16(&b[6..8]);
        if version != FORMAT_VERSION {
            return Err(FormatError::UnsupportedVersion(version));
        }
        let flags = le_u32(&b[8..12]);
        if flags != 0 {
            return Err(FormatError::UnknownFlags {
                what: "header",
                flags,
            });
        }
        if b[84..92].iter().any(|&x| x != 0) {
            return Err(FormatError::Header("reserved bytes are not zero".into()));
        }
        let mut manifest_blake3 = [0u8; 32];
        manifest_blake3.copy_from_slice(&b[52..84]);
        let h = Header {
            manifest_len: le_u64(&b[20..28]),
            dict_len: le_u64(&b[36..44]),
            manifest_blake3,
        };
        if le_u64(&b[12..20]) != h.manifest_off() {
            return Err(FormatError::Header(
                "manifest_off must equal header length".into(),
            ));
        }
        if h.manifest_len == 0 || h.manifest_len > MAX_MANIFEST_LEN {
            return Err(FormatError::Header(format!(
                "manifest_len {} out of range",
                h.manifest_len
            )));
        }
        if h.dict_len > MAX_DICT_LEN {
            return Err(FormatError::Header(format!(
                "dict_len {} out of range",
                h.dict_len
            )));
        }
        if le_u64(&b[28..36]) != h.dict_off() {
            return Err(FormatError::Header(
                "dict_off does not follow manifest".into(),
            ));
        }
        if le_u64(&b[44..52]) != h.first_block_off() {
            return Err(FormatError::Header(
                "first_block_off does not follow dictionary".into(),
            ));
        }
        Ok(h)
    }
}

pub(crate) fn le_u16(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}

pub(crate) fn le_u32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

pub(crate) fn le_u64(b: &[u8]) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[..8]);
    u64::from_le_bytes(a)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Header {
        Header {
            manifest_len: 1234,
            dict_len: 77,
            manifest_blake3: [5; 32],
        }
    }

    #[test]
    fn round_trip() {
        let h = sample();
        assert_eq!(Header::decode(&h.encode()).unwrap(), h);
        assert_eq!(h.first_block_off(), 96 + 1234 + 77);
    }

    #[test]
    fn rejects_corruption_anywhere() {
        let b = sample().encode();
        for i in 0..HEADER_LEN {
            let mut c = b;
            c[i] ^= 0x40;
            assert!(Header::decode(&c).is_err(), "byte {i} flip accepted");
        }
    }

    #[test]
    fn rejects_bad_length_and_zero_manifest() {
        assert!(matches!(
            Header::decode(&[0u8; 10]),
            Err(FormatError::Length { .. })
        ));
        let b = Header {
            manifest_len: 0,
            ..sample()
        }
        .encode();
        assert!(matches!(Header::decode(&b), Err(FormatError::Header(_))));
    }

    #[test]
    fn manifest_check() {
        let region = b"manifest bytes".to_vec();
        let h = Header::for_manifest(&region, 0);
        h.check_manifest(&region).unwrap();
        let mut bad = region.clone();
        bad[3] ^= 1;
        assert_eq!(
            h.check_manifest(&bad).unwrap_err(),
            FormatError::Checksum("manifest")
        );
        assert!(h.check_manifest(&region[1..]).is_err());
    }

    #[test]
    fn layout_snapshot() {
        let b = Header {
            manifest_len: 0x0102,
            dict_len: 0,
            manifest_blake3: [0xAB; 32],
        }
        .encode();
        assert_eq!(&b[0..8], b"TRNC\0\x01\x01\x00");
        assert_eq!(le_u64(&b[12..20]), 96);
        assert_eq!(le_u64(&b[20..28]), 0x0102);
        assert_eq!(le_u64(&b[44..52]), 96 + 0x0102);
        assert_eq!(&b[52..84], &[0xAB; 32]);
    }
}
