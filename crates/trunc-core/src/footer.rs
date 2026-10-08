//! The fixed 128-byte footer that ends every block.
//!
//! ```text
//!   0..8    magic        b"TRNCBLK\0"
//!   8..12   block_index  u32 (0 = first block of the logical stream, stored at EOF)
//!  12..14   codec        u16
//!  14..16   flags        u16 (must be 0 in v1)
//!  16..24   c_len        u64 payload length (bytes immediately before the footer)
//!  24..32   u_len        u64 decoded length
//!  32..40   stream_off   u64 offset of the decoded bytes in the logical stream
//!  40..72   blake3_c     BLAKE3 of the payload
//!  72..104  blake3_u     BLAKE3 of the decoded bytes
//! 104..120  archive_id   copied from the manifest
//! 120..124  reserved     zero
//! 124..128  crc32c       over bytes 0..124
//! ```
//!
//! A footer is self-sufficient for decoding its block: after a crash, the consumer reads the
//! footer at EOF and knows exactly which bytes precede it and what they must decode to.

use crate::header::{le_u16, le_u32, le_u64};
use crate::{CodecId, FormatError, MAX_BLOCK_U, max_c_len};

pub const FOOTER_LEN: usize = 128;
pub const FOOTER_MAGIC: [u8; 8] = *b"TRNCBLK\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Footer {
    pub block_index: u32,
    pub codec: CodecId,
    pub c_len: u64,
    pub u_len: u64,
    pub stream_off: u64,
    pub blake3_c: [u8; 32],
    pub blake3_u: [u8; 32],
    pub archive_id: [u8; 16],
}

impl Footer {
    pub fn encode(&self) -> [u8; FOOTER_LEN] {
        let mut b = [0u8; FOOTER_LEN];
        b[0..8].copy_from_slice(&FOOTER_MAGIC);
        b[8..12].copy_from_slice(&self.block_index.to_le_bytes());
        b[12..14].copy_from_slice(&self.codec.as_u16().to_le_bytes());
        b[14..16].copy_from_slice(&0u16.to_le_bytes());
        b[16..24].copy_from_slice(&self.c_len.to_le_bytes());
        b[24..32].copy_from_slice(&self.u_len.to_le_bytes());
        b[32..40].copy_from_slice(&self.stream_off.to_le_bytes());
        b[40..72].copy_from_slice(&self.blake3_c);
        b[72..104].copy_from_slice(&self.blake3_u);
        b[104..120].copy_from_slice(&self.archive_id);
        let crc = trunc_hash::crc32c(&b[0..124]);
        b[124..128].copy_from_slice(&crc.to_le_bytes());
        b
    }

    pub fn decode(b: &[u8]) -> Result<Self, FormatError> {
        if b.len() != FOOTER_LEN {
            return Err(FormatError::Length {
                what: "footer",
                expected: FOOTER_LEN,
                got: b.len(),
            });
        }
        if b[0..8] != FOOTER_MAGIC {
            return Err(FormatError::BadMagic("block footer"));
        }
        if trunc_hash::crc32c(&b[0..124]) != le_u32(&b[124..128]) {
            return Err(FormatError::Checksum("footer"));
        }
        let flags = le_u16(&b[14..16]);
        if flags != 0 {
            return Err(FormatError::UnknownFlags {
                what: "footer",
                flags: u32::from(flags),
            });
        }
        if b[120..124].iter().any(|&x| x != 0) {
            return Err(FormatError::Manifest(
                "footer reserved bytes are not zero".into(),
            ));
        }
        let mut blake3_c = [0u8; 32];
        let mut blake3_u = [0u8; 32];
        let mut archive_id = [0u8; 16];
        blake3_c.copy_from_slice(&b[40..72]);
        blake3_u.copy_from_slice(&b[72..104]);
        archive_id.copy_from_slice(&b[104..120]);
        let f = Footer {
            block_index: le_u32(&b[8..12]),
            codec: CodecId::try_from(le_u16(&b[12..14]))?,
            c_len: le_u64(&b[16..24]),
            u_len: le_u64(&b[24..32]),
            stream_off: le_u64(&b[32..40]),
            blake3_c,
            blake3_u,
            archive_id,
        };
        if f.u_len == 0 || f.u_len > MAX_BLOCK_U || f.c_len > max_c_len(f.u_len) {
            return Err(FormatError::Manifest(format!(
                "footer sizes out of range (c_len {}, u_len {})",
                f.c_len, f.u_len
            )));
        }
        Ok(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Footer {
        Footer {
            block_index: 7,
            codec: CodecId::Zstd,
            c_len: 1000,
            u_len: 4096,
            stream_off: 8 << 20,
            blake3_c: [1; 32],
            blake3_u: [2; 32],
            archive_id: [3; 16],
        }
    }

    #[test]
    fn round_trip() {
        let f = sample();
        assert_eq!(Footer::decode(&f.encode()).unwrap(), f);
    }

    #[test]
    fn rejects_any_bit_flip() {
        let b = sample().encode();
        for i in 0..FOOTER_LEN {
            let mut c = b;
            c[i] ^= 0x01;
            assert!(Footer::decode(&c).is_err(), "byte {i} flip accepted");
        }
    }

    #[test]
    fn rejects_out_of_range_sizes() {
        let mut f = sample();
        f.u_len = 0;
        assert!(Footer::decode(&f.encode()).is_err());
        let mut f = sample();
        f.c_len = max_c_len(f.u_len) + 1;
        assert!(Footer::decode(&f.encode()).is_err());
    }
}
