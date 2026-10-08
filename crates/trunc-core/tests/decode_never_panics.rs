//! Lightweight always-on fuzzing: decoders must return errors, never panic, on arbitrary input.
//! The cargo-fuzz targets in `fuzz/` explore the same entry points far more deeply.

use proptest::prelude::*;
use trunc_core::{FOOTER_LEN, Footer, HEADER_LEN, Header, SignedManifest};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn header_decode(bytes in proptest::collection::vec(any::<u8>(), HEADER_LEN..=HEADER_LEN)) {
        let _ = Header::decode(&bytes);
    }

    #[test]
    fn footer_decode(bytes in proptest::collection::vec(any::<u8>(), FOOTER_LEN..=FOOTER_LEN)) {
        let _ = Footer::decode(&bytes);
    }

    #[test]
    fn manifest_open(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = SignedManifest::open(&bytes);
    }

    /// Valid magic and checksum but arbitrary fields: exercises the field validation paths.
    #[test]
    fn footer_fields(
        idx in any::<u32>(), codec in any::<u16>(), c in any::<u64>(), u in any::<u64>(), off in any::<u64>()
    ) {
        let mut b = [0u8; FOOTER_LEN];
        b[0..8].copy_from_slice(b"TRNCBLK\0");
        b[8..12].copy_from_slice(&idx.to_le_bytes());
        b[12..14].copy_from_slice(&codec.to_le_bytes());
        b[16..24].copy_from_slice(&c.to_le_bytes());
        b[24..32].copy_from_slice(&u.to_le_bytes());
        b[32..40].copy_from_slice(&off.to_le_bytes());
        let crc = trunc_hash::crc32c(&b[0..124]);
        b[124..128].copy_from_slice(&crc.to_le_bytes());
        if let Ok(f) = Footer::decode(&b) {
            prop_assert!(f.u_len > 0 && f.u_len <= trunc_core::MAX_BLOCK_U);
            prop_assert!(f.c_len <= trunc_core::max_c_len(f.u_len));
        }
    }
}
