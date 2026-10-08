//! Destructive extraction for existing archive formats.
//!
//! Phase 4 implements the ZIP parser (EOCD, Zip64, central directory cross-checked against
//! local headers, refcounted extent map), entry-granularity consumption by truncation in
//! descending offset order, and intra-entry hole punching driven by checkpointable inflate.
