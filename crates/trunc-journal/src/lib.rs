//! Append-only write-ahead journal (`<archive>.trncj`).
//!
//! Phase 4.2 implements two alternating 4 KiB superblocks followed by CRC32C-framed records, as
//! specified in `docs/spec/journal-v1.md`. The native format needs it only for the final
//! staging-to-destination rename phase and for space-exhaustion pauses; legacy ZIP consumption
//! records every state transition in it.
