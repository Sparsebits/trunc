//! The seam between the trunc engine and product variants.
//!
//! Phase 7 defines `InputSource`, `OutputSink` and `Heuristics` here. The core ships a plain
//! filesystem source/sink; variants (VM disk images, ML weights) add their own without changing
//! the engine.
