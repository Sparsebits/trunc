//! weightdrop: unpack sharded model weights and datasets on machines whose disk cannot hold
//! the archives and their contents at once. Each shard is consumed by trunc (its compressed
//! bytes are freed as they are decoded, crash-safe and resumable), one shard after another, so
//! the disk only ever needs room for the archives plus about one shard's worth of slack.

pub mod inputs;
pub mod plan;
pub mod run;
pub mod shards;
pub mod state;

pub use run::{Event, PlanReport, UnpackOptions, UnpackSummary, plan_set, unpack};

/// `1.50 GB`-style sizes (decimal units, as disks are sold).
pub fn fmt_bytes(n: u64) -> String {
    const UNITS: [&str; 6] = ["B", "kB", "MB", "GB", "TB", "PB"];
    if n < 1000 {
        return format!("{n} B");
    }
    let mut unit = 0;
    let mut div = 1u64;
    while unit + 1 < UNITS.len() && n / div >= 1000 {
        div *= 1000;
        unit += 1;
    }
    let whole = n / div;
    let hundredths = (n % div) / (div / 100);
    format!("{whole}.{hundredths:02} {}", UNITS[unit])
}

#[cfg(test)]
mod tests {
    use super::fmt_bytes;

    #[test]
    fn sizes() {
        assert_eq!(fmt_bytes(0), "0 B");
        assert_eq!(fmt_bytes(999), "999 B");
        assert_eq!(fmt_bytes(1500), "1.50 kB");
        assert_eq!(fmt_bytes(300_000_000_000), "300.00 GB");
        assert_eq!(fmt_bytes(u64::MAX), "18446.74 PB");
    }
}
