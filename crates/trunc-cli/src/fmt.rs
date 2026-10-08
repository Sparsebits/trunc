//! Human-readable sizes.

/// Format a byte count with binary units.
pub fn bytes(n: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    format!("{v:.2} {}", UNITS[u])
}

/// Parse sizes like `4096`, `64K`, `8M`, `1G` (binary multiples; optional trailing `B`/`iB`).
pub fn parse_size(s: &str) -> Result<u64, String> {
    let t = s.trim();
    let t = t
        .strip_suffix("iB")
        .or_else(|| t.strip_suffix('B'))
        .unwrap_or(t);
    let (num, mult) = match t.char_indices().last() {
        Some((i, c)) if c.is_ascii_alphabetic() => {
            let m = match c.to_ascii_uppercase() {
                'K' => 1u64 << 10,
                'M' => 1 << 20,
                'G' => 1 << 30,
                'T' => 1 << 40,
                _ => return Err(format!("unknown size suffix in {s:?}")),
            };
            (&t[..i], m)
        }
        _ => (t, 1),
    };
    let v: u64 = num
        .trim()
        .parse()
        .map_err(|_| format!("invalid size {s:?}"))?;
    v.checked_mul(mult)
        .ok_or_else(|| format!("size {s:?} overflows"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes() {
        assert_eq!(parse_size("4096"), Ok(4096));
        assert_eq!(parse_size("64K"), Ok(64 << 10));
        assert_eq!(parse_size("8M"), Ok(8 << 20));
        assert_eq!(parse_size("8MiB"), Ok(8 << 20));
        assert_eq!(parse_size("1g"), Ok(1 << 30));
        assert!(parse_size("8X").is_err());
        assert!(parse_size("").is_err());
        assert_eq!(bytes(512), "512 B");
        assert_eq!(bytes(8 << 20), "8.00 MiB");
    }
}
