//! Shannon entropy over a byte slice. Result is in bits/byte, range [0.0, 8.0].

pub fn shannon(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    let mut h = 0.0f64;
    for &c in counts.iter() {
        if c == 0 {
            continue;
        }
        let p = c as f64 / len;
        h -= p * p.log2();
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_zero() {
        assert_eq!(shannon(&[]), 0.0);
    }

    #[test]
    fn uniform_byte_is_zero() {
        assert_eq!(shannon(&[0x41; 1024]), 0.0);
    }

    #[test]
    fn fully_uniform_distribution_is_eight() {
        let bytes: Vec<u8> = (0..=255u8).cycle().take(256 * 16).collect();
        let h = shannon(&bytes);
        assert!((h - 8.0).abs() < 1e-9, "expected ~8.0, got {h}");
    }

    #[test]
    fn realistic_text_is_mid_range() {
        let lorem = b"the quick brown fox jumps over the lazy dog ".repeat(32);
        let h = shannon(&lorem);
        assert!(h > 3.5 && h < 5.0, "expected mid-range, got {h}");
    }
}
