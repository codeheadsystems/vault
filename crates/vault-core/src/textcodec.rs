//! Crockford base32, shared by the secret key and token text forms.

use zeroize::Zeroizing;

const CROCK: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Crockford base32, most significant bit first, no padding. Trailing bits that do not fill a
/// character are zero-filled on the right.
pub(crate) fn crock(b: &[u8]) -> String {
    let mut out = String::with_capacity(b.len() * 8 / 5 + 1);
    let mut acc = 0u32;
    let mut n = 0;
    for &x in b {
        acc = (acc << 8) | x as u32;
        n += 8;
        while n >= 5 {
            n -= 5;
            out.push(CROCK[((acc >> n) & 31) as usize] as char);
        }
        acc &= (1 << n) - 1;
    }
    if n > 0 {
        out.push(CROCK[((acc << (5 - n)) & 31) as usize] as char);
    }
    out
}

/// Tolerant Crockford decode of exactly `nbytes`: case-insensitive, ignores `-` and spaces, maps
/// `O` to `0` and `I` and `L` to `1`. Returns `None` on any other character or a wrong length.
/// The output is sized once and zeroized when dropped, because it holds key material.
pub(crate) fn crock_decode(s: &str, nbytes: usize) -> Option<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(nbytes + 1));
    let mut acc = 0u32;
    let mut n = 0;
    let mut chars = 0usize;
    for c in s.chars() {
        let c = match c.to_ascii_uppercase() {
            '-' | ' ' => continue,
            'O' => '0',
            'I' | 'L' => '1',
            c => c,
        };
        let v = CROCK.iter().position(|&x| x as char == c)? as u32;
        chars += 1;
        acc = (acc << 5) | v;
        n += 5;
        if n >= 8 {
            n -= 8;
            if out.len() > nbytes {
                return None;
            }
            out.push((acc >> n) as u8);
            acc &= (1 << n) - 1;
        }
    }
    (out.len() == nbytes && chars == (nbytes * 8).div_ceil(5)).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn crock_round_trip(b in proptest::collection::vec(any::<u8>(), 0..40)) {
            prop_assert_eq!(crock_decode(&crock(&b), b.len()).unwrap().to_vec(), b);
        }
    }

    #[test]
    fn known_values() {
        assert_eq!(crock(&[]), "");
        assert_eq!(crock(&[0xff]), "ZW");
        assert_eq!(crock(&[0; 5]), "00000000");
        assert_eq!(crock_decode("zw", 1).unwrap().to_vec(), vec![0xff]);
        assert_eq!(
            crock_decode("o-I l", 2),
            None,
            "three characters are 15 bits, not 16"
        );
        assert_eq!(
            crock_decode("oIl0", 2).unwrap(),
            crock_decode("0110", 2).unwrap()
        );
        assert_eq!(crock_decode("U000", 2), None, "U is not in the alphabet");
    }
}
