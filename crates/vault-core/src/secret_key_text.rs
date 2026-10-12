//! The secret key's text form: `VLT1-` and eight groups of four Crockford base32 characters.

use crate::error::{Error, Result};
use crate::prim::sha256;
use crate::secret::{SecretKey, SecretString};
use crate::textcodec::{crock, crock_decode};
use zeroize::Zeroizing;

/// The 4-byte check value: `SHA-256("vlt/v1/secret-key-check" || secret_key)[0..4]`.
pub fn check_value(sk: &SecretKey) -> [u8; 4] {
    let h = sha256(&[b"vlt/v1/secret-key-check", sk.expose()]);
    [h[0], h[1], h[2], h[3]]
}

/// Encodes as `VLT1-XXXX-...-XXXX`.
pub fn encode(sk: &SecretKey) -> SecretString {
    let mut b = Zeroizing::new([0u8; 20]);
    b[..16].copy_from_slice(sk.expose());
    b[16..].copy_from_slice(&check_value(sk));
    let enc = Zeroizing::new(crock(b.as_ref()));
    let mut out = Zeroizing::new(String::with_capacity(44));
    out.push_str("VLT1");
    for g in enc.as_bytes().chunks(4) {
        out.push('-');
        out.push_str(core::str::from_utf8(g).expect("ASCII"));
    }
    out
}

/// Decodes, tolerating case, `-`, spaces, `O` for `0`, and `I` or `L` for `1`. A wrong check value
/// is reported as a typo before any key derivation.
pub fn decode(text: &str) -> Result<SecretKey> {
    let t = text.trim();
    let rest = t
        .get(..5)
        .filter(|p| p.eq_ignore_ascii_case("VLT1-"))
        .map(|_| &t[5..])
        .ok_or(Error::SecretKeyTypo)?;
    let b = crock_decode(rest, 20).ok_or(Error::SecretKeyTypo)?;
    let sk = SecretKey::from_slice(&b[..16]);
    // The check value only catches typos and is printed on the kit, so this need not be constant
    // time.
    if check_value(&sk) != b[16..20] {
        return Err(Error::SecretKeyTypo);
    }
    Ok(sk)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_tolerance() {
        let sk = SecretKey::from_bytes(*b"0123456789abcdef");
        let text = encode(&sk);
        assert_eq!(text.len(), 44);
        assert!(text.starts_with("VLT1-"));
        assert_eq!(decode(&text).unwrap().expose(), sk.expose());
        let loose = text
            .to_ascii_lowercase()
            .replace('-', " ")
            .replace('0', "o");
        let loose = format!("VLT1-{}", &loose[5..]);
        assert_eq!(decode(&loose).unwrap().expose(), sk.expose());
        assert_eq!(
            decode(&format!("  {}\n", text.as_str())).unwrap().expose(),
            sk.expose()
        );
    }

    #[test]
    fn spec_example_decodes() {
        // The example in spec/format.md must carry a valid check value.
        assert!(decode("VLT1-7XH6-NSCF-5P9Y-QKXJ-J745-SZYF-BEQY-C51A").is_ok());
    }

    #[test]
    fn typos_are_rejected() {
        let sk = SecretKey::from_bytes([7; 16]);
        let text = encode(&sk).to_string();
        // Change one character of the key part.
        let mut chars: Vec<char> = text.chars().collect();
        chars[6] = if chars[6] == 'A' { 'B' } else { 'A' };
        let typo: String = chars.into_iter().collect();
        assert!(matches!(decode(&typo), Err(Error::SecretKeyTypo)));
        assert!(matches!(decode(&text[..43]), Err(Error::SecretKeyTypo)));
        assert!(matches!(decode(&text[5..]), Err(Error::SecretKeyTypo)));
        assert!(matches!(
            decode(&text.replace("VLT1", "VLT2")),
            Err(Error::SecretKeyTypo)
        ));
        assert!(matches!(
            decode(&format!("{text}U")),
            Err(Error::SecretKeyTypo)
        ));
    }
}
