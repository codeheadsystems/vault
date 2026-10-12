//! The server token's text form and the hash the server stores.

use crate::error::{InputKind, Result, input};
use crate::prim::sha256;
use crate::secret::{SecretString, Token};
use crate::textcodec::{crock, crock_decode};
use zeroize::Zeroizing;

/// The token's text form: `crock(token)`, 32 upper-case characters.
pub fn encode(token: &Token) -> SecretString {
    Zeroizing::new(crock(token.expose()))
}

/// Decodes a token's text form with the secret key decoder's substitutions: any case, `-` and
/// spaces ignored, `O` read as `0`, and `I` and `L` read as `1`.
pub fn decode(text: &str) -> Result<Token> {
    match crock_decode(text.trim(), 20) {
        Some(b) => Ok(Token::from_slice(&b)),
        None => input(InputKind::Token),
    }
}

/// The value the server stores for a token: the SHA-256 of its decoded bytes.
pub fn stored_hash(token: &Token) -> [u8; 32] {
    sha256(&[token.expose()])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;

    #[test]
    fn text_form_and_hash() {
        let t = Token::from_bytes([0xab; 20]);
        let text = encode(&t);
        assert_eq!(text.len(), 32);
        assert!(
            text.bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        );
        assert_eq!(decode(&text).unwrap().expose(), t.expose());
        assert_eq!(
            decode(&text.to_ascii_lowercase()).unwrap().expose(),
            t.expose()
        );
        assert_eq!(
            hex::encode(stored_hash(&t)),
            hex::encode(sha256(&[&[0xab; 20]]))
        );
    }

    #[test]
    fn substitutions_match_the_secret_key_decoder() {
        let t = Token::from_bytes([0; 20]);
        assert_eq!(encode(&t).as_str(), "00000000000000000000000000000000");
        let typed = "oooo-OOOO 0000 0000 0000 0000 0000 0000";
        assert_eq!(decode(typed).unwrap().expose(), &[0; 20]);
        let ones = decode("11111111111111111111111111111111").unwrap();
        assert_eq!(
            decode("iiiiiiiiiiiiiiiiLLLLLLLLllllllll").unwrap().expose(),
            ones.expose()
        );
    }

    #[test]
    fn wrong_shapes_are_rejected() {
        assert_eq!(
            decode("0000").err(),
            Some(Error::InvalidInput(InputKind::Token))
        );
        assert_eq!(
            decode(&"0".repeat(33)).err(),
            Some(Error::InvalidInput(InputKind::Token))
        );
        assert_eq!(
            decode(&"U".repeat(32)).err(),
            Some(Error::InvalidInput(InputKind::Token))
        );
    }
}
