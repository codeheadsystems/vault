//! The password generator (CORE-3): random characters from chosen classes, optionally without
//! ambiguous characters, or passphrases of words from the BIP-39 English list. Every choice comes
//! from the caller's generator through rejection sampling, so each is uniform and free of modulo
//! bias.

use crate::error::{InputKind, Result, input};
use crate::rng::Rng;
use zeroize::Zeroizing;

/// Upper-case letters.
pub const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
/// Lower-case letters.
pub const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
/// Digits.
pub const DIGITS: &str = "0123456789";
/// Printable ASCII punctuation, without the space.
pub const SYMBOLS: &str = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
/// The characters left out when ambiguous characters are excluded, as in Bitwarden.
pub const AMBIGUOUS: &str = "IOl01";

/// The shortest character password the generator makes.
pub const MIN_LENGTH: usize = 8;
/// The longest character password the generator makes.
pub const MAX_LENGTH: usize = 256;
/// The default character password length.
pub const DEFAULT_LENGTH: usize = 25;
/// The fewest passphrase words.
pub const MIN_WORDS: usize = 4;
/// The most passphrase words.
pub const MAX_WORDS: usize = 64;
/// The default passphrase length: 77 bits.
pub const DEFAULT_WORDS: usize = 7;

const WORDLIST: &str = include_str!("wordlist/bip39-english.txt");
/// Words in the list.
pub const WORDLIST_LEN: usize = 2048;

/// Which characters a password draws from. Every selected class appears at least once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Classes {
    /// `A` to `Z`.
    pub upper: bool,
    /// `a` to `z`.
    pub lower: bool,
    /// `0` to `9`.
    pub digits: bool,
    /// [`SYMBOLS`].
    pub symbols: bool,
    /// Leave out [`AMBIGUOUS`].
    pub avoid_ambiguous: bool,
}

impl Default for Classes {
    /// Every class, ambiguous characters included.
    fn default() -> Self {
        Classes {
            upper: true,
            lower: true,
            digits: true,
            symbols: true,
            avoid_ambiguous: false,
        }
    }
}

impl Classes {
    fn sets(&self) -> Vec<Vec<u8>> {
        [
            (self.upper, UPPER),
            (self.lower, LOWER),
            (self.digits, DIGITS),
            (self.symbols, SYMBOLS),
        ]
        .into_iter()
        .filter(|(on, _)| *on)
        .map(|(_, set)| {
            set.bytes()
                .filter(|b| !(self.avoid_ambiguous && AMBIGUOUS.as_bytes().contains(b)))
                .collect()
        })
        .collect()
    }
}

/// A uniform index below `n`, by rejection sampling on 32-bit draws.
fn uniform(rng: &mut dyn Rng, n: usize) -> Result<usize> {
    debug_assert!(n > 0 && n <= u32::MAX as usize);
    let n = n as u64;
    let zone = (1u64 << 32) - ((1u64 << 32) % n);
    loop {
        let mut b = Zeroizing::new([0u8; 4]);
        rng.fill(b.as_mut())?;
        let v = u64::from(u32::from_le_bytes(*b));
        if v < zone {
            return Ok((v % n) as usize);
        }
    }
}

fn check_length(length: usize, classes: &Classes) -> Result<Vec<Vec<u8>>> {
    let sets = classes.sets();
    if sets.is_empty() || !(MIN_LENGTH..=MAX_LENGTH).contains(&length) {
        return input(InputKind::Generator);
    }
    Ok(sets)
}

/// A random password of `length` characters from `classes`, with at least one character of each
/// selected class. Draws 4 bytes per character, and more on rejection.
pub fn password(rng: &mut dyn Rng, length: usize, classes: &Classes) -> Result<Zeroizing<String>> {
    let sets = check_length(length, classes)?;
    let alphabet: Vec<u8> = sets.concat();
    // Drawing whole passwords until every class appears keeps the result uniform over the
    // passwords that satisfy the rule.
    loop {
        let mut out = Zeroizing::new(String::with_capacity(length));
        for _ in 0..length {
            out.push(alphabet[uniform(rng, alphabet.len())?] as char);
        }
        if sets.iter().all(|s| out.bytes().any(|b| s.contains(&b))) {
            return Ok(out);
        }
    }
}

fn word(i: usize) -> &'static str {
    WORDLIST.lines().nth(i).unwrap_or_default()
}

/// A passphrase of `words` words from the BIP-39 English list, joined by `separator`. Draws
/// 4 bytes per word, and more on rejection.
pub fn passphrase(rng: &mut dyn Rng, words: usize, separator: &str) -> Result<Zeroizing<String>> {
    if !(MIN_WORDS..=MAX_WORDS).contains(&words) || separator.contains(['\n', '\r']) {
        return input(InputKind::Generator);
    }
    let mut out = Zeroizing::new(String::new());
    for n in 0..words {
        if n > 0 {
            out.push_str(separator);
        }
        out.push_str(word(uniform(rng, WORDLIST_LEN)?));
    }
    Ok(out)
}

/// The entropy of [`password`] in bits: the base-2 logarithm of the number of passwords that
/// contain every selected class, by inclusion and exclusion over the classes left out.
pub fn password_bits(length: usize, classes: &Classes) -> Result<f64> {
    let sets = check_length(length, classes)?;
    let n: usize = sets.iter().map(Vec::len).sum();
    let l = length as i32;
    let mut fraction = 0.0f64;
    for mask in 0u32..(1 << sets.len()) {
        let missing: usize = (0..sets.len())
            .filter(|i| mask & (1 << i) != 0)
            .map(|i| sets[i].len())
            .sum();
        let term = ((n - missing) as f64 / n as f64).powi(l);
        if mask.count_ones() % 2 == 0 {
            fraction += term;
        } else {
            fraction -= term;
        }
    }
    Ok(length as f64 * (n as f64).log2() + fraction.log2())
}

/// The entropy of [`passphrase`] in bits: 11 per word.
pub fn passphrase_bits(words: usize) -> f64 {
    words as f64 * (WORDLIST_LEN as f64).log2()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;
    use crate::rng::{BufferRng, CountingRng};
    use proptest::prelude::*;

    #[test]
    fn wordlist_shape() {
        let words: Vec<&str> = WORDLIST.lines().collect();
        assert_eq!(words.len(), WORDLIST_LEN);
        let mut sorted = words.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), WORDLIST_LEN, "unique");
        assert!(
            words
                .iter()
                .all(|w| !w.is_empty() && w.bytes().all(|b| b.is_ascii_lowercase()))
        );
        assert_eq!((word(0), word(2047)), ("abandon", "zoo"));
    }

    #[test]
    fn symbols_are_printable_punctuation() {
        assert_eq!(SYMBOLS.len(), 32);
        assert!(SYMBOLS.bytes().all(|b| b.is_ascii_punctuation()));
    }

    #[test]
    fn rejects_bad_shapes() {
        let none = Classes {
            upper: false,
            lower: false,
            digits: false,
            symbols: false,
            avoid_ambiguous: false,
        };
        let bad = Err(Error::InvalidInput(InputKind::Generator));
        let rng = &mut CountingRng(1);
        assert_eq!(password(rng, 25, &none).map(|_| ()), bad);
        assert_eq!(password(rng, 7, &Classes::default()).map(|_| ()), bad);
        assert_eq!(password(rng, 257, &Classes::default()).map(|_| ()), bad);
        assert_eq!(passphrase(rng, 3, "-").map(|_| ()), bad);
        assert_eq!(passphrase(rng, 65, "-").map(|_| ()), bad);
        assert_eq!(passphrase(rng, 7, "\n").map(|_| ()), bad);
    }

    #[test]
    fn uniform_rejects_the_biased_tail() {
        // n = 3: 2^32 % 3 = 1, so only u32::MAX is rejected.
        let mut rng = BufferRng::new(&[&u32::MAX.to_le_bytes(), &5u32.to_le_bytes()]);
        assert_eq!(uniform(&mut rng, 3).unwrap(), 2);
        rng.assert_consumed();
    }

    #[test]
    fn known_draws() {
        // Index 0 of the 94-character alphabet is 'A'; 26 is 'a'; 52 is '0'; 62 is '!'.
        let draws: Vec<[u8; 4]> = [0u32, 26, 52, 62, 0, 0, 0, 0]
            .iter()
            .map(|v| v.to_le_bytes())
            .collect();
        let parts: Vec<&[u8]> = draws.iter().map(|d| &d[..]).collect();
        let mut rng = BufferRng::new(&parts);
        let p = password(&mut rng, 8, &Classes::default()).unwrap();
        assert_eq!(p.as_str(), "Aa0!AAAA");
        rng.assert_consumed();
        let mut rng = BufferRng::new(&[
            &0u32.to_le_bytes(),
            &2047u32.to_le_bytes(),
            &1u32.to_le_bytes(),
            &2u32.to_le_bytes(),
        ]);
        let w = passphrase(&mut rng, 4, " ").unwrap();
        assert_eq!(w.as_str(), "abandon zoo ability able");
        rng.assert_consumed();
    }

    #[test]
    fn ambiguous_characters_are_left_out() {
        let c = Classes {
            avoid_ambiguous: true,
            ..Classes::default()
        };
        assert_eq!(c.sets().iter().map(Vec::len).sum::<usize>(), 94 - 5);
        let rng = &mut CountingRng(3);
        for _ in 0..200 {
            let p = password(rng, 64, &c).unwrap();
            assert!(!p.bytes().any(|b| AMBIGUOUS.as_bytes().contains(&b)));
        }
    }

    #[test]
    fn entropy() {
        let only_lower = Classes {
            upper: false,
            lower: true,
            digits: false,
            symbols: false,
            avoid_ambiguous: false,
        };
        let b = password_bits(10, &only_lower).unwrap();
        assert!((b - 10.0 * 26f64.log2()).abs() < 1e-9);
        let b = password_bits(
            10,
            &Classes {
                avoid_ambiguous: true,
                ..only_lower
            },
        )
        .unwrap();
        assert!((b - 10.0 * 25f64.log2()).abs() < 1e-9);
        let full = password_bits(25, &Classes::default()).unwrap();
        let naive = 25.0 * 94f64.log2();
        assert!(full < naive && full > naive - 0.5, "{full}");
        assert!((passphrase_bits(7) - 77.0).abs() < 1e-9);
    }

    proptest! {
        #[test]
        fn passwords_cover_every_selected_class(
            seed: u64,
            length in MIN_LENGTH..=64usize,
            upper: bool, lower: bool, digits: bool, symbols: bool,
        ) {
            let c = Classes { upper, lower, digits, symbols, avoid_ambiguous: false };
            prop_assume!(upper || lower || digits || symbols);
            let p = password(&mut CountingRng(seed), length, &c).unwrap();
            prop_assert_eq!(p.len(), length);
            for (on, set) in [(upper, UPPER), (lower, LOWER), (digits, DIGITS), (symbols, SYMBOLS)] {
                let present = p.bytes().any(|b| set.as_bytes().contains(&b));
                prop_assert_eq!(present, on);
            }
        }

        #[test]
        fn passphrases_are_list_words(seed: u64, words in MIN_WORDS..=12usize) {
            let p = passphrase(&mut CountingRng(seed), words, "-").unwrap();
            let parts: Vec<&str> = p.split('-').collect();
            prop_assert_eq!(parts.len(), words);
            for w in parts {
                prop_assert!(WORDLIST.lines().any(|l| l == w));
            }
        }
    }
}
