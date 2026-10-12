//! Randomness. The crate draws every random byte through [`Rng`], which the caller supplies: the
//! operating system CSPRNG in a client, and fixed bytes in tests and vector generation. Each
//! function that draws documents the order of its draws.

use crate::error::Result;

/// A source of random bytes.
pub trait Rng {
    /// Fills `dest` with random bytes, or returns [`crate::Error::Rng`].
    fn fill(&mut self, dest: &mut [u8]) -> Result<()>;
}

/// Draws `N` bytes for a public value (an ID, a salt, or a nonce). Secrets are drawn straight
/// into their zeroizing types instead.
pub(crate) fn draw<const N: usize>(rng: &mut dyn Rng) -> Result<[u8; N]> {
    let mut b = [0u8; N];
    rng.fill(&mut b)?;
    Ok(b)
}

/// Test RNG that serves queued bytes and panics when it runs out, so a miscounted draw in a test
/// fails loudly instead of repeating bytes.
#[cfg(test)]
pub(crate) struct BufferRng {
    bytes: Vec<u8>,
    pos: usize,
}

#[cfg(test)]
impl BufferRng {
    pub(crate) fn new(parts: &[&[u8]]) -> Self {
        BufferRng {
            bytes: parts.concat(),
            pos: 0,
        }
    }

    pub(crate) fn assert_consumed(&self) {
        assert_eq!(self.pos, self.bytes.len(), "BufferRng not fully consumed");
    }
}

#[cfg(test)]
impl Rng for BufferRng {
    fn fill(&mut self, dest: &mut [u8]) -> Result<()> {
        let end = self.pos + dest.len();
        assert!(end <= self.bytes.len(), "BufferRng exhausted");
        dest.copy_from_slice(&self.bytes[self.pos..end]);
        self.pos = end;
        Ok(())
    }
}

/// Test RNG with a counter-based stream, for tests that need many draws but no particular bytes.
#[cfg(test)]
pub(crate) struct CountingRng(pub(crate) u64);

#[cfg(test)]
impl Rng for CountingRng {
    fn fill(&mut self, dest: &mut [u8]) -> Result<()> {
        for b in dest.iter_mut() {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            *b = (self.0 >> 33) as u8;
        }
        Ok(())
    }
}
