//! Secret types. Each holds its bytes in a zeroizing buffer and implements neither `Debug` nor
//! `Display`, so a secret cannot reach a log or panic message through formatting.
//!
//! ```compile_fail
//! let k = vault_core::secret::VaultKey::from_bytes([0u8; 32]);
//! let _ = format!("{:?}", k);
//! ```
//!
//! ```compile_fail
//! let k = vault_core::secret::VaultKey::from_bytes([0u8; 32]);
//! let _ = format!("{}", k);
//! ```
//!
//! ```compile_fail
//! let k = vault_core::secret::SecretKey::from_bytes([0u8; 16]);
//! let _ = format!("{:?}", k);
//! ```
//!
//! ```compile_fail
//! let k = vault_core::secret::Kek::from_bytes([0u8; 32]);
//! let _ = format!("{:?}", k);
//! ```
//!
//! ```compile_fail
//! let k = vault_core::secret::BodyKey::from_bytes([0u8; 32]);
//! let _ = format!("{:?}", k);
//! ```
//!
//! ```compile_fail
//! let k = vault_core::secret::Token::from_bytes([0u8; 20]);
//! let _ = format!("{:?}", k);
//! ```

use crate::error::Result;
use crate::rng::Rng;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

macro_rules! secret_array {
    ($(#[$m:meta])* $name:ident, $n:expr) => {
        $(#[$m])*
        #[derive(Zeroize, ZeroizeOnDrop)]
        pub struct $name([u8; $n]);

        impl $name {
            /// Wraps raw bytes. The argument is the caller's copy, which the caller zeroizes.
            pub fn from_bytes(b: [u8; $n]) -> Self {
                $name(b)
            }

            /// Draws fresh bytes from `rng` straight into the new value, so no other copy exists.
            pub fn generate(rng: &mut dyn Rng) -> Result<Self> {
                let mut s = $name([0u8; $n]);
                rng.fill(&mut s.0)?;
                Ok(s)
            }

            /// Copies exactly the bytes of `b` into a new value without an intermediate array.
            #[allow(dead_code, reason = "generated for every secret type")]
            pub(crate) fn from_slice(b: &[u8]) -> Self {
                let mut s = $name([0u8; $n]);
                s.0.copy_from_slice(b);
                s
            }

            /// The raw bytes, for a caller that stores or caches them.
            pub fn expose(&self) -> &[u8; $n] {
                &self.0
            }

            /// Takes bytes from a zeroizing buffer without leaving an unzeroized copy.
            #[allow(dead_code, reason = "generated for every secret type")]
            pub(crate) fn from_zeroizing(z: Zeroizing<[u8; $n]>) -> Self {
                let mut s = $name([0u8; $n]);
                s.0.copy_from_slice(z.as_ref());
                s
            }

            /// A second copy, explicit so that copies of secrets stay visible in the code.
            pub fn clone_secret(&self) -> Self {
                $name(self.0)
            }
        }
    };
}

secret_array!(
    /// The 16-byte **secret key**, held by every client and printed in the emergency kit.
    SecretKey, 16
);
secret_array!(
    /// The 32-byte vault key (VK), replaced by every credential change.
    VaultKey, 32
);
secret_array!(
    /// The key-encryption key (KEK), derived from the master password and the secret key.
    Kek, 32
);
secret_array!(
    /// `K_body`, derived from the vault key.
    BodyKey, 32
);
secret_array!(
    /// A 20-byte server token.
    Token, 20
);

/// A secret string, such as a master password or a generated password.
pub type SecretString = Zeroizing<String>;
