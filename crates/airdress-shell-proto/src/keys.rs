//! X25519 shell keys and their fingerprints.

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine as _;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Length of an X25519 key, public or secret.
pub const KEY_LEN: usize = 32;

/// A shell key pair: the Noise static key of one end, and on a device also
/// the recipient key for recordings (design §6.1).
///
/// The secret is zeroed on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ShellKeypair {
    secret: [u8; KEY_LEN],
    #[zeroize(skip)]
    public: [u8; KEY_LEN],
}

impl ShellKeypair {
    /// Draw a new key pair from `rng`.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut secret = [0u8; KEY_LEN];
        rng.fill_bytes(&mut secret);
        let kp = Self::from_secret(secret);
        secret.zeroize();
        kp
    }

    /// Rebuild a key pair from its 32-byte secret.
    pub fn from_secret(secret: [u8; KEY_LEN]) -> Self {
        let public = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(secret));
        Self {
            secret,
            public: public.to_bytes(),
        }
    }

    /// The public half.
    pub fn public(&self) -> &[u8; KEY_LEN] {
        &self.public
    }

    /// The secret half. Callers that persist it are responsible for keeping
    /// it out of plain files (D-32).
    pub fn secret(&self) -> &[u8; KEY_LEN] {
        &self.secret
    }
}

impl core::fmt::Debug for ShellKeypair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ShellKeypair")
            .field("public", &fingerprint(&self.public))
            .finish_non_exhaustive()
    }
}

/// The fingerprint a human compares (D-34): `SHA256:` followed by the
/// unpadded base64 of the SHA-256 of the raw public key, the form SSH uses.
pub fn fingerprint(public: &[u8]) -> String {
    let digest = Sha256::digest(public);
    format!("SHA256:{}", STANDARD_NO_PAD.encode(digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_ssh_shaped() {
        let fp = fingerprint(&[0u8; 32]);
        assert!(fp.starts_with("SHA256:"));
        assert_eq!(fp.len(), "SHA256:".len() + 43);
    }

    #[test]
    fn debug_does_not_print_the_secret() {
        let kp = ShellKeypair::from_secret([7u8; 32]);
        let shown = format!("{kp:?}");
        assert!(!shown.contains("secret"));
    }
}
