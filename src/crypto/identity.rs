//! WHICH key set this process holds, as bytes that are safe to store beside the
//! rows it encrypted (ADR-0764, ADR-0765).
//!
//! **A SUBMODULE OF [`super`] RATHER THAN A FILE IN `key_identity`, AND THAT IS
//! THE WHOLE OF ITS PLACEMENT ARGUMENT.** `crypto.rs` opens by saying it is the
//! only module that holds key material. Deriving the marker anywhere else would
//! mean widening `Keys`'s private fields to `pub(crate)` so another module could
//! read them — a permanent loosening of that boundary, bought for one function.
//! A child module already sees them, so nothing widens. `crypto.rs` is also at
//! the 500-line ceiling the `complexity` gate enforces, which is why this is a
//! file and not eleven more lines there.
//!
//! # The derivation, and it is frozen
//!
//! ```text
//! fingerprint = SHA-256( HMAC-SHA256(encryption_key,  domain)
//!                     || HMAC-SHA256(blind_index_key, domain) )
//! ```
//!
//! **BOTH KEYS, because the key SET is what the marker names.** A pod holding
//! the right encryption key and the wrong blind-index key decrypts every name it
//! reads and finds nobody it looks up — a silent, total authentication failure
//! that a fingerprint over the encryption key alone would certify as healthy.
//! `the_fingerprint_covers_both_keys_and_the_domain_names_the_version` is the
//! assertion that reddens if either input is dropped.
//!
//! **HMAC RATHER THAN A BARE HASH OF THE KEY**, which is the estate's existing
//! choice for the same shape: [`super::Keys::blind_index`] keys its hash for the
//! reason stated there, and one primitive used one way is easier to review than
//! two. The domain string is what stops this value colliding with a blind index
//! or a token hash computed from the same material.
//!
//! **SHA-256 OVER THE TWO TAGS rather than the two tags concatenated**, so the
//! stored marker is a fixed 32 bytes and holds no per-key component an attacker
//! could attack in isolation. 32 bytes is well inside `iam-db`'s
//! `VARBINARY(255)`, whose overflow that service refuses with INVALID_ARGUMENT.
//!
//! **NEVER THE KEY, AND ONE-WAY.** HMAC-SHA256 under the key is a PRF, so a
//! stolen backup of `iam-db` yields nothing that decrypts a row — the rule the
//! token hash and the blind index already follow, and the rule that lets the
//! marker live in the database the keys deliberately do not.
//!
//! **CHANGING ANY OF IT IS A MIGRATION AND NOT A RELEASE.** A different domain
//! string, a third input, another primitive: each is an ordinary maintenance
//! change and each makes every pod in every installation read
//! `DERIVATION_SKEW` and never pass. Bump [`crate::key_identity::DERIVATION_VERSION`],
//! change [`crate::key_identity::DOMAIN`] with it, and rewrite every
//! installation's stored marker on purpose.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use super::Keys;

impl Keys {
    /// The opaque bytes `iamdb.v1`'s key-identity arm stores and compares.
    ///
    /// `domain` is [`crate::key_identity::DOMAIN`] and carries the derivation
    /// version; it is a parameter rather than a constant here so the version and
    /// the scheme stay declared in one place, beside the check that sends them.
    pub fn key_identity_fingerprint(&self, domain: &str) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(tag(&self.encryption, domain));
        hasher.update(tag(&self.blind_index, domain));
        hasher.finalize().to_vec()
    }
}

/// One key's contribution: a PRF evaluation of the domain string under it.
fn tag(key: &[u8; 32], domain: &str) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(key)
        .expect("HMAC accepts a 32-byte key");
    mac.update(domain.as_bytes());
    mac.finalize().into_bytes().to_vec()
}
