//! Every key and every hash in the system lives here.
//!
//! **This is the only module that holds key material**, and `iam-db` holds none —
//! which is what makes a stolen database backup useless (D72). Keeping the
//! primitives in one file also means the choices below can be reviewed together
//! rather than discovered one call site at a time.
//!
//! Four different operations on secrets, and they are deliberately NOT the same
//! primitive, because they defend against different things:
//!
//! | | primitive | why not the others |
//! | --- | --- | --- |
//! | password | Argon2id | low entropy and human-chosen, so a stolen hash is guessable — it has to be expensive |
//! | bearer token | SHA-256 | 256 bits of CSPRNG output, nothing to guess; a slow hash would cost latency on every request and buy nothing |
//! | username lookup | HMAC-SHA256 | needs to be *equal* for equal inputs, which encryption is not |
//! | name storage | AES-256-GCM | must be reversible, because a human has to read it back |
//!
//! Using Argon2id for the token, or a bare hash for the username, would each look
//! like the careful choice and be the wrong one.

use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Where the keys are mounted. A directory of files, not environment variables:
/// an env var is visible in `/proc/<pid>/environ`, in a crash dump, and in
/// `kubectl describe pod`, and it is inherited by every child process.
const KEYS_DIR: &str = "YADGAR_KEYS_DIR";

const ENCRYPTION_KEY: &str = "encryption.key";
const BLIND_INDEX_KEY: &str = "blind-index.key";

/// A password hash used only to burn time when no user matched.
///
/// Verifying against a real-looking hash is what makes "no such user" and "wrong
/// password" take the same time. Without it the endpoint enumerates accounts:
/// an unknown username returns in microseconds and a known one takes the ~50ms
/// Argon2id costs, which is trivially measurable over the network.
///
/// Generated once at boot from a random password rather than hard-coded, so this
/// is not a constant an attacker can recognise in the binary.
pub struct Keys {
    encryption: Zeroizing<[u8; 32]>,
    blind_index: Zeroizing<[u8; 32]>,
    dummy_hash: String,
}

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error(
        "{KEYS_DIR} is not set. iam holds the encryption and blind-index keys and \
         cannot start without them — every name it stores would be unreadable and \
         every login would fail to find its user. Mount the key Secret and point \
         {KEYS_DIR} at it."
    )]
    Unconfigured,

    #[error("cannot read {0}: {1}")]
    Unreadable(String, std::io::Error),

    #[error(
        "{0} is {1} bytes; a 256-bit key is 32 bytes of raw material. \
         A short key is not a weaker key here, it is a different one — so this \
         refuses rather than padding or truncating into something that silently \
         does not match what encrypted the existing rows."
    )]
    WrongLength(String, usize),

    #[error("cannot derive the timing-equalisation hash: {0}")]
    Dummy(String),
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("decryption failed — wrong key, or the ciphertext was altered")]
    Decrypt,
    #[error("encryption failed")]
    Encrypt,
    #[error("ciphertext is too short to contain its nonce")]
    Truncated,
    #[error("stored password hash is not parseable: {0}")]
    BadHash(String),
}

fn read_key(dir: &str, name: &str) -> Result<Zeroizing<[u8; 32]>, KeyError> {
    let path = format!("{dir}/{name}");
    let bytes = std::fs::read(&path).map_err(|e| KeyError::Unreadable(path.clone(), e))?;
    if bytes.len() != 32 {
        return Err(KeyError::WrongLength(path, bytes.len()));
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&bytes);
    Ok(key)
}

impl Keys {
    /// Load, or refuse to start.
    ///
    /// D69's rule for capabilities applied to key material: a service that cannot
    /// decrypt what it stored is not degraded, it is broken, and it should say so
    /// at boot rather than on the first request.
    pub fn from_env() -> Result<Self, KeyError> {
        let dir = std::env::var(KEYS_DIR)
            .ok()
            .filter(|d| !d.is_empty())
            .ok_or(KeyError::Unconfigured)?;

        let mut filler = [0u8; 32];
        OsRng.fill_bytes(&mut filler);
        let salt = SaltString::generate(&mut OsRng);
        let dummy_hash = Argon2::default()
            .hash_password(&filler, &salt)
            .map_err(|e| KeyError::Dummy(e.to_string()))?
            .to_string();

        Ok(Self {
            encryption: read_key(&dir, ENCRYPTION_KEY)?,
            blind_index: read_key(&dir, BLIND_INDEX_KEY)?,
            dummy_hash,
        })
    }

    /// Encrypt a name for storage. Randomised — the same name encrypts
    /// differently every time, which is why lookup needs [`Self::blind_index`].
    pub fn encrypt(&self, plaintext: &str) -> Result<Vec<u8>, CryptoError> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&*self.encryption));
        // A FRESH nonce per encryption. GCM's security collapses entirely if a
        // nonce repeats under the same key — not gracefully, but to the point
        // where an attacker can recover the authentication key. 96 bits from the
        // OS CSPRNG is the standard construction.
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let mut out = cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|_| CryptoError::Encrypt)?;
        // Nonce first, then ciphertext. It is not secret — it must not repeat,
        // which is a different property — and storing it alongside is what makes
        // decryption possible without a second column.
        let mut framed = nonce_bytes.to_vec();
        framed.append(&mut out);
        Ok(framed)
    }

    pub fn decrypt(&self, framed: &[u8]) -> Result<String, CryptoError> {
        if framed.len() < 12 {
            return Err(CryptoError::Truncated);
        }
        let (nonce_bytes, ciphertext) = framed.split_at(12);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&*self.encryption));
        let plain = cipher
            .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
            .map_err(|_| CryptoError::Decrypt)?;
        String::from_utf8(plain).map_err(|_| CryptoError::Decrypt)
    }

    /// The equality-searchable index for a username.
    ///
    /// A KEYED hash, not a bare one. A plain SHA-256 of a username is trivially
    /// reversible for any name worth guessing — the input space is small and
    /// public. With a key the attacker needs the key, which lives in a Secret and
    /// not in the database being attacked.
    ///
    /// A SEPARATE key from encryption, so compromising the lookup path does not
    /// decrypt the data behind it.
    pub fn blind_index(&self, username: &str) -> Vec<u8> {
        let mut mac = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(&*self.blind_index)
            .expect("HMAC accepts a 32-byte key");
        mac.update(normalise(username).as_bytes());
        mac.finalize().into_bytes().to_vec()
    }

    /// Hash a bearer token for storage and lookup.
    ///
    /// SHA-256 and not Argon2id, deliberately — see the table at the top. This
    /// runs on every credential resolve, so a deliberately slow function here
    /// would be a latency cost on the whole system in exchange for protecting
    /// something that has no entropy problem to protect.
    pub fn token_hash(token: &str) -> Vec<u8> {
        Sha256::digest(token.as_bytes()).to_vec()
    }

    /// Mint a new bearer token: 256 bits from the OS CSPRNG.
    pub fn mint_token() -> Result<Zeroizing<String>, CryptoError> {
        let mut raw = [0u8; 32];
        OsRng.fill_bytes(&mut raw);
        // URL-safe and unpadded, so it survives a header, a config file and a
        // shell copy-paste without quoting.
        Ok(Zeroizing::new(base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            raw,
        )))
    }

    pub fn hash_password(&self, password: &str) -> Result<String, CryptoError> {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(|e| CryptoError::BadHash(e.to_string()))
    }

    /// Verify a password, taking the same time whether or not the user exists.
    ///
    /// Pass `None` when no user matched. It still runs a full Argon2id
    /// verification, against the dummy hash, and then returns false — because
    /// returning early is exactly what would make the two cases distinguishable.
    pub fn verify_password(&self, stored: Option<&str>, password: &str) -> bool {
        let hash_str = stored.unwrap_or(&self.dummy_hash);
        let Ok(parsed) = PasswordHash::new(hash_str) else {
            // A corrupt stored hash must not be a fast path either.
            let _ = PasswordHash::new(&self.dummy_hash)
                .map(|d| Argon2::default().verify_password(password.as_bytes(), &d));
            return false;
        };
        let ok = Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok();
        // `stored.is_some()` is checked AFTER the work, not before it.
        ok && stored.is_some()
    }
}

/// Usernames compare case-insensitively and without surrounding whitespace.
///
/// Applied before the blind index, so `Max`, `max` and `max ` produce the same
/// index and cannot become three accounts. This has to happen here rather than
/// in the database, because the database only ever sees the finished index.
fn normalise(username: &str) -> String {
    username.trim().to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> Keys {
        Keys {
            encryption: Zeroizing::new([7u8; 32]),
            blind_index: Zeroizing::new([9u8; 32]),
            dummy_hash: Argon2::default()
                .hash_password(b"x", &SaltString::encode_b64(&[3u8; 16]).unwrap())
                .unwrap()
                .to_string(),
        }
    }

    #[test]
    fn a_name_round_trips() {
        let k = keys();
        let ct = k.encrypt("Ada Lovelace").unwrap();
        assert_eq!(k.decrypt(&ct).unwrap(), "Ada Lovelace");
    }

    #[test]
    fn the_same_name_encrypts_differently_every_time() {
        // This is the property that makes a blind index necessary. If this test
        // ever fails, encryption has become deterministic and equal names are
        // linkable in the database.
        let k = keys();
        assert_ne!(k.encrypt("ada").unwrap(), k.encrypt("ada").unwrap());
    }

    #[test]
    fn ciphertext_does_not_contain_the_plaintext() {
        let k = keys();
        let ct = k.encrypt("supersecretname").unwrap();
        assert!(!String::from_utf8_lossy(&ct).contains("supersecretname"));
    }

    #[test]
    fn altered_ciphertext_is_refused_rather_than_returning_rubbish() {
        // GCM authenticates. Without that, a flipped bit would decrypt to a
        // different name and be believed.
        let k = keys();
        let mut ct = k.encrypt("ada").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        assert!(matches!(k.decrypt(&ct), Err(CryptoError::Decrypt)));
    }

    #[test]
    fn a_different_key_cannot_decrypt() {
        let a = keys();
        let mut b = keys();
        b.encryption = Zeroizing::new([8u8; 32]);
        let ct = a.encrypt("ada").unwrap();
        assert!(b.decrypt(&ct).is_err());
    }

    #[test]
    fn the_blind_index_is_stable_and_case_insensitive() {
        let k = keys();
        assert_eq!(k.blind_index("Max"), k.blind_index("max"));
        assert_eq!(k.blind_index(" max "), k.blind_index("max"));
        assert_ne!(k.blind_index("max"), k.blind_index("maxa"));
    }

    #[test]
    fn the_blind_index_depends_on_its_key() {
        // If it did not, the index would be a plain hash of a small public input
        // space and reversible by anyone holding the database.
        let a = keys();
        let mut b = keys();
        b.blind_index = Zeroizing::new([1u8; 32]);
        assert_ne!(a.blind_index("max"), b.blind_index("max"));
    }

    #[test]
    fn a_minted_token_is_unpredictable_and_url_safe() {
        let a = Keys::mint_token().unwrap();
        let b = Keys::mint_token().unwrap();
        assert_ne!(*a, *b);
        assert!(a
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn token_hashing_is_stable_and_distinguishing() {
        assert_eq!(Keys::token_hash("abc"), Keys::token_hash("abc"));
        assert_ne!(Keys::token_hash("abc"), Keys::token_hash("abd"));
        assert_eq!(Keys::token_hash("abc").len(), 32);
    }

    #[test]
    fn a_password_verifies_against_its_own_hash_and_not_another() {
        let k = keys();
        let h = k.hash_password("correct horse").unwrap();
        assert!(k.verify_password(Some(&h), "correct horse"));
        assert!(!k.verify_password(Some(&h), "wrong horse"));
    }

    #[test]
    fn the_same_password_hashes_differently_for_two_users() {
        // Argon2id salts per password. Without it, two people choosing the same
        // password would be visibly identical in the table.
        let k = keys();
        assert_ne!(
            k.hash_password("same").unwrap(),
            k.hash_password("same").unwrap()
        );
    }

    #[test]
    fn an_absent_user_still_fails_verification_rather_than_erroring() {
        // And it does the work first — the timing equalisation the login path
        // depends on. This asserts the contract; the timing itself is not
        // something a unit test can assert reliably.
        let k = keys();
        assert!(!k.verify_password(None, "anything"));
    }
}
