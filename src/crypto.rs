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

// Count one Argon2id verification THAT ACTUALLY COMPUTED SOMETHING.
//
// THE TIMING EQUALISATION IS INVISIBLE TO AN ORDINARY ASSERTION. A test that only
// checks the ANSWER of `verify_password(None, …)` passes with the dummy hash, its
// generation and `KeyError::Dummy` all deleted — the answer is `false` either
// way. Counting the verifications measures the property itself, and does it
// deterministically rather than by reading a clock.
//
// COUNTED INSIDE THE LIBRARY'S HASHING CALL, and not on entry to `verify_counted`
// — see [`CountingArgon2`]. Counting on entry made this read "one verification"
// for calls that touched not one block of memory: the instrument every test below
// leans on, reporting control flow while claiming to report cost. That is
// precisely the mistake this module exists to catch, committed inside the thing
// that catches it.
//
// A THREAD-LOCAL, because the test binary runs tests in parallel in one process
// and a global counter would make each test's reading depend on which others
// happened to be running.
#[cfg(test)]
thread_local! {
    static ARGON2_VERIFICATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn argon2_verifications() -> usize {
    ARGON2_VERIFICATIONS.with(std::cell::Cell::get)
}

/// An `Argon2` that counts at the moment the hashing actually starts.
///
/// THE COUNTER HAS TO BE INDEPENDENT OF THE CODE IT MEASURES, and putting it
/// anywhere in `verify_counted` is not. `verify_counted` decides which hashes are
/// usable; if the counter were derived from that same decision, then a mutation to
/// the decision would move the counter with it and the tests would go on reading
/// "one verification" while nothing was computed — the exact failure this file is
/// fixing, reintroduced one level up.
///
/// `password_hash`'s blanket `PasswordVerifier` impl reaches
/// `hash_password_customized` ONLY once it has committed to hashing: past its
/// `(Some(salt), Some(expected_output))` gate and past `Params::try_from`. So an
/// increment here means the memory really is about to be filled, whatever
/// `verify_counted` believes.
#[cfg(test)]
struct CountingArgon2(Argon2<'static>);

#[cfg(test)]
impl PasswordHasher for CountingArgon2 {
    type Params = argon2::Params;

    fn hash_password_customized<'a>(
        &self,
        password: &[u8],
        algorithm: Option<argon2::password_hash::Ident<'a>>,
        version: Option<argon2::password_hash::Decimal>,
        params: Self::Params,
        salt: impl Into<argon2::password_hash::Salt<'a>>,
    ) -> argon2::password_hash::Result<PasswordHash<'a>> {
        ARGON2_VERIFICATIONS.with(|c| c.set(c.get() + 1));
        self.0
            .hash_password_customized(password, algorithm, version, params, salt)
    }
}

/// Verify once against `parsed`, and record it if the Argon2 work happened.
///
/// `Some(verdict)` means a full Argon2id computation ran and this is its answer.
/// `None` means THE VERIFIER REFUSED THE HASH WITHOUT COMPUTING ANYTHING, and the
/// caller therefore still owes the equalisation a real verification.
///
/// `None` is not hypothetical. `password_hash`'s blanket `PasswordVerifier` impl
/// computes nothing in two cases that a CLEANLY PARSED PHC string reaches, so
/// neither is caught by `PasswordHash::new` failing:
///
/// - no digest, or no salt — the impl is gated on
///   `if let (Some(salt), Some(expected_output)) = (&hash.salt, &hash.hash)` and
///   otherwise falls straight through to `Err(Error::Password)`, the very error a
///   wrong password gets;
/// - a parameter string `Params::try_from` rejects — `m=8,t=1,p=2` is legal PHC
///   and not a legal Argon2 configuration (`m >= 8 * p`), so the `?` returns
///   before the first block of memory is touched.
///
/// Both answer in MICROSECONDS — measured at 511ns to 2.4µs, release build —
/// against the ~12ms a real verification costs there, and
/// that gap is the whole oracle. Telling them apart is why this returns the
/// verdict rather than a bare bool: `Error::Password` is ambiguous ON ITS OWN —
/// a wrong password and the ungated fall-through both return it — and stops being
/// ambiguous only once the digest is known present, which is checked first.
///
/// Compiles to the bare verification outside tests — the counting wrapper exists
/// only under `cfg(test)` and costs nothing in a deployed binary.
fn verify_counted(password: &str, parsed: &PasswordHash<'_>) -> Option<bool> {
    // The library's gate, restated. With no digest there is nothing to compare a
    // computation against, so it does not perform one.
    if parsed.salt.is_none() || parsed.hash.is_none() {
        return None;
    }

    // `Argon2::default()` here sets NOTHING about what this costs: the cost comes
    // from `parsed`, whose parameters `password_hash` reads back out of the PHC
    // string. Which is why both hashes have to be minted by `hash_secret`.
    #[cfg(test)]
    let hasher = CountingArgon2(Argon2::default());
    #[cfg(not(test))]
    let hasher = Argon2::default();

    match hasher.verify_password(password.as_bytes(), parsed) {
        // The digest is present, so both of these are the answer to a real
        // computation rather than a refusal wearing the same error.
        Ok(()) => Some(true),
        Err(argon2::password_hash::Error::Password) => Some(false),
        // An unusable parameter set, a mismatched algorithm: refused BEFORE any
        // hashing, and so not a verification at all.
        Err(_) => None,
    }
}

/// The ONE place a password becomes a PHC string, and so the one place Argon2id
/// is configured.
///
/// Both the stored hash and the dummy hash go through here, and that is the
/// whole point. `verify_password` takes its cost parameters from the PHC STRING
/// it is verifying — `password_hash` rebuilds them with `Params::try_from(hash)`
/// — and NOT from the `Argon2` doing the verifying. Two independently chosen
/// parameter sets would therefore make the absent path cheaper or dearer than
/// the present one, reopening the enumeration oracle this module exists to
/// close, in silence, under a change as ordinary as tuning the cost. One
/// function means tuning it moves both hashes together.
///
/// TUNING THE COST HERE IS NOT A SELF-CONTAINED CHANGE. One function moves both
/// hashes together only from that moment ON; every row written before the tune
/// keeps its old cost, and no rehash can move it without the plaintext. That
/// residual, and the response-time floor that is the only thing which closes it,
/// are worked through at [`Keys::verify_password`]. Read that note BEFORE
/// changing the parameters below — the floor belongs in the same change.
fn hash_secret(secret: &[u8]) -> Result<String, argon2::password_hash::Error> {
    // A fresh salt per hash, so two people choosing the same password are not
    // visibly identical in the table.
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(secret, &salt)
        .map(|h| h.to_string())
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
        Self::from_dir(&dir)
    }

    /// Everything [`Self::from_env`] does except read the environment.
    ///
    /// The split exists so the dummy hash can be asserted on. `from_env` reads a
    /// process-wide variable, which no test can set without racing every other
    /// test in the binary, so the construction that mints `dummy_hash` had no
    /// test at all — and that hash is one half of the timing equalisation.
    fn from_dir(dir: &str) -> Result<Self, KeyError> {
        let mut filler = [0u8; 32];
        OsRng.fill_bytes(&mut filler);
        let dummy_hash = hash_secret(&filler).map_err(|e| KeyError::Dummy(e.to_string()))?;

        Ok(Self {
            encryption: read_key(dir, ENCRYPTION_KEY)?,
            blind_index: read_key(dir, BLIND_INDEX_KEY)?,
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

    /// Hash a password for storage.
    ///
    /// Through [`hash_secret`], and the dummy hash is too — see the note there
    /// for why the two must not be configured separately.
    pub fn hash_password(&self, password: &str) -> Result<String, CryptoError> {
        hash_secret(password.as_bytes()).map_err(|e| CryptoError::BadHash(e.to_string()))
    }

    /// Verify a password, taking the same time whether or not the user exists.
    ///
    /// Pass `None` when no user matched. It still runs a full Argon2id
    /// verification, against the dummy hash, and then returns false — because
    /// returning early is exactly what would make the two cases distinguishable.
    ///
    /// PARSING IS NOT ENOUGH TO KNOW THE WORK HAPPENED, which is what the `None`
    /// arm below is for: a PHC string can parse cleanly and still be refused by
    /// the verifier before it hashes anything. See [`verify_counted`].
    ///
    /// # The residual this does NOT close, and why there is no time floor
    ///
    /// Everything here equalises by making both paths verify a hash with the SAME
    /// PARAMETERS. That holds only while every stored hash shares the dummy's
    /// parameters, and one event breaks it permanently: A GENUINE COST TUNE. The
    /// dummy is minted fresh at boot, so it moves the moment `hash_secret`
    /// changes; rows written before the tune keep the old cost forever. Their
    /// logins then run measurably faster than an unknown username's, and the
    /// oracle is open again for exactly the accounts that are oldest.
    ///
    /// IT CANNOT BE CLOSED BY REHASHING. A password hash cannot be re-derived to
    /// new parameters without the plaintext, so the usual "rehash them at next
    /// login" answer only ever applies to people who log in — and, today, to
    /// nobody: [`Self::hash_password`] has no production caller, `iam` exposes no
    /// `SetPassword`, and `CreateUser` takes no password. The same divergence
    /// reaches a row directly, without any tune at all, because `iam-db`'s
    /// `SetPassword` writes a caller-supplied string verbatim: a stored hash at
    /// `m=8,t=1,p=1` does real Argon2 work and still returns in ~16µs, against
    /// the ~12ms a default-cost hash takes in the same release build.
    ///
    /// The only defence that generalises is A FIXED RESPONSE-TIME FLOOR on the
    /// `Login` RPC — sleep until a constant deadline on every path, so the
    /// response time stops being a function of the work done. It is deliberately
    /// NOT built here:
    ///
    /// - the floor has to exceed the SLOWEST legitimate verification, and one set
    ///   below the true worst case does not close the oracle, it clips it. That
    ///   number is a measurement on the deployment target, which does not exist
    ///   yet, and a guess would buy latency on every login for a property it does
    ///   not actually deliver;
    /// - `Login` already spends a network round trip at `iam-db` before reaching
    ///   here, and a second one when it succeeds. That variance is larger than
    ///   the Argon2 delta a floor would be hiding, so the floor has to cover the
    ///   whole handler, error paths included, or it becomes an oracle of its own;
    /// - the divergence it defends against does not exist yet. Both hashes are
    ///   minted by one `hash_secret` today, and there has been no tune.
    ///
    /// So: build the floor AT THE MOMENT A PARAMETER TUNE IS PROPOSED, and treat
    /// it as part of that change rather than as a separate improvement. This note
    /// is here so the next reader finds the analysis instead of re-deriving it.
    pub fn verify_password(&self, stored: Option<&str>, password: &str) -> bool {
        let hash_str = stored.unwrap_or(&self.dummy_hash);
        let verdict = PasswordHash::new(hash_str)
            .ok()
            .and_then(|parsed| verify_counted(password, &parsed));

        let Some(ok) = verdict else {
            // NOTHING WAS COMPUTED ABOVE — the stored value did not parse, or it
            // parsed into something the verifier refuses before hashing. Either
            // way this branch has so far cost microseconds, and returning here
            // would hand back the fast answer for a username that EXISTS. Buy the
            // time honestly instead, against a hash that is known good.
            let _ = PasswordHash::new(&self.dummy_hash).map(|d| verify_counted(password, &d));
            return false;
        };
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
pub(crate) mod tests;
