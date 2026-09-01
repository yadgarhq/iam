//! Unit tests for [`super`], in their own file.
//!
//! A submodule rather than a `#[cfg(test)]` block at the foot of `crypto.rs`,
//! because the module is at the file-size ceiling and a test module is the seam
//! that already exists. Still a UNIT test module — it reaches the private
//! `read_key`, the private `Keys` fields, and the `cfg(test)` verification
//! counter, none of which an integration test can see.

use super::*;

pub(crate) fn keys() -> Keys {
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

// ---------------------------------------------------------------------------
// The timing equalisation, asserted rather than described.
// ---------------------------------------------------------------------------

#[test]
fn an_absent_user_fails_even_when_the_password_matches_the_dummy() {
    // "x" DELIBERATELY, and not "anything": the fixture's dummy_hash is the hash
    // of "x", so this is the one input for which the Argon2 verification against
    // the dummy SUCCEEDS. `stored.is_some()` is the only thing turning that into
    // `false`.
    //
    // MUTATION THIS CATCHES: drop `&& stored.is_some()` from `verify_password`
    // and this returns true — which is an unknown username authenticating as
    // user_id "". With any other password the verification fails on its own and
    // the assertion passes with the check deleted, which is exactly how the
    // previous version of this test asserted nothing.
    let k = keys();
    assert!(!k.verify_password(None, "x"));
}

#[test]
fn the_absent_path_costs_the_same_argon2_work_as_the_present_path() {
    // MUTATION THIS CATCHES: `let Some(h) = stored else { return false };` — the
    // early return that makes an unknown username answer in microseconds while a
    // known one takes the ~50ms Argon2id costs. The whole dummy_hash field, its
    // generation and KeyError::Dummy can be deleted under that mutation and every
    // other test in this file still passes.
    let k = keys();
    let h = k.hash_password("correct horse").unwrap();

    let before = argon2_verifications();
    let _ = k.verify_password(Some(&h), "correct horse");
    let present = argon2_verifications() - before;

    let before = argon2_verifications();
    let _ = k.verify_password(None, "correct horse");
    let absent = argon2_verifications() - before;

    assert_eq!(present, 1, "a known user costs exactly one verification");
    assert_eq!(
        absent, present,
        "an unknown username must cost the same Argon2 work as a known one"
    );
}

#[test]
fn a_corrupt_stored_hash_is_not_a_fast_path_either() {
    // Reachable: `set_password` accepts any string into VARCHAR(255), so a row
    // holding something that is not a PHC string is a state the store permits.
    //
    // MUTATION THIS CATCHES: replacing the `else` arm's dummy verification with a
    // bare `return false`. The answer is unchanged — so an assertion on the answer
    // alone proves nothing — but the branch then answers in microseconds and
    // reintroduces the enumeration oracle the module exists to close.
    let k = keys();

    let before = argon2_verifications();
    let ok = k.verify_password(Some("not a PHC string at all"), "x");
    let spent = argon2_verifications() - before;

    assert!(!ok, "an unparseable stored hash must never verify");
    assert_eq!(
        spent, 1,
        "a corrupt stored hash must still cost one Argon2 verification"
    );
}

// ---------------------------------------------------------------------------
// KNOWN-ANSWER tests.
//
// Every other test in this file is a WITHIN-RUN property test: it hashes and
// compares in the same process, so it holds under any consistent substitution.
// Swap SHA-256 for another 32-byte digest, or move the AES-GCM nonce to the tail,
// and they all stay green while EVERY EXISTING STORED ROW stops resolving. These
// pin the actual bytes, so the algorithm and the framing cannot change silently.
//
// The vectors are computed OUTSIDE this codebase — the SHA-256 one is the
// published `SHA-256("abc")`, the ciphertext is from OpenSSL via node — so they
// are answers to check against rather than a recording of what this code does.
// ---------------------------------------------------------------------------

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

#[test]
fn token_hashing_is_sha256_and_not_merely_some_32_byte_digest() {
    // The published SHA-256("abc"). MUTATION THIS CATCHES: swapping Sha256 for
    // any other 32-byte digest — every credential row in the store stops
    // resolving, and `token_hashing_is_stable_and_distinguishing` cannot tell.
    assert_eq!(
        hex(&Keys::token_hash("abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn the_blind_index_is_hmac_sha256_of_the_normalised_name() {
    // HMAC-SHA256(key = 32 bytes of 0x09, message = "max"), computed outside this
    // codebase. MUTATION THIS CATCHES: changing the MAC, the digest, or dropping
    // `normalise` — each rewrites every `external_id_blind_index` in the store,
    // so every existing username stops being findable at login.
    let k = keys();
    assert_eq!(
        hex(&k.blind_index("  MAX  ")),
        "95e0f62087b47ac695ffc9b130b23e78e136603333fe01906b6bc7d90ad2f2aa"
    );
}

#[test]
fn a_ciphertext_written_by_the_current_framing_still_decrypts() {
    // AES-256-GCM under 32 bytes of 0x07 with nonce 01..0c, produced by OpenSSL
    // (via node) and framed the way `encrypt` frames it: NONCE FIRST, then
    // ciphertext, then the GCM tag.
    //
    // MUTATION THIS CATCHES: moving the nonce to the tail, or changing the
    // cipher. Both keep `a_name_round_trips` green — it encrypts and decrypts in
    // the same run — while every display_name_ciphertext already in the database
    // becomes undecryptable.
    let k = keys();
    // nonce(12) || ciphertext(12) || GCM tag(16)
    let framed = unhex(concat!(
        "0102030405060708090a0b0c",
        "fa1889be26859449895f617b",
        "959f6b089f5258e686f30033f7dd344c",
    ));
    assert_eq!(k.decrypt(&framed).unwrap(), "Ada Lovelace");
}

// ---------------------------------------------------------------------------
// Minting and key loading.
// ---------------------------------------------------------------------------

#[test]
fn a_minted_token_carries_the_full_256_bits() {
    // MUTATION THIS CATCHES: `[0u8; 32]` to `[0u8; 16]` in `mint_token`. That
    // halves the entropy of every bearer token in the system and leaves
    // `a_minted_token_is_unpredictable_and_url_safe` green, because two 128-bit
    // tokens still differ and are still URL-safe.
    //
    // Asserted on the DECODED length rather than the base64 one, so the assertion
    // is about entropy rather than about an encoding.
    let t = Keys::mint_token().unwrap();
    let raw = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &*t)
        .expect("a minted token is URL-safe base64");
    assert_eq!(raw.len(), 32, "a bearer token is 256 bits of CSPRNG output");
}

/// A private directory under the system temp dir, named for the test using it.
///
/// Hand-rolled rather than a `tempfile` dependency: two files in a directory is
/// not worth a crate in a tree this deliberate about what it links.
fn key_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("yadgar-iam-keytest-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create the key directory");
    dir
}

#[test]
fn a_key_that_is_not_32_bytes_is_refused_rather_than_padded() {
    // MUTATION THIS CATCHES: relaxing `bytes.len() != 32` to `bytes.len() < 32`.
    // A 31-byte key then reaches `copy_from_slice`, which PANICS — so a truncated
    // Secret becomes a crash at boot with a message about slice lengths instead
    // of the explanation `KeyError::WrongLength` spends four lines writing.
    // Nothing pinned either arm before this.
    for len in [31usize, 33] {
        let dir = key_dir(&format!("wrong-length-{len}"));
        std::fs::write(dir.join(super::ENCRYPTION_KEY), vec![0u8; len]).expect("write the key");

        let err = read_key(dir.to_str().unwrap(), super::ENCRYPTION_KEY)
            .expect_err("a key of the wrong length must be refused");
        assert!(
            matches!(err, KeyError::WrongLength(_, n) if n == len),
            "expected WrongLength({len}), got {err:?}"
        );
    }
}

#[test]
fn a_32_byte_key_loads_and_a_missing_one_is_named_in_the_error() {
    let dir = key_dir("present-and-absent");
    std::fs::write(dir.join(super::ENCRYPTION_KEY), [4u8; 32]).expect("write the key");

    let key = read_key(dir.to_str().unwrap(), super::ENCRYPTION_KEY).expect("a 32-byte key loads");
    assert_eq!(*key, [4u8; 32]);

    let err = read_key(dir.to_str().unwrap(), super::BLIND_INDEX_KEY)
        .expect_err("an absent key must be an error, not an empty one");
    assert!(matches!(err, KeyError::Unreadable(path, _) if path.ends_with(super::BLIND_INDEX_KEY)));
}

/// A `Keys` built the way `main` builds it — dummy hash and all.
///
/// The `keys()` fixture above mints its own `dummy_hash`, so a test that used it
/// would be asserting on this file rather than on the construction the binary
/// runs. This goes through the real path, which is what `from_dir` exists for.
fn loaded_keys(name: &str) -> Keys {
    let dir = key_dir(name);
    std::fs::write(dir.join(super::ENCRYPTION_KEY), [4u8; 32]).expect("write the encryption key");
    std::fs::write(dir.join(super::BLIND_INDEX_KEY), [5u8; 32]).expect("write the blind-index key");
    Keys::from_dir(dir.to_str().unwrap()).expect("a fully provisioned key directory loads")
}

#[test]
fn the_dummy_hash_costs_exactly_what_a_stored_hash_costs() {
    // THE COUNTER TESTS ABOVE CANNOT SEE THIS. Argon2 takes its cost parameters
    // from the PHC STRING being verified, not from the `Argon2` doing the
    // verifying — `password-hash` builds them with `Params::try_from(hash)`. So
    // "one verification each" is a statement about control flow, and the oracle
    // is about COST: one verification of a 64 MiB, 4-pass hash and one of a
    // 19 MiB, 2-pass hash are both one verification and are not the same wait.
    //
    // MUTATION THIS CATCHES: tuning `hash_password`'s parameters while the dummy
    // stays at whatever it was. Measured on this code at m=65536,t=4 against a
    // default dummy: present 13.726s, absent 0.250s — a 55x enumeration oracle,
    // with both counter tests green. Nothing pinned the two together.
    //
    // Deterministic rather than a stopwatch: this compares the two parameter sets
    // instead of two durations. A wall-clock assertion would need a tolerance
    // wide enough to survive a loaded CI runner, and a tolerance that wide stops
    // catching the smaller divergences.
    //
    // `Params` covers the digest length too, without a separate assertion:
    // `Params::try_from` recovers `output_len` from the hash itself, because the
    // PHC parameter string does not carry it.
    let k = loaded_keys("dummy-cost");

    let stored = k.hash_password("correct horse").expect("hash a password");
    let stored = PasswordHash::new(&stored).expect("a freshly written hash parses");
    let dummy = PasswordHash::new(&k.dummy_hash).expect("the dummy hash parses");

    assert_eq!(
        stored.algorithm, dummy.algorithm,
        "the dummy hash must use the same Argon2 variant as a stored one"
    );
    assert_eq!(
        stored.version, dummy.version,
        "the dummy hash must use the same Argon2 version as a stored one"
    );
    assert_eq!(
        argon2::Params::try_from(&stored).expect("stored parameters"),
        argon2::Params::try_from(&dummy).expect("dummy parameters"),
        "an absent user must cost the same memory, passes and lanes as a present one"
    );
}
