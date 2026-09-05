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

#[test]
fn a_stored_hash_the_verifier_refuses_before_hashing_is_not_a_fast_path() {
    // THE TEST ABOVE COVERS ONE CORRUPTION SHAPE AND MISSES THESE. "not a PHC
    // string at all" is the shape that is handled CORRECTLY — it fails
    // `PasswordHash::new`, takes the `else` arm, and pays the dummy. The shapes
    // below PARSE, so they sail past that guard and reach a verifier that then
    // computes nothing:
    //
    // - no digest: `password_hash`'s blanket `PasswordVerifier` impl is gated on
    //   `if let (Some(salt), Some(expected_output)) = (&hash.salt, &hash.hash)`
    //   and otherwise falls straight through to `Err(Error::Password)` — the same
    //   error a wrong password gets, without hashing anything;
    // - an illegal parameter set: `Params::try_from` rejects `m=8,p=2` (Argon2
    //   requires `m >= 8 * p`) and the `?` returns before the first block of
    //   memory is touched.
    //
    // AND A THIRD FAMILY, ONE CALL DEEPER, which the two above do not reach:
    // argon2's own `hash_password_customized` rejects a foreign algorithm ident, a
    // version that is neither 0x10 nor 0x13, and a salt DECODING to fewer than
    // `MIN_SALT_LEN` = 8 bytes. `password_hash`'s `Salt::MIN_LENGTH` is 4
    // CHARACTERS and `Params::try_from` never looks at the ident, so all three
    // parse and then die past every guard the two cases above describe. They are
    // in the table below because the production code closes them through the
    // catch-all `Err(_) => None` rather than through the enumeration — see
    // `verify_counted`. Narrowing that arm to the named variants would reopen
    // exactly these rows, and this test is what makes that loud.
    //
    // MEASURED before the fix, release build: every one of these shapes answered
    // in microseconds against the milliseconds a real verification costs — three
    // to four orders of magnitude, which is the oracle. After the fix they are all
    // one full verification, indistinguishable from the absent-user path. The
    // absolute figures are host-dependent and quoted in the pull request against
    // the host they were taken on; the ratio is the part that is not.
    //
    // BOTH counter tests above stayed green throughout, which is the point: the
    // counter incremented on entry to `verify_counted` rather than where the work
    // happens, so it reported control flow while claiming to report cost.
    //
    // MUTATIONS THIS CATCHES: dropping the `salt`/`hash` presence check, or
    // turning the `Err(_) => None` arm into `Some(false)`. Each returns a verdict
    // for a call that hashed nothing, so the dummy that pays for it is skipped.
    //
    // AND the instrumentation regression itself, in both of its forms. Moving the
    // increment out of `CountingArgon2` and back to the top of `verify_counted`
    // makes the counter derived from the decision it is measuring, so a mutation
    // to the decision moves the counter with it and every assertion below reads 1
    // again. Counting on ENTRY to `hash_password_customized` instead of on its
    // `Ok` is the same error at smaller scale: the third family reaches that entry
    // point and fills no memory, so those rows report `spent == 2` — one spurious,
    // one real — and fail here.
    //
    // Reachable the same way the test above is: `iam-db`'s `SetPassword` writes a
    // caller-supplied string verbatim into VARCHAR(255).
    //
    // "x" DELIBERATELY, as elsewhere in this file: the fixture's dummy_hash is the
    // hash of "x", so the fallback verification SUCCEEDS and `stored.is_some()` is
    // the only thing still returning false. A password that failed on its own
    // would let a mutation that authenticates here pass unnoticed.
    let k = keys();

    for (shape, stored) in [
        (
            "no digest",
            "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHRzYWx0c2FsdA",
        ),
        ("no salt and no digest", "$argon2id$v=19$m=19456,t=2,p=1"),
        (
            "an illegal parameter set",
            "$argon2id$v=19$m=8,t=1,p=2$c29tZXNhbHRzYWx0c2FsdA\
             $c29tZXNhbHRzYWx0c2FsdHNhbHRzYWx0c2E",
        ),
        // The third family. Each of these has a legal Argon2 parameter string
        // and a digest, so it is past both guards the two cases above name.
        (
            "an algorithm that is not Argon2",
            "$scrypt$v=19$m=19456,t=2,p=1$c29tZXNhbHRzYWx0c2FsdA\
             $c29tZXNhbHRzYWx0c2FsdHNhbHRzYWx0c2E",
        ),
        (
            "a version Argon2 does not have",
            "$argon2id$v=99$m=19456,t=2,p=1$c29tZXNhbHRzYWx0c2FsdA\
             $c29tZXNhbHRzYWx0c2FsdHNhbHRzYWx0c2E",
        ),
        (
            // Decodes to 7 bytes: legal for `password_hash`, one byte under
            // Argon2's own minimum.
            "a salt shorter than Argon2 accepts",
            "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbA\
             $c29tZXNhbHRzYWx0c2FsdHNhbHRzYWx0c2E",
        ),
    ] {
        // Guards the test itself: if any of these ever stopped parsing it would
        // take the `else` arm and silently become a copy of the test above.
        assert!(
            PasswordHash::new(stored).is_ok(),
            "{shape}: must PARSE, or this asserts nothing the previous test does not"
        );

        let before = argon2_verifications();
        let ok = k.verify_password(Some(stored), "x");
        let spent = argon2_verifications() - before;

        assert!(!ok, "{shape}: must never verify");
        assert_eq!(
            spent, 1,
            "{shape}: parses but hashes nothing, so it must still cost one real \
             Argon2 verification against the dummy"
        );
    }
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
    // WHAT THIS TEST CANNOT SEE, AND THE GENERAL FORM OF THAT BLINDNESS: an
    // equality between two values minted by ONE function cannot detect that
    // function moving both. `hash_secret` mints the stored hash and the dummy, so
    // tuning it to `m=8,t=1,p=1` keeps every assertion below green while password
    // hashing is destroyed. Relative and absolute are different properties and
    // need separate assertions. The floor this test is silent about is pinned by
    // `a_stored_hash_is_expensive_in_absolute_terms`, below. The same shape is
    // what `iam#6` and the change above are each about, one level up: a
    // measurement taken from the thing it is measuring reports agreement, not
    // correctness.
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

#[test]
fn a_stored_hash_is_expensive_in_absolute_terms() {
    // THE EQUALITY TEST ABOVE IS SILENT ABOUT THIS, and that is not a detail of
    // this file — it is the general form. `stored_params == dummy_params` is a
    // RELATIVE assertion, both sides are minted by the one `hash_secret`, and one
    // edit to `hash_secret` moves them together. Tuned to `m=8,t=1,p=1` the whole
    // suite passed with password hashing reduced to about nine microseconds per
    // hash. Nothing anywhere asserted that either hash was STRONG.
    //
    // MUTATION THIS CATCHES: any global collapse of `hash_secret`'s cost —
    // `Argon2::new(.., Params::new(8, 1, 1, None))` in place of
    // `Argon2::default()`. The equality test stays green under it, because the
    // dummy collapses in step; only a floor sees it.
    //
    // THE FLOOR IS OWASP'S ARGON2ID MINIMUM — m = 19 MiB, t = 2, p = 1 (Password
    // Storage Cheat Sheet), which is also what `argon2`'s `Params::DEFAULT`
    // encodes, so today's `Argon2::default()` sits exactly on it. `>=` and not
    // `==` deliberately: raising the cost is a change this test must permit, and
    // lowering it is the one it exists to refuse.
    //
    // BOTH hashes are floored, and independently. Flooring only the stored one
    // would leave the dummy covered by the equality test alone — two tests each
    // load-bearing on the other is the coupling this whole file is about.
    //
    // THE VARIANT IS ASSERTED HERE TOO, AND FOR THE SAME REASON THE COSTS ARE.
    // The equality test compares `stored.algorithm` to `dummy.algorithm`, which
    // is the relative assertion again: `hash_secret` mints both, so switching it
    // to `Algorithm::Argon2d` moves the pair together and the entire suite stays
    // green — measured, before this line existed. The module header's own table
    // rules Argon2d out, and only an ABSOLUTE assertion holds it to that.
    //
    // p = 1 IS NOT ASSERTED, and its absence is deliberate rather than an
    // oversight. `MIN_P_COST: u32 = 1` with `p_cost() >= MIN_P_COST` used to sit
    // beside the two floors below, described as load-bearing with them and unable
    // to fail: `argon2 0.5.3`'s `Params::new` REFUSES `p_cost < 1` (its own
    // `Params::MIN_P_COST`), and `Params::try_from(&PasswordHash)` builds through
    // `ParamsBuilder` into that same constructor — so no PHC string reaching this
    // loop can carry a lower lane count. The crate enforces it; a test that
    // restates a structural invariant reports agreement rather than correctness,
    // which is the failure this whole file is about. Named rather than elided so
    // it is not re-added.
    const MIN_M_COST: u32 = 19 * 1024;
    const MIN_T_COST: u32 = 2;

    let k = loaded_keys("absolute-cost");

    let stored = k.hash_password("correct horse").expect("hash a password");
    for (which, phc) in [
        ("a stored hash", stored.as_str()),
        ("the dummy hash", &k.dummy_hash),
    ] {
        let parsed = PasswordHash::new(phc).expect("the hash parses");
        let params = argon2::Params::try_from(&parsed).expect("its parameters");
        // ABSOLUTE, against the crate's own identifier rather than against the
        // other hash. Argon2d is the GPU-hardened, side-channel-vulnerable
        // variant and Argon2i the reverse; Argon2id is the hybrid, and it is the
        // one the module header commits to for a stored password.
        assert_eq!(
            parsed.algorithm,
            argon2::Algorithm::Argon2id.ident(),
            "{which}: the variant is {}, and a stored password must be Argon2id",
            parsed.algorithm
        );
        assert!(
            params.m_cost() >= MIN_M_COST,
            "{which}: m={} is below OWASP's {MIN_M_COST} KiB minimum for Argon2id",
            params.m_cost()
        );
        assert!(
            params.t_cost() >= MIN_T_COST,
            "{which}: t={} is below OWASP's {MIN_T_COST}-pass minimum for Argon2id",
            params.t_cost()
        );
    }
}

/// THE OVERHEAD [`super::Keys::encrypt`] ADDS, MEASURED RATHER THAN ASSUMED.
///
/// `iam_user.external_id_ciphertext` and `iam_user.display_name_ciphertext` are
/// `VARBINARY(512)` (`iam-db/src/schema.rs`), and what lands in them is what this
/// function returns. So the longest plaintext the column can hold is 512 minus
/// whatever this adds, and `service::MAX_ENCRYPTED_FIELD_BYTES` is that
/// subtraction. This test is where the subtraction is CHECKED against the cipher
/// rather than recited from memory.
///
/// The overhead is 28 bytes and it is two things, neither of them a choice this
/// file makes: a 12-byte nonce prefixed by `encrypt` itself, and AES-256-GCM's
/// 16-byte authentication tag appended by the cipher. AES-GCM is CTR mode
/// underneath, so the enciphered bytes are exactly as many as the plaintext's —
/// that is why a byte of plaintext costs exactly a byte of column and the
/// relationship is a subtraction rather than a ratio.
///
/// **THE NUMBERS ARE LITERALS AND NAME NO CONSTANT** (ADR-0573). A test that
/// wrote `MAX_ENCRYPTED_FIELD_BYTES` here would agree with the constant whatever
/// the constant said, including when it is wrong — which is the whole failure
/// this test exists to catch. 484 and 512 are written out, and if the cipher or
/// the framing ever changes, this is what goes red.
#[test]
fn the_longest_plaintext_the_column_holds_encrypts_to_exactly_the_column_width() {
    let k = keys();
    assert_eq!(k.encrypt(&"a".repeat(484)).unwrap().len(), 512);
    // ONE BYTE OVER, and it is the first value the column refuses. Pinning the
    // last accepted value alone would pass for a bound set anywhere below it.
    assert_eq!(k.encrypt(&"a".repeat(485)).unwrap().len(), 513);
}

/// The same subtraction over MULTI-BYTE plaintext, because the unit is BYTES.
///
/// `VARBINARY` counts bytes and `encrypt` enciphers `plaintext.as_bytes()`, so a
/// character-counted bound would be wrong here in the direction that reopens the
/// storage refusal: 484 `U+1F600` is 1936 bytes and encrypts to 1964, four times
/// the column. This is the mirror of `MAX_LABEL_CHARS`'s argument, which counts
/// CHARACTERS because `VARCHAR(255)` on utf8mb4 does.
#[test]
fn the_bound_is_bytes_and_not_characters() {
    let k = keys();
    // 121 four-byte characters is 484 bytes, so it fills the column exactly.
    assert_eq!(k.encrypt(&"\u{1F600}".repeat(121)).unwrap().len(), 512);
    // 484 of them is 1936 bytes, which is far past it.
    assert_eq!(k.encrypt(&"\u{1F600}".repeat(484)).unwrap().len(), 1964);
}
