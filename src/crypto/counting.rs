//! The `cfg(test)` instrument [`super::verify_counted`] hangs off, in its own
//! file.
//!
//! SEPARATED FROM THE PRIMITIVES IT MEASURES, which is the seam rather than the
//! line count: `crypto.rs` holds the key material and the four operations on
//! secrets, and this holds the counter that proves one of them paid for itself.
//! The whole module is `cfg(test)`, so nothing here reaches a deployed binary.
//!
//! Everything below moved out of `crypto.rs` unchanged, apart from the
//! per-item `#[cfg(test)]` attributes that `#[cfg(test)] mod counting;` now
//! carries once, and the visibility `CountingArgon2` needs to be nameable from
//! its parent.

use argon2::{Argon2, CustomizedPasswordHasher, PasswordHash};

// Count one Argon2id verification THAT ACTUALLY COMPUTED SOMETHING.
//
// THE TIMING EQUALISATION IS INVISIBLE TO AN ORDINARY ASSERTION. A test that only
// checks the ANSWER of `verify_password(None, …)` passes with the dummy hash, its
// generation and `KeyError::Dummy` all deleted — the answer is `false` either
// way. Counting the verifications measures the property itself, and does it
// deterministically rather than by reading a clock.
//
// COUNTED ON THE LIBRARY'S OWN `Ok`, and not on entry to `verify_counted` — see
// [`CountingArgon2`]. Counting on entry made this read "one verification" for
// calls that touched not one block of memory: the instrument every test below
// leans on, reporting control flow while claiming to report cost. That is
// precisely the mistake this module exists to catch, committed inside the thing
// that catches it.
//
// A THREAD-LOCAL, because the test binary runs tests in parallel in one process
// and a global counter would make each test's reading depend on which others
// happened to be running.
thread_local! {
    static ARGON2_VERIFICATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

pub(crate) fn argon2_verifications() -> usize {
    ARGON2_VERIFICATIONS.with(std::cell::Cell::get)
}

/// An `Argon2` that counts the hashings the library actually completed.
///
/// THE COUNTER HAS TO BE INDEPENDENT OF THE CODE IT MEASURES, and putting it
/// anywhere in `verify_counted` is not. `verify_counted` decides which hashes are
/// usable; if the counter were derived from that same decision, then a mutation to
/// the decision would move the counter with it and the tests would go on reading
/// "one verification" while nothing was computed — the exact failure this file is
/// fixing, reintroduced one level up.
///
/// COUNTED ON `Ok`, NOT ON ENTRY, because REACHING `hash_password_customized` IS
/// NOT THE SAME AS FILLING THE MEMORY. It is past `password_hash`'s
/// `(Some(salt), Some(expected_output))` gate and past `Params::try_from`, but
/// argon2's own impl then rejects a foreign algorithm ident and an unknown
/// version — each before the first block, each listed at [`verify_counted`]. An
/// entry-point count reports both as verifications: the same
/// control-flow-wearing-the-name-of-cost mistake, one level further in. A salt
/// below argon2's 8-byte minimum used to be a third such exit; under `phc 0.6`
/// that minimum is enforced at PARSE time, so it never reaches this impl at all.
///
/// `Ok` is the sound predicate because every one of those exits returns `Err`
/// ahead of any hashing, and the one error the library can raise AFTER hashing —
/// re-serialising the parameter string — cannot fire for parameters it has just
/// read back out of a PHC string. If it ever did, this would UNDERCOUNT, which
/// turns an `assert_eq!(spent, 1)` red rather than leaving it green. The counter
/// stays independent of `verify_counted` either way: the predicate is the
/// library's own result, not this module's classification of it.
///
/// THE TRAIT IS `CustomizedPasswordHasher` AND THAT IS FORCED, not stylistic.
/// `password-hash 0.6` split the old single `PasswordHasher` in two: a
/// `PasswordHasher<H>` that mints its own salt, and a
/// `CustomizedPasswordHasher<H>` that takes one along with an algorithm ident, a
/// version and a parameter set. The blanket `PasswordVerifier<phc::PasswordHash>`
/// — the impl that gives [`super::verify_counted`] its `verify_password` — is
/// written over `CustomizedPasswordHasher<phc::PasswordHash>` and NOT over
/// `PasswordHasher`. So implementing the other half of the split would leave this
/// wrapper with no `verify_password` at all, and the counter measuring nothing.
///
/// THE SIGNATURE IS NARROWER THAN IT WAS, and none of what left was a choice of
/// this file's: the salt is a `&[u8]` where it was a `Salt<'a>`, the algorithm an
/// `Option<&str>` where it was an `Option<Ident<'a>>`, the version an
/// `Option<u32>` where it was an `Option<Decimal>`, and `PasswordHash` carries no
/// lifetime because `phc 0.6` made it an owned type. The delegation and the
/// count-on-`Ok` predicate are the same two statements they were.
pub(super) struct CountingArgon2(pub(super) Argon2<'static>);

impl CustomizedPasswordHasher<PasswordHash> for CountingArgon2 {
    type Params = argon2::Params;

    fn hash_password_customized(
        &self,
        password: &[u8],
        salt: &[u8],
        algorithm: Option<&str>,
        version: Option<argon2::password_hash::Version>,
        params: Self::Params,
    ) -> argon2::password_hash::Result<PasswordHash> {
        let computed = self
            .0
            .hash_password_customized(password, salt, algorithm, version, params);
        if computed.is_ok() {
            ARGON2_VERIFICATIONS.with(|c| c.set(c.get() + 1));
        }
        computed
    }
}
