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

use argon2::password_hash::{PasswordHash, PasswordHasher};
use argon2::Argon2;

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
/// argon2's own impl then rejects a foreign algorithm ident, an unknown version
/// and a salt below its 8-byte minimum — each before the first block, each listed
/// at [`verify_counted`]. An entry-point count reports all three as verifications:
/// the same control-flow-wearing-the-name-of-cost mistake, one level further in.
///
/// `Ok` is the sound predicate because every one of those exits returns `Err`
/// ahead of any hashing, and the one error the library can raise AFTER hashing —
/// re-serialising the parameter string — cannot fire for parameters it has just
/// read back out of a PHC string. If it ever did, this would UNDERCOUNT, which
/// turns an `assert_eq!(spent, 1)` red rather than leaving it green. The counter
/// stays independent of `verify_counted` either way: the predicate is the
/// library's own result, not this module's classification of it.
pub(super) struct CountingArgon2(pub(super) Argon2<'static>);

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
        let computed = self
            .0
            .hash_password_customized(password, algorithm, version, params, salt);
        if computed.is_ok() {
            ARGON2_VERIFICATIONS.with(|c| c.set(c.get() + 1));
        }
        computed
    }
}
