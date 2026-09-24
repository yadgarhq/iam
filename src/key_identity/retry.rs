//! How long this pod waits before asking `iam-db` again, and the jitter on it.
//!
//! **THE JITTER IS THE POINT OF THIS FILE.** Measured on PR 2: at three or more
//! concurrent recorders `iam-db` deadlocked and answered UNAVAILABLE to the
//! losers. That is fixed server-side now, and synchronised retries from replicas
//! that all started in the same second are still the traffic shape that produced
//! it. A bare fixed interval reproduces it exactly.

use std::time::Duration;

use sha2::{Digest, Sha256};

/// How long this pod waits before asking again, and the jitter on it.
#[derive(Clone, Copy, Debug)]
pub struct Retry {
    base: Duration,
    cap: Duration,
}

impl Retry {
    /// The cadence this binary retries on.
    ///
    /// **NOT A CONFIGURATION KNOB (ADR-0569), for [`super::RESTATE_AFTER`]'s reason.**
    /// One second to sixty is a backoff, not a setting: nothing renders it,
    /// nothing else reads it, and there is no second source for an operator to
    /// find it disagreeing with.
    pub const fn standard() -> Self {
        Self {
            base: Duration::from_secs(1),
            cap: Duration::from_secs(60),
        }
    }

    /// Any other cadence — which is what makes the retry testable in under a
    /// second rather than over a minute.
    pub const fn of(base: Duration, cap: Duration) -> Self {
        Self { base, cap }
    }

    /// The undithered interval for `attempt`: doubling, then flat at the cap.
    pub(super) fn backoff(&self, attempt: u32) -> Duration {
        self.base
            .saturating_mul(2u32.saturating_pow(attempt.min(31)))
            .min(self.cap)
    }

    /// The interval actually waited: half the backoff, plus a draw from the
    /// other half.
    ///
    /// **THE JITTER IS NOT DECORATION AND THE FLOOR IS NOT EITHER.** Replicas
    /// that started in the same second retry in the same millisecond without it,
    /// and three or more concurrent recorders is the shape that deadlocked
    /// `iam-db` on PR 2 — fixed server-side there, and still the traffic pattern
    /// that produced it. FULL jitter, drawn from `[0, backoff]`, was rejected
    /// rather than not considered: a near-zero draw answers an UNAVAILABLE twin
    /// by calling it again at once, which is a retry loop with no backoff in it.
    pub(super) fn wait(&self, attempt: u32, seed: u64) -> Duration {
        let backoff = self.backoff(attempt);
        let half = backoff / 2;
        let drawn =
            u128::from(draw(seed, attempt)).saturating_mul(half.as_millis()) / u128::from(u64::MAX);
        half + Duration::from_millis(u64::try_from(drawn).unwrap_or(u64::MAX))
    }
}

/// A per-pod, per-attempt draw, with no coordination and no RNG state.
///
/// The seed is [`seed`]'s hash of the pid and the clock, as
/// `yadgar_lifecycle::rotate` draws its splay; hashing the attempt in beside it
/// is what stops two pods that collided once colliding on every attempt after.
fn draw(seed: u64, attempt: u32) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(seed.to_le_bytes());
    hasher.update(attempt.to_le_bytes());
    let digest = hasher.finalize();
    u64::from_le_bytes(digest[..8].try_into().expect("SHA-256 is 32 bytes"))
}

/// A seed that differs between pods without any coordination.
pub(super) fn seed() -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(std::process::id().to_le_bytes());
    hasher.update(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            .to_le_bytes(),
    );
    let digest = hasher.finalize();
    u64::from_le_bytes(digest[..8].try_into().expect("SHA-256 is 32 bytes"))
}
