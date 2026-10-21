//! How long a `Login` or redemption credential lives (ADR-0972 (3)), and how
//! long the gateway may cache a resolution of one.

use std::time::SystemTime;

use super::credential::exceeds_max_lifetime;

/// The gateway cache life for a live credential with time to spare: five
/// minutes, the backstop that bounds how long a missed broker event (D72) can
/// leave a revoked credential working.
const LIVE_CACHE_SECONDS: i64 = 300;

const NANOS_PER_SECOND: i128 = 1_000_000_000;

/// The variable the lifetime is read from, and the chart key that renders it.
/// Every refusal names both, as `upstream::REQUEST_TIMEOUT_CHART_KEY` does.
pub const LIFETIME_ENV: &str = "CREDENTIAL_LIFETIME_SECONDS";
pub const LIFETIME_CHART_KEY: &str = "credential.lifetimeSeconds";

/// `CREDENTIAL_LIFETIME_SECONDS`, parsed and bounded. Construct it only through
/// [`Self::parse`], so an `Iam` cannot hold a lifetime nobody checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CredentialLifetime {
    seconds: i64,
}

impl CredentialLifetime {
    /// Parse the raw environment value: a whole number of seconds with
    /// `0 < value ≤ MAX_EXPIRES_IN_SECONDS`.
    ///
    /// THERE IS NO "NEVER" VALUE (ADR-0972 (3)). `IssueCredential` reads 0 as
    /// "no expiry"; here 0 is refused, because a lifetime is required and a
    /// knob with an escape value bounds nothing. The upper bound is
    /// `IssueCredential`'s, through the one function both paths call.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let seconds: i64 = raw.parse().map_err(|e| {
            format!(
                "CREDENTIAL_LIFETIME_SECONDS is not a whole number of seconds ({e}); set \
                 the chart's credential.lifetimeSeconds"
            )
        })?;
        if seconds <= 0 {
            return Err(format!(
                "CREDENTIAL_LIFETIME_SECONDS is {seconds}, and a credential lifetime must be \
                 positive: there is no \"never expires\" value (ADR-0972 (3)). Set the chart's \
                 credential.lifetimeSeconds"
            ));
        }
        if exceeds_max_lifetime(seconds) {
            return Err(format!(
                "CREDENTIAL_LIFETIME_SECONDS is {seconds}, longer than the ten years this \
                 service grants any credential. Set the chart's credential.lifetimeSeconds \
                 lower"
            ));
        }
        Ok(Self { seconds })
    }

    /// The lifetime in seconds.
    pub fn seconds(self) -> i64 {
        self.seconds
    }
}

/// The deadline a credential minted now carries: now plus the lifetime.
///
/// SATURATING on the wire type, as `IssueCredential` does: the bound makes the
/// overflow unreachable, but `SystemTime + Duration` aborts on overflow and
/// nothing here should depend on the bound staying where it is.
pub(super) fn deadline(lifetime: CredentialLifetime) -> prost_types::Timestamp {
    let now = prost_types::Timestamp::from(SystemTime::now());
    prost_types::Timestamp {
        seconds: now.seconds.saturating_add(lifetime.seconds),
        nanos: now.nanos,
    }
}

/// The gateway cache life for a LIVE resolution (ADR-0972 (3)).
///
/// `min(300, expires_at − now)`, rounded DOWN so it never exceeds the time
/// the credential has left, with a FLOOR OF 1: zero is the gateway's refusal
/// signal, and a credential the store just answered as live must not be
/// cached as refused. The store filters out an expired row, so a value at or
/// below zero here is clock skew between the two processes. With no expiry (a
/// legacy row, not backfilled), the full 300.
pub(super) fn valid_for_seconds(expires_at: Option<&prost_types::Timestamp>) -> i64 {
    let Some(expires_at) = expires_at else {
        return LIVE_CACHE_SECONDS;
    };
    let now = prost_types::Timestamp::from(SystemTime::now());
    // i128, so no stored timestamp can overflow the subtraction.
    let left_nanos = (i128::from(expires_at.seconds) - i128::from(now.seconds)) * NANOS_PER_SECOND
        + i128::from(expires_at.nanos)
        - i128::from(now.nanos);
    let left = left_nanos
        .div_euclid(NANOS_PER_SECOND)
        .clamp(1, i128::from(LIVE_CACHE_SECONDS));
    i64::try_from(left).unwrap_or(LIVE_CACHE_SECONDS)
}
