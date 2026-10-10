//! The dial after a failed first one (ledger 1420).
//!
//! **WHY THIS EXISTS.** `Invalidator::connect` dials once, before the listener
//! binds, and must not block the boot on a broker that is down (D69/ADR-0555).
//! Until ledger 1420 a failed dial there was final: the process kept a
//! publisher that published nothing until it was restarted. PB-3 hit exactly
//! that on 2026-10-09 — both `iam` pods booted during the broker's roll,
//! logged "cannot reach the broker" at 22:05Z, and published no invalidation
//! until they were rolled at 23:42Z.
//!
//! **THE SHAPE IS `gateway`'s** (`invalidate/broker.rs` at v0.12.0, `redial` and
//! `wait_after`): dial again every [`RETRY`], and say on every failure whether
//! it was an outage or a refusal. It differs in one place, on purpose: a
//! refused credential ENDS this loop rather than slowing it, for the reason
//! `Invalidator::connect` gives.
//!
//! Once a dial succeeds the client goes into the slot every clone shares, and
//! `async-nats` owns every reconnect after that.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use super::{connect_options, Credentials};
use crate::upstream;

/// How long a replica waits between dials while the broker is unreachable.
///
/// The same value as `gateway`'s `RETRY`, against the same broker. Every second
/// of it is a second in which a revocation is honoured late, and a dial costs
/// one TCP connection, so it is short.
pub const RETRY: Duration = Duration::from_secs(5); // ADR-0569-EXCEPTION(CC): sized against the window this module exists to close, not a tuning knob — the same value gateway's RETRY carries.

/// Dial until one succeeds or the broker refuses the credential.
///
/// **THE OPTIONS ARE REBUILT FOR EVERY DIAL, THROUGH THE SAME
/// [`connect_options`] THE BOOT DIAL USES** — so the redial carries the same
/// credential, the same B-N3 TLS hop, the same timeout and the same event
/// callback as the dial it replaces, and cannot drift from it.
pub(super) async fn until_connected(
    url: String,
    credentials: Option<Credentials>,
    tls: Option<upstream::UpstreamTls>,
    slot: Arc<OnceLock<async_nats::Client>>,
) {
    loop {
        tokio::time::sleep(RETRY).await;
        match connect_options(&credentials, &tls).connect(&url).await {
            Ok(client) => {
                connected(&url, &credentials, &tls);
                let _ = slot.set(client);
                return;
            }
            Err(e) if e.kind() == async_nats::ConnectErrorKind::AuthorizationViolation => {
                refused(&url, &e, &tls);
                return;
            }
            Err(e) => tracing::error!(
                %url, error = %e, tls = tls.is_some(),
                "still cannot reach the broker, or the TLS handshake with it failed; no \
                 invalidation is being published. Retrying every {} seconds.",
                RETRY.as_secs()
            ),
        }
    }
}

/// The line a successful dial writes, at boot or on a redial — once each.
pub(super) fn connected(
    url: &str,
    credentials: &Option<Credentials>,
    tls: &Option<upstream::UpstreamTls>,
) {
    tracing::info!(
        %url,
        // WHETHER, never WHAT. This log is shipped.
        authenticated = credentials.is_some(),
        tls = tls.is_some(),
        "publishing cache invalidation"
    );
    if credentials.is_none() {
        tracing::warn!(
            "the connection to the broker is UNAUTHENTICATED: no NATS_PASSWORD_FILE \
             is configured, so anything on the pod network can publish D72's \
             invalidation events, or drown them under a flood. Set an authorization \
             block on the broker and mount its Secret."
        );
    }
}

/// The line a refused credential writes, at boot or on a redial. Nothing
/// dials again after it: see [`super::Invalidator::connect`].
pub(super) fn refused(
    url: &str,
    e: &async_nats::ConnectError,
    tls: &Option<upstream::UpstreamTls>,
) {
    tracing::error!(
        %url, error = %e, tls = tls.is_some(),
        "the broker REFUSED this service's credential, so cache invalidation will \
         NOT be published and revocations will be honoured late. This is a \
         deployment error rather than an outage: it does not recover on its own, \
         and this service does not dial again. Check NATS_USER and NATS_PASSWORD_FILE \
         against the broker's authorization block."
    );
}
