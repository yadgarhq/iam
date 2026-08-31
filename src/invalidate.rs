//! Telling the gateway that a cached identity is no longer true.
//!
//! **This is the half of D72's cache that makes it safe.** The gateway caches
//! what a credential resolves to; without a signal, a revoked credential keeps
//! working until its TTL expires and a removed team member keeps reading that
//! team's records. The TTL is a backstop for a missed event, not the mechanism —
//! treating it as the mechanism means every revocation is honoured late by
//! design.
//!
//! **Plain NATS subjects, not JetStream, and not a queue group.** Two reasons,
//! and the second is the one that is easy to get wrong:
//!
//! - Every gateway replica holds its own in-process cache, so every replica must
//!   receive the message. A queue group delivers to exactly one subscriber,
//!   which would invalidate one replica's cache and leave the others serving the
//!   revoked credential — a partial invalidation that looks like it worked.
//! - Durability buys little here. A subscriber that was down has a cold cache
//!   when it returns, so the event it missed had nothing to invalidate. The
//!   backstop covers the narrow case of a replica that stayed up through a
//!   broker outage.
//!
//! **Publishing never fails the call that caused it.** Same rule as telemetry
//! (D25): a revocation that succeeded in the database has happened, and returning
//! an error because the broker was unreachable would tell the caller to retry
//! something already done. A failed publish is logged loudly and the TTL becomes
//! the mechanism for that one event — which is exactly the case it exists for.

/// Subjects, namespaced so a wildcard subscription is possible later.
pub mod subject {
    /// A credential was revoked. Payload: the **user id**, not the credential id.
    ///
    /// That looks wrong and is not. The gateway's cache is keyed on a hash of the
    /// token, which `iam` never sees on a revoke — it is given a credential id.
    /// So there is no key to invalidate directly, and the workable unit is the
    /// person: drop every cached entry for that user.
    ///
    /// It over-invalidates, dropping their other credentials' entries too. That
    /// costs one resolve each and is the safe direction to be wrong in; the
    /// alternative is a cache the event cannot address, which fails by leaving
    /// the revoked credential working.
    pub const CREDENTIAL_REVOKED: &str = "yadgar.iam.credential.revoked";
    /// A user's team membership changed. Payload: the user id.
    ///
    /// Deliberately not "removed": adding a team also changes what a cached
    /// identity says, and a caller that only invalidated on removal would serve
    /// a stale answer to someone who had just been granted access — visible as
    /// a permission that takes five minutes to arrive, which reads as a bug in
    /// the wrong place.
    pub const TEAMS_CHANGED: &str = "yadgar.iam.user.teams-changed";
}

/// A publisher, or nothing.
///
/// `None` when no broker is configured, which is a legitimate state for a local
/// run and NOT for a deployment — `main` warns loudly at boot rather than
/// treating a missing broker as normal, because a gateway cache with no
/// invalidation path is the failure D72 names.
#[derive(Clone)]
pub struct Invalidator {
    client: Option<async_nats::Client>,
}

impl Invalidator {
    /// Connect, or return a publisher that does nothing.
    ///
    /// A broker that cannot be reached at boot does not stop the service: `iam`
    /// still authenticates, and refusing to start would turn a broker outage into
    /// an authentication outage. The cost is recorded in the log, not hidden.
    pub async fn connect(url: Option<&str>) -> Self {
        let Some(url) = url.filter(|u| !u.is_empty()) else {
            tracing::warn!(
                "no broker configured: cache invalidation will NOT be published, so a \
                 revoked credential may be honoured until its TTL expires (D72)"
            );
            return Self { client: None };
        };
        match async_nats::connect(url).await {
            Ok(client) => {
                tracing::info!(%url, "publishing cache invalidation");
                Self {
                    client: Some(client),
                }
            }
            Err(e) => {
                tracing::error!(
                    %url, error = %e,
                    "cannot reach the broker: cache invalidation will NOT be published \
                     until it recovers, and revocations will be honoured late"
                );
                Self { client: None }
            }
        }
    }

    /// Publish, and never fail the caller.
    async fn publish(&self, subject: &'static str, payload: String) {
        let Some(client) = &self.client else {
            tracing::warn!(subject, %payload, "no broker: invalidation not published");
            return;
        };
        if let Err(e) = client.publish(subject, payload.clone().into()).await {
            // Loud, because the consequence is silent: the credential keeps
            // working and nothing else says so.
            tracing::error!(
                subject, %payload, error = %e,
                "invalidation NOT published; the cached identity stays valid until its TTL"
            );
        }
    }

    /// `user_id`, deliberately — see [`subject::CREDENTIAL_REVOKED`].
    pub async fn credential_revoked(&self, user_id: &str) {
        self.publish(subject::CREDENTIAL_REVOKED, user_id.to_string())
            .await;
    }

    pub async fn teams_changed(&self, user_id: &str) {
        self.publish(subject::TEAMS_CHANGED, user_id.to_string())
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn no_broker_is_a_working_publisher_that_publishes_nothing() {
        // The alternative — refusing to construct — would make a missing broker
        // an authentication outage, which is a worse failure than a late
        // revocation.
        let inv = Invalidator::connect(None).await;
        inv.credential_revoked("yadgar:user:x").await;
        inv.teams_changed("yadgar:user:x").await;
    }

    #[tokio::test]
    async fn an_unreachable_broker_does_not_panic_or_block() {
        let inv = Invalidator::connect(Some("nats://127.0.0.1:1")).await;
        inv.credential_revoked("yadgar:user:y").await;
    }

    #[test]
    fn subjects_share_a_namespace_so_one_wildcard_can_catch_them() {
        assert!(subject::CREDENTIAL_REVOKED.starts_with("yadgar.iam."));
        assert!(subject::TEAMS_CHANGED.starts_with("yadgar.iam."));
    }
}
