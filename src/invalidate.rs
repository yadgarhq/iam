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

/// What this service presents to the broker.
///
/// **A pair, and both halves come from the deployment.** The user names an
/// account in the broker's `authorization` block and the password is read from a
/// mounted Secret — see `main`, which refuses to start if the deployment asked
/// for a credential and cannot produce one.
///
/// `Debug` is written by hand rather than derived. A derived one would print the
/// password into any log line, panic message or test failure that formatted the
/// struct, which is how a credential ends up in a place nobody meant to put it.
#[derive(Clone)]
pub struct Credentials {
    pub user: String,
    pub password: String,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("user", &self.user)
            .field("password", &"<redacted>")
            .finish()
    }
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
    /// Every publish this instance made, recorded so a test can assert that a
    /// code path publishes AT ALL.
    ///
    /// Compiled only under `cfg(test)`, so the deployed type is unchanged. It
    /// exists because the alternative — running a broker in the test suite — is
    /// how "does `AddTeamMember` publish?" stays untested, which is precisely the
    /// question that went unanswered until a newly granted team took five minutes
    /// to arrive.
    #[cfg(test)]
    published: std::sync::Arc<std::sync::Mutex<Vec<(&'static str, String)>>>,
}

impl Invalidator {
    /// Connect, or return a publisher that does nothing.
    ///
    /// A broker that cannot be reached at boot does not stop the service: `iam`
    /// still authenticates, and refusing to start would turn a broker outage into
    /// an authentication outage. The cost is recorded in the log, not hidden.
    ///
    /// `credentials` is what this service presents. `None` means the broker asks
    /// for none, and it is a real state rather than an omission — it is what
    /// every deployment of this was before ledger 518, and it is what lets this
    /// image be rolled BEFORE the broker gains an `authorization` block. The
    /// state that is NOT allowed is "the deployment named a credential and could
    /// not produce one", and that never reaches here: `main` exits at boot rather
    /// than calling this with `None`, because connecting anonymously at that
    /// point is precisely the silent fall back to an unauthenticated connection
    /// this exists to stop.
    ///
    /// # A refused credential is not a broker outage, and the log says which
    ///
    /// Both end in a publisher that publishes nothing, because the availability
    /// argument above applies to both: `iam` is the authentication plane and must
    /// not stop authenticating over the broker. They are told apart in the log,
    /// which is the only place the difference can be acted on. An outage ends by
    /// itself; a rejected password does not, and an operator who reads
    /// "cannot reach the broker" for a wrong password goes looking for a network
    /// fault that is not there.
    pub async fn connect(url: Option<&str>, credentials: Option<Credentials>) -> Self {
        let Some(url) = url.filter(|u| !u.is_empty()) else {
            tracing::warn!(
                "no broker configured: cache invalidation will NOT be published, so a \
                 revoked credential may be honoured until its TTL expires (D72)"
            );
            return Self::with(None);
        };
        // BUILT FROM THE PAIR, never spliced into the URL. `nats://user:pass@host`
        // carries a password only URL-encoded, so a password containing `@`, `/`
        // or `#` would be silently truncated and a DIFFERENT one sent than the one
        // in the Secret — a WRONGPASS whose cause is invisible at every layer.
        let options = match &credentials {
            Some(c) => async_nats::ConnectOptions::with_user_and_password(
                c.user.clone(),
                c.password.clone(),
            ),
            None => async_nats::ConnectOptions::new(),
        };
        match options.connect(url).await {
            Ok(client) => {
                tracing::info!(
                    %url,
                    // WHETHER, never WHAT. This log is shipped.
                    authenticated = credentials.is_some(),
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
                Self::with(Some(client))
            }
            // SEPARATED FROM THE OUTAGE ARM, and it is the whole reason this
            // match has two error arms. See the section on this method.
            Err(e) if e.kind() == async_nats::ConnectErrorKind::AuthorizationViolation => {
                tracing::error!(
                    %url, error = %e,
                    "the broker REFUSED this service's credential, so cache invalidation will \
                     NOT be published and revocations will be honoured late. This is a \
                     deployment error rather than an outage: it does not recover on its own. \
                     Check NATS_USER and NATS_PASSWORD_FILE against the broker's authorization \
                     block."
                );
                Self::with(None)
            }
            Err(e) => {
                tracing::error!(
                    %url, error = %e,
                    "cannot reach the broker: cache invalidation will NOT be published \
                     until it recovers, and revocations will be honoured late"
                );
                Self::with(None)
            }
        }
    }

    /// Whether this instance holds a live connection to the broker.
    ///
    /// **A test asserting that a credential was CONFIGURED would pass against a
    /// broker that ignored it.** This is what lets a test assert the outcome
    /// instead: the same fake broker refuses one connection and accepts the
    /// other, and only the pair distinguishes an authenticated broker from an
    /// open one. It is `pub` rather than `cfg(test)` for that reason — the
    /// property is proved from `tests/`, which compiles against the shipped
    /// crate.
    pub fn is_publishing(&self) -> bool {
        self.client.is_some()
    }

    fn with(client: Option<async_nats::Client>) -> Self {
        Self {
            client,
            #[cfg(test)]
            published: std::sync::Arc::default(),
        }
    }

    /// What this instance published, in order. Clones share the log, so a handler
    /// holding a clone is observable from the test that built it.
    #[cfg(test)]
    pub fn published(&self) -> Vec<(&'static str, String)> {
        self.published.lock().expect("the publish log").clone()
    }

    /// Publish, and never fail the caller.
    async fn publish(&self, subject: &'static str, payload: String) {
        // Recorded BEFORE the branch, so what a test sees does not depend on
        // whether a broker happened to be configured.
        #[cfg(test)]
        self.published
            .lock()
            .expect("the publish log")
            .push((subject, payload.clone()));

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
        let inv = Invalidator::connect(None, None).await;
        inv.credential_revoked("yadgar:user:x").await;
        inv.teams_changed("yadgar:user:x").await;
        assert!(!inv.is_publishing());
    }

    #[tokio::test]
    async fn an_unreachable_broker_does_not_panic_or_block() {
        let inv = Invalidator::connect(Some("nats://127.0.0.1:1"), None).await;
        inv.credential_revoked("yadgar:user:y").await;
        assert!(!inv.is_publishing());
    }

    #[test]
    fn a_credential_never_prints_itself() {
        // The one place a password reaches a formatter. A derived `Debug` would
        // put it into every panic message and test failure that touched the
        // struct, which is how a secret ends up in a log nobody meant to write
        // it to.
        let c = Credentials {
            user: "iam".into(),
            password: "sentinel-of-the-nats-password".into(),
        };
        let printed = format!("{c:?}");
        assert!(
            !printed.contains("sentinel-of-the-nats-password"),
            "{printed}"
        );
        assert!(printed.contains("iam"), "{printed}");
    }

    #[test]
    fn subjects_share_a_namespace_so_one_wildcard_can_catch_them() {
        assert!(subject::CREDENTIAL_REVOKED.starts_with("yadgar.iam."));
        assert!(subject::TEAMS_CHANGED.starts_with("yadgar.iam."));
    }
}
