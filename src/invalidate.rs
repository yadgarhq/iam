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
//!
//! # A refused publish is silent, and why this module has an event callback
//!
//! **The `Err` arm in `Invalidator::publish` is very nearly unreachable, and
//! everything below follows from that.** It was written as the loud half of this
//! module. It is not: `Client::publish` returns `Err` only when its command
//! channel closes, that channel closes only when the connection handler task
//! ends, and that task ends only when `Connector::connect` returns `Err` — which
//! it does for exactly one reason, `MaxReconnects`.
//!
//! A wrong password on the BOOT dial is genuinely loud, and it is the one case
//! that is: the broker answers `-ERR 'Authorization Violation'`, closes the
//! connection, and `connect` returns
//! [`async_nats::ConnectErrorKind::AuthorizationViolation`], which the arm below
//! reports before any client exists. Neither of the two failures that happen to
//! a RUNNING process reaches a log by itself:
//!
//! - **A refused publish.** The broker leaves the connection OPEN and answers
//!   `-ERR 'Permissions Violation for Publish to "<subject>"'` asynchronously,
//!   while [`async_nats::Client::publish`] has already returned `Ok(())` — it
//!   resolves when the command is queued locally, and NATS acknowledges no `PUB`.
//! - **A wrong password on a RECONNECT**, which is what a rotated Secret
//!   produces. `max_reconnects` defaults to `None` (`options.rs:103`) and this
//!   module never sets it, so `Connector::connect` matches the
//!   `AuthorizationViolation` under its `other =>` arm and RETRIES FOR EVER
//!   (`connector.rs:249-268`). Publishes keep queueing into the 2048-slot buffer
//!   and keep returning `Ok(())`.
//!
//! So an operator told to grep for `invalidation NOT published` finds nothing in
//! either case. **This callback is what surfaces both** — the ERROR below for a
//! refusal, and a `Disconnected` warning followed by an `authorization violation`
//! `ClientError` on every retry for a stale password. The rotation watch set in
//! `crate::rotate` is what ends the second state; this is what makes it visible
//! while it lasts.
//!
//! That gap was latent until it was not. This account published on `>` until
//! `deploy#18` scoped it to publish-only on the two subjects above, and nothing
//! that cannot be refused can be refused silently. Now one typo in the broker's
//! `publish.allow` list produces an `iam` that logs "publishing cache
//! invalidation" at INFO, reports success on every revocation, and invalidates
//! nothing — for ever. **Every revoked credential then stays usable at every
//! gateway for the whole of its D72 cache TTL**, which is precisely the state
//! this module exists to prevent.
//!
//! `on_event` closes it. The `-ERR` arrives as an
//! [`async_nats::Event::ServerError`]. `gateway` registered a callback for the
//! SUBSCRIBE side of the same problem and this is its twin.
//!
//! **THE DISCRIMINATOR IS THE SUBJECT, never the wording.** A real
//! `nats-server` says `Permissions Violation for Publish to "<subject>"` on this
//! side and `... for Subscription to ...` on the gateway's, and neither phrase
//! is a stable interface. `on_event` matches on the SUBJECT names this crate
//! owns, which are, so a server that rewords its `-ERR` changes nothing here.
//!
//! **WHAT `async-nats` 0.50 PRINTS BY ITSELF, precisely, because `gateway`'s
//! comment gets this wrong and the difference decides whether a callback is
//! worth having.** It logs the frame twice: once at `debug!` in the connection
//! handler, and once at `info!` for every event it dispatches (`lib.rs:1105`).
//! So the claim "it vanishes below the level these pods run at" is not true
//! here — the broker's words DO reach an `info` log. What does not reach it is
//! anything an operator can act on: the line is a bare `event: server error:
//! ...` at the same level as the ordinary connection chatter around it, with no
//! statement that invalidation has stopped and no remedy. This callback supplies
//! the level that makes it findable and the sentence that says what to fix.
//!
//! **IT LOGS AND DOES NOTHING ELSE, and that is the difference from `gateway`'s.**
//! The gateway's callback drives a channel, because a forbidden subscription must
//! END the subscription it holds and be redialled. There is no such object here:
//! a publish is fire-and-forget, so there is nothing to tear down and nothing a
//! later publish could usefully consult. A flag no code reads would be a second
//! mechanism dressed as one.

use crate::upstream;

mod redial;
pub mod transport;

pub use redial::RETRY;

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
    ///
    /// **`SetUserAdmin` PUBLISHES ON THIS SUBJECT AND REVOKES NOTHING, AND THE
    /// NAME THEREFORE OVER-STATES WHAT HAPPENED.** A promotion or a demotion
    /// needs exactly the eviction this subject already drives — the gateway
    /// lands both subjects on `Cache::forget_user` — and the broker permits this
    /// service to publish only the two named here (`deploy/infra/nats.yaml`), so
    /// a third subject would be refused asynchronously while `publish` returned
    /// `Ok(())`: no invalidation AND no record. A mislabelled record beats an
    /// absent one, and that is the whole of the argument.
    ///
    /// **THE COST IS REAL AND IS NOT DEFERRED TO A FUTURE READER.** There is no
    /// audit store on this boundary, so the gateway's eviction line — which
    /// carries the subject as a field — is one of the only records an
    /// administrative act leaves. Every promotion emits one saying a credential
    /// was revoked. **THIS SUBJECT IS AN EVICTION SIGNAL AND NEVER EVIDENCE
    /// THAT A REVOCATION OCCURRED**, and a consumer that reads it as evidence is
    /// reading it wrongly. Renaming it — or splitting an `admin-changed` subject
    /// out — is a `deploy` broker-permission change first and this constant
    /// second, in that order, or the failure above is what ships.
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
///
/// **THE PATH IS KEPT BESIDE THE VALUE, and it is not decoration.** ADR-0523's
/// rule is that every file the process read at boot is watched, and the file
/// this password came from is one — mounted as a DIRECTORY by the chart
/// precisely so it can rotate. `crate::rotate::Inputs` is built from the
/// configuration that was already resolved and NEVER by reading the environment
/// a second time, because a second reading could name a different file from the
/// one actually opened. So the resolved credential has to carry its own
/// provenance, or the watch set cannot include it without breaking that rule.
///
/// A path is not a secret — the chart puts it in `NATS_PASSWORD_FILE`, which is
/// visible in `kubectl describe pod` — so it is printed by `Debug` while the
/// password stays redacted. That is the same split D80 draws everywhere: the
/// location travels, the value does not.
#[derive(Clone)]
pub struct Credentials {
    pub user: String,
    pub password: String,
    /// The file the password was read from, for the rotation watch set.
    pub password_file: std::path::PathBuf,
}

impl Credentials {
    /// The file this password was read from.
    ///
    /// The accessor `Credentials`'s `Material` implementation reads, so the set is
    /// built the same way as every other member: from the resolved
    /// configuration, through a method on it.
    pub fn password_file(&self) -> &std::path::Path {
        &self.password_file
    }
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("user", &self.user)
            .field("password", &"<redacted>")
            .field("password_file", &self.password_file)
            .finish()
    }
}

/// A publisher, or nothing, or a publisher still waiting for its broker.
///
/// **THREE STATES, NOT TWO** (ledger 1420). No broker configured is a
/// legitimate state for a local run and NOT for a deployment — `main` warns
/// loudly at boot rather than treating a missing broker as normal, because a
/// gateway cache with no invalidation path is the failure D72 names. A
/// configured broker whose first dial failed is the third: [`redial`] fills
/// `client` once a dial succeeds, and every clone sees it, because the slot is
/// shared rather than copied — `Iam::new` holds a clone taken at boot.
#[derive(Clone)]
pub struct Invalidator {
    /// Set at most once: by the boot dial, or by the redial that follows a
    /// failed one. After that `async-nats` reconnects underneath it.
    client: std::sync::Arc<std::sync::OnceLock<async_nats::Client>>,
    /// Whether a broker URL was configured at all, so a dropped publish says
    /// which of the two absences it is.
    configured: bool,
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

/// How long one dial may take before it counts as unreachable.
///
/// **Set here rather than left to `async-nats`, because [`Invalidator::connect`]
/// is awaited from `main` before the listener binds** — so whatever bounds
/// this bounds how long this service takes to start serving when the
/// broker's address accepts a connection and then says nothing. The
/// library's own default happens to be five seconds today, and a default in
/// a dependency is not a bound this repository gets to rely on.
///
/// 965 CENSUS ROW M10 (CC): mirrors `gateway`'s `invalidate/broker.rs`
/// `CONNECT_TIMEOUT` exactly — same value, same builder — because the two
/// boot dials are the same shape against the same broker, and a repository
/// that left this one unmarked while the other set it explicitly is exactly
/// the drift 965 exists to name.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// Everything [`Invalidator::connect`] builds before it dials: the pair or
/// the anonymous default, bounded by [`CONNECT_TIMEOUT`], with the event
/// callback that surfaces a refused publish — AND, from B-N3, the broker
/// hop's transport. Pulled out so a test can inspect what this function
/// alone produces — `connect` itself does nothing further to it before
/// `.connect(url).await` — rather than re-deriving the same expression and
/// asserting it equals itself.
///
/// **THE TLS HALF LIVES IN [`transport::connect_options`], not here** (file
/// size). This function adds the one thing that module cannot: the timeout
/// and the event callback, both independent of TLS.
fn connect_options(
    credentials: &Option<Credentials>,
    tls: &Option<upstream::UpstreamTls>,
) -> async_nats::ConnectOptions {
    transport::connect_options(credentials, tls)
        // BOUNDED HERE. See `CONNECT_TIMEOUT`: this is awaited before the
        // listener binds, so an unbounded dial is an unbounded boot.
        .connection_timeout(CONNECT_TIMEOUT)
        // WITHOUT THIS THE WORST FAILURE IN THIS MODULE IS INVISIBLE. See
        // the module comment: a refused PUBLISH leaves the connection
        // open, is answered asynchronously after `publish` has already
        // returned `Ok`, and is logged by `async-nats` itself at `debug!`.
        .event_callback(|event| async move { on_event(event) })
}

impl Invalidator {
    /// Connect, or return a publisher that publishes once a redial connects, or
    /// one that does nothing.
    ///
    /// A broker that cannot be reached at boot does not stop the service: `iam`
    /// still authenticates, and refusing to start would turn a broker outage into
    /// an authentication outage (D69/ADR-0555). The cost is recorded in the log,
    /// not hidden — and it ENDS: the outage arm hands the dial to [`redial`],
    /// which retries every [`RETRY`] in the background and starts publishing
    /// once one succeeds. Before ledger 1420 that arm returned a publisher that
    /// published nothing for the life of the process, which is what PB-3 hit
    /// when both pods booted during the broker's roll.
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
    /// Both boot into a publisher that publishes nothing yet, because the availability
    /// argument above applies to both: `iam` is the authentication plane and must
    /// not stop authenticating over the broker. They are told apart in the log,
    /// which is the only place the difference can be acted on. An outage ends by
    /// itself; a rejected password does not, and an operator who reads
    /// "cannot reach the broker" for a wrong password goes looking for a network
    /// fault that is not there.
    ///
    /// **THE REFUSED ARM IS TERMINAL, AND THAT IS WHY THIS DOES NOT USE
    /// `retry_on_initial_connect`.** With it set, `async-nats` 0.50 returns a
    /// client before any handshake (`lib.rs:1081`) and retries the first dial
    /// inside `Connector::connect`, whose `other =>` arm swallows
    /// `AuthorizationViolation` and loops for ever while `max_reconnects` is its
    /// default `None` (`connector.rs:249-268`, `options.rs:103`). So the boot
    /// could no longer tell a refusal from an outage, and a wrong password
    /// would dial the broker for the life of the process. `gateway` retries a
    /// refusal at a 60-second interval; this service does not, because the
    /// rotation watch set in `crate::rotate` restarts it when the Secret it
    /// would need changes.
    ///
    /// `tls` is the broker hop's transport (B-N3, ADR-0852): `None` dials in
    /// cleartext exactly as this did before; `Some` is
    /// [`transport::broker_tls`]'s resolved, boot-checked configuration.
    /// `main` reads `NATS_TLS_ENABLED` and refuses the boot itself; this
    /// function never reads the environment, so a test can hand it any pair.
    pub async fn connect(
        url: Option<&str>,
        credentials: Option<Credentials>,
        tls: Option<upstream::UpstreamTls>,
    ) -> Self {
        let Some(url) = url.filter(|u| !u.is_empty()) else {
            tracing::warn!(
                "no broker configured: cache invalidation will NOT be published, so a \
                 revoked credential may be honoured until its TTL expires (D72)"
            );
            return Self::with(false);
        };
        let options = connect_options(&credentials, &tls);
        let this = Self::with(true);
        match options.connect(url).await {
            Ok(client) => {
                redial::connected(url, &credentials, &tls);
                let _ = this.client.set(client);
            }
            // SEPARATED FROM THE OUTAGE ARM, and it is the whole reason this
            // match has two error arms. See the section on this method.
            Err(e) if e.kind() == async_nats::ConnectErrorKind::AuthorizationViolation => {
                redial::refused(url, &e, &tls);
            }
            // A REFUSED TLS HANDSHAKE ARRIVES HERE TOO: async-nats has no TLS
            // error kind of its own (gateway#105 measured the same thing), so
            // a wrong CA or a broker that does not speak TLS reaches this arm
            // as a plain I/O error. `tls` on the log line and the wording
            // below are what let an operator tell the two apart without
            // reading the wrapped error.
            Err(e) => {
                tracing::error!(
                    %url, error = %e, tls = tls.is_some(),
                    "cannot reach the broker, or the TLS handshake with it failed: cache \
                     invalidation is NOT published until a dial succeeds, and revocations are \
                     honoured late until then. Retrying every {} seconds.",
                    RETRY.as_secs()
                );
                tokio::spawn(redial::until_connected(
                    url.to_string(),
                    credentials,
                    tls,
                    std::sync::Arc::clone(&this.client),
                ));
            }
        }
        this
    }

    /// Whether this instance has connected to the broker: at boot, or on a
    /// redial since. It stays `true` across the reconnects `async-nats` makes
    /// underneath an established client — those are reported by [`on_event`].
    ///
    /// **A test asserting that a credential was CONFIGURED would pass against a
    /// broker that ignored it.** This is what lets a test assert the outcome
    /// instead: the same fake broker refuses one connection and accepts the
    /// other, and only the pair distinguishes an authenticated broker from an
    /// open one. It is `pub` rather than `cfg(test)` for that reason — the
    /// property is proved from `tests/`, which compiles against the shipped
    /// crate.
    pub fn is_publishing(&self) -> bool {
        self.client.get().is_some()
    }

    fn with(configured: bool) -> Self {
        Self {
            client: std::sync::Arc::default(),
            configured,
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

        let Some(client) = self.client.get() else {
            // TRUE ON BOTH BRANCHES, which the single line this replaces was not:
            // a configured broker that has not answered yet is not "no broker".
            if self.configured {
                tracing::warn!(
                    subject, %payload,
                    "not connected to the broker yet: invalidation not published"
                );
            } else {
                tracing::warn!(subject, %payload, "no broker: invalidation not published");
            }
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

/// Everything the broker says about a connection after it is established.
///
/// **`async-nats` logs these at `debug!` and these pods run at `info`**, so
/// without this function they do not exist. The one that matters is
/// [`async_nats::Event::ServerError`]: a publish permission violation arrives
/// there, leaves the connection open, and is otherwise indistinguishable from a
/// service whose invalidations are all landing.
fn on_event(event: async_nats::Event) {
    match event {
        async_nats::Event::ServerError(e) => {
            let error = e.to_string();
            // NAMED SUBJECTS ONLY. A `-ERR` about anything else is still worth an
            // operator's attention and still logged at ERROR, but it is not a
            // statement that THIS service's invalidations are being dropped, and
            // a remedy naming the publish allow-list would send somebody to the
            // wrong file.
            if error.contains(subject::CREDENTIAL_REVOKED) || error.contains(subject::TEAMS_CHANGED)
            {
                tracing::error!(
                    error,
                    "the broker REFUSED this service's publish, so NO invalidation is \
                     delivered and a revoked credential is honoured until its cache entry \
                     expires (D72). The connection stays OPEN, `publish` returned Ok, and \
                     nothing else reports this. It is a deployment error rather than an \
                     outage: check the publish permissions for this account against {} and \
                     {}.",
                    subject::CREDENTIAL_REVOKED,
                    subject::TEAMS_CHANGED
                );
            } else {
                tracing::error!(error, "the broker reported an error on this connection");
            }
        }
        // LOUD, because the window it opens is the one this module exists to
        // close: nothing published while it is open is delivered, and no caller
        // is told. `async-nats` reconnects underneath this, so the `Connected`
        // below is the end of the window.
        async_nats::Event::Disconnected => tracing::warn!(
            "disconnected from the broker; no invalidation is being published until it reconnects"
        ),
        async_nats::Event::Connected => tracing::info!("connected to the broker"),
        async_nats::Event::ClientError(e) => {
            tracing::warn!(error = %e, "the broker connection reported a client error");
        }
        other => tracing::info!(event = %other, "broker event"),
    }
}

#[cfg(test)]
mod tests;
