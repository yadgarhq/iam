//! Wiring, and one decision worth naming: this service does NOT wait for
//! `iam-db` to be reachable before reporting ready.
//!
//! **THAT SENTENCE WAS FALSE UNTIL `dial` v0.2.0, and the pin move is what made
//! it true.** The twin's own boot is gated — probe, migrate, then listen (D69) —
//! so a `-db` that is not ready has no DNS endpoint behind the headless Service;
//! `yadgar_dial::connect` returned `BalanceError::Dns` for that — CoreDNS
//! answers NXDOMAIN for a headless Service with no ready endpoint, and
//! `connect_with` propagated the resolver's error before it ever reached the
//! empty-answer branch — and the `?` on the dial below turned it into a failed
//! boot. So the cascading outage this
//! paragraph exists to reject is exactly what a `iam-db` that had not finished
//! migrating produced. ADR-0532 made the boot dial lazy: the name is seeded into
//! the balancer and dialled until an address answers, `connect` returns a
//! channel, and the failure moves to the request — which is what the rest of
//! this paragraph always assumed. Blocking this service's startup on the twin
//! would turn one module's slow migration into a cascading outage across
//! everything that depends on it, and under D68 a pod stuck in startup is one
//! the autoscaler cannot help. Failing a request with UNAVAILABLE is
//! recoverable; refusing to start is not.
//!
//! **WHAT IT COSTS, stated rather than left to be found.** The readiness probe
//! is a `tcpSocket` on the gRPC port, so this pod reports Ready as soon as it is
//! listening. With `iam-db` absent that is a pod that is Ready and answers
//! UNAVAILABLE to everything touching a credential or an encrypted
//! personal-data field — which is every RPC this service serves, so the cost of
//! the ruling above is total here too. The probe is deliberately NOT changed to
//! gate on the upstream, and the reason is D69's own scope rather than a
//! preference. **D69's boot-failure rule is about a capability of an engine the
//! module OWNS** — it is why the sequence it names is probe, migrate, then
//! listen, and why the twin is where that sequence lives. This service owns no
//! engine and has nothing to migrate, so the only thing it COULD gate on is an
//! RPC asking the twin whether the twin is up. That is inference by proxy, which
//! D69's first rule refuses by name, and a readiness built on it is the cascade
//! this paragraph rejects, moved one layer up.
//!
//! **The discriminator that generalises is whether a RESTART could change the
//! outcome.** A CA bundle that is unreadable, a client certificate that is not
//! mounted, a host that is not a URI authority: a permanent gap, identical after
//! a restart, so fail boot. An upstream that has not appeared yet: transient,
//! and a restart only costs backoff, so dial lazily and fail the request.
//!
//! What makes the absent state visible instead is `yadgar_dial`'s refresh loop,
//! which logs at ERROR on every tick while a host has NEVER resolved —
//! distinctly from the warning a blip gets. **That line reaches `kubectl logs`
//! and nothing else today**: `dial` exports no metric for the never-resolved
//! state, no chart here ships a `PrometheusRule`, and nothing shipping logs off
//! the node. So the signal exists and is not yet alertable, which is the part of
//! the crash loop this change genuinely removes.
//!
//! The crypto keys are a different story: they are NOT optional and their
//! absence DOES block startup. A service that started without them would boot
//! successfully and then fail every request touching a credential or a personal
//! data field (D72) — a failure mode that looks like a healthy pod until traffic
//! hits it. Failing fast at boot turns that into a CrashLoopBackOff, which is
//! legible, instead of a pod that passes its readiness probe and is wrong.
//!
//! **The TRANSPORT to `iam-db` follows the crypto keys' rule, not the twin's.**
//! Whether `iam-db` is REACHABLE is an outage and degrades a request; whether the
//! CA bundle it is verified against is usable is a deployment mistake, and D69
//! fails boot on those. A bundle that is missing, undecodable or empty therefore
//! stops the process, because the only other thing to do with it is connect in
//! cleartext — and this connection carries every password verification and every
//! encrypted personal-data field in the system.
//!
//! **The transport this service LISTENS on follows the same rule, in the other
//! direction**, and is decided FIRST — before the keys, before the dial. A
//! certificate that is missing, unreadable, undecodable, or paired with a key
//! belonging to something else stops the process rather than binding a plaintext
//! listener. That downgrade is the one failure an operator who asked for
//! encryption cannot see: the pod is Running, the readiness probe passes, and
//! every caller is in the clear.
//!
//! Both transports are OPT-IN and OFF by default, so an unconfigured deployment
//! dials and listens exactly as it always has.
//!
//! **AND BOTH ARE READ EXACTLY ONCE, HERE.** tonic cannot swap a running
//! listener's certificate, so a pod serves its day-0 leaf until it restarts —
//! which is why [`yadgar_iam::rotate`] watches the files this function opened
//! and ends the serve when they change. That is the only mechanism by which
//! this process ever picks up a renewed certificate — and it works only because
//! [`yadgar_lifecycle::shutdown`] hears the signal Kubernetes actually sends.
//! This binary listened for SIGINT alone, which kubelet never sends, so the
//! drain was reached on no rollout at all.

use std::net::SocketAddr;
use std::time::Duration;

use yadgar_lifecycle::{drain_within, shutdown, Drain, DRAIN_BUDGET};

use yadgar_iam::crypto::Keys;
use yadgar_iam::pb::yadgar::iam::v1::iam_service_server::IamServiceServer;
use yadgar_iam::rotate;
use yadgar_iam::serve;
use yadgar_iam::service::{EnrolmentConfig, Iam, ResponseFloors};
use yadgar_iam::upstream;

/// One configuration knob, read from its ONE source, with no compiled-in
/// default behind it (ADR-0569).
///
/// This replaced `env_or(key, default)`, and the deletion is the point rather
/// than the rename: while the helper took a `default` argument, every knob in
/// this binary had somewhere for a fallback to live, and a fallback is invisible
/// at the point of use, survives an upgrade unnoticed, and makes the effective
/// setting depend on which layer a reader happens to inspect.
///
/// AN EMPTY VALUE REFUSES TOO, and with its own message. A set-but-empty
/// variable and an absent one collapsing into a single branch is a defect this
/// estate found three separate times in one week: Helm renders an unset value as
/// `""`, so the empty case is what a nulled chart value actually produces, and it
/// is the one an operator is most likely to hit.
fn env_required(key: &str) -> Result<String, String> {
    match std::env::var(key) {
        Ok(value) if !value.is_empty() => Ok(value),
        Ok(_) => Err(format!(
            "{key} is set but EMPTY. It has no compiled-in default (ADR-0569), so there is \
             nothing to fall back to. The chart renders it; a values override that nulls it \
             produces exactly this."
        )),
        Err(_) => Err(format!(
            "{key} is NOT SET. It has no compiled-in default (ADR-0569): this process reads \
             it from the environment alone and refuses to start rather than invent a value. \
             The chart renders it."
        )),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .json()
        // A DEFAULT, because from_default_env() with RUST_LOG unset enables
        // NOTHING — the service runs silently and its boot sequence, its
        // capability probe result and its errors all vanish. Found by deploying:
        // two replicas were Running and `kubectl logs` returned nothing at all,
        // so the only way to see why one had restarted was the previous
        // container's exit output.
        //
        // A service nobody can observe is one D67 cannot measure either.
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // THE TRANSPORT THIS SERVICE LISTENS ON, decided before anything else. A
    // missing certificate, an unreadable one, a file holding no certificate at
    // all and a key belonging to a different certificate are all refused HERE —
    // never downgraded to the plaintext listener, because a listener that
    // quietly stayed in the clear is the one failure an operator who asked for
    // TLS cannot see.
    //
    // `.to_string()` on the way out for the reason spelled out on the dial
    // below: `Box<dyn Error>` prints with DEBUG, and these messages are
    // sentences naming a file.
    let listen_tls = serve::ServerTls::from_env(serve::LISTEN).map_err(|e| e.to_string())?;
    let mut server = serve::builder(listen_tls.as_ref()).map_err(|e| e.to_string())?;

    // Fails boot loudly if the keys are absent or unreadable — deliberately
    // before the listener binds. See the module doc above for why this one
    // dependency is NOT allowed to degrade gracefully the way iam-db is.
    let keys = Keys::from_env()?;
    tracing::info!("crypto keys loaded; names are encrypted at rest (D72)");

    // The HEADLESS Service name (D23). Resolving it yields every ready pod
    // address rather than one virtual IP.
    let db_host = env_required("IAM_DB_HOST")?;
    let db_port: u16 = env_required("IAM_DB_PORT")?.parse()?;

    // OPT-IN, and OFF unless a deployment asks for it. Nothing configured means
    // the cleartext dial this service has always done. `iam-db` can now serve
    // TLS, also opt-in and also off, so the cut-over is a later change that
    // turns both ends on together and can be reverted on its own.
    //
    // `.to_string()` on the way out, and not decoration: `main` returns
    // `Box<dyn Error>`, which Rust prints with DEBUG — so a bare `?` would put
    // `NoCaFile("IAM_DB")` on the operator's terminal instead of the sentence
    // naming the missing variable and saying why cleartext is not the answer.
    let db_tls = upstream::UpstreamTls::from_env(upstream::IAM_DB).map_err(|e| e.to_string())?;
    let db = upstream::connect(&db_host, db_port, db_tls.as_ref())
        .await
        // Same reasoning, and it matters more here: `BalanceError`'s messages
        // are paragraphs explaining that an empty bundle trusts nobody and that
        // a missing one is not a reason to connect in cleartext. Debug prints
        // the struct and throws all of that away.
        .map_err(|e| e.to_string())?;
    tracing::info!(
        reresolve_secs = yadgar_dial::reresolve_interval().as_secs(),
        tls = db_tls.is_some(),
        "connected to iam-db"
    );

    // How often those files are re-hashed, and how long THIS pod waits before
    // acting on a change. The splay is what stops both replicas exiting inside
    // the same kubelet sync window — a PDB constrains eviction and does not
    // govern a self-exit.
    //
    // STEP 2A OF THE ROTATION-KNOB CUT-OVER (ADR-0569, ADR-0570). The document
    // `yadgarhq/config` renders into the `shared` ConfigMap, mounted at
    // `/etc/yadgar/config/shared/shared.yaml`. There is no compiled-in default
    // behind it any more: an absent, empty, or half-written document refuses
    // the boot and names the file. The chart still sets TLS_ROTATION_POLL_SECS
    // and TLS_ROTATION_SPLAY_MAX_SECS — this binary no longer reads either, but
    // they stay so a rollout that lands this chart before this binary's digest
    // still resolves a schedule on the old one. The runbook is
    // `yadgarhq/deploy`'s MIGRATION_NOTES.md, steps 2a and 2b — NOT this
    // repository's, which has no such section.
    //
    // `.to_string()` on the way out because `Box<dyn Error>` prints with DEBUG
    // and these messages are sentences.
    let config = rotate::Configuration::mounted();
    let schedule = config.schedule().map_err(|e| e.to_string())?;

    // The BINARY installs the exporter, never the library — a library that
    // installs one picks the backend for every service linking it. A failure here
    // is logged and ignored: a service that cannot export metrics should still
    // serve traffic, which is D25's rule applied to the metrics path too.
    let metrics_addr: SocketAddr = env_required("METRICS_LISTEN")?.parse()?;
    if let Err(e) = yadgar_telemetry::metrics::install_prometheus(metrics_addr) {
        tracing::warn!(error = %e, "metrics endpoint unavailable; continuing without it");
    }

    // The broker, for D72's cache invalidation. Does NOT gate startup: a broker
    // outage must not become an authentication outage, and the TTL is the
    // backstop for exactly this. The warning at connect time is what makes the
    // degraded state visible rather than assumed.
    //
    // THE CREDENTIAL IS READ BEFORE THE CONNECTION IS ATTEMPTED, and its absence
    // is the one thing here that DOES gate startup. The distinction is the same
    // one D69 draws everywhere else: an unreachable broker is an outage of one
    // component, and a deployment that named a credential it cannot produce is a
    // mistake somebody made. Connecting anonymously at that point would be the
    // silent fall back to an unauthenticated broker this exists to stop, and it
    // would look exactly like success.
    //
    // NOT `required` IN THE CHART EITHER: unset means the broker asks for no
    // password, which is what every deployment of this was until ledger 518 and
    // is what lets this image roll before the broker's authorization block does.
    //
    // THE DECISION ITSELF LIVES IN `boot`, not here, because nothing in a binary
    // entry point is reachable from a test — and the outcome of getting this
    // wrong is either a refusal or an anonymous connection that looks healthy.
    // See [`yadgar_iam::boot::nats_credentials`] for the four half-configured
    // states it refuses.
    let nats_credentials = yadgar_iam::boot::nats_credentials(|key| std::env::var(key).ok())?;
    // WARNS AND DEGRADES ONE RPC. It does NOT fail boot, and the difference
    // matters more here than anywhere else in this file: `iam` is the
    // authentication plane. A CrashLoopBackOff would stop `Login` at once and
    // every dependent service's credential resolution as soon as the gateway's
    // 300s cache expired — an estate-wide outage caused by a value that belongs
    // to ONE administrative RPC.
    //
    // The contract's rule is about the TOKEN — never mint one carrying an empty
    // gateway — and `IssueEnrolment` keeps it whole by refusing with
    // FAILED_PRECONDITION. That is loud to the operator who calls it, and this
    // warning is loud to the operator who deploys it; between them nothing is
    // silent, and nothing else stops working.
    //
    // Contrast the crypto keys above, which DO fail boot: without them every
    // request touching a credential fails, so there is no reduced service left
    // to protect. Here there is.
    let enrolment = match EnrolmentConfig::from_env() {
        Ok(config) => {
            tracing::info!("enrolment tokens carry this deployment's gateway and CA (D73)");
            Some(config)
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "IssueEnrolment is UNAVAILABLE on this deployment and will refuse \
                 with FAILED_PRECONDITION; everything else, ResolveCredential and \
                 Login included, is unaffected. Set ENROLMENT_GATEWAY to enable it."
            );
            None
        }
    };

    // THE WATCH SET, ASSEMBLED FROM THE RESOLVED CONFIGURATION IN ONE PLACE AND
    // BEFORE ANYTHING IT NAMES IS MOVED AWAY (ADR-0523). Every entry is hashed
    // as `watch_set` folds it, and the fold happens INSIDE boot: deferring the
    // first reading to the watcher's first poll would put the rest of boot
    // inside a window where a kubelet swap quietly becomes the baseline, and the
    // real rotation would never be noticed.
    //
    // FIVE MATERIALS, THREE OF WHICH ARE NOT TRANSPORT. The broker password is a
    // file this process read at boot, mounted as a directory so it can rotate
    // and about to be baked into a `Client` cached for the life of the process;
    // the enrolment CA is token payload the chart mounts the same way. ADR-0523's
    // rule is about provenance rather than payload, so both are watched exactly
    // as the certificates are.
    //
    // THE MOUNTED CONFIGURATION DOCUMENT JOINS THE SAME SET, as a fifth
    // `Material` and the only one that is never absent (step 2a) — `config` is
    // `&Configuration`, not `Option<&Configuration>`. An operator editing
    // `shared.yaml` now restarts this pod exactly as editing a CA bundle would.
    //
    // ONE CALL, AND THE SAME ONE A TEST MAKES. This used to be four builder calls
    // scattered across this function, up to a hundred and fifty lines apart,
    // where nothing could reach them: no test spawns this binary, so deleting any
    // one of them compiled and passed everything. The list lives in
    // `rotate::watch_set` now and `tests/assembly.rs` calls it.
    let watch_inputs = rotate::watch_set(
        listen_tls.as_ref(),
        db_tls.as_ref(),
        nats_credentials.as_ref(),
        enrolment.as_ref(),
        &config,
    );

    // AFTER THE EXPORTER, NEVER BEFORE IT: a value recorded while there is no
    // recorder is a value nobody ever sees. This is the half of the rotation work
    // that makes a failure LOUD — if the watcher below dies, this gauge still
    // shows the loaded leaf ageing out.
    watch_inputs.export_not_after();

    let invalidator = yadgar_iam::invalidate::Invalidator::connect(
        std::env::var("NATS_URL").ok().as_deref(),
        nats_credentials,
    )
    .await;

    // The shortest time `Login` may answer in, whatever it found. Argon2id takes
    // its cost from the PHC string it is verifying, so a stored hash provisioned
    // at parameters other than this build's makes the response time report which
    // usernames exist — see `crypto::Keys::verify_password`.
    //
    // PARSED, NOT SALVAGED, AND NOT INVENTED EITHER: the chart is the one source
    // of this number (ADR-0569), so an absent, empty or mistyped value fails the
    // boot naming the variable. There is no longer a compiled-in floor to fall
    // back to. Substituting one silently would leave an operator who believes
    // they raised the floor running the old one, and a security control nobody
    // can tell is misconfigured is the failure this floor's own warning exists
    // to prevent. `service::DEFAULT_LOGIN_RESPONSE_FLOOR` survives as the
    // MEASUREMENT the chart's value was calibrated from — documentation, read by
    // no knob path.
    let login_response_floor =
        Duration::from_millis(env_required("LOGIN_RESPONSE_FLOOR_MS")?.parse()?);

    // ITS OWN VALUE, because `RedeemEnrolment` legitimately does more work — two
    // Argon2id operations and a further round trip — and a floor sized for
    // `Login` would be exceeded by every successful redemption, turning the
    // warning that says "raise this" into one that fires on every call.
    let redeem_response_floor =
        Duration::from_millis(env_required("REDEEM_RESPONSE_FLOOR_MS")?.parse()?);
    tracing::info!(
        login_floor_ms = login_response_floor.as_millis() as u64,
        redeem_floor_ms = redeem_response_floor.as_millis() as u64,
        "Login and RedeemEnrolment answer no sooner than their response-time floors"
    );

    let addr: SocketAddr = env_required("LISTEN")?.parse()?;

    // ARMED BEFORE THE SERVER IS SPAWNED, and that ordering is the fix rather
    // than an accident of where the line sits. `yadgar_lifecycle::shutdown`
    // installs both signal handlers when it is CALLED — a SIGTERM arriving between here and
    // the first poll of the future would otherwise take the process's default
    // disposition and kill it outright.
    let signals = shutdown().map_err(|e| {
        format!("the SIGTERM and SIGINT handlers could not be installed: {e}. Refusing to start: a server that cannot hear SIGTERM cannot drain, and Kubernetes ends every pod with one")
    })?;
    // `tls` is recorded because "is this listener encrypted?" must be answerable
    // from the boot log rather than inferred from which variables somebody
    // believes they set.
    tracing::info!(
        %addr,
        tls = listen_tls.is_some(),
        watching = watch_inputs.watched().len(),
        rotation_poll_secs = schedule.poll().as_secs(),
        rotation_splay_max_secs = schedule.splay_max().as_secs(),
        drain_budget_secs = DRAIN_BUDGET.as_secs(),
        "iam listening"
    );

    // THE SERVER IS SPAWNED WITH A ONESHOT AS ITS SHUTDOWN FUTURE, and the wait
    // happens OUTSIDE it. `drain_within` starts the budget's clock when
    // shutdown is REQUESTED; a `timeout` wrapped round the serving future itself
    // would fix its deadline at boot and end the process 25 seconds later on
    // every boot, having asked nothing to stop. That defect shipped on this
    // branch, and `yadgar-lifecycle`'s own `tests/drain.rs` is what keeps it
    // dead.
    let (ask_to_stop, stop_requested) = tokio::sync::oneshot::channel();
    let serving = tokio::spawn(
        server
            .add_service(IamServiceServer::new(Iam::new(
                keys,
                db,
                invalidator,
                ResponseFloors {
                    login: login_response_floor,
                    redeem: redeem_response_floor,
                },
                enrolment,
            )))
            // ONE DRAIN PATH, TWO REASONS TO TAKE IT. `serve_with_shutdown` stops
            // accepting and lets in-flight calls finish, so the rotation exit
            // gets the same drain a signal does rather than a second mechanism
            // beside it.
            .serve_with_shutdown(addr, async {
                let _ = stop_requested.await;
            }),
    );

    // WHAT ENDS THE SERVE, and nothing else does.
    let stop = async {
        tokio::select! {
            // SIGTERM and SIGINT, already armed above. SIGTERM is the one
            // Kubernetes sends, and the one this binary used to ignore.
            () = signals => {}
            // `rotate::watch` resolves ONLY when it has read a change, and never
            // at all when there is nothing to watch.
            () = rotate::watch(watch_inputs, schedule) => {}
        }
    };

    match drain_within(serving, ask_to_stop, stop, DRAIN_BUDGET).await {
        Drain::Finished(result) => result?,
        // EXIT 0 ANYWAY. The restart is the point; a drain that overran is worth
        // an error in the log, not a CrashLoopBackOff on top of it.
        Drain::Overran => tracing::error!(
            budget_secs = DRAIN_BUDGET.as_secs(),
            "the drain did not finish within its budget; ending anyway with calls still in \
             flight. A request blocked this long is the thing to look at"
        ),
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::env_required;

    // Each test owns a UNIQUE key. `std::env` is process-global and `cargo test`
    // runs these on threads of one process, so tests sharing a variable name
    // would pass or fail depending on scheduling.

    /// The case a naive test omits, and the only one that proves the value is
    /// USED. A test that merely asserts "boot succeeds" passes just as happily
    /// with a compiled-in default still in place behind the read.
    #[test]
    fn a_set_value_is_returned_verbatim() {
        std::env::set_var("YADGAR_TEST_IAM_REQUIRED_PRESENT", "0.0.0.0:50052");
        assert_eq!(
            env_required("YADGAR_TEST_IAM_REQUIRED_PRESENT").as_deref(),
            Ok("0.0.0.0:50052")
        );
    }

    #[test]
    fn an_absent_knob_refuses_and_names_itself() {
        std::env::remove_var("YADGAR_TEST_IAM_REQUIRED_ABSENT");
        let err = env_required("YADGAR_TEST_IAM_REQUIRED_ABSENT").unwrap_err();
        assert!(
            err.contains("YADGAR_TEST_IAM_REQUIRED_ABSENT"),
            "the refusal must name the knob, got: {err}"
        );
        assert!(err.contains("NOT SET"), "got: {err}");
    }

    /// **THE CASE THAT DISCRIMINATES.** Helm renders an unset value as `""`, so
    /// a nulled chart value arrives here as set-but-empty rather than as absent.
    /// An implementation that collapses the two into one branch is the defect
    /// this estate found three separate times in one week, so the messages are
    /// asserted to DIFFER rather than merely to exist.
    #[test]
    fn an_empty_knob_refuses_with_its_own_message() {
        std::env::set_var("YADGAR_TEST_IAM_REQUIRED_EMPTY", "");
        std::env::remove_var("YADGAR_TEST_IAM_REQUIRED_EMPTY_ABSENT");
        let empty = env_required("YADGAR_TEST_IAM_REQUIRED_EMPTY").unwrap_err();
        let absent = env_required("YADGAR_TEST_IAM_REQUIRED_EMPTY_ABSENT").unwrap_err();
        assert!(empty.contains("set but EMPTY"), "got: {empty}");
        assert!(
            empty.replace("YADGAR_TEST_IAM_REQUIRED_EMPTY", "K")
                != absent.replace("YADGAR_TEST_IAM_REQUIRED_EMPTY_ABSENT", "K"),
            "empty and absent must not share one message"
        );
    }
}
