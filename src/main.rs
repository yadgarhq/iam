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

use tonic::transport::Server;
use yadgar_lifecycle::{drain_within, shutdown, Drain, DRAIN_BUDGET};

use yadgar_iam::boot;
use yadgar_iam::crypto::Keys;
use yadgar_iam::pb::yadgar::iam::v1::iam_service_server::IamServiceServer;
use yadgar_iam::rotate;
use yadgar_iam::serve;
use yadgar_iam::service::Iam;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    boot::logging();

    let (listen_tls, server) = boot::listener()?;

    // Fails boot loudly if the keys are absent or unreadable — deliberately
    // before the listener binds. See the module doc above for why this one
    // dependency is NOT allowed to degrade gracefully the way iam-db is.
    let keys = Keys::from_env()?;
    tracing::info!("crypto keys loaded; names are encrypted at rest (D72)");

    let (db, db_tls) = boot::iam_db().await?;

    let (config, schedule) = boot::rotation()?;

    boot::metrics()?;

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
    let nats_credentials = boot::nats_credentials(|key| std::env::var(key).ok())?;

    let enrolment = boot::enrolment();

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

    let floors = boot::response_floors()?;

    let addr: SocketAddr = boot::env_required("LISTEN")?.parse()?;

    serve_and_drain(
        server,
        addr,
        Iam::new(keys, db, invalidator, floors, enrolment),
        listen_tls.as_ref(),
        watch_inputs,
        schedule,
    )
    .await
}

/// Serve until a signal or a rotation ends it, then drain within the budget.
///
/// A SEPARATE FUNCTION AND NOT A `boot` ONE. Everything [`yadgar_iam::boot`]
/// holds is a decision made before the listener binds; this is the process's
/// whole life after it. It stays in the binary because there is nothing here a
/// test could assert that `yadgar-lifecycle`'s own `tests/drain.rs` does not.
async fn serve_and_drain(
    mut server: Server,
    addr: SocketAddr,
    iam: Iam,
    listen_tls: Option<&serve::ServerTls>,
    watch_inputs: rotate::Inputs,
    schedule: rotate::Schedule,
) -> Result<(), Box<dyn std::error::Error>> {
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
            .add_service(IamServiceServer::new(iam))
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
