//! Wiring, and one decision worth naming: this service does NOT wait for
//! `iam-db` to be reachable before reporting ready.
//!
//! The twin's own boot is gated — probe, migrate, then listen (D69) — so a
//! `-db` that is not ready has no DNS endpoint behind the headless Service, and
//! `yadgar_dial::connect` fails loudly. Blocking this service's startup on that would
//! turn one module's slow migration into a cascading outage across everything
//! that depends on it, and under D68 a pod stuck in startup is one the autoscaler
//! cannot help. Failing a request with UNAVAILABLE is recoverable; refusing to
//! start is not.
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

use std::net::SocketAddr;
use std::time::Duration;

use yadgar_iam::crypto::Keys;
use yadgar_iam::pb::yadgar::iam::v1::iam_service_server::IamServiceServer;
use yadgar_iam::serve;
use yadgar_iam::service::{
    EnrolmentConfig, Iam, ResponseFloors, DEFAULT_LOGIN_RESPONSE_FLOOR,
    DEFAULT_REDEEM_RESPONSE_FLOOR,
};
use yadgar_iam::upstream;

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
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
    let db_host = env_or("IAM_DB_HOST", "iam-db");
    let db_port: u16 = env_or("IAM_DB_PORT", "50051").parse()?;

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

    // The BINARY installs the exporter, never the library — a library that
    // installs one picks the backend for every service linking it. A failure here
    // is logged and ignored: a service that cannot export metrics should still
    // serve traffic, which is D25's rule applied to the metrics path too.
    let metrics_addr: SocketAddr = env_or("METRICS_LISTEN", "0.0.0.0:9090").parse()?;
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
    // PARSED, NOT SALVAGED: a mistyped value fails boot rather than falling back
    // to the default. Silently substituting one would leave an operator who
    // believes they raised the floor running the old one, and a security control
    // nobody can tell is misconfigured is the failure this floor's own warning
    // exists to prevent.
    let default_floor_ms = DEFAULT_LOGIN_RESPONSE_FLOOR.as_millis().to_string();
    let login_response_floor =
        Duration::from_millis(env_or("LOGIN_RESPONSE_FLOOR_MS", &default_floor_ms).parse()?);

    // ITS OWN VALUE, because `RedeemEnrolment` legitimately does more work — two
    // Argon2id operations and a further round trip — and a floor sized for
    // `Login` would be exceeded by every successful redemption, turning the
    // warning that says "raise this" into one that fires on every call.
    let default_redeem_ms = DEFAULT_REDEEM_RESPONSE_FLOOR.as_millis().to_string();
    let redeem_response_floor =
        Duration::from_millis(env_or("REDEEM_RESPONSE_FLOOR_MS", &default_redeem_ms).parse()?);
    tracing::info!(
        login_floor_ms = login_response_floor.as_millis() as u64,
        redeem_floor_ms = redeem_response_floor.as_millis() as u64,
        "Login and RedeemEnrolment answer no sooner than their response-time floors"
    );

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

    let addr: SocketAddr = env_or("LISTEN", "0.0.0.0:50052").parse()?;
    // `tls` is recorded because "is this listener encrypted?" must be answerable
    // from the boot log rather than inferred from which variables somebody
    // believes they set.
    tracing::info!(%addr, tls = listen_tls.is_some(), "iam listening");
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
        .serve_with_shutdown(addr, async {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("shutting down");
        })
        .await?;

    Ok(())
}
