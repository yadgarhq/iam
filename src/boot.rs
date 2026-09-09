//! What `main` decides before it connects to anything — in a place a test can
//! reach.
//!
//! `main` is a binary entry point, so nothing in it is reachable from a test.
//! That is fine for wiring and not fine for decisions. The broker credential is
//! exactly the kind that is not: every outcome of getting it wrong is a boot
//! that either stops or connects ANONYMOUSLY, and the second one looks healthy.
//! `iam-db` grew a `boot` module for the same reason and this is its twin.

use std::net::SocketAddr;
use std::time::Duration;

use tonic::transport::{Channel, Server};

use crate::invalidate::Credentials;
use crate::rotate::{self, Configuration, Schedule};
use crate::serve::{self, ServerTls};
use crate::service::{EnrolmentConfig, ResponseFloors};
use crate::upstream::{self, UpstreamTls};

/// The file holding the broker password. A PATH, never the value (D80).
const PASSWORD_FILE_KEY: &str = "NATS_PASSWORD_FILE";

/// The account that password belongs to.
const USER_KEY: &str = "NATS_USER";

/// What this service presents to the broker, or `None` if it presents nothing.
///
/// A PATH rather than a value (D80), the same shape `YADGAR_KEYS_DIR` and
/// `ENROLMENT_CA_PEM_FILE` already use, and for the same reason twice over: a
/// deployment that is not the reference one assembles the Secret by hand, and a
/// password in an environment variable is a password in `kubectl describe pod`.
///
/// **Every way of being half-configured is a boot failure**, and there are four:
/// a path that cannot be read, a file that is empty, a password with no user to
/// go with it, and a user with no password. All four describe a deployment that
/// asked for authentication and cannot perform it, and the only alternative to
/// refusing is connecting anonymously — which succeeds, looks healthy, and leaves
/// D72's invalidation events publishable by anything on the pod network.
///
/// **THE FOURTH ARM IS THE ONE THAT WAS MISSING, and it is the asymmetry that
/// made the other three worth less than they read.** A password with no user
/// refused; a user with no password returned `Ok(None)` and connected
/// anonymously with a warning. The chart never produces that state — its
/// `NATS_USER` and `NATS_PASSWORD_FILE` are rendered together inside one
/// `{{- if .Values.nats.passwordSecret }}`, so clearing the Secret drops both and
/// an adopter whose broker asks for nothing is unaffected. A deployment
/// assembled by hand has no such guard, and D80's whole premise is that such
/// deployments exist.
///
/// Takes the environment as a lookup rather than reading it directly, so a test
/// can state a whole environment without mutating the process — `std::env` is
/// global and `cargo test` runs threads in parallel.
pub fn nats_credentials(
    env: impl Fn(&str) -> Option<String>,
) -> Result<Option<Credentials>, BootError> {
    // AN UNSET KEY AND AN EMPTY ONE ARE THE SAME DEPLOYMENT. A chart that renders
    // a variable with no value must not be a different configuration from one
    // that omits it, so both collapse to the empty string here and every arm
    // below tests emptiness rather than presence.
    let user = env(USER_KEY).unwrap_or_default();
    let path = env(PASSWORD_FILE_KEY).unwrap_or_default();

    if path.is_empty() {
        return match user.is_empty() {
            // NEITHER, which is how a deployment says the broker asks for none.
            true => Ok(None),
            false => Err(BootError::NatsUserWithoutPassword),
        };
    }

    // ADR-0523-WATCHED: Credentials
    let raw =
        std::fs::read_to_string(&path).map_err(|source| BootError::NatsPasswordUnreadable {
            path: path.clone(),
            source,
        })?;
    // TRAILING NEWLINE ONLY. `kubectl create secret --from-file` of a file a
    // person edited keeps the newline their editor added, and a password with a
    // `\n` on the end is a different password — rejected by a broker configured
    // from the same 1Password item, as an authorization violation nobody can see.
    // Inner whitespace is a legitimate part of a password and is left alone.
    let password = raw.trim_end_matches(['\n', '\r']).to_string();
    if password.is_empty() {
        return Err(BootError::NatsPasswordEmpty { path });
    }
    if user.is_empty() {
        return Err(BootError::NatsPasswordWithoutUser);
    }
    // THE PATH TRAVELS WITH THE VALUE. `rotate::Inputs` watches every file this
    // process read at boot and is forbidden from reading the environment a
    // second time to find out which they were, so the resolved credential is
    // the only thing that can carry it there. See `Credentials`.
    Ok(Some(Credentials {
        user,
        password,
        password_file: path.into(),
    }))
}

#[derive(Debug, thiserror::Error)]
pub enum BootError {
    #[error(
        "{PASSWORD_FILE_KEY} names {path}, which cannot be read: {source}. It is the password \
         iam presents to the broker (D22) for D72's cache invalidation. Refusing to start rather \
         than connecting to the broker without one."
    )]
    NatsPasswordUnreadable {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error(
        "{PASSWORD_FILE_KEY} names {path}, which is empty. A blank password is not one. \
         Either put the broker's password in that file or unset the variable, which is how \
         a deployment says the broker asks for none."
    )]
    NatsPasswordEmpty { path: String },

    #[error(
        "{PASSWORD_FILE_KEY} is set and {USER_KEY} is not. The broker's authorization block \
         names an account and a password together, so a password with no user cannot \
         authenticate against it. Set both, or neither."
    )]
    NatsPasswordWithoutUser,

    #[error(
        "{USER_KEY} is set and {PASSWORD_FILE_KEY} is not. The broker's authorization block \
         names an account and a password together, so a named account with no password cannot \
         authenticate against it — and connecting anonymously instead is the silent fall back \
         this refusal exists to remove. Set both, or neither."
    )]
    NatsUserWithoutPassword,
}

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
pub fn env_required(key: &str) -> Result<String, String> {
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

/// The `iam-db` boot refusal, flattened through the estate's one error-chain
/// walker (ledger 733, ledger 740, ADR-0591) instead of a second copy.
///
/// **THE ONLY `to_string()` SITE IN THIS FILE THAT TAKES IT.** Every other
/// refusal here — `serve::ServerTls`, `upstream::UpstreamTls`,
/// `rotate::Configuration` — already returns a complete sentence with nothing
/// further under it worth a walk. `upstream::connect` is different: it returns
/// `yadgar_dial::BalanceError`, and `BalanceError::Tls` wraps a
/// `tonic::transport::Error` whose entire `Display` is the two words
/// `transport error` — measured, this is the one place in this file where the
/// head of the chain is a dead end and the reason sits one `source()` hop
/// below it. `gateway#44` measured the same signature at its own two call
/// sites and took the walk there for the identical reason; this is the same
/// class, ledger 740, reaching the two repositories `gateway` does not dial.
///
/// **NOT A SECOND FLATTENER.** The body is a call to
/// `yadgar_telemetry::diagnose::chain` and nothing else. It exists as a named
/// function only because `main` is a binary target: every `map_err` closure
/// inside it is unreachable from a test, so routing this one call through a
/// seam is what gives the property somewhere to be asserted. Reverting this
/// body to `error.to_string()` turns
/// `a_refusal_carries_the_layer_below_transport_error` red.
///
/// **THE DUPLICATION `gateway#44` ACCEPTED NO LONGER APPLIES.** `BalanceError`
/// has ten variants, six of which carry `#[source]`, `Tls` included; on the
/// pin this file carried through `yadgar-dial` v0.2.1 all six also
/// interpolated `{source}` into their own `#[error]` string, so the walk
/// appended a duplicate tail on every one of them — a CA bundle that could not
/// be read rendered `... (os error 2). TLS was requested ...: No such file or
/// directory (os error 2)`. `yadgar-dial` v0.2.5 (ledger 737) dropped the
/// interpolation and reordered the six messages so the chain walk supplies the
/// cause exactly once; this file adopted that tag and the duplicate tail is
/// gone.
pub fn refusal(error: &dyn std::error::Error) -> String {
    yadgar_telemetry::diagnose::chain(error)
}

/// Structured logging, before anything that could want to report a refusal.
///
/// FIRST, and that is the whole of its placement argument: every refusal below
/// is reported through `tracing`, so a subscriber installed later would lose
/// the ones that fire earliest — the very ones an operator diagnosing a boot
/// needs.
pub fn logging() {
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
}

/// The transport this service LISTENS on, and the server built on it.
pub fn listener() -> Result<(Option<ServerTls>, Server), Box<dyn std::error::Error>> {
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
    let server = serve::builder(listen_tls.as_ref()).map_err(|e| e.to_string())?;
    Ok((listen_tls, server))
}

/// The channel to `iam-db`, and the TLS configuration it was dialled under.
///
/// The configuration comes back with the channel because [`crate::rotate`]
/// watches the files it names; a dial that dropped it would leave a rotated CA
/// bundle unnoticed.
pub async fn iam_db() -> Result<(Channel, Option<UpstreamTls>), Box<dyn std::error::Error>> {
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
        // `refusal` rather than `to_string()` (ledger 733, ledger 740): see its
        // own doc comment for why this is the one site in this file that takes
        // the chain walk. `BalanceError`'s other messages are already complete
        // paragraphs explaining that an empty bundle trusts nobody and that a
        // missing one is not a reason to connect in cleartext — `Tls` is not
        // one of them, and Debug would print the struct and throw all of that
        // away regardless.
        .map_err(|e| refusal(&e))?;
    tracing::info!(
        reresolve_secs = yadgar_dial::reresolve_interval().as_secs(),
        tls = db_tls.is_some(),
        "connected to iam-db"
    );
    Ok((db, db_tls))
}

/// The mounted configuration document, and the rotation schedule it states.
pub fn rotation() -> Result<(Configuration, Schedule), Box<dyn std::error::Error>> {
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
    Ok((config, schedule))
}

/// The Prometheus exporter.
pub fn metrics() -> Result<(), Box<dyn std::error::Error>> {
    // The BINARY installs the exporter, never the library — a library that
    // installs one picks the backend for every service linking it. A failure here
    // is logged and ignored: a service that cannot export metrics should still
    // serve traffic, which is D25's rule applied to the metrics path too.
    let metrics_addr: SocketAddr = env_required("METRICS_LISTEN")?.parse()?;
    if let Err(e) = yadgar_telemetry::metrics::install_prometheus(metrics_addr) {
        tracing::warn!(error = %e, "metrics endpoint unavailable; continuing without it");
    }
    Ok(())
}

/// What this deployment fills into an enrolment token, or `None` if it cannot
/// mint one at all.
pub fn enrolment() -> Option<EnrolmentConfig> {
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
    match EnrolmentConfig::from_env() {
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
    }
}

/// The shortest times `Login` and `RedeemEnrolment` may answer in.
pub fn response_floors() -> Result<ResponseFloors, Box<dyn std::error::Error>> {
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
    Ok(ResponseFloors {
        login: login_response_floor,
        redeem: redeem_response_floor,
    })
}

#[cfg(test)]
mod tests;
