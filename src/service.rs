//! `IamService`. The only service that turns a credential into an identity.
//!
//! It holds the keys and `iam-db` holds none (D72), so every name and secret is
//! encrypted or hashed *here* before it crosses the storage boundary. The
//! division is what makes a stolen database backup worthless on its own.
//!
//! **ONE MODULE, SEVEN FILES, SPLIT BY RPC AND NOT BY LAYER.** This file holds
//! what every handler needs — the [`Iam`] value, the request plumbing, the
//! response floors, the enrolment configuration — and each submodule holds one
//! group of RPCs together with the bounds and the validation that only those
//! RPCs are subject to:
//!
//! | file | what is in it |
//! | --- | --- |
//! | [`login`] | `Login`, and the response-time floor it is held to |
//! | [`enrolment`] | `IssueEnrolment` and `RedeemEnrolment` (D73) |
//! | [`credential`] | resolving, listing, minting and revoking a credential |
//! | [`admin`] | the administrative writes on a user and on a team |
//! | [`settings`] | an inherited setting and a rate-limit override |
//! | [`validate`] | the bounds on fields that appear in more than one request |
//! | [`rpc`] | the `IamService` impl: contract docs, telemetry scope, dispatch |
//!
//! A BOUND STAYS WITH THE REQUEST IT WAS ARGUED FOR, which is ADR-0565's rule
//! about re-arguing a bound per field, applied to where the bound lives. Only
//! the genuinely shared ones — a label, an idempotency key, an entity id — sit
//! in [`validate`].

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use base64::Engine as _;
use tonic::{Request, Response, Status};
use yadgar_telemetry::observe::{Call, Outcome};
use yadgar_telemetry::pb::yadgar::telemetry::v1::Kind;

use crate::crypto::Keys;
use crate::invalidate::Invalidator;
use crate::pb::yadgar::common::v1::{Idempotency, SettingScope, SettingValue};
use crate::pb::yadgar::iam::v1::iam_service_server::IamService;
use crate::pb::yadgar::iam::v1::*;
use crate::pb::yadgar::iamdb::v1 as db;
use crate::pb::yadgar::iamdb::v1::iam_db_service_client::IamDbServiceClient;

mod admin;
mod credential;
mod enrolment;
mod login;
mod rpc;
mod settings;
mod validate;

/// The `service` label every metric this binary emits carries (D67). Public so
/// that [`crate::rotate`]'s expiry gauge lands on the same bounded label as
/// every call metric, rather than on a second spelling of the same name.
pub const SERVICE: &str = "iam";

/// The default response-time floor for [`IamService::login`].
///
/// A FLOOR, NOT A TARGET. It is the shortest time `Login` is allowed to answer
/// in, not the time it is expected to take: a call that already costs more than
/// this is not slowed further, and is warned about instead.
///
/// 250ms COMES FROM A MEASUREMENT, and the measurement is on DEV HARDWARE — treat
/// it as a starting point for a deployment rather than a constant. Through the
/// live edge, 25 samples per class, wrong password throughout: a stored hash at
/// `m=16384,t=2,p=1` answered in 27ms median / 41ms max, the unknown-user dummy
/// at `Argon2::default()` (`m=19456,t=2,p=1`) in 29ms / 47ms, and a stored hash
/// at `m=65536,t=3,p=1` in 98ms median / 136ms max. 250ms clears that worst case
/// with room, which is the property that matters: A FLOOR SET BELOW THE SLOWEST
/// LEGITIMATE VERIFICATION DOES NOT CLOSE THE ORACLE, IT CLIPS IT.
///
/// Re-measure on the deployment target and raise `LOGIN_RESPONSE_FLOOR_MS` if
/// the slowest legitimate login there approaches this. `Login` says so itself
/// when it happens — see `Iam::hold_until_floor`.
pub const DEFAULT_LOGIN_RESPONSE_FLOOR: Duration = Duration::from_millis(250);

/// The default response-time floor for [`IamService::redeem_enrolment`].
///
/// **ITS OWN VALUE, AND NOT `Login`'s, BECAUSE IT DOES MORE WORK.** A redemption
/// pays TWO Argon2id operations against `Login`'s one — it HASHES the chosen
/// password and then VERIFIES it against what the store holds, which is how a
/// replay is told from a first attempt without remembering anything — and up to
/// three round trips to the twin against `Login`'s two. Sharing `Login`'s 250ms
/// would put every legitimate redemption OVER the floor, so `hold_until_floor`
/// would warn on every successful call: an alert that fires always is an alert
/// on nothing, and it would drown the `Login` warning that means something.
///
/// 750ms IS 250ms SIZED TO THAT WORK — twice the Argon2 and a further round trip
/// — and it inherits [`DEFAULT_LOGIN_RESPONSE_FLOOR`]'s caveat unchanged: the
/// measurement behind it is DEV HARDWARE, so re-measure on the deployment target
/// and raise `REDEEM_RESPONSE_FLOOR_MS` if the slowest legitimate redemption
/// there approaches it. A FLOOR SET BELOW THE SLOWEST LEGITIMATE CALL DOES NOT
/// CLOSE THE ORACLE, IT CLIPS IT.
pub const DEFAULT_REDEEM_RESPONSE_FLOOR: Duration = Duration::from_millis(750);

/// One RPC's floor, with the two names an operator needs the moment it is
/// exceeded.
///
/// THE ENV VAR TRAVELS WITH THE VALUE deliberately. `hold_until_floor`'s warning
/// exists to tell an operator to raise the floor, and one that does not say
/// WHICH variable to raise is one they must read the source to act on. With two
/// floors configured separately, guessing wrong raises the one that was already
/// fine and leaves the leak open.
#[derive(Clone, Copy)]
struct Floor {
    rpc: &'static str,
    env: &'static str,
    value: Duration,
}

/// Both floors, chosen by the caller.
///
/// A STRUCT RATHER THAN TWO POSITIONAL `Duration`s: two arguments of one type,
/// one of them three times the other, is exactly the pair a call site swaps in
/// silence — and swapped, `Login` gets the loose floor and redemption the tight
/// one, which is the failure in both directions at once.
pub struct ResponseFloors {
    pub login: Duration,
    pub redeem: Duration,
}

/// What `iam` fills into every enrolment token it mints, from its own
/// configuration.
///
/// **HELD BY THE SERVICE, NOT ASKED FOR PER CALL.** `IssueEnrolmentRequest` has
/// no field for either, deliberately: an admin never assembles the gateway
/// address or the CA and so cannot get them wrong. That puts the whole burden of
/// holding correct values on this service.
#[derive(Clone, Debug)]
pub struct EnrolmentConfig {
    gateway: String,
    ca_pem: Option<String>,
    /// WHERE that PEM was read from, kept alongside the bytes rather than
    /// discarded.
    ///
    /// The value is what a token carries; the PATH is what [`crate::rotate`]
    /// watches. cert-manager rewrites the gateway's Secret and kubelet refreshes
    /// this file — the chart mounts it as a DIRECTORY precisely so that
    /// propagation happens — but this process read it once. Without the path,
    /// nothing can notice, and `iam` goes on minting D73 tokens carrying a CA
    /// that no longer signs anything, with no exit, no gauge movement and no log.
    ///
    /// `None` when no CA is configured, which is a deployment rather than an
    /// error: it means the gateway has a publicly-trusted certificate.
    ca_path: Option<PathBuf>,
}

#[derive(Debug, thiserror::Error)]
pub enum EnrolmentConfigError {
    #[error(
        "{0} is not set. Every enrolment token carries the gateway address a \
         person's first client connects to, and that field has no presence — an \
         unset value mints a structurally valid token pointing at nothing, and \
         the failure then surfaces on a stranger's machine, on their first \
         contact with this deployment, as an undiagnosable connection error."
    )]
    NoGateway(&'static str),

    #[error(
        "{0} names a file holding an empty CA. ABSENT and EMPTY are different \
         instructions: absent means this deployment uses a publicly-trusted \
         certificate and system trust applies, which is legitimate, while an \
         empty one is a token assembled wrong and a client is required to refuse \
         it. Unset the variable to mean system trust."
    )]
    EmptyCa(&'static str),

    #[error("cannot read the CA at {0}: {1}")]
    UnreadableCa(String, std::io::Error),
}

const GATEWAY_ENV: &str = "ENROLMENT_GATEWAY";
const CA_PEM_ENV: &str = "ENROLMENT_CA_PEM_FILE";

impl EnrolmentConfig {
    /// The values as given, checked.
    pub fn new(gateway: String, ca_pem: Option<String>) -> Result<Self, EnrolmentConfigError> {
        if gateway.is_empty() {
            return Err(EnrolmentConfigError::NoGateway(GATEWAY_ENV));
        }
        if ca_pem.as_deref().is_some_and(|p| p.trim().is_empty()) {
            return Err(EnrolmentConfigError::EmptyCa(CA_PEM_ENV));
        }
        Ok(Self {
            gateway,
            ca_pem,
            // NO PATH, because this constructor was handed the VALUE. Only
            // `load` reads a file, so only `load` has a path to record.
            ca_path: None,
        })
    }

    /// Everything [`Self::from_env`] does except read the environment.
    ///
    /// The split is `crypto::Keys::from_dir`'s, for its reason: `from_env` reads
    /// process-wide variables, which no test can set without racing every other
    /// test in the binary. Reading the CA FILE is the part with a failure mode
    /// worth asserting on, so it lives here where it can be.
    pub fn load(gateway: &str, ca_path: Option<&str>) -> Result<Self, EnrolmentConfigError> {
        // ABSENT IS A DEPLOYMENT, NOT AN ERROR: no CA means a publicly-trusted
        // certificate and the client's own system trust.
        let ca_path = ca_path.filter(|p| !p.is_empty());
        let ca_pem = match ca_path {
            None => None,
            // ADR-0523-WATCHED: EnrolmentConfig
            Some(path) => Some(
                std::fs::read_to_string(path)
                    .map_err(|e| EnrolmentConfigError::UnreadableCa(path.to_string(), e))?,
            ),
        };
        Ok(Self {
            ca_path: ca_path.map(PathBuf::from),
            ..Self::new(gateway.to_string(), ca_pem)?
        })
    }

    /// The file this deployment's CA was read from, for [`crate::rotate`] to
    /// watch. `None` when no CA is configured.
    pub fn ca_path(&self) -> Option<&Path> {
        self.ca_path.as_deref()
    }

    /// Load from the environment.
    ///
    /// **AN ERROR HERE DISABLES ONE RPC, IT DOES NOT STOP THE PROCESS**, and the
    /// distinction is deliberate — an earlier revision of this code failed boot
    /// and was wrong about the blast radius. The contract's rule is that a
    /// minted token NEVER carries an empty `gateway`; refusing to MINT keeps
    /// that rule completely. Refusing to START also stops `ResolveCredential`,
    /// and `iam` is the authentication plane: a CrashLoopBackOff here halts
    /// every dependent service's credential resolution the moment the gateway's
    /// 300s cache expires — an estate-wide outage for a value belonging to one
    /// administrative RPC.
    ///
    /// The crypto keys are the opposite case and stay a boot failure: without
    /// them EVERY request touching a credential fails, so there is no reduced
    /// service left to protect. Here there is.
    ///
    /// `main` turns this into a WARN naming the variable, and
    /// `Iam::issue_enrolment` refuses with `FAILED_PRECONDITION` naming it
    /// again — loud at boot AND at the call, rather than loud once and then
    /// silent.
    pub fn from_env() -> Result<Self, EnrolmentConfigError> {
        // **THE ONE ARGUED EXCEPTION TO ADR-0569 IN THIS BINARY**, and the
        // argument is the paragraph above rather than convenience. Every other
        // knob here reads through `main`'s `env_required` and refuses the boot
        // when absent; this one keeps its fallback because `iam` is the
        // authentication plane, so a CrashLoopBackOff would halt every dependent
        // service's credential resolution over a value belonging to one
        // administrative RPC. Unset means `IssueEnrolment` refuses with
        // `FAILED_PRECONDITION` naming the variable while the process keeps
        // serving — loud at the call rather than fatal at the boot. The chart
        // says the same thing at its `ENROLMENT_GATEWAY` block.
        //
        // The marker sits on the READ ITSELF, so `git grep ADR-0569-EXCEPTION`
        // lands on the line that takes the fallback rather than on prose near it.
        let gateway = std::env::var(GATEWAY_ENV).unwrap_or_default(); // ADR-0569-EXCEPTION
        let ca_path = std::env::var(CA_PEM_ENV).ok();
        Self::load(&gateway, ca_path.as_deref())
    }
}

pub struct Iam {
    keys: Keys,
    channel: tonic::transport::Channel,
    invalidator: Invalidator,
    /// See [`DEFAULT_LOGIN_RESPONSE_FLOOR`] and `Iam::hold_until_floor`.
    login_floor: Floor,
    /// See [`DEFAULT_REDEEM_RESPONSE_FLOOR`].
    redeem_floor: Floor,
    /// `None` when this deployment has not configured enrolment. ONE RPC IS
    /// THEN UNAVAILABLE AND THE REST OF THE SERVICE IS NOT — see
    /// [`EnrolmentConfig::from_env`] for why that is not a boot failure.
    enrolment: Option<EnrolmentConfig>,
}

impl Iam {
    /// `floors` is REQUIRED rather than defaulted, so that the one place they are
    /// chosen is the one place they can be read — `main`, from
    /// `LOGIN_RESPONSE_FLOOR_MS` and `REDEEM_RESPONSE_FLOOR_MS`. A constructor
    /// that silently supplied the defaults would let a caller build an `Iam`
    /// whose floors nobody selected, which is how a security control ends up
    /// configured by accident.
    ///
    /// THE `LOGIN_` VARIABLE KEEPS ITS NAME even though the mechanism now serves
    /// two RPCs. Renaming a variable a deployment already sets does not move
    /// that deployment onto the new name — it silently reverts it to the
    /// default, which for a security control is the change nobody sees.
    pub fn new(
        keys: Keys,
        channel: tonic::transport::Channel,
        invalidator: Invalidator,
        floors: ResponseFloors,
        enrolment: Option<EnrolmentConfig>,
    ) -> Self {
        Self {
            keys,
            channel,
            invalidator,
            login_floor: Floor {
                rpc: "Login",
                env: "LOGIN_RESPONSE_FLOOR_MS",
                value: floors.login,
            },
            redeem_floor: Floor {
                rpc: "RedeemEnrolment",
                env: "REDEEM_RESPONSE_FLOOR_MS",
                value: floors.redeem,
            },
            enrolment,
        }
    }

    pub(super) fn client(&self) -> IamDbServiceClient<tonic::transport::Channel> {
        IamDbServiceClient::new(self.channel.clone())
    }
}

/// One refusal for every way an enrolment can fail to redeem.
///
/// Unknown, already spent, expired — all return exactly this. The store tells
/// them apart and records which; a caller that could would learn whether a
/// secret it does not hold ever existed, and whether it has been used.
fn enrolment_refused() -> Status {
    Status::unauthenticated("this enrolment cannot be redeemed")
}

/// D67's join key, forwarded to the twin as metadata.
///
/// These RPCs carry no `Scope` — they run before a caller has an identity — so
/// the correlation id travels in a header instead. Propagating it is what keeps
/// the `iam-db` hop joined to the rest of the trace; drop it and a login's
/// database time floats free of the login that caused it.
fn forward_request_id<T, U>(from: &Request<T>, to: &mut Request<U>) {
    if let Some(v) = from.metadata().get("x-yadgar-request-id") {
        to.metadata_mut().insert("x-yadgar-request-id", v.clone());
    }
}

fn request_id_of<T>(req: &Request<T>) -> String {
    req.metadata()
        .get("x-yadgar-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

fn tel(request_id: String, user_id: &str) -> yadgar_telemetry::observe::Scope {
    yadgar_telemetry::observe::Scope {
        request_id,
        instance_id: String::new(),
        user_id: user_id.to_string(),
        project_id: String::new(),
    }
}

/// One refusal for every way a login can fail.
///
/// Wrong password, unknown user, no password set, expired credential — all
/// return exactly this. A message that distinguished them would tell an attacker
/// which usernames exist, which is the same leak the timing equalisation in
/// `verify_password` exists to close; leaking it in the text instead would make
/// that work pointless.
fn refused() -> Status {
    Status::unauthenticated("invalid username or password")
}

/// Log an upstream failure and return one whose message is this service's own.
///
/// A `Status` from `iam-db` can carry storage detail, and on this service that
/// detail names the identity schema. The code propagates; the words stay here.
///
/// **This used to be an `inspect_err`, which logged and then returned the
/// upstream `Status` unchanged** — so the doc above described a redaction that
/// did not happen and two upstream sentences reached the caller verbatim: "a user
/// with that name already exists" and "no such credential". Replacing the message
/// rather than correcting the doc, because the doc was right about what should
/// happen.
fn upstream_failed(e: Status) -> Status {
    tracing::error!(code = ?e.code(), message = %e.message(), "upstream iam-db call failed");
    Status::new(e.code(), refusal_for(e.code()))
}

/// One fixed sentence per code, chosen HERE rather than upstream.
///
/// The code is what a caller branches on and it survives untouched; the words are
/// only for a human, and a fixed set of them cannot leak a table name, a column
/// or a fragment of a query. Deliberately not the empty string: a `Status` with
/// no message at all reads as a bug in the caller's client library.
fn refusal_for(code: tonic::Code) -> &'static str {
    match code {
        tonic::Code::AlreadyExists => "already exists",
        tonic::Code::NotFound => "no such record",
        tonic::Code::InvalidArgument => "the store refused the request",
        tonic::Code::Unavailable => "storage unavailable",
        _ => "the iam-db call failed",
    }
}

#[cfg(test)]
mod tests;
