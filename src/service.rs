//! `IamService`. The only service that turns a credential into an identity.
//!
//! It holds the keys and `iam-db` holds none (D72), so every name and secret is
//! encrypted or hashed *here* before it crosses the storage boundary. The
//! division is what makes a stolen database backup worthless on its own.

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

/// The `service` label every metric this binary emits carries (D67). Public so
/// that [`crate::rotate`]'s expiry gauge lands on the same bounded label as
/// every call metric, rather than on a second spelling of the same name.
pub const SERVICE: &str = "iam";

/// D73's 24 hours, and NOT configurable.
///
/// The deadline is written into the store at creation rather than recomputed at
/// read time, so a value that moved would silently re-date every live token
/// rather than only the ones minted after the change. A constant is what makes
/// "every enrolment expires 24 hours after it was minted" true of the rows as
/// well as of the code.
const ENROLMENT_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);

/// The longest password `RedeemEnrolment` accepts.
///
/// A BOUND, NOT A POLICY. It is here because the password is hashed BEFORE the
/// enrolment secret is looked up — which is what stops `INVALID_ARGUMENT` from
/// reporting that the secret was good — and an unbounded input on an
/// unauthenticated path is then work anyone can ask for without presenting
/// anything. Nothing about strength is asserted; that belongs to whatever sets
/// policy, and this file is not it.
const MAX_PASSWORD_BYTES: usize = 1024;

/// The longest `label` accepted, IN CHARACTERS, because that is what stores it.
///
/// A BOUND AND NOT A REQUIREMENT: an EMPTY label is accepted, because the
/// contract says this field is `LoginRequest.label` exactly and `Login` requires
/// nothing of it. Refusing an empty one here would be a refusal a caller written
/// against `Login` newly meets.
///
/// **255 AND NOT 256, AND CHARACTERS AND NOT BYTES.** This was
/// `MAX_LABEL_BYTES = 256`, tested with `>`, and it was wrong twice over. The
/// column is `label VARCHAR(255)` on `CHARSET=utf8mb4`
/// (`iam-db/src/schema.rs`), and `VARCHAR(n)` in utf8mb4 bounds CHARACTERS.
/// Measured against `mariadb:11.8.9` — the image `iam-db`'s README stands up —
/// with that column declared exactly as the schema declares it, at the stock
/// `sql_mode` (`STRICT_TRANS_TABLES,…`):
///
/// | label                     | characters | bytes | outcome                                        |
/// | ------------------------- | ---------- | ----- | ---------------------------------------------- |
/// | 255 × `l`                 | 255        | 255   | stored                                         |
/// | 256 × `l`                 | 256        | 256   | `ERROR 1406 Data too long for column 'label'`  |
/// | 255 × `U+1F600`           | 255        | 1020  | stored                                         |
/// | 256 × `U+1F600`           | 256        | 1024  | `ERROR 1406 Data too long for column 'label'`  |
/// | 100 × `U+1F600`           | 100        | 400   | stored                                         |
///
/// So the old bound was wrong in BOTH directions. It ADMITTED a 256-byte ASCII
/// label the column refuses — and because `iam-db` renders every engine error as
/// `UNAVAILABLE "storage unavailable"`, that refusal reached the caller as an
/// outage of a database that was working. It also REFUSED a 100-character emoji
/// label the column stores without complaint.
///
/// **THE NUMBER IS THE COLUMN'S AND THAT COUPLING IS DELIBERATE**, which is the
/// one way this differs from [`MAX_EXPIRES_IN_SECONDS`] above. That bound is a
/// judgement about what a field MEANS, and it deliberately refuses to import a
/// storage ceiling that moved between engine minor versions. A `VARCHAR` width
/// does not move on its own: it is a declaration in a migration, and changing it
/// is a migration somebody writes. The alternatives to naming it here are worse
/// — leaving the lockout, or accepting a silent truncation under a `sql_mode`
/// nothing asserts (the same INSERTs above store a CLIPPED 255-character label
/// and report success under `sql_mode = ''`). Refusing here makes the outcome
/// this service's own, and independent of a `sql_mode` it neither sets nor
/// checks. If the column widens, this constant is what has to move with it.
const MAX_LABEL_CHARS: usize = 255;

/// The longest life [`IamService::issue_credential`] will grant: ten years.
///
/// A BOUND ON THE DURATION ASKED FOR, NOT ON THE INSTANT IT PRODUCES, and that
/// distinction is the whole reason the number is this one. The store writes the
/// deadline into a MariaDB `TIMESTAMP` through `FROM_UNIXTIME`, and that
/// column's ceiling MOVES BETWEEN MINOR VERSIONS of the engine. Measured against
/// `mariadb:11.8.9`, the image `iam-db`'s README stands up, at its stock
/// `sql_mode`: `FROM_UNIXTIME(2147483648)` stores `2038-01-19 03:14:08` without
/// complaint — the classic 32-bit bound is NOT where 11.8 refuses, because 11.5
/// widened the column — while `FROM_UNIXTIME(4294967296)` is NULL and the INSERT
/// is refused outright with `ERROR 1292`. A ceiling copied from that measurement
/// into this file would be `iam` hardcoding a number owned by a version of a
/// database it does not talk to directly and does not deploy.
///
/// SO THE REFUSAL IS ABOUT WHAT THE FIELD MEANS INSTEAD. `expires_in_seconds`
/// asks for a bearer credential's life, and the expiry exists to bound what a
/// leaked token is worth. A token asked to live longer than a decade is asking
/// for no bound at all — which this contract already offers, spelled `0`, and
/// which a caller that wants it should say rather than approximate. Ten years
/// stays under the measured store ceiling until roughly 2096, so the refusal a
/// caller meets here is this service's own and never the store's.
const MAX_EXPIRES_IN_SECONDS: i64 = 315_360_000;

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
        let gateway = std::env::var(GATEWAY_ENV).unwrap_or_default();
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

    fn client(&self) -> IamDbServiceClient<tonic::transport::Channel> {
        IamDbServiceClient::new(self.channel.clone())
    }

    /// Everything `Login` actually does. Wrapped by the trait method, which is
    /// what holds it to the response-time floor.
    ///
    /// SPLIT SO THE FLOOR CANNOT BE PARTIAL. With the work in its own function
    /// there is one place the elapsed time is read and one place it is paid, and
    /// no `return` inside this body can skip either — the early refusal below is
    /// exactly the path that would otherwise answer fastest.
    ///
    /// D67's `Call` IS OPENED BY THE HANDLER AND FINISHED HERE, so it spans the
    /// work and NOT the wait. An operator sets the floor from the real duration
    /// distribution, and a metric padded to a constant would report the constant
    /// instead — deleting the one signal that says the floor needs raising. The
    /// gap between what this records and what a client observes is deliberate,
    /// and [`Self::hold_until_floor`] is what makes it visible when it closes.
    ///
    /// TAKING `call` AS A PARAMETER IS ALSO WHAT KEEPS `observe-coverage` HONEST.
    /// That hook follows same-file calls to find a `Call::start`, but its
    /// `BARE_CALL` pattern excludes an identifier preceded by `.`, so a
    /// `self.login_inner(…)` hop is invisible to it: opening the `Call` in here
    /// would leave the handler reading as uninstrumented. Opening it in the
    /// handler and passing it down satisfies the check by being true rather than
    /// by an exemption.
    async fn login_inner(
        &self,
        req: Request<LoginRequest>,
        call: Call,
    ) -> Result<Response<LoginResponse>, Status> {
        // VALIDATION BEFORE LOOKUP, and this check was ABSENT ENTIRELY. `Login`
        // stores a caller-supplied `label` in the same column `RedeemEnrolment`
        // and `IssueCredential` do, and it was the only one of the three with no
        // bound on it — so an over-long label verified the password, minted a
        // token, and then failed the INSERT, which reaches the caller as
        // `UNAVAILABLE "storage unavailable"`. A sign-in that reports an outage
        // for a request that was never well-formed sends a person to an operator
        // instead of to their own input.
        //
        // **INSIDE `login_inner` AND NOT IN THE HANDLER**, which is the same
        // reason this function exists: the handler is what pays the
        // response-time floor, so a refusal placed above the call to this one
        // would be the fast path the floor exists to close. Here it is floored
        // like every other answer.
        //
        // NO ORACLE. The check is answerable from the request alone and says
        // nothing about whether the username exists — which is exactly the
        // property `iam.proto` states as VALIDATION BEFORE LOOKUP for the
        // sharper case, `RedeemEnrolment`.
        if let Err(refusal) = check_label(&req.get_ref().label) {
            // WITHOUT THIS THE REFUSAL IS RECORDED AS `UNRECORDED`. `Call::fail`
            // takes `self` by value so the compiler holds it ahead of the `Err`,
            // but a path that never calls it compiles fine and drops the `Call`
            // — and this branch is brand new, so there was nothing to copy.
            call.fail("INVALID_ARGUMENT");
            return Err(refusal);
        }

        // The username never leaves this process. What goes to the store is its
        // blind index, so the plaintext reaches no query log and no backup.
        let mut lookup = Request::new(db::GetPasswordHashRequest {
            // DEAD FIELD, AND EMPTY IS THE SECURITY PROPERTY RATHER THAN AN
            // OMISSION. The plaintext username never crosses this boundary — it
            // would otherwise reach a query log and a database backup — so the
            // superseded field is written out empty rather than left to a rest
            // pattern that would say the same thing silently.
            //
            // THE EXPECTATION IS ON THIS FIELD AND NOT ON THE STATEMENT, which
            // is the same distinction the rest of this change is about. On the
            // statement it is satisfied by ANY deprecated field in the literal,
            // so a `#[deprecated]` later landing on `username_blind_index` would
            // be absorbed silently and `unfulfilled_lint_expectations` would
            // never fire. One field, one expectation.
            #[expect(
                deprecated,
                reason = "the dead field is written out rather than defaulted: see above"
            )]
            username: String::new(),
            username_blind_index: self.keys.blind_index(&req.get_ref().username),
        });
        forward_request_id(&req, &mut lookup);

        let found = self
            .client()
            .get_password_hash(lookup)
            .await
            .map_err(upstream_failed)?
            .into_inner();

        // THE ORDER HERE IS THE SECURITY PROPERTY.
        //
        // `verify_password` is called whether or not a user was found, and it
        // does a full Argon2id verification either way — against the real hash if
        // there is one, against a dummy otherwise. Returning early on an unknown
        // username would make it answer in microseconds while a known one takes
        // the ~50ms Argon2id costs, and that difference is measurable over a
        // network. The endpoint would enumerate accounts.
        let stored = (!found.user_id.is_empty()).then_some(found.argon2id_hash.as_str());
        if !self.keys.verify_password(stored, &req.get_ref().password) {
            call.fail("UNAUTHENTICATED");
            return Err(refused());
        }

        let token = Keys::mint_token().map_err(|_| Status::internal("cannot mint a credential"))?;
        let mut create = Request::new(db::CreateCredentialRequest {
            // NOTHING TO SUPPLY: `LoginRequest` carries no idempotency key. D9's
            // key covers mutating RPCs a caller can retry, and a sign-in is not
            // one this contract gives a key to.
            idempotency: None,
            user_id: found.user_id.clone(),
            token_hash: Keys::token_hash(&token),
            label: req.get_ref().label.clone(),
            // NOTHING TO SUPPLY: `LoginRequest` has no field to ask for an
            // expiry, so there is no deadline to carry.
            expires_at: None,
            // NOTHING TO SUPPLY, AND NOT MERELY UNWIRED. `Login` is the person
            // themselves signing in, not an administrator acting on someone —
            // `LoginRequest` carries no actor and ADR-0534's field is for
            // administrative requests.
            unverified_actor: None,
        });
        forward_request_id(&req, &mut create);

        let created = self
            .client()
            .create_credential(create)
            .await
            .map_err(upstream_failed)?
            .into_inner();

        call.finish(Outcome {
            status: "OK",
            ..Default::default()
        });
        Ok(Response::new(LoginResponse {
            // The only time this value is ever returned. The store holds a hash.
            token: token.to_string(),
            credential_id: created.credential_id,
        }))
    }

    /// Wait out whatever is left of the floor, or say that there was nothing left.
    ///
    /// **A FLOOR CLOSES ONLY THE FAST SIDE.** Padding a short call up to a
    /// constant makes every call that is FASTER than the constant look alike; a
    /// call that is SLOWER answers late and still reports how much work it did.
    /// So when `elapsed` exceeds the floor the control is not merely inactive for
    /// that call, it is covering nothing — and the only thing that can be done
    /// about it is to raise the configured value, which needs an operator who
    /// knows. Hence the warning, naming both numbers: the observed duration and
    /// the floor it passed.
    ///
    /// Without it this degrades in silence. The floor keeps being applied, the
    /// tests keep passing, and the property it is supposed to deliver is simply
    /// gone for whichever rows are slow — a check that cannot fail, which is
    /// worse than none.
    ///
    /// **NOT AN ERROR, deliberately.** A verification slower than the floor is
    /// still a CORRECT verification. Refusing it would lock out exactly the
    /// accounts whose unusual cost this exists to hide, turning a leak into an
    /// outage; the same trade is worked through at
    /// [`crate::crypto::Keys::verify_password`], where refusing a cheap stored
    /// hash before verifying it would make every pre-tune account a permanent
    /// lockout.
    ///
    /// `checked_sub` returns `None` ONLY when `elapsed` is STRICTLY greater than
    /// the floor, so answering exactly on it sleeps zero and warns nothing —
    /// "exceeds" means exceeds.
    ///
    /// **ONE MECHANISM FOR BOTH FLOORED RPCs, AND TWO CONFIGURED VALUES.** The
    /// rule is identical for `Login` and `RedeemEnrolment`, so a second copy of
    /// it would be a second place to get it wrong; the VALUES cannot be shared,
    /// because a redemption legitimately costs more and would then warn on every
    /// call. Which RPC is naming its floor travels in the event, so the two do
    /// not merge into one indistinguishable stream of warnings.
    async fn hold_until_floor(&self, floor: Floor, elapsed: Duration) {
        let Some(remaining) = floor.value.checked_sub(elapsed) else {
            tracing::warn!(
                rpc = floor.rpc,
                observed_ms = elapsed.as_millis() as u64,
                floor_ms = floor.value.as_millis() as u64,
                floor_env = floor.env,
                "this call took longer than its response-time floor; the floor is \
                 hiding nothing for it. Raise the named variable above the slowest \
                 legitimate call of this RPC on this deployment."
            );
            return;
        };
        tokio::time::sleep(remaining).await;
    }

    /// Everything `RedeemEnrolment` actually does, split from the handler for
    /// the reason [`Self::login_inner`] is split: with the work in its own
    /// function there is one place the elapsed time is read and one place it is
    /// paid, and no `return` in this body can skip either.
    ///
    /// **THE ORDER OF THE FOUR STEPS IS THE WHOLE SECURITY PROPERTY**, and each
    /// is placed against a named leak:
    ///
    /// 1. **VALIDATE FIRST.** Every check that does not need the secret runs
    ///    before the secret is looked up. Otherwise `INVALID_ARGUMENT` comes
    ///    back only once the secret has been confirmed, and the STATUS CODE
    ///    itself says the secret was good — an oracle cleaner than timing, and
    ///    one no amount of constant work touches.
    /// 2. **HASH BEFORE THE LOOKUP.** The Argon2id cost is paid on every path
    ///    because it is paid before anything is known about the secret. An
    ///    implementation that hashed only after a hit would answer an unknown
    ///    secret in microseconds and a valid one in tens of milliseconds.
    /// 3. **ONE REFUSAL FOR THREE OUTCOMES.** Unknown, spent and expired are all
    ///    `UNAUTHENTICATED` with one message. The store tells them apart and
    ///    records which; the caller cannot. The refusal path ALSO pays the
    ///    verification the success path is about to pay, so the two cost the
    ///    same two Argon2id operations rather than two against one. **The
    ///    store's own ERROR is a fourth outcome and is collapsed with them**:
    ///    an idempotency key already recorded against a different secret is
    ///    refused there with `INVALID_ARGUMENT`, before the presented secret is
    ///    looked up, and forwarding that code told a caller holding no secret
    ///    whether the key had been redeemed. See the call site.
    /// 4. **THE REPLAY CHECK, WHICH REMEMBERS NOTHING.** `iam` holds no store
    ///    (D4), so it cannot know whether this key has been seen. It does not
    ///    need to: it verifies the presented password against the hash the store
    ///    already holds — the comparison `Login` makes on every call. A first
    ///    attempt always passes, because the store has just written that very
    ///    hash. A key replayed with a DIFFERENT password fails, and is refused
    ///    rather than answered with the first attempt's outcome — which would
    ///    leave the FIRST password live while the person believed the second had
    ///    taken effect.
    async fn redeem_inner(
        &self,
        req: Request<RedeemEnrolmentRequest>,
        call: Call,
    ) -> Result<Response<RedeemEnrolmentResponse>, Status> {
        // 1. VALIDATION BEFORE LOOKUP.
        if let Err(refusal) = validate_redemption(req.get_ref()) {
            call.fail("INVALID_ARGUMENT");
            return Err(refusal);
        }

        // 2. THE HASHING, PAID BEFORE ANYTHING IS KNOWN. `iam` does it and the
        // plaintext stops here: the store is given a finished PHC string, so no
        // chosen password reaches a query log, a slow-query log or a backup.
        // Through `crypto`'s single mint point, so this hash and the dummy the
        // equalisation verifies against cannot drift apart in cost.
        let argon2id_hash = self
            .keys
            .hash_password(&req.get_ref().password)
            .map_err(|_| Status::internal("cannot hash the password"))?;

        // SPEND AND SET IN ONE TRANSACTION, at the store. The caller's key goes
        // through UNCHANGED and nothing is remembered against it here (D9 puts
        // the deduplication in the owning module's store, D4 leaves `iam`
        // without one).
        let mut spend = Request::new(db::RedeemEnrolmentRequest {
            idempotency: req.get_ref().idempotency.clone(),
            // Deterministic, because the store looks a secret up by it. SHA-256
            // and not Argon2id: this secret is 256 bits of CSPRNG output and has
            // no entropy problem for a slow hash to solve.
            secret_hash: Keys::token_hash(&req.get_ref().secret),
            argon2id_hash,
        });
        forward_request_id(&req, &mut spend);

        // THE STORE'S OWN REFUSALS ARE PART OF "ONE REFUSAL FOR THREE OUTCOMES",
        // and forwarding their status code untouched was an oracle on an
        // unauthenticated endpoint. `upstream_failed` replaces the MESSAGE and
        // keeps the CODE — correct everywhere else, and exactly the leak here.
        //
        // WHAT IT LEAKED, with no secret needed: the store compares a presented
        // `secret_hash` against the one its ledger holds for this key BEFORE it
        // looks the secret up, and refuses a mismatch with INVALID_ARGUMENT. So a
        // caller sending any key with a garbage secret learned whether that key
        // had been redeemed — INVALID_ARGUMENT if it had, UNAUTHENTICATED if it
        // had not. The response-time floor equalises TIME and never STATUS.
        //
        // NOTHING IS LOST BY COLLAPSING IT. The only other INVALID_ARGUMENT that
        // call can produce is the store refusing an `argon2id_hash` too long for
        // its column, and `iam` mints that PHC string itself — its length is
        // fixed and unreachable from the request.
        //
        // THE OTHER CODES STAY. UNAVAILABLE and INTERNAL describe the deployment
        // rather than the secret: every caller sees them at once, so they tell an
        // attacker nothing about the key they presented, and collapsing an outage
        // into "this enrolment cannot be redeemed" would send a person to reissue
        // an enrolment that is fine.
        //
        // THE GENERAL RULE, because one call site is not the lesson: a design
        // promising ONE refusal for N outcomes must audit the status code of
        // EVERY upstream error it forwards, not only its own refusal paths. The
        // two remaining `upstream_failed` sites in this function — the password
        // lookup and the credential mint — are safe for the reason step 4 gives:
        // both run only after the secret is confirmed and spent, so their codes
        // report nothing the caller does not already know.
        let spent = match self.client().redeem_enrolment(spend).await {
            Ok(answered) => answered.into_inner(),
            Err(refused) if refused.code() == tonic::Code::InvalidArgument => {
                // THE VERIFICATION THE SUCCESS PATH PAYS, paid here too — the same
                // reason step 3 below pays it, and this path would otherwise be
                // the one refusal costing a single Argon2id operation.
                let _ = self.keys.verify_password(None, &req.get_ref().password);
                // At INFO beside step 3's refusal and for the same reason: the
                // operator diagnosing a failed enrolment needs the store's own
                // words, and the caller must not have them.
                tracing::info!(
                    upstream = %refused.message(),
                    "enrolment redemption refused by the store"
                );
                call.fail("UNAUTHENTICATED");
                return Err(enrolment_refused());
            }
            Err(other) => return Err(upstream_failed(other)),
        };

        // 3. ONE FAILURE, NOT THREE.
        if spent.outcome() != db::RedeemOutcome::Redeemed {
            // THE VERIFICATION THE SUCCESS PATH IS ABOUT TO PAY, paid here too.
            // Without it a refusal costs one Argon2id operation and a redemption
            // costs two, and the response time says which — the same enumeration
            // `Login` closes with the same call, and the reason this one ignores
            // its answer.
            let _ = self.keys.verify_password(None, &req.get_ref().password);
            // The server tells the three apart and the caller does not. Recorded
            // at INFO because it is an ordinary event on an unauthenticated
            // endpoint; an operator diagnosing a failed enrolment needs to know
            // WHICH of the three it was, and that is the only place it exists.
            tracing::info!(
                outcome = spent.outcome().as_str_name(),
                "enrolment redemption refused"
            );
            call.fail("UNAUTHENTICATED");
            return Err(enrolment_refused());
        }

        // The username, decrypted exactly as it was encrypted. A person
        // enrolling on their first machine has no in-band way to learn it, and
        // `iam` holds no store to have remembered it in — so the store returning
        // the ciphertext in the same transaction is the only place a retry can
        // recover it from.
        let username = self
            .keys
            .decrypt(&spent.external_id_ciphertext)
            .map_err(|_| Status::internal("cannot decrypt the stored username"))?;

        // 4. THE REPLAY CHECK. The blind index is computed here from the name
        // just decrypted; the plaintext still crosses no boundary.
        let mut lookup = Request::new(db::GetPasswordHashRequest {
            // DEAD FIELD, EMPTY FOR THE REASON GIVEN IN `login`: the plaintext
            // name just decrypted must not cross this boundary either. The
            // expectation is per-field for the reason given there too.
            #[expect(
                deprecated,
                reason = "the dead field is written out rather than defaulted: see above"
            )]
            username: String::new(),
            username_blind_index: self.keys.blind_index(&username),
        });
        forward_request_id(&req, &mut lookup);
        let held = self
            .client()
            .get_password_hash(lookup)
            .await
            .map_err(upstream_failed)?
            .into_inner();

        let stored = (!held.user_id.is_empty()).then_some(held.argon2id_hash.as_str());
        if !self.keys.verify_password(stored, &req.get_ref().password) {
            call.fail("INVALID_ARGUMENT");
            // NAMED, AND SAFE TO NAME. Reaching this line means the secret was
            // already confirmed and spent under this very key, so the refusal
            // reports nothing the caller did not already know. That is the
            // opposite of the refusals above it, and the reason validation runs
            // before the lookup rather than here.
            return Err(Status::invalid_argument(
                "this idempotency key was used with a different password; a \
                 replay cannot change the password the first attempt set",
            ));
        }

        // A FRESH CREDENTIAL UNDER ITS OWN KEY. The caller's key deliberately
        // does not cover this write: the token is shown once and kept as a hash,
        // so no replay could return the first one, and a store able to hand its
        // own tokens back is a different class of risk. A retry therefore mints
        // a credential the earlier attempt's owner never holds — the orphan the
        // contract accepts, findable through ListCredentials.
        let token = Keys::mint_token().map_err(|_| Status::internal("cannot mint a credential"))?;
        let mut create = Request::new(db::CreateCredentialRequest {
            idempotency: Some(Idempotency {
                key: uuid::Uuid::now_v7().to_string(),
            }),
            user_id: spent.user_id.clone(),
            token_hash: Keys::token_hash(&token),
            label: req.get_ref().label.clone(),
            // NO EXPIRY, because this request has no field to ask for one.
            expires_at: None,
            // NOT STAMPED. This credential is minted by RedeemEnrolment, whose
            // request carries no actor to record — the holder of the enrolment
            // secret is the subject, not an administrator acting on one. The
            // field exists on the boundary from v1.10.0 and is left absent
            // rather than filled with a value nothing supplied.
            unverified_actor: None,
        });
        forward_request_id(&req, &mut create);

        let created = self
            .client()
            .create_credential(create)
            .await
            .map_err(upstream_failed)?
            .into_inner();

        call.finish(Outcome {
            status: "OK",
            ..Default::default()
        });
        Ok(Response::new(RedeemEnrolmentResponse {
            token: token.to_string(),
            credential_id: created.credential_id,
            username,
        }))
    }
}

/// Everything that can be refused WITHOUT looking the secret up.
///
/// **THIS IS THE LIST, AND ITS SHORTNESS IS THE POINT.** Any check added here
/// must be answerable from the request alone; a check that needs to know whether
/// the secret exists belongs after the lookup and must refuse with
/// `UNAUTHENTICATED` like every other outcome there, or the status code becomes
/// the oracle constant work was meant to close.
///
/// THE SECRET IS DELIBERATELY NOT VALIDATED. An empty or malformed one is left
/// to fall through to the lookup and be refused as unknown, which is what it is.
/// A shape check on it would be a second way for this endpoint to answer, told
/// apart from the first by its status code.
fn validate_redemption(r: &RedeemEnrolmentRequest) -> Result<(), Status> {
    // REQUIRED, and this is the field the whole retry-safety story rests on. A
    // redemption spends the secret and mints the credential, so a lost response
    // with no key leaves the person holding a password they chose, a spent
    // secret, no credential and no username — and a bare retry answers
    // UNAUTHENTICATED. The key is what makes the retry reach the store as the
    // same write.
    if r.idempotency.as_ref().is_none_or(|i| i.key.is_empty()) {
        return Err(Status::invalid_argument(
            "an idempotency key is required: without one a retry spends the \
             secret a second time instead of replaying the first attempt, and a \
             lost response locks the person out",
        ));
    }
    // A password nobody typed is not a password. The only strength rule stated
    // here, deliberately — see MAX_PASSWORD_BYTES.
    if r.password.is_empty() {
        return Err(Status::invalid_argument("a password is required"));
    }
    if r.password.len() > MAX_PASSWORD_BYTES {
        return Err(Status::invalid_argument(
            "the password is longer than this service will hash",
        ));
    }
    check_label(&r.label)?;
    Ok(())
}

/// The ONE bound on a caller-supplied `label`, shared by the three RPCs that
/// store one.
///
/// **ONE FUNCTION FOR THREE FIELDS, AND THAT IS NOT THE SHORTCUT IT LOOKS
/// LIKE.** ADR-0565 says a bound is re-argued per field rather than shared —
/// but that is about the NUMBER, and `LoginRequest.label`,
/// `RedeemEnrolmentRequest.label` and `IssueCredentialRequest.label` are the
/// same field, described in `iam.proto` as the same free text, travelling to
/// `iam-db` as the same `CreateCredentialRequest.label`, and landing in the same
/// column. Three copies of one number is how two of them end up stale.
///
/// **THE SWEEP, BECAUSE FIXING AN INSTANCE IS NOT CLOSING A CLASS.**
/// `iam.proto` carries exactly three caller-supplied labels and every one is
/// checked here. `Credential.label` on `ListCredentials` is a READ of a stored
/// value and not an input. `iam` builds no other `CreateCredentialRequest`.
///
/// **CHARACTERS COUNTED AS `char`s, WHICH IS THE COLUMN'S OWN UNIT.** A Rust
/// `char` is a Unicode scalar value and utf8mb4 stores one per character, so the
/// two counts agree exactly. Graphemes would NOT: a flag or a family emoji is
/// several scalar values and one grapheme, so counting graphemes under-counts
/// against the column and re-opens the refusal this exists to prevent — and it
/// would need a crate to do it.
fn check_label(label: &str) -> Result<(), Status> {
    if label.chars().count() > MAX_LABEL_CHARS {
        return Err(Status::invalid_argument(
            "the label is longer than the store will hold: at most 255 \
             characters, counted as characters and not as bytes",
        ));
    }
    Ok(())
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

/// The one member of the setting vocabulary (ADR-0522).
///
/// A CLOSED SET, ENFORCED RATHER THAN DOCUMENTED. A store that accepted free
/// text would accrete settings nothing reads, and a typo would be persisted as a
/// new setting instead of being refused at the call that made it. Adding a
/// member is a contract release, never a data change.
const OWNER_READS_OWN_RECORD: &str = "owner_reads_own_record";

/// Every clause `yadgar.common.v1.SettingScope` states, applied HERE.
///
/// **THE VALIDATION IS THE CONTRACT'S AND IS STATED ONCE, THERE.** This function
/// applies it and deliberately does not restate the reasoning: two normative
/// copies in two files must stay in step for ever, and the copy that drifts is
/// the one a reader happens to open. Each refusal below names the clause it
/// enforces so a reader can find it, and every one is `INVALID_ARGUMENT`.
///
/// **IT RUNS BEFORE THE STORE IS CALLED**, which is what makes `iam` refuse
/// these itself rather than forward them. A refused request leaves no row and
/// burns no idempotency key.
///
/// **WHAT IT DELIBERATELY DOES NOT REFUSE: a `value` holding a number this
/// contract does not name.** The clause list is closed, and it names non-member
/// refusal for `scope` ALONE — because a `switch` on the scope whose `default:`
/// falls through writes the ORGANISATION's policy for a request that named
/// neither level. `iam` does not interpret `value` at all, so it has no such
/// fall-through, and adding a refusal `iam-db` does not share would make the two
/// boundaries disagree about one request. The number is copied through and the
/// store applies its own check (D5: one RPC is one transaction, so a refusal
/// there changes nothing).
fn check_inherited_setting(r: &SetInheritedSettingRequest) -> Result<(), Status> {
    // `scope` IS NOT ONE OF THE MEMBERS THIS ENUM DECLARES. proto3 enums are
    // open, so an unrecognised number arrives intact rather than collapsing to
    // the zero — and it must not be treated as either level.
    let scope = SettingScope::try_from(r.scope).map_err(|_| {
        Status::invalid_argument(
            "scope names no level this contract declares; there are two, an \
             organisation and a team",
        )
    })?;

    match scope {
        SettingScope::Unspecified => {
            return Err(Status::invalid_argument(
                "scope is required: a write addresses the organisation's level \
                 or one team's, and neither is the default",
            ));
        }
        SettingScope::Org => {
            // There is ONE organisation (D27), so a team id here is a caller
            // that meant TEAM.
            if r.team_id.is_some() {
                return Err(Status::invalid_argument(
                    "a team id at organisation scope is a request that meant \
                     team scope; there is one organisation and it is not named",
                ));
            }
            // Every default is wrong: false is the unsafe direction, true locks
            // a deployment that never asked, and keeping the stored value stops
            // the verb from stating a wanted result.
            if r.locked.is_none() {
                return Err(Status::invalid_argument(
                    "locked is required at organisation scope: it has no safe \
                     default, and an unstated lock is the permissive half of a \
                     policy nobody chose",
                ));
            }
            // The organisation always holds a value — the resolution's first
            // step refuses an unset one — so there is nothing there to clear.
            if r.clear {
                return Err(Status::invalid_argument(
                    "the organisation's value cannot be cleared: it always \
                     holds one, and a deployment changes it by stating the \
                     other value",
                ));
            }
        }
        SettingScope::Team => {
            // Nothing names the row to write. ABSENT and PRESENT-AND-EMPTY are
            // two cases, and this boundary has to refuse the second.
            if !r.team_id.as_deref().is_some_and(|t| !t.is_empty()) {
                return Err(Status::invalid_argument(
                    "a team id is required at team scope: nothing else names \
                     the override to write",
                ));
            }
            // The lock is meaningful at organisation scope only, and `false`
            // silently discarded is exactly the case this refusal exists for.
            if r.locked.is_some() {
                return Err(Status::invalid_argument(
                    "locked is meaningful at organisation scope only: a team \
                     cannot state whether teams may override",
                ));
            }
        }
    }

    // SENT EXPLICITLY, THE ZERO IS STILL A REFUSAL AND NEVER A CLEAR — at either
    // scope. It is what a caller that populated nothing sends.
    if r.value == Some(SettingValue::Unspecified as i32) {
        return Err(Status::invalid_argument(
            "value was sent unspecified: that is what an unpopulated field \
             looks like, and it is never read as a value or as a withdrawal",
        ));
    }

    // AN OMITTED VALUE CAN NEVER BE READ AS A DELETION (ADR-0524).
    if r.value.is_none() && !r.clear {
        return Err(Status::invalid_argument(
            "value is required unless clear is set: a request that states \
             neither says nothing at all",
        ));
    }

    // Two contradicting instructions, and neither is the obvious one to discard.
    if r.clear && r.value.is_some() {
        return Err(Status::invalid_argument(
            "clear and value contradict each other: withdraw the override or \
             state one, never both in the same request",
        ));
    }

    if r.name != OWNER_READS_OWN_RECORD {
        return Err(Status::invalid_argument(
            "name is not a setting this contract declares; the vocabulary is \
             closed and adding to it is a contract release",
        ));
    }

    Ok(())
}

/// The two `expires_in_seconds` values `IssueCredential` refuses, and why the
/// refusal belongs on this boundary rather than at the store.
///
/// The contract says of this field exactly one thing — "Zero means no expiry" —
/// so neither value below is one a caller written against it sends, and refusing
/// them is not a refusal such a caller newly meets. What each one did before is
/// different, and only one of them ever reached the database.
///
/// **ABOVE THE BOUND ALREADY FAILED CLOSED, and the fix is the message rather
/// than the outcome.** Measured against `mariadb:11.8.9` — the image `iam-db`'s
/// README stands up — at its stock `sql_mode`, which is strict:
/// `FROM_UNIXTIME(4294967296)` is NULL, and the INSERT is REFUSED with `ERROR
/// 1292 Truncated incorrect unixtime value` rather than storing that NULL. So no
/// credential was ever written with a swallowed deadline. But `iam-db` renders
/// every engine error as "storage unavailable", so a malformed request came back
/// to its caller reading as an outage, implicating a database that was working.
/// Refusing here is ADR-0512's shape: the negative outcome is documented on the
/// boundary the caller compiles against. It also makes the outcome independent
/// of the store's `sql_mode` — the same INSERT stores the NULL under `sql_mode
/// = ''`, which nothing here deploys and nothing here asserts either.
///
/// **A NEGATIVE FAILED OPEN, and never involved the store at all.** The deadline
/// is only sent when the request asks for a positive one, so a negative sent
/// `expires_at: None` — the unlimited life `0` asks for, handed to the request
/// that asked for the shortest one possible. That is the credential that
/// authenticates forever, and it lives in this file rather than in the database.
fn check_issue_credential(r: &IssueCredentialRequest) -> Result<(), Status> {
    // HAD NO BOUND AT ALL, on the same handler that gained a validation function
    // for `expires_in_seconds`. See `check_label`: an over-long one reached the
    // column and came back as `UNAVAILABLE "storage unavailable"`, which
    // implicates a database that is working for a request that was never
    // well-formed — ADR-0512's misattribution, on the administrative path.
    check_label(&r.label)?;
    if r.expires_in_seconds < 0 {
        return Err(Status::invalid_argument(
            "expires_in_seconds cannot be negative: a deadline already past is \
             not a shorter life, and it will not be read as the unlimited one \
             that 0 asks for",
        ));
    }
    if r.expires_in_seconds > MAX_EXPIRES_IN_SECONDS {
        return Err(Status::invalid_argument(
            "expires_in_seconds is longer than this service will grant a \
             credential; send 0 to ask for no expiry at all",
        ));
    }
    Ok(())
}

#[tonic::async_trait]
impl IamService for Iam {
    /// The hot path: a bearer token to an identity.
    ///
    /// Hashes and forwards. `iam` does not cache — the GATEWAY does (D72), because
    /// a cache here would still cost a network round trip per request and defeat
    /// the point.
    async fn resolve_credential(
        &self,
        req: Request<ResolveCredentialRequest>,
    ) -> Result<Response<ResolveCredentialResponse>, Status> {
        let rid = request_id_of(&req);
        let call = Call::start(SERVICE, "ResolveCredential", Kind::Read, tel(rid, ""));

        let mut upstream = Request::new(db::ResolveCredentialRequest {
            token_hash: Keys::token_hash(&req.get_ref().token),
        });
        forward_request_id(&req, &mut upstream);

        let got = self
            .client()
            .resolve_credential(upstream)
            .await
            .map_err(upstream_failed)?
            .into_inner();

        // AN EMPTY user_id IS A NEGATIVE ANSWER, and it must not be cacheable.
        //
        // `iam-db` returns an empty response for "no live credential" — unknown,
        // revoked, expired, or belonging to a soft-deleted person. Copying that
        // through with the ordinary TTL tells the gateway to remember, for five
        // minutes, that a token resolves to user_id "". Nothing consumes this
        // field yet, which is exactly why the shape is pinned now: the consumer
        // that caches on it has not been written, and by the time it is, a
        // `valid_for_seconds: 300` beside an empty user id looks deliberate.
        //
        // Zero, not a shorter TTL: there is no interval over which "this token
        // belongs to nobody" is worth remembering, and a revoked credential's
        // negative answer is the one thing that must never be served from a
        // cache.
        let resolved = !got.user_id.is_empty();
        let resp = ResolveCredentialResponse {
            user_id: got.user_id,
            team_ids: got.team_ids,
            // The gateway's cache TTL. A BACKSTOP, not the invalidation
            // mechanism — revocation and team changes arrive as broker events
            // (D72). Five minutes bounds how long a missed event can leave a
            // revoked credential working.
            valid_for_seconds: if resolved { 300 } else { 0 },
            // D73's flag, read in the same transaction as the credential and
            // passed straight through. FALSE IS THE SAFE DEFAULT — an `iam` that
            // did not set it denies administration rather than granting it —
            // which is why it is forwarded rather than left to that default: the
            // safe reading of an absent value is not a reason to make every
            // admin absent.
            is_admin: got.is_admin,
            // DELIBERATELY LEFT EMPTY IN THIS CHANGE, and empty is a defined
            // answer rather than a missing one: no override for any bucket, so
            // the gateway's configured defaults apply unmodified. It is NOT
            // "deny everything". D74's overrides need a mapping between the
            // storage and API shapes of `RateLimitOverride` and are not part of
            // enrolment; forwarding them is the follow-up this line marks.
            rate_limit_overrides: Vec::new(),
            // ADR-0522's setting, MOVED WHOLE AND NEVER REBUILT.
            //
            // **THE INPUTS, NEVER THE ANSWER.** `iam` resolves none of this. The
            // resolution depends on the team of the ROW being read, which no
            // caller upstream of the query knows, so it happens where the reach
            // is computed. `yadgar.common.v1.InheritedSetting` states the rule
            // once; writing a second copy of it here is the mistake that
            // comment exists to prevent.
            //
            // **NO DEFAULT IS SUBSTITUTED FOR AN ABSENT ONE, AND THAT IS THE
            // WHOLE POINT.** `iam-db` answers with the message ABSENT when the
            // organisation row is not there, and with `org_locked` FALSE — and
            // false is the PERMISSIVE half of a policy the deployment never
            // stated. An `unwrap_or_default()` here, or any field-by-field
            // reconstruction, would hand a -db a policy nobody chose. Absent and
            // present-holding-UNSPECIFIED are ONE case, which a -db that reads
            // this setting REFUSES rather than reading as OFF. A single move is
            // what makes substituting a default unwritable rather than merely
            // discouraged.
            //
            // NOT BRANCHED ON `resolved`, unlike `valid_for_seconds` above. That
            // TTL is zeroed on the negative path because a negative answer is
            // worth caching for no interval. This setting is DEPLOYMENT-WIDE
            // rather than credential-scoped, and no rule in the contract makes
            // it conditional on a credential matching.
            owner_reads_own_record: got.owner_reads_own_record,
        };
        call.finish(Outcome {
            status: "OK",
            ..Default::default()
        });
        Ok(Response::new(resp))
    }

    /// Username and password to a long-lived token. The one sign-in a person
    /// performs (D72).
    ///
    /// **The whole call is held to a response-time floor**, both the success and
    /// the failure path — see `Iam::hold_until_floor` for why it is one rule with
    /// no branch, and `crypto::Keys::verify_password` for the leak it closes.
    async fn login(&self, req: Request<LoginRequest>) -> Result<Response<LoginResponse>, Status> {
        // THE CLOCK STARTS BEFORE ANYTHING ELSE, and the answer is computed to
        // completion before a single byte of it is returned. Flooring the whole
        // handler is what makes the round trips to `iam-db` — one on every path,
        // a second on the success path — part of what the floor covers rather
        // than a residual outside it.
        let started = Instant::now();
        let rid = request_id_of(&req);
        let call = Call::start(SERVICE, "Login", Kind::Write, tel(rid.clone(), ""));
        let answered = self.login_inner(req, call).await;
        self.hold_until_floor(self.login_floor, started.elapsed())
            .await;
        answered
    }

    /// An enrolment secret and a chosen password to a credential (D73).
    ///
    /// **UNAUTHENTICATED BY CONSTRUCTION** — the secret is all the caller has —
    /// so this carries `Login`'s enumeration problem in a sharper form, and it
    /// takes the same two precautions plus one. `Self::redeem_inner` holds the
    /// order that makes constant work and validation-before-lookup true; this
    /// handler holds it to a response-time floor.
    ///
    /// **THE FLOOR IS NOT `Login`'s ARGUMENT RECYCLED.** `Login` needs one
    /// because the Argon2id cost of a stored hash is a property of the ROW, and
    /// `iam` can equalise its own work but not what a row costs. Here the three
    /// refusals — unknown, spent, expired — are decided INSIDE `iam-db`, by a
    /// `RedeemOutcome` this service only reads. A miss, a row found spent and a
    /// row found expired need not cost the store the same, and NO amount of
    /// constant work in this process can equalise a difference that arises in
    /// another one. Collapsing the three into one status code and then letting
    /// the response time separate them again would leave the contract's "ONE
    /// FAILURE, NOT THREE" true of the code and false of the endpoint. A floor
    /// over the WHOLE handler is the only thing that covers an upstream
    /// difference, which is why it is here and why it is not optional.
    async fn redeem_enrolment(
        &self,
        req: Request<RedeemEnrolmentRequest>,
    ) -> Result<Response<RedeemEnrolmentResponse>, Status> {
        // THE CLOCK STARTS BEFORE ANYTHING ELSE, and the answer is computed to
        // completion before a byte of it is returned — the round trips to
        // `iam-db` included, which is where the difference this hides arises.
        let started = Instant::now();
        let rid = request_id_of(&req);
        let call = Call::start(SERVICE, "RedeemEnrolment", Kind::Write, tel(rid, ""));
        let answered = self.redeem_inner(req, call).await;
        self.hold_until_floor(self.redeem_floor, started.elapsed())
            .await;
        answered
    }

    /// Mint the enrolment an admin hands to a person (D73).
    ///
    /// Administrative, and the ONLY path that sets a password on an account
    /// which already has one: a fresh enrolment, redeemed, sets it
    /// unconditionally. That is the recovery for a forgotten password and for a
    /// redemption that spent its secret without leaving a usable credential.
    ///
    /// **THE ADMIN NEVER LEARNS THE PASSWORD**, which is the whole of D73 — but
    /// an admin may mint an enrolment for any existing user and redeem it
    /// themselves. The literal guarantee survives and its rationale is MITIGATED
    /// RATHER THAN ELIMINATED: the issuance is recorded and the victim's old
    /// password stops working, so the act is loud rather than silent.
    ///
    /// **A REPLAYED KEY RETURNS A TOKEN THAT CANNOT BE REDEEMED, AND THAT IS A
    /// KNOWN GAP IN THE CONTRACT RATHER THAN AN OVERSIGHT HERE.** The key is
    /// forwarded to `CreateEnrolment` unchanged, because D9 applies to every
    /// mutating RPC and the store is where deduplication lives (D4). On a replay
    /// the store answers with the ORIGINAL `enrolment_id` and keeps the ORIGINAL
    /// `secret_hash` — while this call has minted a FRESH secret, whose hash was
    /// never stored. The contract asks for a replay to return the same token and
    /// in the same breath records why it cannot: the store "keeps only a hash",
    /// which is also why D73 puts token RESEND outside the first cut. Nothing in
    /// this service can reconcile the two; deriving the secret from the key
    /// would, and is refused — it makes a caller-chosen string the entropy of an
    /// unauthenticated endpoint's whole authenticator.
    ///
    /// The consequence is bounded and recoverable: a replay hands the admin a
    /// dead token, its redemption is refused like any unknown secret, and the
    /// fix is the one this RPC already is — mint another. Not forwarding the key
    /// would trade that for `iam` unilaterally disabling a mechanism the
    /// contract mandates, which is the worse of the two.
    ///
    /// **UNCONFIGURED ENROLMENT REFUSES HERE RATHER THAN AT BOOT.** The contract
    /// rule is about the TOKEN — never mint one carrying an empty `gateway` —
    /// and refusing to mint keeps it whole. Refusing to start would also stop
    /// `ResolveCredential`, which is the authentication plane for the whole
    /// estate; see [`EnrolmentConfig::from_env`].
    async fn issue_enrolment(
        &self,
        req: Request<IssueEnrolmentRequest>,
    ) -> Result<Response<IssueEnrolmentResponse>, Status> {
        let rid = request_id_of(&req);
        let call = Call::start(
            SERVICE,
            "IssueEnrolment",
            Kind::Write,
            tel(rid, &req.get_ref().user_id),
        );

        // BEFORE THE SECRET IS MINTED AND BEFORE THE STORE IS TOUCHED, so a
        // deployment without enrolment configured leaves no enrolment row and
        // no secret behind. FAILED_PRECONDITION rather than INTERNAL: the
        // request is well formed and the service is not broken, it is not
        // configured for this — and the message names the variable, because the
        // operator reading it is the one who can fix it.
        let Some(enrolment) = self.enrolment.as_ref() else {
            call.fail("FAILED_PRECONDITION");
            return Err(Status::failed_precondition(
                "enrolment is not configured on this deployment: ENROLMENT_GATEWAY \
                 is unset or the CA it names could not be read, and a token minted \
                 without them would point a new client at nothing",
            ));
        };

        // 256 bits from the OS CSPRNG, through the same mint point a bearer
        // token uses. This secret IS the whole authenticator of an
        // unauthenticated endpoint, so its entropy is the single property that
        // decides whether that endpoint is brute-forceable — and one mint point
        // is what stops a second, weaker one from appearing beside it.
        let secret =
            Keys::mint_token().map_err(|_| Status::internal("cannot mint an enrolment"))?;

        // WRITTEN DOWN AT CREATION, not recomputed at read time: a policy change
        // must not silently re-date every live token.
        let expires_at = prost_types::Timestamp::from(SystemTime::now() + ENROLMENT_LIFETIME);

        let mut create = Request::new(db::CreateEnrolmentRequest {
            idempotency: req.get_ref().idempotency.clone(),
            user_id: req.get_ref().user_id.clone(),
            // The HASH. The secret itself never crosses this boundary, so it
            // reaches no query log and no backup — and deterministic, because
            // redemption looks an enrolment up by exactly this value.
            secret_hash: Keys::token_hash(&secret),
            expires_at: Some(expires_at),
            // NOT FORWARDED, DELIBERATELY. `IssueEnrolmentRequest` grew this
            // field in proto v1.10.0 and nothing in the estate populates it
            // yet, so copying it across would carry `None` under a different
            // name and read as a relay that works. Wiring the relay is
            // ADR-0534's own change, not this pin bump.
            unverified_actor: None,
        });
        forward_request_id(&req, &mut create);

        let created = self
            .client()
            .create_enrolment(create)
            .await
            .map_err(upstream_failed)?
            .into_inner();

        // THE TRUST ANCHOR TRAVELS WITH THE SECRET, and not merely the secret. A
        // client that has never met this deployment has nothing to verify the
        // gateway against; the out-of-band channel this token is pasted over is
        // already trusted, so the anchor goes on it. `gateway` and `ca_pem` come
        // from this service's configuration, so an admin assembles neither and
        // can get neither wrong.
        let token = EnrolmentToken {
            secret: secret.to_string(),
            gateway: enrolment.gateway.clone(),
            // ABSENT means system trust applies, which is a legitimate
            // deployment. It is never PRESENT AND EMPTY: `EnrolmentConfig`
            // refuses that at boot, because absence is the whole of "use system
            // trust" and an empty string is a token assembled wrong.
            ca_pem: enrolment.ca_pem.clone(),
            expires_at: Some(expires_at),
        };

        // STANDARD ALPHABET, WITH PADDING (RFC 4648 section 4), and NOT the
        // URL-safe unpadded encoding `Keys::mint_token` uses inside the message.
        // The contract names the alphabet because getting it wrong produces a
        // token that decodes to noise on precisely the machines that have never
        // met this deployment and can least diagnose it.
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(prost::Message::encode_to_vec(&token));

        call.finish(Outcome {
            status: "OK",
            ..Default::default()
        });
        Ok(Response::new(IssueEnrolmentResponse {
            token: encoded,
            enrolment_id: created.enrolment_id,
            expires_at: Some(expires_at),
        }))
    }

    /// NOT IMPLEMENTED IN THIS CHANGE, and named rather than silently absent.
    ///
    /// This RPC exists in the contract BECAUSE of `RedeemEnrolment`'s residual: a
    /// lost redemption response leaves a credential nobody holds, and without
    /// this list it is reachable only by someone with direct access to the
    /// database. Shipping the residual before its remedy is a deliberate,
    /// recorded gap — `UNIMPLEMENTED` is what makes it visible to a caller
    /// instead of an empty list that looks like an answer.
    async fn list_credentials(
        &self,
        req: Request<ListCredentialsRequest>,
    ) -> Result<Response<ListCredentialsResponse>, Status> {
        // INSTRUMENTED EVEN THOUGH IT REFUSES (D67). A handler that emits
        // nothing is indistinguishable from one nobody called, so an operator
        // asking whether anything has needed this RPC yet would read silence as
        // an answer. `fail` is what makes "asked for, and refused" countable.
        let rid = request_id_of(&req);
        let call = Call::start(
            SERVICE,
            "ListCredentials",
            Kind::Read,
            tel(rid, &req.get_ref().user_id),
        );
        call.fail("UNIMPLEMENTED");
        Err(Status::unimplemented(
            "ListCredentials is not implemented yet; an orphaned credential is \
             currently findable only in the store",
        ))
    }

    /// NOT IMPLEMENTED IN THIS CHANGE. D73's admin flag reaches the store
    /// (`iamdb.v1.SetUserAdmin`) and this service does not drive it yet.
    async fn set_user_admin(
        &self,
        req: Request<SetUserAdminRequest>,
    ) -> Result<Response<SetUserAdminResponse>, Status> {
        let rid = request_id_of(&req);
        let call = Call::start(
            SERVICE,
            "SetUserAdmin",
            Kind::Write,
            tel(rid, &req.get_ref().user_id),
        );
        call.fail("UNIMPLEMENTED");
        Err(Status::unimplemented("SetUserAdmin is not implemented yet"))
    }

    /// NOT IMPLEMENTED IN THIS CHANGE. D74's overrides are contract surface this
    /// change does not touch.
    async fn set_rate_limit_override(
        &self,
        req: Request<SetRateLimitOverrideRequest>,
    ) -> Result<Response<SetRateLimitOverrideResponse>, Status> {
        let rid = request_id_of(&req);
        let call = Call::start(
            SERVICE,
            "SetRateLimitOverride",
            Kind::Write,
            tel(rid, &req.get_ref().user_id),
        );
        call.fail("UNIMPLEMENTED");
        Err(Status::unimplemented(
            "SetRateLimitOverride is not implemented yet",
        ))
    }

    /// Write ONE LEVEL of ADR-0522's inheritable setting: validate here, store
    /// there.
    ///
    /// **THIS SERVICE REFUSES THE CONTRACT'S CLAUSES ITSELF RATHER THAN
    /// FORWARDING THEM** — `yadgar.iam.v1`'s comment on this RPC says so, and
    /// [`check_inherited_setting`] is where it happens. Every refusal lands
    /// BEFORE the store is called, so a rejected request leaves no row, no
    /// ledger entry and no idempotency key behind.
    ///
    /// **IT RESOLVES NOTHING.** The response carries the setting whole, exactly
    /// as the store answered. The resolution depends on the team of the ROW
    /// being read and belongs where the reach is computed; see
    /// `yadgar.common.v1.InheritedSetting`, which states it once.
    ///
    /// **THE AUTHORISATION GAP, STATED RATHER THAN LEFT TO BE FOUND.** This
    /// request carries no attested caller identity, in common with every
    /// administrative RPC on this service. So `iam` can neither VERIFY that the
    /// caller is an administrator nor RECORD which one changed a policy that
    /// governs who may read which records. The check belongs at the gateway, on
    /// D73's admin flag, because the gateway is the one place identity is
    /// attested (ADR-0488) — a second authentication path invented here would be
    /// a second place for it to be wrong, holding the same secret twice.
    /// **D73's BOOTSTRAP TOKEN DOES NOT REACH THIS VERB**, and must not be
    /// extended to it: a token that exists to create the FIRST admin would
    /// otherwise rewrite the read policy for the whole deployment before an
    /// admin exists to notice.
    ///
    /// **NOTHING IS INVALIDATED, AND THAT IS THE CONTRACT'S ANSWER RATHER THAN
    /// AN OMISSION.** The setting travels on the credential a gateway caches
    /// (ADR-0491). An organisation-level write touches every cached credential
    /// in the deployment and no event on this contract says so, and the
    /// per-user subjects [`crate::invalidate`] publishes need a `user_id` this
    /// request does not carry. A deployment that tightens this policy WAITS THE
    /// CACHE OUT.
    async fn set_inherited_setting(
        &self,
        req: Request<SetInheritedSettingRequest>,
    ) -> Result<Response<SetInheritedSettingResponse>, Status> {
        let rid = request_id_of(&req);
        let call = Call::start(SERVICE, "SetInheritedSetting", Kind::Write, tel(rid, ""));

        if let Err(refusal) = check_inherited_setting(req.get_ref()) {
            call.fail("INVALID_ARGUMENT");
            return Err(refusal);
        }

        let r = req.get_ref();
        // FIELD BY FIELD ONLY BECAUSE THE TWO REQUEST TYPES ARE DIFFERENT — one
        // per boundary, as every other forwarded write here is. `value` and
        // `locked` are copied with their PRESENCE intact: absence is a distinct
        // instruction from any value, and collapsing it would make `clear` the
        // only way this service can express a withdrawal (ADR-0524).
        let mut upstream = Request::new(db::SetInheritedSettingRequest {
            idempotency: r.idempotency.clone(),
            scope: r.scope,
            team_id: r.team_id.clone(),
            name: r.name.clone(),
            value: r.value,
            locked: r.locked,
            clear: r.clear,
            // NOT FORWARDED, for the reason given at IssueEnrolment above: the
            // field is new in proto v1.10.0, no caller sets it, and the
            // upstream this forwards to still vendors v1.8.0 and has no field
            // to receive it. See the follow-up task on ADR-0534's relay.
            unverified_actor: None,
        });
        forward_request_id(&req, &mut upstream);

        let set = self
            .client()
            .set_inherited_setting(upstream)
            .await
            .map_err(upstream_failed)?
            .into_inner();

        call.finish(Outcome {
            status: "OK",
            ..Default::default()
        });
        // MOVED WHOLE. The store's answer carries the OTHER level and every
        // OTHER team's override, which the caller did not send — rebuilding it
        // here is how a field goes missing from a policy an operator is reading
        // back.
        Ok(Response::new(SetInheritedSettingResponse {
            setting: set.setting,
        }))
    }

    async fn issue_credential(
        &self,
        req: Request<IssueCredentialRequest>,
    ) -> Result<Response<IssueCredentialResponse>, Status> {
        let rid = request_id_of(&req);
        let call = Call::start(
            SERVICE,
            "IssueCredential",
            Kind::Write,
            tel(rid, &req.get_ref().user_id),
        );

        let r = req.get_ref();
        // BEFORE THE MINT, so a refused request leaves no token in existence.
        if let Err(refusal) = check_issue_credential(r) {
            call.fail("INVALID_ARGUMENT");
            return Err(refusal);
        }

        let token = Keys::mint_token().map_err(|_| Status::internal("cannot mint a credential"))?;
        let mut create = Request::new(db::CreateCredentialRequest {
            // NOT FORWARDED, AND THIS IS THE ONE PLACE THAT SILENCE WAS A
            // DECISION RATHER THAN AN OVERSIGHT. `yadgar.common.v1.Idempotency`
            // names `IssueCredential` as the case ADR-0519's single-use-secret
            // carve-out "would reach", and says moving it "is its own decision
            // and its own contract release, and it is not made here". Handing
            // the caller's key to the store would decide it from this file: the
            // store would replay the key and answer with a credential whose
            // token was minted in the first call and kept only as a hash, so the
            // second caller receives a token that authenticates nobody — the
            // dead-token failure ADR-0519 exists to name. `RedeemEnrolment` puts
            // its own mint outside the caller's key for exactly this reason.
            //
            // **AND THE OTHER HALF, BECAUSE NOT FORWARDING IT IS NOT FREE.**
            // That same comment enumerates the carve-out's members and says "AN
            // RPC NOT NAMED HERE IS NOT A MEMBER, however well it fits the
            // description" — and today the list is one, `IssueEnrolment`. So as
            // published, `IssueCredential` is governed by D9's ORDINARY rule,
            // under which a retry of the same key returns the first answer. It
            // does not: `iam` accepts a key it then discards, so a caller
            // retrying a lost response mints a SECOND live credential and the
            // first is orphaned — a token nobody holds, revocable by nobody who
            // knows it exists, live until its expiry. Forwarding the key here
            // would trade that for the dead-token failure above, which is worse
            // and is not this file's to choose. The resolution is a contract
            // release that classifies this RPC, not a change on this line.
            idempotency: None,
            user_id: r.user_id.clone(),
            token_hash: Keys::token_hash(&token),
            label: r.label.clone(),
            // THE DEADLINE THE CALLER ASKED FOR. Zero means no expiry, which the
            // contract states in as many words, and it is the ONLY remaining way
            // to reach `None` here: a negative and an absurd value are both
            // refused above, by `check_issue_credential`, which carries the
            // measurement that argues for each refusal.
            //
            // ADDED IN SECONDS ON THE WIRE TYPE. Kept SATURATING although the
            // bound makes the saturation unreachable — a ten-year offset cannot
            // carry an epoch second past `i64::MAX` — because `SystemTime +
            // Duration` aborts the process on overflow and nothing about this
            // handler should depend on a bound staying where it is today.
            expires_at: (r.expires_in_seconds > 0).then(|| {
                let now = prost_types::Timestamp::from(SystemTime::now());
                prost_types::Timestamp {
                    seconds: now.seconds.saturating_add(r.expires_in_seconds),
                    nanos: now.nanos,
                }
            }),
            // NOT FORWARDED, AND THE FIELD IS ON BOTH SIDES OF THIS HOP.
            // `IssueCredentialRequest` grew ADR-0534's actor in proto v1.10.0 and
            // nothing populates it: the gateway reaches three RPCs and this is
            // not one of them, so there is no administrative path for an actor to
            // arrive on. Relaying `r.unverified_actor` today would move `None`
            // and READ AS A RELAY THAT WORKS.
            //
            // **THE RELAY HAS SEVEN SITES AND THIS IS ONE**: here,
            // `revoke_credential`, `create_user`, `add_team_member`,
            // `remove_team_member`, and the two that already said so before this
            // change — `issue_enrolment` and `set_inherited_setting`. Five of the
            // seven were invisible until this file stopped using a rest pattern,
            // so whoever wires the path by grepping for the field would have
            // found two.
            unverified_actor: None,
        });
        forward_request_id(&req, &mut create);

        let created = self
            .client()
            .create_credential(create)
            .await
            .map_err(upstream_failed)?
            .into_inner();

        call.finish(Outcome {
            status: "OK",
            ..Default::default()
        });
        Ok(Response::new(IssueCredentialResponse {
            token: token.to_string(),
            credential_id: created.credential_id,
        }))
    }

    /// Revoke, and publish the invalidation.
    ///
    /// **Publishing is what makes the gateway's cache safe** (D72). Without it a
    /// revoked credential keeps working until its TTL expires, which turns the
    /// backstop into the mechanism and makes every revocation late by design.
    ///
    /// The publish happens AFTER the store confirms, and its failure does not
    /// fail this call: the revocation has already happened, and returning an
    /// error would tell the caller to retry something that is done.
    async fn revoke_credential(
        &self,
        req: Request<RevokeCredentialRequest>,
    ) -> Result<Response<RevokeCredentialResponse>, Status> {
        let rid = request_id_of(&req);
        let call = Call::start(SERVICE, "RevokeCredential", Kind::Write, tel(rid, ""));

        let mut upstream = Request::new(db::RevokeCredentialRequest {
            // D9's key travels. A revocation is a mutating RPC a retrying load
            // balancer will deliver twice, and the key is what makes the second
            // delivery a replay rather than a second write.
            idempotency: req.get_ref().idempotency.clone(),
            credential_id: req.get_ref().credential_id.clone(),
            // NOT FORWARDED, for the reason given at `issue_credential`: nothing
            // populates the field, so a relay would move `None` and read as one
            // that works. One of that comment's seven relay sites.
            unverified_actor: None,
        });
        forward_request_id(&req, &mut upstream);

        let done = self
            .client()
            .revoke_credential(upstream)
            .await
            .map_err(upstream_failed)?
            .into_inner();

        // The USER, not the credential — the gateway's cache is keyed on a token
        // hash this service never sees, so the person is the addressable unit.
        // This is why RevokeCredential returns user_id at all.
        self.invalidator.credential_revoked(&done.user_id).await;

        call.finish(Outcome {
            status: "OK",
            ..Default::default()
        });
        Ok(Response::new(RevokeCredentialResponse {}))
    }

    async fn create_user(
        &self,
        req: Request<CreateUserRequest>,
    ) -> Result<Response<CreateUserResponse>, Status> {
        let rid = request_id_of(&req);
        let call = Call::start(SERVICE, "CreateUser", Kind::Write, tel(rid, ""));
        let r = req.get_ref();

        let enc = |s: &str| {
            self.keys
                .encrypt(s)
                .map_err(|_| Status::internal("cannot encrypt"))
        };

        let mut upstream = Request::new(db::CreateUserRequest {
            // D9's key travels, on `revoke_credential`'s reasoning.
            idempotency: r.idempotency.clone(),
            // DEAD FIELDS, AND EMPTY IS THE SECURITY PROPERTY. The plaintext name
            // and display name never cross this boundary; the ciphertexts and the
            // blind index below are what the store receives. Written out empty
            // rather than defaulted, so the boundary's own rule is legible here.
            //
            // TWO FIELDS, TWO EXPECTATIONS, for the reason given in `login`: one
            // attribute covering both is satisfied by either, so the day one of
            // them stops being deprecated the lint stays quiet about the other.
            #[expect(
                deprecated,
                reason = "the dead field is written out rather than defaulted: see above"
            )]
            external_id: String::new(),
            #[expect(
                deprecated,
                reason = "the dead field is written out rather than defaulted: see above"
            )]
            display_name: String::new(),
            external_id_ciphertext: enc(&r.external_id)?,
            display_name_ciphertext: enc(&r.display_name)?,
            external_id_blind_index: self.keys.blind_index(&r.external_id),
            // D73'S ADMIN FLAG, AND IT HAS TO ARRIVE. It is settable at creation
            // for exactly one reason the contract states: the FIRST administrator
            // must exist before anyone can log in to promote one. This service
            // does not decide the value and does not authorise on it — it carries
            // what the caller sent, which is what `SetUserAdmin` exists to change
            // afterwards.
            is_admin: r.is_admin,
            // NOT FORWARDED, for the reason given at `issue_credential`. One of
            // that comment's seven relay sites.
            unverified_actor: None,
        });
        forward_request_id(&req, &mut upstream);

        let created = self
            .client()
            .create_user(upstream)
            .await
            .map_err(upstream_failed)?
            .into_inner();

        call.finish(Outcome {
            status: "OK",
            ..Default::default()
        });
        Ok(Response::new(CreateUserResponse { meta: created.meta }))
    }

    async fn add_team_member(
        &self,
        req: Request<AddTeamMemberRequest>,
    ) -> Result<Response<AddTeamMemberResponse>, Status> {
        let rid = request_id_of(&req);
        let call = Call::start(
            SERVICE,
            "AddTeamMember",
            Kind::Write,
            tel(rid, &req.get_ref().user_id),
        );

        let mut upstream = Request::new(db::AddTeamMemberRequest {
            // D9's key travels, on `revoke_credential`'s reasoning.
            idempotency: req.get_ref().idempotency.clone(),
            team_id: req.get_ref().team_id.clone(),
            user_id: req.get_ref().user_id.clone(),
            // NOT FORWARDED, for the reason given at `issue_credential`. One of
            // that comment's seven relay sites.
            unverified_actor: None,
        });
        forward_request_id(&req, &mut upstream);

        self.client()
            .add_team_member(upstream)
            .await
            .map_err(upstream_failed)?;

        // ADDING invalidates too, and the subject is named `teams-changed`
        // rather than `teams-removed` precisely so this is not forgotten — see
        // `invalidate::subject::TEAMS_CHANGED`. Granting a team changes what a
        // cached identity says just as removing one does; without this, a newly
        // granted permission arrives up to 300s late and reads as a bug in
        // whatever the person was trying to reach.
        self.invalidator.teams_changed(&req.get_ref().user_id).await;

        call.finish(Outcome {
            status: "OK",
            ..Default::default()
        });
        Ok(Response::new(AddTeamMemberResponse {}))
    }

    /// Removing a member narrows what that user can see, so the cached identity
    /// has to be invalidated or they keep reading the team's records.
    async fn remove_team_member(
        &self,
        req: Request<RemoveTeamMemberRequest>,
    ) -> Result<Response<RemoveTeamMemberResponse>, Status> {
        let rid = request_id_of(&req);
        let call = Call::start(
            SERVICE,
            "RemoveTeamMember",
            Kind::Write,
            tel(rid, &req.get_ref().user_id),
        );

        let mut upstream = Request::new(db::RemoveTeamMemberRequest {
            // D9's key travels, on `revoke_credential`'s reasoning.
            idempotency: req.get_ref().idempotency.clone(),
            team_id: req.get_ref().team_id.clone(),
            user_id: req.get_ref().user_id.clone(),
            // NOT FORWARDED, for the reason given at `issue_credential`. One of
            // that comment's seven relay sites.
            unverified_actor: None,
        });
        forward_request_id(&req, &mut upstream);

        self.client()
            .remove_team_member(upstream)
            .await
            .map_err(upstream_failed)?;

        self.invalidator.teams_changed(&req.get_ref().user_id).await;

        call.finish(Outcome {
            status: "OK",
            ..Default::default()
        });
        Ok(Response::new(RemoveTeamMemberResponse {}))
    }
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
