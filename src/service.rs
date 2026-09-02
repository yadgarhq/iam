//! `IamService`. The only service that turns a credential into an identity.
//!
//! It holds the keys and `iam-db` holds none (D72), so every name and secret is
//! encrypted or hashed *here* before it crosses the storage boundary. The
//! division is what makes a stolen database backup worthless on its own.

use std::time::{Duration, Instant};

use tonic::{Request, Response, Status};
use yadgar_telemetry::observe::{Call, Outcome};
use yadgar_telemetry::pb::yadgar::telemetry::v1::Kind;

use crate::crypto::Keys;
use crate::invalidate::Invalidator;
use crate::pb::yadgar::iam::v1::iam_service_server::IamService;
use crate::pb::yadgar::iam::v1::*;
use crate::pb::yadgar::iamdb::v1 as db;
use crate::pb::yadgar::iamdb::v1::iam_db_service_client::IamDbServiceClient;

const SERVICE: &str = "iam";

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

pub struct Iam {
    keys: Keys,
    channel: tonic::transport::Channel,
    invalidator: Invalidator,
    /// See [`DEFAULT_LOGIN_RESPONSE_FLOOR`] and `Iam::hold_until_floor`.
    login_response_floor: Duration,
}

impl Iam {
    /// `login_response_floor` is REQUIRED rather than defaulted, so that the one
    /// place it is chosen is the one place it can be read — `main`, from
    /// `LOGIN_RESPONSE_FLOOR_MS`. A constructor that silently supplied
    /// [`DEFAULT_LOGIN_RESPONSE_FLOOR`] would let a caller build an `Iam` whose
    /// floor nobody selected, which is how a security control ends up configured
    /// by accident.
    pub fn new(
        keys: Keys,
        channel: tonic::transport::Channel,
        invalidator: Invalidator,
        login_response_floor: Duration,
    ) -> Self {
        Self {
            keys,
            channel,
            invalidator,
            login_response_floor,
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
        // The username never leaves this process. What goes to the store is its
        // blind index, so the plaintext reaches no query log and no backup.
        let mut lookup = Request::new(db::GetPasswordHashRequest {
            username_blind_index: self.keys.blind_index(&req.get_ref().username),
            ..Default::default()
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
            user_id: found.user_id.clone(),
            token_hash: Keys::token_hash(&token),
            label: req.get_ref().label.clone(),
            ..Default::default()
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
    async fn hold_until_floor(&self, elapsed: Duration) {
        let Some(remaining) = self.login_response_floor.checked_sub(elapsed) else {
            tracing::warn!(
                observed_ms = elapsed.as_millis() as u64,
                floor_ms = self.login_response_floor.as_millis() as u64,
                "Login took longer than its response-time floor; the floor is \
                 hiding nothing for this call. Raise LOGIN_RESPONSE_FLOOR_MS above \
                 the slowest legitimate login on this deployment."
            );
            return;
        };
        tokio::time::sleep(remaining).await;
    }
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
        self.hold_until_floor(started.elapsed()).await;
        answered
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

        let token = Keys::mint_token().map_err(|_| Status::internal("cannot mint a credential"))?;
        let mut create = Request::new(db::CreateCredentialRequest {
            user_id: req.get_ref().user_id.clone(),
            token_hash: Keys::token_hash(&token),
            label: req.get_ref().label.clone(),
            ..Default::default()
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
            credential_id: req.get_ref().credential_id.clone(),
            ..Default::default()
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
            external_id_ciphertext: enc(&r.external_id)?,
            display_name_ciphertext: enc(&r.display_name)?,
            external_id_blind_index: self.keys.blind_index(&r.external_id),
            ..Default::default()
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
            team_id: req.get_ref().team_id.clone(),
            user_id: req.get_ref().user_id.clone(),
            ..Default::default()
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
            team_id: req.get_ref().team_id.clone(),
            user_id: req.get_ref().user_id.clone(),
            ..Default::default()
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
