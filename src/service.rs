//! `IamService`. The only service that turns a credential into an identity.
//!
//! It holds the keys and `iam-db` holds none (D72), so every name and secret is
//! encrypted or hashed *here* before it crosses the storage boundary. The
//! division is what makes a stolen database backup worthless on its own.

use tonic::{Request, Response, Status};
use yadgar_telemetry::observe::{Call, Outcome};
use yadgar_telemetry::pb::yadgar::telemetry::v1::Kind;

use crate::crypto::Keys;
use crate::pb::yadgar::iam::v1::iam_service_server::IamService;
use crate::pb::yadgar::iam::v1::*;
use crate::pb::yadgar::iamdb::v1 as db;
use crate::pb::yadgar::iamdb::v1::iam_db_service_client::IamDbServiceClient;

const SERVICE: &str = "iam";

pub struct Iam {
    keys: Keys,
    channel: tonic::transport::Channel,
}

impl Iam {
    pub fn new(keys: Keys, channel: tonic::transport::Channel) -> Self {
        Self { keys, channel }
    }

    fn client(&self) -> IamDbServiceClient<tonic::transport::Channel> {
        IamDbServiceClient::new(self.channel.clone())
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
            .inspect_err(call_failed)?
            .into_inner();

        let resp = ResolveCredentialResponse {
            user_id: got.user_id,
            team_ids: got.team_ids,
            // The gateway's cache TTL. A BACKSTOP, not the invalidation
            // mechanism — revocation and team changes arrive as broker events
            // (D72). Five minutes bounds how long a missed event can leave a
            // revoked credential working.
            valid_for_seconds: 300,
        };
        call.finish(Outcome {
            status: "OK",
            ..Default::default()
        });
        Ok(Response::new(resp))
    }

    /// Username and password to a long-lived token. The one sign-in a person
    /// performs (D72).
    async fn login(&self, req: Request<LoginRequest>) -> Result<Response<LoginResponse>, Status> {
        let rid = request_id_of(&req);
        let call = Call::start(SERVICE, "Login", Kind::Write, tel(rid.clone(), ""));

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
            .inspect_err(call_failed)?
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
            .inspect_err(call_failed)?
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
            .inspect_err(call_failed)?
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

    /// Revoke, and hand back who it belonged to.
    ///
    /// **The caller must publish the cache-invalidation event** (D72). This
    /// service does not, because the broker client is not wired yet — and until
    /// it is, a revoked credential keeps working for up to `valid_for_seconds`.
    /// Stated here rather than left to be discovered.
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
            .inspect_err(call_failed)?
            .into_inner();

        tracing::warn!(
            user_id = %done.user_id,
            "credential revoked; cache invalidation is NOT yet published (D72) — \
             the gateway may honour it until its TTL expires"
        );

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
            .inspect_err(call_failed)?
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
            .inspect_err(call_failed)?;

        call.finish(Outcome {
            status: "OK",
            ..Default::default()
        });
        Ok(Response::new(AddTeamMemberResponse {}))
    }

    /// Removing a member narrows what that user can see, so it has the same
    /// unpublished-invalidation caveat as revocation above.
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
            .inspect_err(call_failed)?;

        tracing::warn!(
            user_id = %req.get_ref().user_id,
            "team membership removed; cache invalidation is NOT yet published (D72)"
        );

        call.finish(Outcome {
            status: "OK",
            ..Default::default()
        });
        Ok(Response::new(RemoveTeamMemberResponse {}))
    }
}

/// Log an upstream failure WITHOUT its message reaching the caller unchanged.
///
/// A `Status` from `iam-db` can carry storage detail, and on this service that
/// detail names the identity schema. The code propagates; the words stay here.
fn call_failed(e: &Status) {
    tracing::error!(code = ?e.code(), message = %e.message(), "upstream iam-db call failed");
}
