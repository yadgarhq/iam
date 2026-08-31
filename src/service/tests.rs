//! Unit tests for [`super`], against a fake `IamDbService`.
//!
//! **`iam/src/service.rs` had no tests at all**, which is how an
//! `add_team_member` that published no invalidation, a `call_failed` that
//! redacted nothing, and a negative resolve carrying a five-minute cache TTL all
//! survived review. Nothing new is needed to test it: `build.rs` already
//! generates the `IamDbService` SERVER half, so the twin can be faked on a
//! loopback port and `Iam` given a real `Channel` to it.
//!
//! A UNIT test module rather than `tests/`, deliberately. It reaches two seams an
//! integration test cannot see: the `cfg(test)` Argon2 verification counter in
//! [`crate::crypto`], which is what makes "an unknown username still costs a full
//! verification" a deterministic assertion rather than a wall-clock guess, and
//! the `cfg(test)` publish log on [`crate::invalidate::Invalidator`], which is
//! what makes "this path publishes" assertable without running a broker.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tonic::transport::{Channel, Endpoint};

use super::*;
use crate::crypto::argon2_verifications;
use crate::invalidate::subject;
use crate::pb::yadgar::iamdb::v1::iam_db_service_server::{IamDbService, IamDbServiceServer};

/// Everything the fake twin was asked to do.
#[derive(Default)]
struct Recorded {
    create_credential: Vec<db::CreateCredentialRequest>,
    get_password_hash: Vec<db::GetPasswordHashRequest>,
}

/// A stand-in for `iam-db`: answers from a fixed script and records the asking.
#[derive(Default)]
struct FakeDb {
    /// What `GetPasswordHash` answers: `(user_id, argon2id_hash)`, or nothing for
    /// an unknown username.
    password: Option<(String, String)>,
    /// A `(code, message)` to fail `CreateUser` with, for the redaction test.
    create_user_fails: Option<(tonic::Code, &'static str)>,
    /// What `ResolveCredential` answers.
    resolves_to: Option<String>,
    recorded: Arc<Mutex<Recorded>>,
}

#[tonic::async_trait]
impl IamDbService for FakeDb {
    async fn resolve_credential(
        &self,
        _req: Request<db::ResolveCredentialRequest>,
    ) -> Result<Response<db::ResolveCredentialResponse>, Status> {
        Ok(Response::new(db::ResolveCredentialResponse {
            user_id: self.resolves_to.clone().unwrap_or_default(),
            ..Default::default()
        }))
    }

    async fn get_password_hash(
        &self,
        req: Request<db::GetPasswordHashRequest>,
    ) -> Result<Response<db::GetPasswordHashResponse>, Status> {
        self.recorded
            .lock()
            .expect("recorded")
            .get_password_hash
            .push(req.into_inner());
        let (user_id, argon2id_hash) = self.password.clone().unwrap_or_default();
        Ok(Response::new(db::GetPasswordHashResponse {
            user_id,
            argon2id_hash,
        }))
    }

    async fn set_password(
        &self,
        _req: Request<db::SetPasswordRequest>,
    ) -> Result<Response<db::SetPasswordResponse>, Status> {
        Ok(Response::new(db::SetPasswordResponse {}))
    }

    async fn create_credential(
        &self,
        req: Request<db::CreateCredentialRequest>,
    ) -> Result<Response<db::CreateCredentialResponse>, Status> {
        self.recorded
            .lock()
            .expect("recorded")
            .create_credential
            .push(req.into_inner());
        Ok(Response::new(db::CreateCredentialResponse {
            credential_id: "yadgar:credential:fake".into(),
        }))
    }

    async fn revoke_credential(
        &self,
        _req: Request<db::RevokeCredentialRequest>,
    ) -> Result<Response<db::RevokeCredentialResponse>, Status> {
        Ok(Response::new(db::RevokeCredentialResponse {
            user_id: "yadgar:user:1".into(),
        }))
    }

    async fn create_user(
        &self,
        _req: Request<db::CreateUserRequest>,
    ) -> Result<Response<db::CreateUserResponse>, Status> {
        if let Some((code, message)) = self.create_user_fails {
            return Err(Status::new(code, message));
        }
        Ok(Response::new(db::CreateUserResponse::default()))
    }

    async fn add_team_member(
        &self,
        _req: Request<db::AddTeamMemberRequest>,
    ) -> Result<Response<db::AddTeamMemberResponse>, Status> {
        Ok(Response::new(db::AddTeamMemberResponse {}))
    }

    async fn remove_team_member(
        &self,
        _req: Request<db::RemoveTeamMemberRequest>,
    ) -> Result<Response<db::RemoveTeamMemberResponse>, Status> {
        Ok(Response::new(db::RemoveTeamMemberResponse {}))
    }
}

/// A port nothing is listening on, learned rather than guessed.
fn free_port() -> std::net::SocketAddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("addr");
    drop(l);
    addr
}

/// Serve `fake`, and return a `Channel` to it plus the log of what it was asked.
async fn twin(fake: FakeDb) -> (Channel, Arc<Mutex<Recorded>>) {
    let recorded = fake.recorded.clone();
    let addr = free_port();
    tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(IamDbServiceServer::new(fake))
            .serve(addr)
            .await;
    });

    // Poll for the listener rather than sleeping a guessed interval: a fixed
    // sleep is either slow or flaky, and on a loaded machine it is both.
    for _ in 0..200 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let channel = Endpoint::from_shared(format!("http://{addr}"))
        .expect("endpoint")
        .connect()
        .await
        .expect("connect to the fake twin");
    (channel, recorded)
}

async fn iam_with(fake: FakeDb) -> (Iam, Arc<Mutex<Recorded>>, Invalidator) {
    let (channel, recorded) = twin(fake).await;
    let invalidator = Invalidator::connect(None).await;
    let iam = Iam::new(crate::crypto::tests::keys(), channel, invalidator.clone());
    (iam, recorded, invalidator)
}

fn login(username: &str, password: &str) -> Request<LoginRequest> {
    Request::new(LoginRequest {
        username: username.into(),
        password: password.into(),
        label: "laptop".into(),
    })
}

/// A user the fake twin knows, with a real Argon2id hash of `password`.
fn known_user(password: &str) -> Option<(String, String)> {
    let hash = crate::crypto::tests::keys()
        .hash_password(password)
        .expect("hash");
    Some(("yadgar:user:1".to_string(), hash))
}

// ---------------------------------------------------------------------------
// Login: the account-enumeration and auth-bypass properties.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_unknown_username_still_costs_a_full_argon2_verification() {
    // MUTATION THIS CATCHES: returning early from `login` when
    // `found.user_id.is_empty()`, or from `verify_password` when `stored` is
    // None. Either makes an unknown username answer in microseconds while a known
    // one takes the ~50ms Argon2id costs, and the endpoint enumerates accounts
    // over the network. No assertion on the ANSWER can see the difference — both
    // return the same refusal.
    let (iam, _rec, _inv) = iam_with(FakeDb::default()).await;

    let before = argon2_verifications();
    let err = iam
        .login(login("nobody", "hunter2"))
        .await
        .expect_err("an unknown username must not authenticate");
    let spent = argon2_verifications() - before;

    assert_eq!(err.code(), tonic::Code::Unauthenticated);
    assert_eq!(
        spent, 1,
        "an unknown username must cost the same one Argon2 verification a known one does"
    );
}

#[tokio::test]
async fn a_failed_login_issues_no_credential() {
    // THE AUTH-BYPASS TEST. If `stored.is_some()` is ever lost from
    // `verify_password`, an unknown username verifies against the dummy hash,
    // `login` proceeds, and `CreateCredential` is called with user_id "" — a
    // working bearer token for nobody. That is a successful login, so no
    // assertion on the error can catch it; only the absence of the write can.
    // "x" for the unknown-username case DELIBERATELY. The test fixture's dummy
    // hash is the hash of "x", so this is the one submitted password for which
    // the dummy verification SUCCEEDS — which is what makes the bypass reachable
    // here at all. Any other password fails against the dummy on its own and the
    // assertion below would hold with `stored.is_some()` already deleted.
    for (name, fake, password) in [
        ("unknown username", FakeDb::default(), "x"),
        (
            "wrong password",
            FakeDb {
                password: known_user("correct horse"),
                ..Default::default()
            },
            "wrong horse",
        ),
    ] {
        let (iam, recorded, _inv) = iam_with(fake).await;
        iam.login(login("max", password))
            .await
            .expect_err("a failed login must not succeed");

        assert!(
            recorded
                .lock()
                .expect("recorded")
                .create_credential
                .is_empty(),
            "{name}: a failed login must issue ZERO credentials"
        );
    }
}

#[tokio::test]
async fn wrong_password_and_unknown_username_are_byte_identical() {
    // A message that distinguished them would tell an attacker which usernames
    // exist — the same leak the timing equalisation exists to close, and leaking
    // it in the text would make that work pointless.
    //
    // MUTATION THIS CATCHES: replacing either `refused()` call site with a
    // message of its own, e.g. "no such user".
    let (iam, _r, _i) = iam_with(FakeDb::default()).await;
    let unknown = iam.login(login("nobody", "hunter2")).await.unwrap_err();

    let (iam, _r, _i) = iam_with(FakeDb {
        password: known_user("correct horse"),
        ..Default::default()
    })
    .await;
    let wrong = iam.login(login("max", "wrong horse")).await.unwrap_err();

    assert_eq!(unknown.code(), wrong.code());
    assert_eq!(unknown.message(), wrong.message());
    assert_eq!(unknown.details(), wrong.details());
}

#[tokio::test]
async fn the_token_returned_is_the_one_that_was_stored() {
    // Two properties in one, because they are the same property from both sides:
    // the store holds SHA-256 of the token the caller got, and the plaintext token
    // never crosses the boundary.
    //
    // MUTATION THIS CATCHES: minting twice — hashing one token and returning
    // another. Every credential issued would then be unresolvable, and no test
    // that only checks "a token came back" can tell.
    let (iam, recorded, _inv) = iam_with(FakeDb {
        password: known_user("correct horse"),
        ..Default::default()
    })
    .await;

    let out = iam
        .login(login("max", "correct horse"))
        .await
        .expect("a correct password logs in")
        .into_inner();

    let stored = recorded.lock().expect("recorded").create_credential.clone();
    assert_eq!(stored.len(), 1, "one login is one credential");
    assert_eq!(
        stored[0].token_hash,
        Keys::token_hash(&out.token),
        "the store must hold the hash of the token the caller was given"
    );
    assert!(!out.token.is_empty());
    assert!(
        !format!("{:?}", stored[0]).contains(&out.token),
        "the plaintext token must not appear anywhere in the outbound request"
    );
}

// ---------------------------------------------------------------------------
// Cache invalidation (D72).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn adding_a_team_member_publishes_the_invalidation() {
    // MUTATION THIS CATCHES — and the bug this test was written for: no publish
    // at all on the add path. `remove_team_member` published and `add` did not, so
    // a newly granted team arrived up to 300s late, visible as a permission that
    // takes five minutes to appear and reads as a bug in whatever the person was
    // trying to reach.
    let (iam, _rec, invalidator) = iam_with(FakeDb::default()).await;

    iam.add_team_member(Request::new(AddTeamMemberRequest {
        team_id: "yadgar:team:t1".into(),
        user_id: "yadgar:user:1".into(),
        ..Default::default()
    }))
    .await
    .expect("add");

    assert_eq!(
        invalidator.published(),
        vec![(subject::TEAMS_CHANGED, "yadgar:user:1".to_string())]
    );
}

#[tokio::test]
async fn removing_a_team_member_publishes_the_invalidation() {
    let (iam, _rec, invalidator) = iam_with(FakeDb::default()).await;

    iam.remove_team_member(Request::new(RemoveTeamMemberRequest {
        team_id: "yadgar:team:t1".into(),
        user_id: "yadgar:user:1".into(),
        ..Default::default()
    }))
    .await
    .expect("remove");

    assert_eq!(
        invalidator.published(),
        vec![(subject::TEAMS_CHANGED, "yadgar:user:1".to_string())]
    );
}

#[tokio::test]
async fn revoking_a_credential_publishes_the_invalidation() {
    let (iam, _rec, invalidator) = iam_with(FakeDb::default()).await;

    iam.revoke_credential(Request::new(RevokeCredentialRequest {
        credential_id: "yadgar:credential:fake".into(),
        ..Default::default()
    }))
    .await
    .expect("revoke");

    assert_eq!(
        invalidator.published(),
        vec![(subject::CREDENTIAL_REVOKED, "yadgar:user:1".to_string())]
    );
}

// ---------------------------------------------------------------------------
// What crosses the boundary outward.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_upstream_message_does_not_reach_the_caller() {
    // MUTATION THIS CATCHES — and the bug this test was written for:
    // `inspect_err(call_failed)`, which logged the upstream Status and then
    // returned it unchanged, message included. `iam-db`'s words name the identity
    // schema; the CODE is what a caller branches on and it must survive.
    const UPSTREAM: &str = "a user with that name already exists";
    let (iam, _rec, _inv) = iam_with(FakeDb {
        create_user_fails: Some((tonic::Code::AlreadyExists, UPSTREAM)),
        ..Default::default()
    })
    .await;

    let err = iam
        .create_user(Request::new(CreateUserRequest::default()))
        .await
        .expect_err("the upstream failure propagates");

    assert_eq!(
        err.code(),
        tonic::Code::AlreadyExists,
        "the code propagates"
    );
    assert_ne!(err.message(), UPSTREAM, "the words stay in this service");
}

#[tokio::test]
async fn a_negative_resolve_is_not_cacheable() {
    // MUTATION THIS CATCHES: an unconditional `valid_for_seconds: 300`. An empty
    // user_id means "no live credential" — unknown, revoked, expired, or a
    // soft-deleted person — and pairing it with the ordinary TTL tells the
    // gateway to remember for five minutes that a token belongs to nobody.
    //
    // Nothing consumes this field yet. That is why it is pinned NOW: the
    // consumer that caches on it has not been written.
    let (iam, _rec, _inv) = iam_with(FakeDb::default()).await;
    let empty = iam
        .resolve_credential(Request::new(ResolveCredentialRequest::default()))
        .await
        .expect("an unknown token is not an error")
        .into_inner();

    assert!(empty.user_id.is_empty());
    assert_eq!(
        empty.valid_for_seconds, 0,
        "a negative answer must not be cached for any interval"
    );

    let (iam, _rec, _inv) = iam_with(FakeDb {
        resolves_to: Some("yadgar:user:1".into()),
        ..Default::default()
    })
    .await;
    let found = iam
        .resolve_credential(Request::new(ResolveCredentialRequest::default()))
        .await
        .expect("resolve")
        .into_inner();

    // The other half: if the TTL were zeroed unconditionally the assertion above
    // would still pass and the gateway's cache would do nothing at all.
    assert_eq!(found.valid_for_seconds, 300);
}
