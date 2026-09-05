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
use std::time::{Duration, Instant};

// `base64::Engine` is NOT imported here: `use super::*` already carries
// `service.rs`'s own anonymous import of it, and a second one is an unused
// import. `prost::Message` is not in that glob and IS needed, for
// `EnrolmentToken::decode`.
use prost::Message as _;
use tonic::transport::{Channel, Endpoint};

use super::*;
use crate::crypto::argon2_verifications;
use crate::invalidate::subject;
use crate::pb::yadgar::common::v1::InheritedSetting;
use crate::pb::yadgar::iamdb::v1::iam_db_service_server::{IamDbService, IamDbServiceServer};

/// Everything the fake twin was asked to do.
#[derive(Default)]
struct Recorded {
    create_credential: Vec<db::CreateCredentialRequest>,
    get_password_hash: Vec<db::GetPasswordHashRequest>,
    create_enrolment: Vec<db::CreateEnrolmentRequest>,
    /// **THE ORDERING WITNESS.** `validation_runs_before_the_secret_is_looked_up`
    /// asserts this is EMPTY, which is the only way to see that a refusal came
    /// before the lookup rather than after it — the status code is identical
    /// either way, and it is the status code that would become the oracle.
    redeem_enrolment: Vec<db::RedeemEnrolmentRequest>,
    /// **THE SECOND ORDERING WITNESS**, on the first one's reasoning. `iam.proto`
    /// says this service refuses `SetInheritedSetting`'s clauses ITSELF rather
    /// than forwarding them, and every clause is `INVALID_ARGUMENT` — so the
    /// status code cannot tell a refusal made here from one the store made. An
    /// EMPTY vector is what says the store was never asked.
    set_inherited_setting: Vec<db::SetInheritedSettingRequest>,
    /// THE ADMINISTRATIVE WRITES, recorded for one reason: what this service
    /// forwards on them was invisible. Every one of these was built with
    /// `..Default::default()`, so no test could see a field that never left —
    /// and the fake did not even keep the request to look at.
    revoke_credential: Vec<db::RevokeCredentialRequest>,
    create_user: Vec<db::CreateUserRequest>,
    add_team_member: Vec<db::AddTeamMemberRequest>,
    remove_team_member: Vec<db::RemoveTeamMemberRequest>,
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
    /// D73's flag, as the STORE reports it. Separate from `resolves_to` so a
    /// test can pin that the value travels rather than being invented here.
    resolves_admin: bool,
    /// What `RedeemEnrolment` answers. `None` is an unknown secret, which is the
    /// default an attacker's presentation gets.
    redeem: Option<db::RedeemEnrolmentResponse>,
    /// ADR-0522's setting, as the STORE reports it on `ResolveCredential`.
    ///
    /// **AN `Option` SO ABSENT IS REACHABLE.** `iam-db` answers with this message
    /// ABSENT when the organisation row is not there, which is the case a
    /// substituted default is invisible in — a fake that could only ever answer
    /// with a present message could not see it at all.
    resolves_setting: Option<InheritedSetting>,
    /// What `SetInheritedSetting` answers with. The setting WHOLE, including the
    /// level and the team overrides the caller did not send.
    setting_now: Option<InheritedSetting>,
    /// A `(code, message)` to fail `RedeemEnrolment` with, rather than answering
    /// with an outcome.
    ///
    /// **THE STORE HAS A REFUSAL THE OUTCOME ENUM CANNOT CARRY**, and it is the
    /// one an unauthenticated caller can provoke: an idempotency key already
    /// recorded against a DIFFERENT secret is `INVALID_ARGUMENT`, decided before
    /// the presented secret is looked up. Without this field the fake can only
    /// answer, so no test could see what `iam` does with that error.
    redeem_fails: Option<(tonic::Code, &'static str)>,
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
            is_admin: self.resolves_admin,
            owner_reads_own_record: self.resolves_setting.clone(),
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

    async fn create_enrolment(
        &self,
        req: Request<db::CreateEnrolmentRequest>,
    ) -> Result<Response<db::CreateEnrolmentResponse>, Status> {
        self.recorded
            .lock()
            .expect("recorded")
            .create_enrolment
            .push(req.into_inner());
        Ok(Response::new(db::CreateEnrolmentResponse {
            enrolment_id: "yadgar:enrolment:fake".into(),
        }))
    }

    async fn redeem_enrolment(
        &self,
        req: Request<db::RedeemEnrolmentRequest>,
    ) -> Result<Response<db::RedeemEnrolmentResponse>, Status> {
        self.recorded
            .lock()
            .expect("recorded")
            .redeem_enrolment
            .push(req.into_inner());
        if let Some((code, message)) = self.redeem_fails {
            return Err(Status::new(code, message));
        }
        Ok(Response::new(self.redeem.clone().unwrap_or(
            db::RedeemEnrolmentResponse {
                outcome: db::RedeemOutcome::NotFound as i32,
                ..Default::default()
            },
        )))
    }

    async fn list_credentials(
        &self,
        _req: Request<db::ListCredentialsRequest>,
    ) -> Result<Response<db::ListCredentialsResponse>, Status> {
        Ok(Response::new(db::ListCredentialsResponse::default()))
    }

    async fn set_user_admin(
        &self,
        _req: Request<db::SetUserAdminRequest>,
    ) -> Result<Response<db::SetUserAdminResponse>, Status> {
        Ok(Response::new(db::SetUserAdminResponse {}))
    }

    async fn set_rate_limit_override(
        &self,
        _req: Request<db::SetRateLimitOverrideRequest>,
    ) -> Result<Response<db::SetRateLimitOverrideResponse>, Status> {
        Ok(Response::new(db::SetRateLimitOverrideResponse {}))
    }

    async fn set_inherited_setting(
        &self,
        req: Request<db::SetInheritedSettingRequest>,
    ) -> Result<Response<db::SetInheritedSettingResponse>, Status> {
        self.recorded
            .lock()
            .expect("recorded")
            .set_inherited_setting
            .push(req.into_inner());
        Ok(Response::new(db::SetInheritedSettingResponse {
            setting: self.setting_now.clone(),
        }))
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
        req: Request<db::RevokeCredentialRequest>,
    ) -> Result<Response<db::RevokeCredentialResponse>, Status> {
        self.recorded
            .lock()
            .expect("recorded")
            .revoke_credential
            .push(req.into_inner());
        Ok(Response::new(db::RevokeCredentialResponse {
            user_id: "yadgar:user:1".into(),
        }))
    }

    async fn create_user(
        &self,
        req: Request<db::CreateUserRequest>,
    ) -> Result<Response<db::CreateUserResponse>, Status> {
        self.recorded
            .lock()
            .expect("recorded")
            .create_user
            .push(req.into_inner());
        if let Some((code, message)) = self.create_user_fails {
            return Err(Status::new(code, message));
        }
        Ok(Response::new(db::CreateUserResponse::default()))
    }

    async fn add_team_member(
        &self,
        req: Request<db::AddTeamMemberRequest>,
    ) -> Result<Response<db::AddTeamMemberResponse>, Status> {
        self.recorded
            .lock()
            .expect("recorded")
            .add_team_member
            .push(req.into_inner());
        Ok(Response::new(db::AddTeamMemberResponse {}))
    }

    async fn remove_team_member(
        &self,
        req: Request<db::RemoveTeamMemberRequest>,
    ) -> Result<Response<db::RemoveTeamMemberResponse>, Status> {
        self.recorded
            .lock()
            .expect("recorded")
            .remove_team_member
            .push(req.into_inner());
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

/// The floor for every test that is NOT about the floor.
///
/// Small deliberately. The production default is 250ms and paying it in each of
/// the login tests below would buy nothing — those assert on answers and on what
/// the twin was asked, none of which the floor changes. The tests that ARE about
/// the floor name their own through [`iam_with_floor`].
///
/// THE FLOOR PUT AN `await` INSIDE EVERY `login`, WHICH THE COUNTER TESTS NOW
/// DEPEND ON NOT CROSSING A THREAD. `argon2_verifications` is a THREAD-LOCAL, and
/// `hold_until_floor` sleeps — so a test reading the counter either side of a
/// `login` is only correct while the task resumes on the thread it started on.
/// Bare `#[tokio::test]` builds a CURRENT-THREAD runtime and that holds. Adding
/// `flavor = "multi_thread"` to one of those tests would break it in the shape of
/// a count that is mysteriously zero, so this is written down rather than
/// discovered.
const NOMINAL_FLOOR: Duration = Duration::from_millis(5);

/// The gateway address and CA a minted token carries, in tests.
///
/// FIXED VALUES SO THE TOKEN CAN BE ASSERTED ON. An admin never assembles
/// either, so the only way to see that `iam` put its OWN configuration into the
/// token — rather than an empty string, which the contract forbids and no client
/// can diagnose — is to configure something recognisable and look for it.
const TEST_GATEWAY: &str = "gateway.yadgar.test:443";
const TEST_CA: &str = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n";

fn enrolment_config() -> Option<EnrolmentConfig> {
    Some(EnrolmentConfig::new(TEST_GATEWAY.into(), Some(TEST_CA.into())).expect("a valid config"))
}

async fn iam_with(fake: FakeDb) -> (Iam, Arc<Mutex<Recorded>>, Invalidator) {
    iam_with_floor(fake, NOMINAL_FLOOR).await
}

async fn iam_with_floor(fake: FakeDb, floor: Duration) -> (Iam, Arc<Mutex<Recorded>>, Invalidator) {
    iam_with_floors(
        fake,
        ResponseFloors {
            login: floor,
            redeem: NOMINAL_FLOOR,
        },
        enrolment_config(),
    )
    .await
}

async fn iam_with_redeem_floor(
    fake: FakeDb,
    floor: Duration,
) -> (Iam, Arc<Mutex<Recorded>>, Invalidator) {
    iam_with_floors(
        fake,
        ResponseFloors {
            login: NOMINAL_FLOOR,
            redeem: floor,
        },
        enrolment_config(),
    )
    .await
}

/// An `Iam` on a deployment that has NOT configured enrolment.
async fn iam_without_enrolment(fake: FakeDb) -> (Iam, Arc<Mutex<Recorded>>, Invalidator) {
    iam_with_floors(
        fake,
        ResponseFloors {
            login: NOMINAL_FLOOR,
            redeem: NOMINAL_FLOOR,
        },
        None,
    )
    .await
}

async fn iam_with_floors(
    fake: FakeDb,
    floors: ResponseFloors,
    enrolment: Option<EnrolmentConfig>,
) -> (Iam, Arc<Mutex<Recorded>>, Invalidator) {
    let (channel, recorded) = twin(fake).await;
    let invalidator = Invalidator::connect(None, None).await;
    let iam = Iam::new(
        crate::crypto::tests::keys(),
        channel,
        invalidator.clone(),
        floors,
        enrolment,
    );
    // LAST, and both halves of that matter. It installs the WARN tap, so no login
    // any test performs can precede the global subscriber; and it drains this
    // thread's list, so setup noise — `Invalidator::connect(None)` warns that it
    // has no broker — cannot be mistaken for something a login said.
    warnings_from_here();
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

/// A user whose STORED hash is far cheaper than this build mints.
///
/// **This is not a hypothetical row.** `iamdb.v1.SetPassword` takes an
/// already-formed `argon2id_hash` and stores it verbatim, and `verify_password`
/// reads its cost out of the PHC STRING rather than from this service's
/// configuration — so any provisioning path that does not go through
/// `crypto::hash_secret` picks its own cost, and one gRPC call is enough to
/// create this. Verifying it is microseconds of real Argon2 work against the
/// milliseconds `Argon2::default()` costs, which is the gap the response-time
/// floor exists to hide.
///
/// `m=8,t=1,p=1` DELIBERATELY, and it is the cheapest legal set rather than the
/// cheapest writable one: `Params::try_from` enforces `m >= 8 * p`, so `m=8,p=2`
/// is refused BEFORE any hashing and `verify_counted` would return `None` — the
/// call would fall through to the dummy at full cost and this fixture would
/// quietly stop being fast.
fn cheap_user(password: &str) -> Option<(String, String)> {
    let params = argon2::Params::new(8, 1, 1, None).expect("m=8,t=1,p=1 is a legal Argon2 set");
    let hasher = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let salt = argon2::password_hash::SaltString::encode_b64(&[1u8; 16]).expect("salt");
    let hash =
        argon2::password_hash::PasswordHasher::hash_password(&hasher, password.as_bytes(), &salt)
            .expect("hash at a deliberately low cost")
            .to_string();
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
// The response-time floor.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn every_login_path_takes_at_least_the_floor() {
    // THIS IS THE SECURITY PROPERTY, and it is one assertion applied to four
    // paths rather than an assertion about a sleep. `verify_password` equalises
    // by making both paths verify a hash with the SAME PARAMETERS, which holds
    // only while every stored hash costs what the dummy costs. A row provisioned
    // through `iamdb.v1.SetPassword` at another cost breaks that with one gRPC
    // call, and then the response time says which usernames exist again.
    //
    // MUTATION THIS CATCHES: deleting the floor, or flooring only the failure
    // arm. `a cheap stored hash` answers in single-digit milliseconds without it,
    // against the ~30ms an unknown username costs — measured through the live
    // edge as a 70ms median gap with non-overlapping p90s, which is separable
    // with a handful of samples. No assertion on the ANSWER can see it: all
    // three refusals are byte-identical.
    //
    // A LOWER BOUND AND NEVER AN UPPER ONE. "At least the floor" is what the
    // property says; a ceiling would assert that a loaded CI runner is fast,
    // which it is not, and would fail for a reason that has nothing to do with
    // this code.
    //
    // 400ms, AND THE SIZE IS NOT ARBITRARY. `cargo test` builds unoptimised, so
    // an `Argon2::default()` verification here costs ~250ms against the ~30ms it
    // costs in the release binary. A floor UNDER that leaves the slow cases
    // exceeding it and the fast one padded to it, so the four paths would answer
    // at visibly different times with every assertion still green.
    //
    // WHICH IS WHY THIS TEST IS NOT THE ONE THAT PROVES THE PROPERTY. A bound
    // cannot express a convergence, and sizing the constant so the paths happen
    // to converge is a demonstration, not an assertion — on a slow enough runner
    // it silently stops holding. The convergence itself is pinned as an EQUALITY
    // under a paused clock by
    // `the_floor_is_anchored_to_the_start_not_added_to_the_work`. What this test
    // adds is the end-to-end reach the paused-clock one gives up: the real
    // handler, the real Argon2 work, the real round trips to the twin.
    const FLOOR: Duration = Duration::from_millis(400);

    for (name, fake, username, password) in [
        // The divergence itself: real Argon2 work, at a cost that answers in
        // microseconds.
        (
            "a cheap stored hash",
            FakeDb {
                password: cheap_user("correct horse"),
                ..Default::default()
            },
            "max",
            "wrong horse",
        ),
        // The dummy, at this build's cost.
        (
            "an unknown username",
            FakeDb::default(),
            "nobody",
            "hunter2",
        ),
        (
            "a default-cost stored hash",
            FakeDb {
                password: known_user("correct horse"),
                ..Default::default()
            },
            "max",
            "wrong horse",
        ),
        // THE SUCCESS PATH IS FLOORED TOO. Not because a successful login is
        // ambiguous — it answers with a token, which is as distinguishable as a
        // response gets — but because one rule with no branch cannot be got wrong
        // by editing one arm of it. It also costs a second round trip to the
        // twin, so leaving it out would make the floor an oracle of its own.
        (
            "a successful login",
            FakeDb {
                password: known_user("correct horse"),
                ..Default::default()
            },
            "max",
            "correct horse",
        ),
    ] {
        let (iam, _rec, _inv) = iam_with_floor(fake, FLOOR).await;

        let started = Instant::now();
        let _ = iam.login(login(username, password)).await;
        let elapsed = started.elapsed();

        assert!(
            elapsed >= FLOOR,
            "{name}: Login answered in {elapsed:?}, inside the {FLOOR:?} floor — \
             its response time still reports how much work it did"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn the_floor_is_anchored_to_the_start_not_added_to_the_work() {
    // THE CONVERGENCE, AND IT IS THE PROPERTY THE TEST ABOVE CANNOT SEE. Every
    // assertion there is a per-path LOWER BOUND, and a lower bound says nothing
    // about how two paths relate to each other — which is the entire point of a
    // floor. `assert!(elapsed >= FLOOR)` holds for any implementation that waits
    // AT LEAST long enough, including ones that wait longer the more work they
    // did, which is the leak wearing the floor's clothes.
    //
    // MUTATION THIS CATCHES, and it is not hypothetical — it was found by
    // mutating this code and watching the whole suite stay green: sleeping
    // `self.login_response_floor` instead of `remaining`, so the total becomes
    // `elapsed + floor` rather than `floor`. Measured under that mutant: a cheap
    // stored hash answered in 408ms and an unknown username in 773ms — a 365ms
    // gap, FIVE TIMES the 70ms this change exists to close — with 39 tests
    // passing. The bound survived; the property was gone.
    //
    // AN EQUALITY, WHICH ONLY A PAUSED CLOCK MAKES SAFE. `start_paused` means no
    // wall clock is consulted: time advances only when the runtime is idle, so
    // this measures the SLEEP THAT WAS ASKED FOR rather than how long a loaded
    // runner took to deliver it. That is what lets the assertion be `==` without
    // imposing a ceiling on anything real, and why it cannot flake.
    //
    // TWO WORK VALUES, DELIBERATELY. One would fix a single point and any
    // constant sleep of that length would satisfy it. Two pin the functional
    // dependence — the hold must SHRINK as the work grows, which is what
    // "anchored to the start" means.
    const FLOOR: Duration = Duration::from_millis(400);

    let (iam, _rec, _inv) = iam_with_floor(FakeDb::default(), FLOOR).await;

    for work in [Duration::from_millis(1), Duration::from_millis(200)] {
        let t0 = tokio::time::Instant::now();
        iam.hold_until_floor(iam.login_floor, work).await;
        assert_eq!(
            t0.elapsed(),
            FLOOR - work,
            "work {work:?}: the hold must be the floor MINUS the work already \
             done, or the response time is still a function of that work"
        );
    }
}

// Every WARN this THREAD has emitted since it last drained the list.
//
// A THREAD-LOCAL BEHIND ONE PROCESS-WIDE SUBSCRIBER, and both halves of that are
// forced. The obvious shape — build a subscriber per test and attach it to the
// login future with `WithSubscriber` — passed locally and FAILED IN CI with an
// empty capture, because `tracing`'s enabled-check consults a PROCESS-WIDE max
// level hint before it ever reaches a scoped dispatcher. With no global
// subscriber installed, that hint is whatever the other tests running in
// parallel last left it as, so whether the warning was recorded depended on test
// interleaving. Installing one global subscriber that accepts WARN pins the hint
// for the whole binary; the thread-local keeps each test reading only its own
// events, which is the same reason [`crate::crypto`]'s verification counter is
// one.
//
// THE REAL `tracing` EVENT AND NOT A STAND-IN. A `cfg(test)` counter beside the
// `tracing::warn!` would be a second thing to delete, and deleting the warning
// while leaving the counter is precisely the mutation these tests exist to
// catch — the instrument has to be downstream of the call, not next to it.
thread_local! {
    static WARNINGS: std::cell::RefCell<Vec<String>> = const {
        std::cell::RefCell::new(Vec::new())
    };
}

/// Renders an event as `LEVEL "message" field=value …`, which is what the
/// assertions match on.
struct Rendered(String);

impl tracing::field::Visit for Rendered {
    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.0.push_str(&format!(" {}={}", field.name(), value));
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.0.push_str(&format!(" {}={}", field.name(), value));
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0.push_str(&format!(" {value:?}"));
        } else {
            self.0.push_str(&format!(" {}={:?}", field.name(), value));
        }
    }
}

struct WarnTap;

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for WarnTap {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        let level = *event.metadata().level();
        // `Level` orders ERROR < WARN < INFO, so this keeps WARN and above.
        if level > tracing::Level::WARN {
            return;
        }
        let mut rendered = Rendered(level.to_string());
        event.record(&mut rendered);
        WARNINGS.with(|w| w.borrow_mut().push(rendered.0));
    }
}

/// Install the tap once for the whole test binary, and drain this thread's list.
///
/// Called at the START of the login helpers rather than inside a test, so the
/// global default is in place before ANY login can emit anything — an install
/// racing a warning already in flight is the flakiness this exists to remove.
/// Draining is what keeps setup noise (`Invalidator::connect(None)` has its own
/// warnings) out of a test that asserts on emptiness.
fn warnings_from_here() {
    static INSTALLED: std::sync::Once = std::sync::Once::new();
    INSTALLED.call_once(|| {
        use tracing_subscriber::layer::SubscriberExt;
        tracing::subscriber::set_global_default(tracing_subscriber::registry().with(WarnTap))
            .expect("nothing else installs a global subscriber in this test binary");
    });
    WARNINGS.with(|w| w.borrow_mut().clear());
}

/// Everything this thread has warned since [`warnings_from_here`].
fn warnings() -> Vec<String> {
    WARNINGS.with(|w| w.borrow().clone())
}

/// Just `Login`'s floor warnings, so nothing else can pass for one.
///
/// **FILTERED ON THE `rpc` FIELD AS WELL AS THE TEXT**, because the text is no
/// longer unique: `RedeemEnrolment` is floored by the same mechanism and emits
/// the same sentence. Every enrolment test below runs against `NOMINAL_FLOOR`
/// and two Argon2id operations, so each of them exceeds its floor and warns —
/// matching on the text alone would let one of those stand in for the `Login`
/// warning these assertions are about. Today the thread-local keeps them apart
/// anyway; that is a property of how the tests happen to be scheduled, and this
/// filter is the one that does not depend on it.
fn floor_warnings() -> Vec<String> {
    floor_warnings_for("Login")
}

/// The same, for `RedeemEnrolment`.
///
/// **THIS IS WHAT LETS THE REDEEM FLOOR TESTS FAIL RATHER THAN GO VACUOUS.** A
/// per-path lower bound passes whether the floor padded anything or not: on a
/// loaded runner every path exceeds the floor, nothing is padded, the response
/// times separate by whatever the work cost, and the assertion is still green.
/// The warning is the service's own report that it padded NOTHING, so asserting
/// on its absence turns that silent vacuity into a failure.
fn redeem_floor_warnings() -> Vec<String> {
    floor_warnings_for("RedeemEnrolment")
}

fn floor_warnings_for(rpc: &str) -> Vec<String> {
    let field = format!("rpc={rpc}");
    warnings()
        .into_iter()
        .filter(|w| w.contains("response-time floor") && w.contains(&field))
        .collect()
}

#[tokio::test]
async fn a_login_slower_than_the_floor_answers_normally_and_warns() {
    // THE SELF-CHECK, and it is the half that makes this a control rather than a
    // decoration. A floor closes the FAST side only: a verification slower than
    // the floor answers late and still leaks. When that happens the floor is
    // hiding nothing, and the only remedy is an operator raising it — so the
    // service has to say so.
    //
    // MUTATION THIS CATCHES: deleting the `tracing::warn!`. Every other assertion
    // in this file stays green without it. The floor goes on being applied, the
    // property it is supposed to deliver is gone for whichever rows are slow, and
    // nothing anywhere fails — a check that cannot fail, which is worse than
    // none.
    //
    // A 1ms floor against an `Argon2::default()` verification, which costs two
    // orders of magnitude more than that in any build. No timing tolerance is
    // involved: the gap is the oracle.
    const FLOOR: Duration = Duration::from_millis(1);

    let (iam, recorded, _inv) = iam_with_floor(
        FakeDb {
            password: known_user("correct horse"),
            ..Default::default()
        },
        FLOOR,
    )
    .await;

    let out = iam
        .login(login("max", "correct horse"))
        .await
        .expect("EXCEEDING THE FLOOR IS NOT AN ERROR — a slow verification is still a correct one")
        .into_inner();

    // The call is untouched by the warning: still a real login, still one
    // credential. Refusing here would lock out exactly the accounts whose
    // unusual cost the floor exists to hide.
    assert!(
        !out.token.is_empty(),
        "a warned login still issues its token"
    );
    assert_eq!(
        recorded.lock().expect("recorded").create_credential.len(),
        1,
        "a warned login is still a login"
    );

    let warned = floor_warnings();
    let all = warnings();
    assert_eq!(
        warned.len(),
        1,
        "exceeding the floor must warn exactly once; everything this thread \
         emitted: {all:?}"
    );
    let text = &warned[0];
    assert!(
        text.contains("WARN"),
        "the floor must WARN, not be noted at a level nobody alerts on: {text:?}"
    );
    assert!(
        text.contains("floor_ms=1"),
        "the warning must name the CONFIGURED floor, or an operator cannot tell \
         what to raise: {text:?}"
    );
    assert!(
        text.contains("observed_ms="),
        "the warning must name the OBSERVED duration, or an operator cannot tell \
         what to raise it TO: {text:?}"
    );
}

#[tokio::test]
async fn a_login_inside_the_floor_warns_about_nothing() {
    // THE OTHER HALF, and without it the test above is satisfied by warning
    // unconditionally — which would be an alert on every login, i.e. an alert on
    // none of them.
    //
    // MUTATION THIS CATCHES: warning whenever the floor is applied rather than
    // only when it is exceeded, and the off-by-one next to it — `elapsed >=
    // floor` in place of a strict `>`. A call answering exactly on the floor has
    // not exceeded it.
    const FLOOR: Duration = Duration::from_millis(400);

    let (iam, _rec, _inv) = iam_with_floor(
        FakeDb {
            password: cheap_user("correct horse"),
            ..Default::default()
        },
        FLOOR,
    )
    .await;

    let _ = iam.login(login("max", "wrong horse")).await;

    assert_eq!(
        floor_warnings(),
        Vec::<String>::new(),
        "a login the floor actually covered must warn about nothing; everything \
         this thread emitted: {:?}",
        warnings()
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

// ---------------------------------------------------------------------------
// Enrolment (D73). An admin creates the account, the PERSON sets the password.
// ---------------------------------------------------------------------------

/// A store answer for a secret that was accepted and spent.
///
/// `external_id_ciphertext` is encrypted with the SAME fixture keys the service
/// holds, because that is the only way the boundary is honest: the store never
/// sees a plaintext name in either direction, so a redemption can only learn the
/// username by decrypting what it is handed.
fn redeemed(username: &str) -> Option<db::RedeemEnrolmentResponse> {
    Some(db::RedeemEnrolmentResponse {
        outcome: db::RedeemOutcome::Redeemed as i32,
        user_id: "yadgar:user:1".into(),
        enrolment_id: "yadgar:enrolment:fake".into(),
        external_id_ciphertext: crate::crypto::tests::keys()
            .encrypt(username)
            .expect("encrypt the fixture username"),
    })
}

fn refusal(outcome: db::RedeemOutcome) -> Option<db::RedeemEnrolmentResponse> {
    Some(db::RedeemEnrolmentResponse {
        outcome: outcome as i32,
        ..Default::default()
    })
}

fn redeem(secret: &str, password: &str, key: &str) -> Request<RedeemEnrolmentRequest> {
    Request::new(RedeemEnrolmentRequest {
        secret: secret.into(),
        password: password.into(),
        label: "laptop".into(),
        idempotency: Some(Idempotency { key: key.into() }),
    })
}

fn issue(key: &str) -> Request<IssueEnrolmentRequest> {
    Request::new(IssueEnrolmentRequest {
        idempotency: Some(Idempotency { key: key.into() }),
        user_id: "yadgar:user:1".into(),
        unverified_actor: None,
    })
}

#[tokio::test]
async fn an_enrolment_token_carries_the_secret_whose_hash_was_stored() {
    // TWO PROPERTIES THAT ARE ONE PROPERTY FROM BOTH SIDES: the store holds the
    // hash of the secret the admin was handed, and the plaintext secret never
    // crosses the boundary.
    //
    // MUTATION THIS CATCHES: minting twice — hashing one secret and putting
    // another in the token. Every enrolment issued would then be unredeemable,
    // and no assertion that merely checks "a token came back" can tell. It is
    // the same mutation `the_token_returned_is_the_one_that_was_stored` catches
    // for a credential, and it is worth catching twice because the two mints are
    // separate code.
    let (iam, recorded, _inv) = iam_with(FakeDb::default()).await;

    let out = iam
        .issue_enrolment(issue("attempt-1"))
        .await
        .expect("issue")
        .into_inner();

    // STANDARD ALPHABET, WITH PADDING (RFC 4648 section 4). Decoding is not
    // enough on its own — a URL-safe unpadded string of the right length can
    // decode under a permissive reader — so the assertion is a ROUND TRIP:
    // re-encoding the bytes must reproduce the string byte for byte, which no
    // other alphabet or padding rule does.
    let raw = base64::engine::general_purpose::STANDARD
        .decode(&out.token)
        .expect("the token must decode under the standard alphabet");
    assert_eq!(
        base64::engine::general_purpose::STANDARD.encode(&raw),
        out.token,
        "the token must be standard-alphabet base64 WITH padding; a URL-safe or \
         unpadded one decodes to noise on exactly the machines that have never \
         met this deployment"
    );

    let token = EnrolmentToken::decode(&raw[..]).expect("the bytes are an EnrolmentToken");

    assert!(
        !token.secret.is_empty(),
        "a minted token never carries an empty secret"
    );
    assert_eq!(
        token.gateway, TEST_GATEWAY,
        "iam fills the gateway from its OWN configuration, so an admin cannot \
         get it wrong — and an empty one mints a token pointing at nothing"
    );
    assert_eq!(
        token.ca_pem.as_deref(),
        Some(TEST_CA),
        "the trust anchor travels with the secret, on the channel that is \
         already trusted"
    );

    let stored = recorded.lock().expect("recorded").create_enrolment.clone();
    assert_eq!(stored.len(), 1, "one issuance is one enrolment");
    assert_eq!(
        stored[0].secret_hash,
        Keys::token_hash(&token.secret),
        "the store must hold the hash of the secret the admin was handed, or the \
         enrolment cannot be redeemed by anyone"
    );
    assert!(
        !format!("{:?}", stored[0]).contains(&token.secret),
        "the plaintext secret must not appear anywhere in the outbound request"
    );
    assert_eq!(
        stored[0].idempotency.as_ref().map(|i| i.key.as_str()),
        Some("attempt-1"),
        "the caller's key reaches the store, which is where D9's deduplication \
         lives"
    );
}

#[tokio::test]
async fn an_enrolment_expires_in_twenty_four_hours() {
    // MUTATION THIS CATCHES: reporting one deadline and storing another. The
    // stored one is what the store enforces against its own clock, so a response
    // that named a later time would have an admin hand over a token that stops
    // working before the person is told it would — a failure nobody can diagnose
    // from either end.
    let (iam, recorded, _inv) = iam_with(FakeDb::default()).await;

    let out = iam
        .issue_enrolment(issue("attempt-1"))
        .await
        .expect("issue")
        .into_inner();

    let stored = recorded.lock().expect("recorded").create_enrolment.clone();
    assert_eq!(
        out.expires_at, stored[0].expires_at,
        "the deadline reported must be the deadline stored"
    );

    let raw = base64::engine::general_purpose::STANDARD
        .decode(&out.token)
        .expect("decode");
    let token = EnrolmentToken::decode(&raw[..]).expect("decode");
    assert_eq!(
        token.expires_at, out.expires_at,
        "the token states its own deadline, so a client can say WHY an enrolment \
         failed rather than reporting a generic refusal"
    );

    let now = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after the epoch")
        .as_secs() as i64;
    let deadline = out.expires_at.expect("set").seconds;
    assert!(
        (deadline - now - 24 * 60 * 60).abs() <= 60,
        "D73's 24 hours; got {} seconds from now",
        deadline - now
    );
}

#[tokio::test]
async fn an_unknown_enrolment_secret_costs_the_same_argon2_work_as_a_valid_one() {
    // THE CONSTANT-WORK PROPERTY, AND IT IS AN EQUALITY BETWEEN TWO PATHS rather
    // than a bound on each. A per-path assertion against a constant this code
    // chose proves only that the code does what it does; what the property says
    // is that the two paths cost THE SAME, and only a comparison between them
    // can say it. Deterministic, and no clock is read.
    //
    // WHAT THE COUNTER ACTUALLY COUNTS, stated precisely because an earlier
    // version of this comment overclaimed: `CountingArgon2` is constructed only
    // inside `verify_counted`, so it counts VERIFICATIONS and not every Argon2
    // hashing. `hash_secret` mints through a bare `Argon2::default()` and is
    // invisible here. So this reads 1 against 1 — the verification each path
    // pays — and NOT 2 against 2.
    //
    // MUTATION THIS CATCHES: deleting the `verify_password(None, …)` on the
    // refusal path. A refusal would then cost zero verifications against a
    // redemption's one, and the response time says which secrets exist.
    //
    // THE OTHER ORDERING — hashing only after the store confirms the secret — is
    // NOT tested here because it is STRUCTURALLY UNREACHABLE: the hash is a
    // FIELD of `db::RedeemEnrolmentRequest`, so it must exist before the store
    // call is built. The contract's constant-work rule is kept by the type, not
    // by this assertion, and claiming otherwise would be an assertion taking
    // credit for something it cannot see.
    //
    // Both paths are driven on ONE thread, which the counter's thread-local
    // storage requires — see the note on NOMINAL_FLOOR.
    let (iam, _rec, _inv) = iam_with(FakeDb {
        redeem: redeemed("ada"),
        password: known_user("chosen one"),
        ..Default::default()
    })
    .await;

    let before = argon2_verifications();
    iam.redeem_enrolment(redeem("s3cret", "chosen one", "k1"))
        .await
        .expect("a valid secret redeems");
    let valid = argon2_verifications() - before;

    let (iam, _rec, _inv) = iam_with(FakeDb::default()).await;

    let before = argon2_verifications();
    let err = iam
        .redeem_enrolment(redeem("not a secret", "chosen one", "k2"))
        .await
        .expect_err("an unknown secret must not redeem");
    let unknown = argon2_verifications() - before;

    assert_eq!(err.code(), tonic::Code::Unauthenticated);
    assert!(
        valid > 0,
        "a redemption must do real Argon2 work, or this equality is 0 == 0 and \
         asserts nothing"
    );
    assert_eq!(
        unknown, valid,
        "an unknown secret must cost the same Argon2 work a valid one does; \
         {unknown} against {valid} is a response time that says which secrets \
         exist"
    );
}

#[tokio::test]
async fn unknown_spent_and_expired_are_one_refusal() {
    // ONE FAILURE, NOT THREE. The store tells the three apart and records which;
    // a caller that could would learn whether a secret it does not hold ever
    // existed, and whether somebody has already used it.
    //
    // MUTATION THIS CATCHES: mapping the outcomes to three statuses, or to one
    // status with three messages. Either is an oracle in the response itself,
    // which no amount of constant work touches.
    let mut refusals = Vec::new();
    for outcome in [
        db::RedeemOutcome::NotFound,
        db::RedeemOutcome::Spent,
        db::RedeemOutcome::Expired,
    ] {
        let (iam, recorded, _inv) = iam_with(FakeDb {
            redeem: refusal(outcome),
            ..Default::default()
        })
        .await;

        let err = iam
            .redeem_enrolment(redeem("s3cret", "chosen one", "k1"))
            .await
            .expect_err("none of the three redeems");

        assert!(
            recorded
                .lock()
                .expect("recorded")
                .create_credential
                .is_empty(),
            "{outcome:?}: a refused redemption must mint ZERO credentials"
        );
        refusals.push((
            err.code(),
            err.message().to_string(),
            err.details().to_vec(),
        ));
    }

    assert_eq!(
        refusals[0].0,
        tonic::Code::Unauthenticated,
        "all three are UNAUTHENTICATED"
    );
    assert_eq!(
        refusals[0], refusals[1],
        "unknown and spent must be identical"
    );
    assert_eq!(
        refusals[1], refusals[2],
        "spent and expired must be identical"
    );
}

#[tokio::test]
async fn a_redeemed_key_and_an_unredeemed_one_refuse_identically() {
    // THE STATUS-CODE ORACLE ON THE UNAUTHENTICATED ENDPOINT, and it needs no
    // secret at all. The store compares a presented `secret_hash` against the one
    // its ledger already holds for this key BEFORE it looks the secret up — by
    // design, because a refusal issued after the lookup would report whether that
    // secret exists. So an attacker sends any key with a garbage secret:
    //
    //   - the key HAS been redeemed  -> the ledger row's hash differs -> the store
    //     refuses with INVALID_ARGUMENT;
    //   - the key has NOT been redeemed -> no ledger row -> the spend matches
    //     nothing -> the store answers NOT_FOUND, and this service refuses with
    //     UNAUTHENTICATED.
    //
    // Two codes, one bit, no credential spent. `RedeemEnrolment`'s response-time
    // floor equalises TIME and never STATUS, which is exactly why the status code
    // has to be equalised here instead.
    //
    // THE ASSERTION RELATES THE TWO PATHS TO EACH OTHER rather than each to a
    // constant. A test asserting only "a refusal happened" passes against the
    // broken version, because both paths do refuse — what differed was which
    // refusal, and only a comparison sees that.
    //
    // MUTATION THIS CATCHES: restoring `.map_err(upstream_failed)?` on the
    // `RedeemEnrolment` call. `upstream_failed` replaces the MESSAGE and keeps the
    // CODE, deliberately and correctly for every other call site — so the leak
    // survives redaction and is invisible to any test that reads messages alone.
    let garbage = "not the secret this key redeemed";

    let (iam, _recorded, _inv) = iam_with(FakeDb {
        // The store's own words, so a reader can see what is being collapsed.
        redeem_fails: Some((
            tonic::Code::InvalidArgument,
            "this idempotency key was used with a different enrolment secret",
        )),
        ..Default::default()
    })
    .await;
    let redeemed_key = iam
        .redeem_enrolment(redeem(garbage, "chosen one", "k1"))
        .await
        .expect_err("a key already spent on another secret does not redeem");

    let (iam, _recorded, _inv) = iam_with(FakeDb {
        redeem: refusal(db::RedeemOutcome::NotFound),
        ..Default::default()
    })
    .await;
    let unredeemed_key = iam
        .redeem_enrolment(redeem(garbage, "chosen one", "k1"))
        .await
        .expect_err("an unknown secret does not redeem either");

    assert_eq!(
        redeemed_key.code(),
        tonic::Code::Unauthenticated,
        "a key the store refuses must not answer in a code of its own"
    );
    assert_eq!(
        (
            redeemed_key.code(),
            redeemed_key.message().to_string(),
            redeemed_key.details().to_vec()
        ),
        (
            unredeemed_key.code(),
            unredeemed_key.message().to_string(),
            unredeemed_key.details().to_vec()
        ),
        "a spent idempotency key and an unspent one must be indistinguishable to a \
         caller presenting a secret it does not hold"
    );
}

#[tokio::test]
async fn validation_runs_before_the_secret_is_looked_up() {
    // THE STATUS CODE IS THE ORACLE THIS CLOSES, and constant work does not
    // touch it. If a check that needs no secret ran AFTER the lookup, then
    // INVALID_ARGUMENT would come back only once the secret had been confirmed —
    // so the code itself would say the secret was good, cleanly and without any
    // timing measurement at all.
    //
    // ASSERTING THE STORE WAS NEVER ASKED IS THE ONLY WAY TO SEE THE ORDER. The
    // status code is INVALID_ARGUMENT either way; what differs is whether the
    // secret was presented before the refusal, and the recorded call is the
    // witness.
    for (name, req) in [
        (
            "no password",
            Request::new(RedeemEnrolmentRequest {
                secret: "s3cret".into(),
                password: String::new(),
                label: "laptop".into(),
                idempotency: Some(Idempotency { key: "k1".into() }),
            }),
        ),
        (
            "no idempotency key",
            Request::new(RedeemEnrolmentRequest {
                secret: "s3cret".into(),
                password: "chosen one".into(),
                label: "laptop".into(),
                idempotency: None,
            }),
        ),
        (
            "an oversized label",
            Request::new(RedeemEnrolmentRequest {
                secret: "s3cret".into(),
                password: "chosen one".into(),
                label: "l".repeat(4096),
                idempotency: Some(Idempotency { key: "k1".into() }),
            }),
        ),
    ] {
        // The twin would ACCEPT this secret, so nothing but the ordering can
        // produce the refusal below.
        let (iam, recorded, _inv) = iam_with(FakeDb {
            redeem: redeemed("ada"),
            password: known_user("chosen one"),
            ..Default::default()
        })
        .await;

        // `expect_err` takes a `&str` and NOT a format string, so `name` is
        // passed rather than interpolated. Written the wrong way it emits the
        // braces literally, and the panic message on a regression names nothing
        // — in the one test whose whole job is proving an ordering.
        let err = iam.redeem_enrolment(req).await.expect_err(name);

        assert_eq!(err.code(), tonic::Code::InvalidArgument, "{name}");
        assert!(
            recorded
                .lock()
                .expect("recorded")
                .redeem_enrolment
                .is_empty(),
            "{name}: the secret must not be presented to the store before a \
             check that did not need it has refused the request"
        );
    }

    // THE POSITIVE CONTROL, and without it every assertion above is satisfied by
    // a validator that refuses everything. A label AT the bound is accepted, so
    // MAX_LABEL_CHARS is a bound on an oversized label rather than a refusal of
    // ordinary ones — and the loop above is discriminating rather than
    // universal.
    //
    // **THIS LINE SAID `256`, AND IT WAS PINNING THE DEFECT.** The column stores
    // 255 characters and refuses 256, measured; the old constant was `256`
    // tested with `>`, so exactly 256 passed here and was then refused by the
    // store — after the enrolment secret had been spent. A test asserting the
    // wrong bound is part of why review did not find it.
    let (iam, _rec, _inv) = iam_with(FakeDb {
        redeem: redeemed("ada"),
        password: known_user("chosen one"),
        ..Default::default()
    })
    .await;

    let mut at_the_bound = redeem("s3cret", "chosen one", "k1");
    at_the_bound.get_mut().label = "l".repeat(255);
    iam.redeem_enrolment(at_the_bound)
        .await
        .expect("a label at the bound is accepted, not refused");
}

#[tokio::test]
async fn a_key_replayed_with_a_different_password_is_refused() {
    // REFUSED, NOT REPLAYED. The store's replay does not re-apply the password,
    // so answering with the first attempt's outcome would leave the FIRST
    // password live while the person believed the second had taken effect.
    //
    // `iam` tells the two apart REMEMBERING NOTHING — it holds no store (D4) —
    // by verifying the presented password against the hash the store already
    // holds. Here the store holds a hash of "the first password" and the caller
    // presents another, which is exactly the shape of a replay under a reused
    // key.
    //
    // MUTATION THIS CATCHES: deleting the verification and returning the store's
    // outcome directly. Every assertion about a successful redemption stays
    // green, and the person's chosen password silently does not take effect.
    let (iam, recorded, _inv) = iam_with(FakeDb {
        redeem: redeemed("ada"),
        password: known_user("the first password"),
        ..Default::default()
    })
    .await;

    let err = iam
        .redeem_enrolment(redeem("s3cret", "a second password", "k1"))
        .await
        .expect_err("a key reused with a different password is refused");

    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(
        recorded
            .lock()
            .expect("recorded")
            .create_credential
            .is_empty(),
        "a refused replay must mint no credential"
    );
}

#[tokio::test]
async fn a_redemption_returns_the_username_and_the_credential_the_store_holds() {
    // THE USERNAME IS THE HALF A LOST RESPONSE TAKES AWAY. A person enrolling on
    // their first machine has no in-band way to learn it, and `iam` holds no
    // store to have remembered it in — so it is re-read from the store on every
    // attempt, as ciphertext, and decrypted here.
    //
    // MUTATION THIS CATCHES: returning `user_id` in its place, or leaving it
    // empty. Both look like a successful redemption and leave the person unable
    // to log in afterwards.
    let (iam, recorded, _inv) = iam_with(FakeDb {
        redeem: redeemed("Ada Lovelace"),
        password: known_user("chosen one"),
        ..Default::default()
    })
    .await;

    let out = iam
        .redeem_enrolment(redeem("s3cret", "chosen one", "attempt-1"))
        .await
        .expect("a valid secret redeems")
        .into_inner();

    assert_eq!(
        out.username, "Ada Lovelace",
        "the response carries who they now are"
    );

    let credentials = recorded.lock().expect("recorded").create_credential.clone();
    assert_eq!(credentials.len(), 1, "one redemption is one credential");
    assert!(!out.token.is_empty());
    assert_eq!(
        credentials[0].token_hash,
        Keys::token_hash(&out.token),
        "the store must hold the hash of the token the caller was given"
    );

    // THE CREDENTIAL IS NOT COVERED BY THE CALLER'S KEY, and cannot be: the
    // token is shown once and kept as a hash, so no replay could return the
    // first one. A retry mints a FRESH credential under its own key — which is
    // what leaves the orphan the contract accepts and ListCredentials exists to
    // find.
    //
    // MUTATION THIS CATCHES: passing the caller's key through to
    // CreateCredential. The store would then replay the FIRST credential row and
    // hand back a credential_id whose token nobody holds — a retry that reports
    // success and leaves the person with nothing.
    let key = credentials[0]
        .idempotency
        .as_ref()
        .expect("the credential is written under a key of its own")
        .key
        .clone();
    assert!(
        !key.is_empty(),
        "a write with an empty key is a write D9 cannot deduplicate"
    );
    assert_ne!(
        key, "attempt-1",
        "the credential must NOT be minted under the caller's key"
    );

    // The spend, though, IS the caller's key: that is what makes a retry reach
    // the store as the same write rather than as a second presentation.
    let spends = recorded.lock().expect("recorded").redeem_enrolment.clone();
    assert_eq!(
        spends[0].idempotency.as_ref().map(|i| i.key.as_str()),
        Some("attempt-1"),
        "the caller's key is passed through unchanged"
    );
    assert!(
        !format!("{:?}", spends[0]).contains("chosen one"),
        "the plaintext password must never cross the storage boundary"
    );
}

#[tokio::test(start_paused = true)]
async fn the_redeem_floor_is_anchored_to_the_start_on_every_path() {
    // THE FLOOR'S OWN ARGUMENT HERE IS NOT `Login`'s. The three refusals are
    // decided INSIDE `iam-db`, by a RedeemOutcome this service only reads, and a
    // miss, a row found spent and a row found expired need not cost the store
    // the same. No amount of constant work in THIS process can equalise a
    // difference that arises in another one, so collapsing the three into one
    // status code and leaving the response time free would make "one failure,
    // not three" true of the code and false of the endpoint.
    //
    // MUTATION THIS CATCHES, and it is the reason this test is not the
    // wall-clock lower bound it started as: passing `Duration::ZERO` in place of
    // `started.elapsed()`, so the floor PADS the work instead of being ANCHORED
    // to the start of the call. The total becomes `work + floor` rather than
    // `floor`, and the response time goes on reporting exactly how much work was
    // done — the leak wearing the floor's clothes.
    //
    // A LOWER BOUND CANNOT SEE THAT, and the first version of this test was one.
    // `assert!(elapsed >= FLOOR)` holds for any implementation that waits AT
    // LEAST long enough, the padding mutant included. Worse, it passes VACUOUSLY
    // the moment a runner is slow enough that the work alone clears the bound:
    // measured on CI at a 700ms floor, every path exceeded it, nothing was
    // padded, and the assertion was green while the paths separated by whatever
    // their work cost. Raising the constant only moves the load at which that
    // happens — under 40 spinners on 24 cores even 2s was beaten. No wall-clock
    // constant survives an arbitrarily loaded runner.
    //
    // A PAUSED CLOCK IS WHAT REMOVES THE RUNNER FROM THE QUESTION, exactly as it
    // does for `the_floor_is_anchored_to_the_start_not_added_to_the_work` beside
    // it. Time advances only when the runtime is idle, so what is measured is
    // THE SLEEP THE CODE ASKED FOR rather than how long the machine took to
    // deliver it. `started.elapsed()` inside the handler is a `std::time::Instant`
    // and still measures the REAL Argon2 work, so this runs the real handler,
    // the real hashing and the real round trips to the twin — it just reads the
    // hold on a clock no load can move.
    //
    // THE ASSERTION IS STRICTLY LESS THAN THE FLOOR, and that is the anchoring
    // property itself: the hold must SHRINK by the work already done. It holds
    // however slow the machine is — if the work exceeded the floor the hold is
    // zero, which is also less — and it fails under the padding mutant, which
    // always holds for the full floor. There is no regime in which it is
    // vacuous and none in which it flakes.
    //
    // 10 SECONDS COSTS NO WALL TIME, because the sleep is instantaneous under a
    // paused clock. A floor far above the real work is therefore free here, and
    // it is what keeps the warning assertion below meaningful rather than a
    // second thing to tune.
    const FLOOR: Duration = Duration::from_secs(10);

    for (name, fake) in [
        ("an unknown secret", FakeDb::default()),
        (
            "a spent secret",
            FakeDb {
                redeem: refusal(db::RedeemOutcome::Spent),
                ..Default::default()
            },
        ),
        (
            // THE STORE'S OWN REFUSAL, which is a fourth path and not a fourth
            // outcome — it arrives as an ERROR rather than a `RedeemOutcome`, so
            // it leaves the handler through a `return` of its own. A path that
            // escapes the floor would answer in the microseconds the store took
            // to refuse, which is the same oracle in time that collapsing its
            // status code closes in the response.
            "a key the store refuses",
            FakeDb {
                redeem_fails: Some((
                    tonic::Code::InvalidArgument,
                    "this idempotency key was used with a different enrolment secret",
                )),
                ..Default::default()
            },
        ),
        (
            "a successful redemption",
            FakeDb {
                redeem: redeemed("ada"),
                password: known_user("chosen one"),
                ..Default::default()
            },
        ),
    ] {
        let (iam, _rec, _inv) = iam_with_redeem_floor(fake, FLOOR).await;

        let t0 = tokio::time::Instant::now();
        let _ = iam
            .redeem_enrolment(redeem("s3cret", "chosen one", "k1"))
            .await;
        let held = t0.elapsed();

        // BOTH SIDES, AND THE LOWER ONE IS WHAT GIVES THIS TEST ITS REACH.
        // `held < FLOOR` is one-sided: it is satisfied by a hold of ZERO, so on
        // its own it would pass against a handler that never called
        // `hold_until_floor` at all — and it would also pass if the virtual
        // clock had moved for some reason other than that sleep, leaving the
        // test asserting on a number it did not produce. A correct handler here
        // sleeps roughly `FLOOR` minus a second of real Argon2 work, so a hold
        // of zero means the sleep did not happen and the round trips are not
        // reaching the handler the way this test claims.
        assert!(
            held > Duration::ZERO,
            "{name}: the hold was {held:?} — the floor was not applied to this \
             path at all, so the assertion below proves nothing about anchoring"
        );
        assert!(
            held < FLOOR,
            "{name}: the hold was {held:?} against a {FLOOR:?} floor — the floor \
             was ADDED to the work rather than anchored to the start of the \
             call, so the response time is still a function of that work"
        );

        // AND THE FLOOR MUST HAVE COVERED SOMETHING. The service warns exactly
        // when it did not, so its silence is the evidence. At this floor a
        // warning would mean the real work exceeded ten seconds, which is a
        // broken machine rather than a slow one.
        assert!(
            redeem_floor_warnings().is_empty(),
            "{name}: the floor covered nothing — this call cost more than \
             {FLOOR:?} of real work, so the assertion above proved nothing about \
             padding. Warnings: {:?}",
            redeem_floor_warnings()
        );
    }
}

#[tokio::test]
async fn a_redemption_slower_than_the_floor_answers_normally_and_warns() {
    // THE SELF-CHECK, and it is the half that makes this a control rather than a
    // decoration — the same half `a_login_slower_than_the_floor_answers_normally_and_warns`
    // provides for `Login`, and which `RedeemEnrolment` shipped without.
    //
    // MUTATION THIS CATCHES, and it is the one a lower bound cannot see: passing
    // `Duration::ZERO` in place of `started.elapsed()`, so the floor PADS the
    // work instead of being ANCHORED to the start of the call. The total becomes
    // `work + floor` rather than `floor`, every path still clears the bound, and
    // the response time goes on reporting exactly how much work was done. Under
    // that mutant nothing ever exceeds the floor, so nothing ever warns — and
    // this assertion is what turns that silence red.
    //
    // A 1ms floor against real Argon2id work, which costs two orders of
    // magnitude more in any build. No timing tolerance is involved: the gap is
    // the oracle.
    const FLOOR: Duration = Duration::from_millis(1);

    let (iam, recorded, _inv) = iam_with_redeem_floor(
        FakeDb {
            redeem: redeemed("ada"),
            password: known_user("chosen one"),
            ..Default::default()
        },
        FLOOR,
    )
    .await;

    let out = iam
        .redeem_enrolment(redeem("s3cret", "chosen one", "k1"))
        .await
        .expect("EXCEEDING THE FLOOR IS NOT AN ERROR — a slow redemption is still a correct one")
        .into_inner();

    assert!(
        !out.token.is_empty(),
        "a warned redemption still issues its credential"
    );
    assert_eq!(
        recorded.lock().expect("recorded").create_credential.len(),
        1,
        "a warned redemption is still a redemption"
    );

    let warned = redeem_floor_warnings();
    let all = warnings();
    assert_eq!(
        warned.len(),
        1,
        "exceeding the floor must warn exactly once; everything this thread \
         emitted: {all:?}"
    );
    let text = &warned[0];
    assert!(
        text.contains("WARN"),
        "the floor must WARN, not be noted at a level nobody alerts on: {text:?}"
    );
    assert!(
        text.contains("floor_ms=1"),
        "the warning must name the CONFIGURED floor: {text:?}"
    );
    assert!(
        text.contains("observed_ms="),
        "the warning must name the OBSERVED duration, or an operator cannot tell \
         what to raise it TO: {text:?}"
    );
    // THE WHOLE REASON `Floor` CARRIES ITS ENV VAR. Two floors are configured
    // separately now, so a warning that does not say WHICH variable to raise
    // sends an operator to raise the one that was already fine.
    assert!(
        text.contains("floor_env=REDEEM_RESPONSE_FLOOR_MS"),
        "the warning must name the variable an operator raises, and it is NOT \
         Login's: {text:?}"
    );

    assert!(
        floor_warnings().is_empty(),
        "the Login floor warned about nothing here; its filter must not pick up \
         a redemption's warning: {:?}",
        floor_warnings()
    );
}

// ---------------------------------------------------------------------------
// Enrolment configuration, and what an unconfigured deployment does.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_unconfigured_deployment_refuses_to_mint_and_serves_everything_else() {
    // THE BLAST RADIUS OF A MISSING ENROLMENT_GATEWAY, pinned. An earlier
    // revision failed BOOT on this, which keeps the contract's rule — never mint
    // a token with an empty gateway — by stopping the authentication plane for
    // the whole estate. Refusing to MINT keeps the same rule and costs nothing
    // else.
    //
    // MUTATION THIS CATCHES: minting anyway with an empty gateway. The contract
    // says a client that decodes such a token refuses it and names the field, so
    // the failure would surface on a stranger's machine on their first contact
    // with this deployment — the one place it cannot be diagnosed.
    let (iam, recorded, _inv) = iam_without_enrolment(FakeDb {
        resolves_to: Some("yadgar:user:1".into()),
        ..Default::default()
    })
    .await;

    let err = iam
        .issue_enrolment(issue("attempt-1"))
        .await
        .expect_err("an unconfigured deployment cannot mint an enrolment");

    assert_eq!(
        err.code(),
        tonic::Code::FailedPrecondition,
        "the request is well formed and the service is not broken — it is not \
         configured for this"
    );
    assert!(
        err.message().contains("ENROLMENT_GATEWAY"),
        "the refusal must name the variable an operator sets: {:?}",
        err.message()
    );
    assert!(
        recorded
            .lock()
            .expect("recorded")
            .create_enrolment
            .is_empty(),
        "the refusal must come BEFORE the store is touched, or a deployment that \
         cannot hand a token over still spends a row and a secret"
    );

    // AND THE REST OF THE SERVICE IS UNAFFECTED. This is the whole argument for
    // not failing boot: `iam` is the authentication plane, and one unset
    // administrative value must not stop credential resolution for the estate.
    let resolved = iam
        .resolve_credential(Request::new(ResolveCredentialRequest::default()))
        .await
        .expect("ResolveCredential is unaffected by enrolment configuration")
        .into_inner();
    assert_eq!(resolved.user_id, "yadgar:user:1");
}

#[test]
fn an_absent_ca_is_a_deployment_and_an_empty_one_is_a_mistake() {
    // ABSENT AND EMPTY ARE DIFFERENT INSTRUCTIONS TO A CLIENT, and the contract
    // states the rule for both ends. Absent means the deployment uses a
    // publicly-trusted certificate and system trust applies — legitimate, so it
    // is modelled rather than treated as an error. Present-and-empty is a token
    // assembled wrong, which a client is required to refuse; minting one would
    // put that refusal on a stranger's machine instead of here.
    //
    // MUTATION THIS CATCHES: collapsing the two into `unwrap_or_default()`, so
    // an empty CA silently becomes "use system trust" and the misconfiguration
    // never surfaces at all.
    let absent = EnrolmentConfig::load(TEST_GATEWAY, None).expect("no CA is a deployment");
    assert!(
        format!("{absent:?}").contains("ca_pem: None"),
        "absence must survive as absence: {absent:?}"
    );

    let dir = std::env::temp_dir().join(format!("iam-ca-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");

    let empty = dir.join("empty.pem");
    std::fs::write(&empty, "   \n").expect("write");
    assert!(
        matches!(
            EnrolmentConfig::load(TEST_GATEWAY, empty.to_str()),
            Err(EnrolmentConfigError::EmptyCa(_))
        ),
        "a CA file with nothing in it is a mistake, not a deployment without a CA"
    );

    let real = dir.join("ca.pem");
    std::fs::write(&real, TEST_CA).expect("write");
    let loaded = EnrolmentConfig::load(TEST_GATEWAY, real.to_str()).expect("a real CA loads");
    assert!(
        format!("{loaded:?}").contains("BEGIN CERTIFICATE"),
        "the CA is read from the file, not merely its path recorded: {loaded:?}"
    );

    assert!(
        matches!(
            EnrolmentConfig::load(TEST_GATEWAY, dir.join("nope.pem").to_str()),
            Err(EnrolmentConfigError::UnreadableCa(_, _))
        ),
        "a CA path naming no file is refused rather than read as absence"
    );

    assert!(
        matches!(
            EnrolmentConfig::load("", None),
            Err(EnrolmentConfigError::NoGateway(_))
        ),
        "an empty gateway is refused; the field has no presence to say so with"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// What v1.6.0 added and this change does NOT implement.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_unbuilt_rpcs_refuse_rather_than_answering() {
    // MUTATION THIS CATCHES, and it is the one the doc-comment on
    // `list_credentials` claims to prevent: returning
    // `Ok(ListCredentialsResponse::default())`. An empty list is an ANSWER — it
    // says this user holds no credentials — and the orphan a lost redemption
    // response leaves is exactly what a caller would be looking for. Silence
    // that reads as an answer is worse than a refusal.
    let (iam, _rec, _inv) = iam_with(FakeDb::default()).await;

    let listed = iam
        .list_credentials(Request::new(ListCredentialsRequest::default()))
        .await
        .expect_err("ListCredentials is not built");
    assert_eq!(listed.code(), tonic::Code::Unimplemented);

    let admin = iam
        .set_user_admin(Request::new(SetUserAdminRequest::default()))
        .await
        .expect_err("SetUserAdmin is not built");
    assert_eq!(admin.code(), tonic::Code::Unimplemented);

    let limit = iam
        .set_rate_limit_override(Request::new(SetRateLimitOverrideRequest::default()))
        .await
        .expect_err("SetRateLimitOverride is not built");
    assert_eq!(limit.code(), tonic::Code::Unimplemented);
}

#[tokio::test]
async fn the_admin_flag_travels_from_the_store_rather_than_being_decided_here() {
    // D73's FLAG ON THE HOT PATH, and it is privilege-bearing: the gateway gates
    // the administrative path on it and filters `tools/list` with it.
    //
    // MUTATION THIS CATCHES — both directions, which is why both are asserted. A
    // hardcoded `false` silently denies administration to every admin, and a
    // hardcoded `true` grants it to everyone. Neither is visible from a response
    // that is only checked in one state.
    for reported in [true, false] {
        let (iam, _rec, _inv) = iam_with(FakeDb {
            resolves_to: Some("yadgar:user:1".into()),
            resolves_admin: reported,
            ..Default::default()
        })
        .await;

        let got = iam
            .resolve_credential(Request::new(ResolveCredentialRequest::default()))
            .await
            .expect("resolve")
            .into_inner();

        assert_eq!(
            got.is_admin, reported,
            "is_admin must be what the store said, not what this service assumed"
        );
    }
}

// ---------------------------------------------------------------------------
// ADR-0522's inheritable setting. `iam` carries the INPUTS and resolves nothing.
// ---------------------------------------------------------------------------

/// A setting with something in every field, so a rebuild that drops one dies.
///
/// The map is NON-EMPTY deliberately: `team_override` is the field a
/// field-by-field reconstruction is most likely to leave behind, and an empty
/// one is indistinguishable from a dropped one.
fn stated(value: SettingValue, locked: bool) -> Option<InheritedSetting> {
    Some(InheritedSetting {
        org_value: value as i32,
        org_locked: locked,
        team_override: [
            ("yadgar:team:a".to_string(), SettingValue::On as i32),
            ("yadgar:team:b".to_string(), SettingValue::Off as i32),
        ]
        .into_iter()
        .collect(),
    })
}

async fn resolved_setting(fake: FakeDb) -> Option<InheritedSetting> {
    let (iam, _rec, _inv) = iam_with(fake).await;
    iam.resolve_credential(Request::new(ResolveCredentialRequest::default()))
        .await
        .expect("resolve")
        .into_inner()
        .owner_reads_own_record
}

#[tokio::test]
async fn an_absent_setting_stays_absent_rather_than_becoming_a_default() {
    // MUTATION THIS CATCHES: `got.owner_reads_own_record.unwrap_or_default()`,
    // or any `.unwrap_or(InheritedSetting { .. })`.
    //
    // `iam-db` answers with the message ABSENT when the organisation row is not
    // there. Absent and present-holding-UNSPECIFIED are ONE case, which a -db
    // that reads this setting REFUSES rather than reading as OFF — so
    // manufacturing a present message here would convert a refusal the
    // deployment is owed into a policy nobody stated.
    assert!(
        resolved_setting(FakeDb {
            resolves_to: Some("yadgar:user:1".into()),
            resolves_setting: None,
            ..Default::default()
        })
        .await
        .is_none(),
        "an absent setting must arrive absent: substituting one states a policy \
         the deployment never chose"
    );
}

#[tokio::test]
async fn an_unstated_setting_travels_unstated_rather_than_being_completed() {
    // MUTATION THIS CATCHES, AND IT IS A DIFFERENT ONE FROM THE TEST ABOVE: the
    // message is PRESENT, so `unwrap_or_default` cannot fire. What fires here is
    // a handler that reads the falsy zero and helpfully fills it in —
    // `if org_value == 0 { org_value = ON }` — or one that hardcodes the lock.
    //
    // (UNSPECIFIED, false) IS THE SHAPE THE HAZARD WEARS. `org_locked` is a bool
    // and cannot say "unknown", so false is indistinguishable from a stated
    // "clear" — the PERMISSIVE half of a policy nobody stated. Only `org_value`
    // can carry "nothing was said", and only if it arrives unchanged.
    let got = resolved_setting(FakeDb {
        resolves_to: Some("yadgar:user:1".into()),
        resolves_setting: Some(InheritedSetting::default()),
        ..Default::default()
    })
    .await
    .expect("the message was present");

    assert_eq!(
        got.org_value,
        SettingValue::Unspecified as i32,
        "an unset organisation value must reach the resolution unset, so it can \
         be refused there"
    );
    assert!(
        !got.org_locked,
        "a lock nobody set must not arrive set, and must not arrive as anything \
         this service decided"
    );
}

#[tokio::test]
async fn the_setting_travels_from_the_store_rather_than_being_decided_here() {
    // BOTH DIRECTIONS OF BOTH FIELDS, for `the_admin_flag_travels_...`'s reason:
    // a hardcode is invisible from a response only ever checked in one state. A
    // locked organisation with contradicting overrides and a clear one with the
    // same overrides are the two combinations that discriminate, and they are
    // the two an implementation gets right by accident.
    //
    // **AND ON THE NEGATIVE PATH TOO**, which is a THIRD mutant and not a
    // thoroughness flourish: `owner_reads_own_record: if resolved { .. } else
    // { None }`. That edit reads as the obvious analogy to `valid_for_seconds`
    // directly above it, and it is wrong for a stated reason — the TTL is zeroed
    // because a negative answer is worth caching for no interval, while this
    // setting is DEPLOYMENT-WIDE rather than credential-scoped. Without a
    // negative-path case the whole suite goes green on a handler that drops what
    // the store sent.
    for user in [Some("yadgar:user:1".to_string()), None] {
        for value in [SettingValue::On, SettingValue::Off] {
            for locked in [true, false] {
                let reported = stated(value, locked);
                let got = resolved_setting(FakeDb {
                    resolves_to: user.clone(),
                    resolves_setting: reported.clone(),
                    ..Default::default()
                })
                .await;

                assert_eq!(
                    got, reported,
                    "the setting must be what the store said, whole — the value, \
                     the lock and every team override — and on the negative path \
                     as much as the positive one"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SetInheritedSetting (ADR-0524). Validate here, store there.
// ---------------------------------------------------------------------------

/// A well-formed organisation-level write. Every refusal case below is this with
/// exactly one thing changed, so what the test names is what the test changes.
fn org_write() -> SetInheritedSettingRequest {
    SetInheritedSettingRequest {
        idempotency: Some(Idempotency {
            key: "01J0000000000000000000000K".into(),
        }),
        scope: SettingScope::Org as i32,
        team_id: None,
        name: "owner_reads_own_record".into(),
        value: Some(SettingValue::On as i32),
        locked: Some(true),
        clear: false,
        unverified_actor: None,
    }
}

/// A well-formed team-level write.
fn team_write() -> SetInheritedSettingRequest {
    SetInheritedSettingRequest {
        team_id: Some("yadgar:team:a".into()),
        scope: SettingScope::Team as i32,
        locked: None,
        value: Some(SettingValue::Off as i32),
        ..org_write()
    }
}

#[tokio::test]
async fn a_write_reaches_the_store_with_its_presence_intact() {
    // MUTATION THIS CATCHES: `value: r.value.unwrap_or_default()` or
    // `locked: Some(r.locked.unwrap_or(false))` — anything that collapses an
    // Option on the way through. Presence is what separates "said nothing" from
    // "said this", and it is the whole of ADR-0524's guard.
    let (iam, rec, _inv) = iam_with(FakeDb {
        setting_now: stated(SettingValue::On, true),
        ..Default::default()
    })
    .await;

    let sent = org_write();
    let got = iam
        .set_inherited_setting(Request::new(sent.clone()))
        .await
        .expect("a well-formed organisation write")
        .into_inner();

    let seen = rec.lock().expect("recorded").set_inherited_setting.clone();
    assert_eq!(seen.len(), 1, "the store is asked exactly once");
    let seen = &seen[0];
    assert_eq!(seen.idempotency, sent.idempotency, "D9's key travels");
    assert_eq!(seen.scope, sent.scope);
    assert_eq!(seen.team_id, sent.team_id);
    assert_eq!(seen.name, sent.name);
    assert_eq!(seen.value, sent.value, "the value keeps its presence");
    assert_eq!(seen.locked, sent.locked, "the lock keeps its presence");
    assert_eq!(seen.clear, sent.clear);

    // MUTATION THIS CATCHES: rebuilding the response. What comes back carries
    // the OTHER level and every OTHER team's override, none of which the caller
    // sent — a reconstruction here silently narrows a policy an operator is
    // reading back.
    assert_eq!(
        got.setting,
        stated(SettingValue::On, true),
        "the response is the store's setting, whole"
    );
}

#[tokio::test]
async fn a_withdrawal_is_forwarded_as_a_withdrawal() {
    // THE ONE DELETING SHAPE: team scope, `clear` set, `value` absent. It must
    // survive the hop with `value` still absent — a handler that filled it in
    // would turn a withdrawal into a statement of whatever it chose.
    let (iam, rec, _inv) = iam_with(FakeDb {
        setting_now: stated(SettingValue::On, false),
        ..Default::default()
    })
    .await;

    let sent = SetInheritedSettingRequest {
        value: None,
        clear: true,
        ..team_write()
    };
    iam.set_inherited_setting(Request::new(sent))
        .await
        .expect("clearing an override is well formed");

    let seen = rec.lock().expect("recorded").set_inherited_setting.clone();
    assert_eq!(seen.len(), 1);
    assert!(seen[0].clear, "the affirmative byte travels");
    assert_eq!(
        seen[0].value, None,
        "an absent value must stay absent, or the withdrawal becomes a statement"
    );
}

#[tokio::test]
async fn every_refusal_lands_before_the_store_is_asked() {
    // THE CLAUSES ARE `yadgar.common.v1.SettingScope`'s, and `iam.proto` says
    // THIS service refuses them rather than forwarding them.
    //
    // THE ORDERING IS THE PART A STATUS CODE CANNOT SHOW. All of them are
    // `INVALID_ARGUMENT`, and the fake store answers `Ok` to everything — so a
    // handler that forwarded first and refused afterwards would produce an
    // identical code on every row here. The EMPTY recording is the only witness.
    //
    // MUTATION THIS CATCHES, per row: deleting that clause from
    // `check_inherited_setting`. The fake answers `Ok`, so a deleted clause
    // turns the row's `expect_err` into a success.
    let cases: Vec<(&str, SetInheritedSettingRequest)> = vec![
        (
            "scope unspecified",
            SetInheritedSettingRequest {
                scope: SettingScope::Unspecified as i32,
                locked: None,
                ..org_write()
            },
        ),
        (
            "scope is not a member this contract declares",
            SetInheritedSettingRequest {
                // proto3 enums are OPEN, so this arrives intact rather than
                // collapsing to the zero. A `default:` that fell through would
                // write the ORGANISATION's policy for a request naming neither.
                scope: 7,
                ..org_write()
            },
        ),
        (
            "team scope with no team id",
            SetInheritedSettingRequest {
                team_id: None,
                ..team_write()
            },
        ),
        (
            "team scope with an empty team id",
            SetInheritedSettingRequest {
                team_id: Some(String::new()),
                ..team_write()
            },
        ),
        (
            "org scope carrying a team id",
            SetInheritedSettingRequest {
                team_id: Some("yadgar:team:a".into()),
                ..org_write()
            },
        ),
        (
            "team scope carrying the lock, set",
            SetInheritedSettingRequest {
                locked: Some(true),
                ..team_write()
            },
        ),
        (
            // FALSE IS THE HALF A BARE BOOL COULD NOT REFUSE, which is why the
            // field carries presence. Its instruction would otherwise be
            // discarded in silence.
            "team scope carrying the lock, clear",
            SetInheritedSettingRequest {
                locked: Some(false),
                ..team_write()
            },
        ),
        (
            "org scope with no lock",
            SetInheritedSettingRequest {
                locked: None,
                ..org_write()
            },
        ),
        (
            "an explicitly unspecified value at org scope",
            SetInheritedSettingRequest {
                value: Some(SettingValue::Unspecified as i32),
                ..org_write()
            },
        ),
        (
            "an explicitly unspecified value at team scope",
            SetInheritedSettingRequest {
                value: Some(SettingValue::Unspecified as i32),
                ..team_write()
            },
        ),
        (
            "an absent value with no clear, at org scope",
            SetInheritedSettingRequest {
                value: None,
                ..org_write()
            },
        ),
        (
            "an absent value with no clear, at team scope",
            SetInheritedSettingRequest {
                value: None,
                ..team_write()
            },
        ),
        (
            "clear set alongside a value",
            SetInheritedSettingRequest {
                clear: true,
                ..team_write()
            },
        ),
        (
            "clear at org scope",
            SetInheritedSettingRequest {
                value: None,
                clear: true,
                ..org_write()
            },
        ),
        (
            "a name outside the vocabulary",
            SetInheritedSettingRequest {
                name: "owner_reads_own_recrod".into(),
                ..org_write()
            },
        ),
    ];

    for (why, request) in cases {
        let (iam, rec, _inv) = iam_with(FakeDb {
            setting_now: stated(SettingValue::On, true),
            ..Default::default()
        })
        .await;

        let err = iam
            .set_inherited_setting(Request::new(request))
            .await
            .expect_err(why);
        assert_eq!(err.code(), tonic::Code::InvalidArgument, "{why}");
        assert!(
            rec.lock()
                .expect("recorded")
                .set_inherited_setting
                .is_empty(),
            "{why}: the store must never be asked — a refusal that forwarded \
             first would leave a row, a ledger entry, or a burnt idempotency key"
        );
    }
}

#[tokio::test]
async fn a_setting_write_publishes_no_invalidation() {
    // NOT AN OMISSION — the contract's answer. The setting travels on a cached
    // credential, an organisation-level write touches EVERY cached credential in
    // the deployment, and no event on this contract says so. Every subject
    // `invalidate` publishes is keyed on a `user_id` this request does not
    // carry, so reaching for one would invent a mechanism for a request that
    // names nobody. A deployment that tightens this policy WAITS THE CACHE OUT.
    let (iam, _rec, inv) = iam_with(FakeDb {
        setting_now: stated(SettingValue::Off, true),
        ..Default::default()
    })
    .await;

    iam.set_inherited_setting(Request::new(org_write()))
        .await
        .expect("a well-formed organisation write");

    assert!(
        inv.published().is_empty(),
        "a setting write must publish nothing: there is no user to key an \
         invalidation on, and a wrong key is worse than none"
    );
}

// ---------------------------------------------------------------------------
// WHAT THE ADMINISTRATIVE WRITES ACTUALLY CARRY TO THE STORE.
//
// Every request below was built with `..Default::default()`, which supplies a
// field the caller DID send and reads, at the call site, as though there were
// nothing to send. The rest pattern is why no compiler and no test in this
// repository could see the difference. These tests are the ones that can.
//
// AND THE TESTS THEMSELVES STILL USE THE REST PATTERN, which is not a
// contradiction. What made the rest pattern dangerous in `service.rs` is that
// the value it supplied was SENT — it stood in for a field on a real wire
// message and no reader could tell. Here it supplies fields the assertion does
// not read, in a request under this test's own control, and the cost it avoids
// is editing every literal below on every additive proto bump.
// ---------------------------------------------------------------------------

/// D9's key, on the four administrative writes that forward one.
///
/// **NOT `IssueCredential`, and its absence here is the point.** That RPC's
/// idempotency classification is explicitly UNDECIDED on the contract — see the
/// `yadgar.common.v1.Idempotency` comment, which names it as the case ADR-0519's
/// rule "would reach" and says the move "is its own decision and its own contract
/// release". Forwarding its key would make that decision silently, from here.
///
/// **AND THE ABSENCE COSTS SOMETHING, which the handler's comment now states.**
/// The same contract text enumerates the carve-out's members and today the list
/// is one, `IssueEnrolment`, so `IssueCredential` is governed by D9's ordinary
/// rule and `iam` accepts a key it discards. A caller retrying a lost response
/// mints a second live credential and orphans the first. That is a contract
/// release to resolve, not a line in this file, which is why no test here pins
/// the behaviour either way.
#[tokio::test]
async fn d9s_key_travels_on_every_administrative_write() {
    let key = || {
        Some(Idempotency {
            key: "01J0000000000000000000000K".into(),
        })
    };

    let (iam, rec, _inv) = iam_with(FakeDb::default()).await;

    iam.revoke_credential(Request::new(RevokeCredentialRequest {
        idempotency: key(),
        credential_id: "yadgar:credential:1".into(),
        ..Default::default()
    }))
    .await
    .expect("a revocation");

    iam.create_user(Request::new(CreateUserRequest {
        idempotency: key(),
        external_id: "someone".into(),
        display_name: "Some One".into(),
        is_admin: false,
        ..Default::default()
    }))
    .await
    .expect("a user");

    iam.add_team_member(Request::new(AddTeamMemberRequest {
        idempotency: key(),
        team_id: "yadgar:team:a".into(),
        user_id: "yadgar:user:1".into(),
        ..Default::default()
    }))
    .await
    .expect("a grant");

    iam.remove_team_member(Request::new(RemoveTeamMemberRequest {
        idempotency: key(),
        team_id: "yadgar:team:a".into(),
        user_id: "yadgar:user:1".into(),
        ..Default::default()
    }))
    .await
    .expect("a removal");

    let seen = rec.lock().expect("recorded");
    assert_eq!(
        seen.revoke_credential[0].idempotency,
        key(),
        "D9's key travels"
    );
    assert_eq!(seen.create_user[0].idempotency, key(), "D9's key travels");
    assert_eq!(
        seen.add_team_member[0].idempotency,
        key(),
        "D9's key travels"
    );
    assert_eq!(
        seen.remove_team_member[0].idempotency,
        key(),
        "D9's key travels"
    );
}

/// D73's admin flag reaches the store, or the first admin cannot be created.
///
/// The flag is settable at creation for exactly one reason, and the contract
/// says it: the FIRST admin has to exist before anyone can log in to promote
/// one. A `CreateUser` that drops it answers `OK` and writes an ordinary user,
/// so the bootstrap appears to succeed and the deployment has no administrator.
#[tokio::test]
async fn create_user_carries_d73s_admin_flag() {
    let (iam, rec, _inv) = iam_with(FakeDb::default()).await;

    iam.create_user(Request::new(CreateUserRequest {
        idempotency: None,
        external_id: "the-first-admin".into(),
        display_name: "The First Admin".into(),
        is_admin: true,
        ..Default::default()
    }))
    .await
    .expect("an administrator");

    assert!(
        rec.lock().expect("recorded").create_user[0].is_admin,
        "the store must be told this user is an administrator; a dropped flag \
         reports success and leaves the deployment with nobody who can promote \
         anyone"
    );
}

/// The expiry the caller asked for reaches the store.
///
/// `expires_in_seconds` is the only way a caller of `IssueCredential` can bound
/// a token's life, and the store's field is an absolute deadline. A request that
/// drops it mints a credential that NEVER EXPIRES while answering as though the
/// bound had been applied.
#[tokio::test]
async fn issue_credential_carries_the_expiry_the_caller_asked_for() {
    let (iam, rec, _inv) = iam_with(FakeDb::default()).await;

    let before = SystemTime::now();
    iam.issue_credential(Request::new(IssueCredentialRequest {
        idempotency: None,
        user_id: "yadgar:user:1".into(),
        label: "a laptop".into(),
        expires_in_seconds: 3600,
        ..Default::default()
    }))
    .await
    .expect("a credential");

    let deadline = rec.lock().expect("recorded").create_credential[0]
        .expires_at
        .expect(
            "the deadline the caller asked for; absent means this credential \
             never expires",
        )
        .seconds;

    // A WINDOW RATHER THAN AN EQUALITY, because the deadline is computed from
    // the clock inside the call. The window is 60 seconds wide and FORWARD
    // ONLY: `before` is read outside the call, so the handler's own clock is at
    // or after it and a deadline earlier than `asked` is wrong rather than
    // merely early. Sixty seconds is slack for a slow machine and nothing more —
    // it still excludes a zero, a reading in milliseconds, and the hour applied
    // twice, which are the three ways this arithmetic goes wrong.
    let asked = before
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("after the epoch")
        .as_secs() as i64
        + 3600;
    assert!(
        (asked..asked + 60).contains(&deadline),
        "the store was told {deadline} and the caller asked for about {asked}"
    );
}

/// Zero seconds means no expiry, which the contract states in as many words.
///
/// The pair matters: without it, `expires_at: Some(now)` would satisfy the test
/// above and silently expire every credential minted without a bound.
#[tokio::test]
async fn issue_credential_with_zero_seconds_carries_no_expiry() {
    let (iam, rec, _inv) = iam_with(FakeDb::default()).await;

    iam.issue_credential(Request::new(IssueCredentialRequest {
        idempotency: None,
        user_id: "yadgar:user:1".into(),
        label: "a laptop".into(),
        expires_in_seconds: 0,
        ..Default::default()
    }))
    .await
    .expect("a credential");

    assert_eq!(
        rec.lock().expect("recorded").create_credential[0].expires_at,
        None,
        "zero means no expiry, so the store must be given no deadline at all"
    );
}

/// The `expires_in_seconds` values this service refuses, and it refuses them
/// HERE rather than letting the store answer for them.
///
/// **THE TWO ENDS FAIL DIFFERENTLY, AND ONLY ONE OF THEM EVER REACHED THE
/// STORE.** Measured against `mariadb:11.8.9` — the image `iam-db`'s README
/// stands up — at its stock `sql_mode`, which is strict:
/// `FROM_UNIXTIME(4294967296)` is NULL, and the INSERT is REFUSED with
/// `ERROR 1292 Truncated incorrect unixtime value` rather than storing that
/// NULL. So an absurd expiry already failed CLOSED. What it did instead was
/// reach `iam-db`, which renders every engine error as "storage unavailable",
/// so a request that was never well-formed came back reading as an outage.
///
/// **A NEGATIVE never involved the store at all, and it failed OPEN.**
/// `expires_in_seconds > 0` sent `expires_at: None`, so a caller asking for a
/// deadline already PAST received the credential that never expires — the
/// unlimited life `0` asks for, handed to the request that asked for the
/// shortest one.
///
/// Both are values `IssueCredentialRequest` gives no meaning to: the contract
/// says "Zero means no expiry" and nothing else, so no caller written against it
/// sends either, and refusing them is not a refusal such a caller newly meets.
#[tokio::test]
async fn issue_credential_refuses_an_expiry_the_contract_gives_no_meaning_to() {
    let (iam, rec, _inv) = iam_with(FakeDb::default()).await;

    for asked in [-1, i64::MIN, MAX_EXPIRES_IN_SECONDS + 1, i64::MAX] {
        let err = iam
            .issue_credential(Request::new(IssueCredentialRequest {
                user_id: "yadgar:user:1".into(),
                expires_in_seconds: asked,
                ..Default::default()
            }))
            .await
            .expect_err("an expiry the contract gives no meaning to is refused");

        // THE CODE, because it is what tells the caller whose mistake this is.
        // `UNAVAILABLE` or `INTERNAL` says the service is broken and invites a
        // retry that cannot succeed; `INVALID_ARGUMENT` says the request is, and
        // is the answer ADR-0512 asks a boundary to document.
        assert_eq!(
            err.code(),
            tonic::Code::InvalidArgument,
            "expires_in_seconds = {asked}"
        );
        // AND THE FIELD BY NAME. `IssueCredentialRequest` has four fields a
        // caller fills; a refusal that does not say which one is wrong leaves
        // the caller to guess, and this is the only place that knows.
        assert!(
            err.message().contains("expires_in_seconds"),
            "the refusal must name the field: expires_in_seconds = {asked} gave \
             {:?}",
            err.message()
        );
    }

    assert!(
        rec.lock().expect("recorded").create_credential.is_empty(),
        "a refused request must mint nothing: the check runs before the token is \
         minted, so no credential row exists for a call that answered an error"
    );
}

/// The other side of the same bound, because a refusal alone pins nothing.
///
/// `MAX_EXPIRES_IN_SECONDS + 1` refused while `MAX_EXPIRES_IN_SECONDS` is
/// granted is what makes the constant the actual bound. Without this case an
/// off-by-one, or a check that refused every non-zero expiry, passes the test
/// above.
#[tokio::test]
async fn issue_credential_grants_the_longest_life_the_bound_allows() {
    let (iam, rec, _inv) = iam_with(FakeDb::default()).await;

    let before = SystemTime::now();
    iam.issue_credential(Request::new(IssueCredentialRequest {
        user_id: "yadgar:user:1".into(),
        expires_in_seconds: MAX_EXPIRES_IN_SECONDS,
        ..Default::default()
    }))
    .await
    .expect("the longest life this service grants is a life it grants");

    let deadline = rec.lock().expect("recorded").create_credential[0]
        .expires_at
        .expect("the deadline the caller asked for")
        .seconds;

    let asked = before
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("after the epoch")
        .as_secs() as i64
        + MAX_EXPIRES_IN_SECONDS;
    assert!(
        (asked..asked + 60).contains(&deadline),
        "the store was told {deadline} and the caller asked for about {asked}"
    );
}

// ---------------------------------------------------------------------------
// The `label`: one bound, in the unit the column measures, on all three paths.
// ---------------------------------------------------------------------------

/// 255 of a codepoint utf8mb4 encodes in FOUR bytes.
///
/// 1020 bytes and 255 characters, which is the pair that separates a byte bound
/// from a character one. `iam_credential.label` accepts this row, and the
/// `MAX_LABEL_BYTES = 256` this change deletes refused the request that would
/// write it.
fn wide_label(chars: usize) -> String {
    "\u{1F600}".repeat(chars)
}

/// Drive `Login` with `label`, on a twin that would issue the credential.
async fn login_with_label(label: &str) -> (Result<(), Status>, Arc<Mutex<Recorded>>) {
    let (iam, rec, _inv) = iam_with(FakeDb {
        password: known_user("pw"),
        ..Default::default()
    })
    .await;
    let mut req = login("ada", "pw");
    req.get_mut().label = label.into();
    let answered = iam.login(req).await.map(|_| ());
    (answered, rec)
}

/// Drive `RedeemEnrolment` with `label`, on a twin that would redeem the secret.
async fn redeem_with_label(label: &str) -> (Result<(), Status>, Arc<Mutex<Recorded>>) {
    let (iam, rec, _inv) = iam_with(FakeDb {
        redeem: redeemed("ada"),
        password: known_user("chosen one"),
        ..Default::default()
    })
    .await;
    let mut req = redeem("s3cret", "chosen one", "k1");
    req.get_mut().label = label.into();
    let answered = iam.redeem_enrolment(req).await.map(|_| ());
    (answered, rec)
}

/// Drive `IssueCredential` with `label`.
async fn issue_credential_with_label(label: &str) -> (Result<(), Status>, Arc<Mutex<Recorded>>) {
    let (iam, rec, _inv) = iam_with(FakeDb::default()).await;
    let answered = iam
        .issue_credential(Request::new(IssueCredentialRequest {
            user_id: "yadgar:user:1".into(),
            label: label.into(),
            ..Default::default()
        }))
        .await
        .map(|_| ());
    (answered, rec)
}

/// The last label `iam_credential.label` accepts is a label this service grants.
///
/// **MEASURED, NOT ASSUMED.** Against `mariadb:11.8.9` at its stock `sql_mode`,
/// with the column exactly as `iam-db/src/schema.rs` declares it — `label
/// VARCHAR(255) NOT NULL DEFAULT ''` on `ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`
/// — a 255-character label stores and a 256-character one is refused with `ERROR
/// 1406 Data too long for column 'label'`. That holds for ASCII and for a
/// four-byte codepoint alike: `VARCHAR(255)` in utf8mb4 bounds CHARACTERS.
#[tokio::test]
async fn the_last_label_the_column_stores_is_one_every_path_accepts() {
    let at_the_bound = "l".repeat(255);

    for (rpc, (answered, rec)) in [
        ("Login", login_with_label(&at_the_bound).await),
        ("RedeemEnrolment", redeem_with_label(&at_the_bound).await),
        (
            "IssueCredential",
            issue_credential_with_label(&at_the_bound).await,
        ),
    ] {
        answered.unwrap_or_else(|e| {
            panic!("{rpc}: the longest label the column stores must be granted, got {e:?}")
        });
        // AND IT REACHED THE STORE UNCHANGED. A bound that silently TRUNCATED
        // would satisfy the line above while writing a label nobody named.
        let stored = rec.lock().expect("recorded").create_credential[0]
            .label
            .clone();
        assert_eq!(
            stored, at_the_bound,
            "{rpc}: the label must reach the store whole, never clipped to fit"
        );
    }
}

/// The first label the column refuses is one every path refuses FIRST.
///
/// **THIS IS THE LOCKOUT, and only on `RedeemEnrolment` is it permanent.** That
/// handler SPENDS the enrolment secret at the store before it builds the
/// credential, so a label the column will not take passed validation, spent the
/// secret, and then failed the INSERT — which `iam-db` renders as `UNAVAILABLE
/// "storage unavailable"` for every engine error. The person holds no
/// credential, the answer blames a database that is working, and the retry
/// presents a spent secret. Refusing here is what makes the request never reach
/// the point of no return.
#[tokio::test]
async fn the_first_label_the_column_refuses_is_refused_before_anything_is_spent() {
    let past_the_bound = "l".repeat(256);

    for (rpc, (answered, rec)) in [
        ("Login", login_with_label(&past_the_bound).await),
        ("RedeemEnrolment", redeem_with_label(&past_the_bound).await),
        (
            "IssueCredential",
            issue_credential_with_label(&past_the_bound).await,
        ),
    ] {
        let err = answered.expect_err(rpc);

        // THE CODE, because it is what tells the caller whose mistake this is.
        // `UNAVAILABLE` — which is what the store's refusal arrives as — says
        // the service is broken and invites a retry that cannot succeed.
        assert_eq!(err.code(), tonic::Code::InvalidArgument, "{rpc}");
        // AND THE FIELD BY NAME (ADR-0512). A refusal that does not say which
        // field is wrong leaves the caller to guess, and this is the only place
        // that knows.
        assert!(
            err.message().contains("label"),
            "{rpc}: the refusal must name the field, got {:?}",
            err.message()
        );

        let seen = rec.lock().expect("recorded");
        assert!(
            seen.create_credential.is_empty(),
            "{rpc}: a refused request must mint nothing"
        );
        assert!(
            seen.redeem_enrolment.is_empty(),
            "{rpc}: the refusal must precede the spend — a check answerable from \
             the request alone that runs after the secret is gone is the lockout \
             itself"
        );
    }
}

/// A label the column accepts is not refused for the bytes it happens to occupy.
///
/// **THIS IS THE CASE A BYTE BOUND GETS WRONG, and it is the reason the fix is
/// not a smaller number in the same unit.** 255 four-byte codepoints is 1020
/// bytes; the column stores it, measured, and `MAX_LABEL_BYTES = 256` refused
/// it. So did every shorter multibyte label past 64 characters: 100 of the same
/// codepoint is 400 bytes, stores fine, and was refused.
///
/// **EVERY LABEL FIXTURE IN THIS FILE IS A TYPED LITERAL, never
/// `MAX_LABEL_CHARS`, and that is deliberate.** A bound test written against its
/// own constant pins the relationship and never the number. Measured on this
/// branch: with the fixtures written as `repeat(MAX_LABEL_CHARS)`, the whole
/// label suite passes green with the constant set to 254, to 300, and to **256**
/// — which is the exact defect this change exists to close, and the number every
/// historical doc comment here still carries. The literal is the only evidence
/// in the suite that the implementation could not supply. Re-measure the column
/// before changing it. Do not tidy it back into the constant.
#[tokio::test]
async fn a_multibyte_label_the_column_stores_is_not_refused_for_its_byte_length() {
    for label in [wide_label(255), wide_label(100)] {
        assert!(
            label.len() > 256,
            "the fixture must exceed the old byte bound or it proves nothing: \
             {} bytes",
            label.len()
        );

        for (rpc, (answered, rec)) in [
            ("Login", login_with_label(&label).await),
            ("RedeemEnrolment", redeem_with_label(&label).await),
            ("IssueCredential", issue_credential_with_label(&label).await),
        ] {
            answered.unwrap_or_else(|e| {
                panic!(
                    "{rpc}: {} characters is {} bytes, and the column stores it: {e:?}",
                    label.chars().count(),
                    label.len()
                )
            });
            assert_eq!(
                rec.lock().expect("recorded").create_credential[0].label,
                label,
                "{rpc}: the label must reach the store whole"
            );
        }
    }
}

/// An EMPTY label stays accepted, on every path.
///
/// **THE DOCUMENTED SENTINEL, pinned so a future editor's `is_empty()` guard
/// fails a test rather than the contract.** `iam.proto` describes this field as
/// free text and requires nothing of it, and the column's `DEFAULT ''` says the
/// same. A bound is not a requirement.
#[tokio::test]
async fn an_empty_label_is_accepted_because_the_contract_requires_nothing_of_it() {
    for (rpc, (answered, rec)) in [
        ("Login", login_with_label("").await),
        ("RedeemEnrolment", redeem_with_label("").await),
        ("IssueCredential", issue_credential_with_label("").await),
    ] {
        answered.unwrap_or_else(|e| panic!("{rpc}: an empty label is legal, not a refusal: {e:?}"));
        assert_eq!(
            rec.lock().expect("recorded").create_credential[0].label,
            "",
            "{rpc}: the empty label travels rather than being substituted"
        );
    }
}

/// The `outcome` a label refusal records is one the SHARED MAPPING produces.
///
/// **ADR-0558: `yadgar_calls_total` has ONE `outcome` label space and this
/// binary writes into it by hand.** The assertion is membership in
/// `telemetry::grpc::status_name`'s range COMPUTED over every `tonic::Code`,
/// plus the literal — a test comparing only against `"INVALID_ARGUMENT"` goes
/// green for any invented value somebody also typed into the test.
///
/// **AND IT IS WHAT CATCHES A REFUSAL PATH WITH NO `call.fail` AT ALL.**
/// `Call::fail` takes `self` by value, so the compiler enforces that it precedes
/// the `Err` — but a path that never calls it compiles, and the dropped `Call`
/// records `UNRECORDED`. `Login` had no validation and therefore no `call.fail`
/// on this branch before this change, which is exactly the shape this test
/// exists to see.
#[test]
fn the_outcome_of_a_label_refusal_is_one_the_shared_mapping_produces() {
    // A LOCAL recorder rather than `metrics::set_global_recorder`: a global one
    // is process-wide and this crate runs its tests in parallel.
    let recorder = metrics_util::debugging::DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    // CURRENT-THREAD, and that is load-bearing: `with_local_recorder` installs a
    // THREAD-LOCAL, so work that resumed on another thread would record into
    // nothing and every assertion below would pass vacuously.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");

    metrics::with_local_recorder(&recorder, || {
        rt.block_on(async {
            let past_the_bound = "l".repeat(256);
            for (rpc, (answered, _rec)) in [
                ("Login", login_with_label(&past_the_bound).await),
                ("RedeemEnrolment", redeem_with_label(&past_the_bound).await),
                (
                    "IssueCredential",
                    issue_credential_with_label(&past_the_bound).await,
                ),
            ] {
                answered.expect_err(rpc);
            }
        });
    });

    let emitted = snapshotter.snapshot().into_vec();
    // LENGTH FIRST. A `metrics-util` resolving against another `metrics` major
    // links a SECOND facade; then this snapshot is empty and every assertion
    // built on it passes vacuously.
    assert!(
        !emitted.is_empty(),
        "the recorder saw no metric at all, which is what a second metrics \
         facade in the tree looks like"
    );

    let outcomes: Vec<String> = emitted
        .iter()
        .filter(|(key, _, _, _)| key.key().name() == yadgar_telemetry::metrics::CALLS)
        .flat_map(|(key, _, _, _)| {
            key.key()
                .labels()
                .filter(|l| l.key() == "outcome")
                .map(|l| l.value().to_string())
                .collect::<Vec<_>>()
        })
        .collect();
    assert_eq!(
        outcomes.len(),
        3,
        "three refused calls, three series — one per path that stores a label: \
         {emitted:?}"
    );

    // The mapping's whole range, derived rather than retyped. `Code::from_i32`
    // saturates to `Unknown` above the enum, so the sweep covers every code
    // tonic defines and the catch-all arm besides.
    let mapped: std::collections::BTreeSet<&'static str> = (0..32)
        .map(|i| {
            yadgar_telemetry::grpc::status_name(&tonic::Status::new(tonic::Code::from_i32(i), ""))
        })
        .collect();
    for outcome in &outcomes {
        assert!(
            mapped.contains(outcome.as_str()),
            "the outcome {outcome:?} is not a value \
             telemetry::grpc::status_name can produce; its range is {mapped:?}"
        );
        assert_eq!(
            outcome, "INVALID_ARGUMENT",
            "a label the caller sent that the column cannot store is the \
             caller's mistake, and UNRECORDED is what a missing call.fail looks \
             like"
        );
    }
}
