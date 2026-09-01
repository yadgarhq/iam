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

async fn iam_with(fake: FakeDb) -> (Iam, Arc<Mutex<Recorded>>, Invalidator) {
    iam_with_floor(fake, NOMINAL_FLOOR).await
}

async fn iam_with_floor(fake: FakeDb, floor: Duration) -> (Iam, Arc<Mutex<Recorded>>, Invalidator) {
    let (channel, recorded) = twin(fake).await;
    let invalidator = Invalidator::connect(None).await;
    let iam = Iam::new(
        crate::crypto::tests::keys(),
        channel,
        invalidator.clone(),
        floor,
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
        iam.hold_until_floor(work).await;
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

/// Just the floor's own warnings, so an unrelated one cannot pass for it.
fn floor_warnings() -> Vec<String> {
    warnings()
        .into_iter()
        .filter(|w| w.contains("response-time floor"))
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
