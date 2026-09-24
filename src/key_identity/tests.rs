//! Unit tests for [`super`], against a fake `IamDbService` scripted per call.
//!
//! A UNIT test module rather than `tests/`, for the reason
//! [`crate::service::tests`] gives: it reaches the private `Identity` fields and
//! the private [`super::Step`] classification, neither of which an integration
//! test can see. The twin is the REAL generated server half on a loopback port
//! and the client is the REAL generated client, so "this arm calls
//! `GetKeyIdentity` and that one calls `SetKeyIdentity`" is exercised rather
//! than assumed — a trait seam over the two calls would have left exactly that
//! wiring untested.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tonic::transport::{Channel, Endpoint};
use tonic::{Request, Response, Status};

use super::*;
use crate::pb::yadgar::iamdb::v1::iam_db_service_server::{IamDbService, IamDbServiceServer};

/// One scripted answer from the fake twin.
#[derive(Clone, Copy, Debug)]
enum Answer {
    /// An OK response carrying this RAW enum value.
    ///
    /// **RAW, AND THAT IS WHAT LETS A FUTURE MEMBER BE SCRIPTED.** A
    /// `KeyIdentityOutcome` could only ever carry a member this build knows, so
    /// the "a member added after this tag does not pass" case would be
    /// unreachable — and that case is the whole reason the rule is a whitelist.
    Outcome(i32),
    /// A non-OK status. Every one of them is not-passed.
    Failed(tonic::Code),
}

/// What the fake twin answers, in order. The LAST entry repeats for ever, so a
/// script of one value is a twin that always answers it.
#[derive(Default, Clone)]
struct Script {
    get: Vec<Answer>,
    set: Vec<Answer>,
}

/// What the fake twin was asked. The ONLY witness that separates "the check
/// passed" from "the check is still retrying": a passed check stops calling.
#[derive(Default)]
struct Asked {
    get: Vec<db::GetKeyIdentityRequest>,
    set: Vec<db::SetKeyIdentityRequest>,
}

struct FakeTwin {
    script: Script,
    asked: Arc<Mutex<Asked>>,
}

fn answer(script: &[Answer], n: usize) -> Answer {
    match script.is_empty() {
        true => Answer::Failed(tonic::Code::Unavailable),
        false => script[n.min(script.len() - 1)],
    }
}

#[tonic::async_trait]
impl IamDbService for FakeTwin {
    async fn get_key_identity(
        &self,
        r: Request<db::GetKeyIdentityRequest>,
    ) -> Result<Response<db::GetKeyIdentityResponse>, Status> {
        let n = {
            let mut asked = self.asked.lock().expect("asked");
            asked.get.push(r.into_inner());
            asked.get.len() - 1
        };
        match answer(&self.script.get, n) {
            Answer::Failed(code) => Err(Status::new(code, "scripted")),
            Answer::Outcome(outcome) => Ok(Response::new(db::GetKeyIdentityResponse { outcome })),
        }
    }

    async fn set_key_identity(
        &self,
        r: Request<db::SetKeyIdentityRequest>,
    ) -> Result<Response<db::SetKeyIdentityResponse>, Status> {
        let n = {
            let mut asked = self.asked.lock().expect("asked");
            asked.set.push(r.into_inner());
            asked.set.len() - 1
        };
        match answer(&self.script.set, n) {
            Answer::Failed(code) => Err(Status::new(code, "scripted")),
            Answer::Outcome(outcome) => Ok(Response::new(db::SetKeyIdentityResponse { outcome })),
        }
    }

    // THE FOURTEEN ARMS THE KEY-IDENTITY CHECK NEVER REACHES. Written out
    // rather than generated: `#[tonic::async_trait]` rewrites the `async fn`s it
    // can SEE, and a macro invocation inside the impl is expanded after it has
    // already run — measured, as fourteen E0195 lifetime mismatches.
    //
    // `unimplemented!` rather than a benign `Ok(Default::default())`: this fake
    // exists to answer two RPCs, and a check that reached a third would be a
    // defect this module should fail loudly on rather than absorb.

    async fn resolve_credential(
        &self,
        _r: Request<db::ResolveCredentialRequest>,
    ) -> Result<Response<db::ResolveCredentialResponse>, Status> {
        unimplemented!("the key-identity check never calls this arm")
    }

    async fn get_password_hash(
        &self,
        _r: Request<db::GetPasswordHashRequest>,
    ) -> Result<Response<db::GetPasswordHashResponse>, Status> {
        unimplemented!("the key-identity check never calls this arm")
    }

    async fn set_password(
        &self,
        _r: Request<db::SetPasswordRequest>,
    ) -> Result<Response<db::SetPasswordResponse>, Status> {
        unimplemented!("the key-identity check never calls this arm")
    }

    async fn create_enrolment(
        &self,
        _r: Request<db::CreateEnrolmentRequest>,
    ) -> Result<Response<db::CreateEnrolmentResponse>, Status> {
        unimplemented!("the key-identity check never calls this arm")
    }

    async fn redeem_enrolment(
        &self,
        _r: Request<db::RedeemEnrolmentRequest>,
    ) -> Result<Response<db::RedeemEnrolmentResponse>, Status> {
        unimplemented!("the key-identity check never calls this arm")
    }

    async fn create_credential(
        &self,
        _r: Request<db::CreateCredentialRequest>,
    ) -> Result<Response<db::CreateCredentialResponse>, Status> {
        unimplemented!("the key-identity check never calls this arm")
    }

    async fn revoke_credential(
        &self,
        _r: Request<db::RevokeCredentialRequest>,
    ) -> Result<Response<db::RevokeCredentialResponse>, Status> {
        unimplemented!("the key-identity check never calls this arm")
    }

    async fn list_credentials(
        &self,
        _r: Request<db::ListCredentialsRequest>,
    ) -> Result<Response<db::ListCredentialsResponse>, Status> {
        unimplemented!("the key-identity check never calls this arm")
    }

    async fn create_user(
        &self,
        _r: Request<db::CreateUserRequest>,
    ) -> Result<Response<db::CreateUserResponse>, Status> {
        unimplemented!("the key-identity check never calls this arm")
    }

    async fn set_user_admin(
        &self,
        _r: Request<db::SetUserAdminRequest>,
    ) -> Result<Response<db::SetUserAdminResponse>, Status> {
        unimplemented!("the key-identity check never calls this arm")
    }

    async fn set_rate_limit_override(
        &self,
        _r: Request<db::SetRateLimitOverrideRequest>,
    ) -> Result<Response<db::SetRateLimitOverrideResponse>, Status> {
        unimplemented!("the key-identity check never calls this arm")
    }

    async fn add_team_member(
        &self,
        _r: Request<db::AddTeamMemberRequest>,
    ) -> Result<Response<db::AddTeamMemberResponse>, Status> {
        unimplemented!("the key-identity check never calls this arm")
    }

    async fn remove_team_member(
        &self,
        _r: Request<db::RemoveTeamMemberRequest>,
    ) -> Result<Response<db::RemoveTeamMemberResponse>, Status> {
        unimplemented!("the key-identity check never calls this arm")
    }

    async fn set_inherited_setting(
        &self,
        _r: Request<db::SetInheritedSettingRequest>,
    ) -> Result<Response<db::SetInheritedSettingResponse>, Status> {
        unimplemented!("the key-identity check never calls this arm")
    }
}

/// A port nothing is listening on, learned rather than guessed.
fn free_port() -> std::net::SocketAddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("addr");
    drop(l);
    addr
}

/// Serve `script`, and return a client to it plus the log of what it was asked.
async fn twin(script: Script) -> (IamDbServiceClient<Channel>, Arc<Mutex<Asked>>) {
    let (channel, asked) = twin_channel(script).await;
    (IamDbServiceClient::new(channel), asked)
}

/// The same twin, as the raw [`Channel`] `main` holds.
///
/// [`Check::new`] takes the channel rather than a client, because that is what
/// `main` has — so the test that proves the wiring has to start from the same
/// value `main` starts from, or it is not testing the wiring.
async fn twin_channel(script: Script) -> (Channel, Arc<Mutex<Asked>>) {
    let asked = Arc::new(Mutex::new(Asked::default()));
    let fake = FakeTwin {
        script,
        asked: asked.clone(),
    };
    let addr = free_port();
    tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(IamDbServiceServer::new(fake))
            .serve(addr)
            .await;
    });

    // Poll for the listener rather than sleeping a guessed interval, which on a
    // loaded machine is both slow and flaky.
    for _ in 0..500 {
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
    (channel, asked)
}

/// Retries fast enough that "it kept retrying" is measurable inside [`WINDOW`].
///
/// A check that has PASSED stops calling, so a call count well above one is the
/// discriminator, and it needs many retries to fit in the window. The production
/// cadence would fit one.
fn brisk() -> Retry {
    Retry::of(Duration::from_millis(2), Duration::from_millis(8))
}

/// How long a "this never resolves" assertion waits before believing it.
const WINDOW: Duration = Duration::from_millis(400);

fn identity() -> Identity {
    Identity::of(&crate::crypto::tests::keys())
}

/// Every member this build knows, as the raw value that travels.
fn raw(outcome: db::KeyIdentityOutcome) -> i32 {
    outcome as i32
}

// ---------------------------------------------------------------------------
// THE TWO CASES THE PLAN NAMES
// ---------------------------------------------------------------------------

/// **WRONG KEY REFUSES.** Both halves of the claim, because neither alone is it.
///
/// THE ASSERTIONS THAT REDDEN. Inverting the identity comparison, or reading
/// MISMATCH as anything but a refusal, reddens `refusal.is_ok()` — the watch
/// would never resolve and the timeout would elapse. Making the process exit 0
/// on a refusal reddens `into_exit().is_err()`: `Ended::into_exit` is the ONLY
/// thing that turns the refusal into a non-zero exit, and `main` has no other
/// path to one.
#[tokio::test]
async fn a_wrong_key_ends_the_serve_and_exits_non_zero() {
    let (client, asked) = twin(Script {
        get: vec![Answer::Outcome(raw(db::KeyIdentityOutcome::Mismatch))],
        ..Default::default()
    })
    .await;

    let refusal = tokio::time::timeout(WINDOW, watch(client, identity(), brisk())).await;
    let refusal = refusal.expect("a MISMATCH ends the serve rather than being retried");

    // THE SERVE ENDS: `until_stopped` reaches this arm and reports it as the
    // key-identity refusal rather than as an ordinary stop.
    let ended = until_stopped(
        std::future::pending(),
        std::future::pending(),
        std::future::ready(refusal),
    )
    .await;
    assert!(matches!(ended, Ended::KeyIdentityRefused(_)));

    // AND THE PROCESS EXITS NON-ZERO: `main` returns this `Err`, which is exit 1.
    assert!(
        ended.into_exit(false).is_err(),
        "a mismatch must not end the process successfully"
    );

    // NOTHING WAS WRITTEN. A pod holding the wrong key must not record its own
    // fingerprint, and the store's write-once rule is not this service's excuse
    // for trying.
    assert!(asked.lock().expect("asked").set.is_empty());
}

/// **THE EMPTY-DATABASE BOUNDARY.** First boot RECORDS and then PASSES.
///
/// Getting this wrong bricks every fresh install, in one of two directions: a
/// check that never records leaves the gate permanently unpassed, and a check
/// that records but does not treat RECORDED as a pass does the same.
///
/// THE ASSERTIONS THAT REDDEN. Dropping the ABSENT arm, so nothing is recorded,
/// reddens `set.len(), 1`. Dropping RECORDED from the passing whitelist reddens
/// `get.len(), 1` — an unpassed check keeps calling, and at [`brisk`]'s cadence
/// [`WINDOW`] holds scores of retries. The payload assertions redden if the pair
/// sent to record is not the pair that was asked about.
#[tokio::test]
async fn an_empty_store_is_recorded_and_then_passes() {
    let (client, asked) = twin(Script {
        get: vec![Answer::Outcome(raw(db::KeyIdentityOutcome::Absent))],
        set: vec![Answer::Outcome(raw(db::KeyIdentityOutcome::Recorded))],
    })
    .await;
    let id = identity();

    let outcome = tokio::time::timeout(WINDOW, watch(client, id.clone(), brisk())).await;
    assert!(
        outcome.is_err(),
        "a passed check never resolves, so it never ends the serve"
    );

    let asked = asked.lock().expect("asked");
    assert_eq!(asked.get.len(), 1, "a passed check stops calling");
    assert_eq!(
        asked.set.len(),
        1,
        "an absent marker is recorded exactly once"
    );
    assert_eq!(asked.set[0].key_fingerprint, id.fingerprint());
    assert_eq!(asked.set[0].derivation_version, DERIVATION_VERSION);
    assert_eq!(
        asked.set[0].idempotency.as_ref().expect("D9's key").key,
        id.idempotency_key()
    );
}

// ---------------------------------------------------------------------------
// THE WHITELIST: PASS ONLY ON AN EXPLICITLY POSITIVE MEMBER
// ---------------------------------------------------------------------------

/// A helper for every "this does not pass and does not exit" case.
///
/// Returns how many times the twin was asked. A check that passed stops asking,
/// so a count above one is the whole oracle.
async fn never_passes_and_never_exits(script: Script) -> Asked {
    let (client, asked) = twin(script).await;
    let outcome = tokio::time::timeout(WINDOW, watch(client, identity(), brisk())).await;
    assert!(
        outcome.is_err(),
        "this must not end the serve: it is not a MISMATCH"
    );
    Arc::try_unwrap(asked)
        .map(|m| m.into_inner().expect("asked"))
        .unwrap_or_else(|m| std::mem::take(&mut *m.lock().expect("asked")))
}

/// UNSPECIFIED is what a response that populated nothing carries, and it is the
/// zero value every proto3 enum field defaults to.
///
/// THE ASSERTION THAT REDDENS if the rule becomes "anything but MISMATCH
/// passes": `retried > 1`. Under that mutation the check passes on the first
/// call and never asks again.
#[tokio::test]
async fn the_zero_value_never_passes() {
    let asked = never_passes_and_never_exits(Script {
        get: vec![Answer::Outcome(raw(db::KeyIdentityOutcome::Unspecified))],
        ..Default::default()
    })
    .await;
    assert!(asked.get.len() > 1, "an unpassed check keeps asking");
    assert!(
        asked.set.is_empty(),
        "nothing about it says the store is empty"
    );

    // AND AN OPERATOR IS TOLD. All three things `UNREADABLE` covers are a
    // version disagreement between the two binaries, and a deploy is what mends
    // every one of them — `UNIMPLEMENTED`'s case exactly. THE ASSERTION THAT
    // REDDENS if it is classified transient again, which warns for ever.
    assert!(
        Unverified::UNREADABLE.is_permanent(),
        "an outcome this build cannot read needs a deploy, not a retry"
    );
}

/// A member added after this tag. It cannot be named here, which is the point —
/// it is scripted as the raw value a later contract would put on the wire.
///
/// THE ASSERTION THAT REDDENS under a blacklist of MISMATCH: `get.len() > 1`.
#[tokio::test]
async fn a_member_this_build_does_not_know_never_passes() {
    let asked = never_passes_and_never_exits(Script {
        get: vec![Answer::Outcome(97)],
        ..Default::default()
    })
    .await;
    assert!(asked.get.len() > 1, "an unpassed check keeps asking");
}

/// RECORDED is documented as never sent by the READ arm, which writes nothing.
/// A twin that sends it there has contradicted its own contract, and a gate does
/// not pass on a claim from a peer that just broke the rule the claim rests on.
///
/// THE ASSERTION THAT REDDENS if the whitelist is applied to the two arms
/// jointly rather than per arm: `get.len() > 1`.
#[tokio::test]
async fn recorded_from_the_read_arm_never_passes() {
    let asked = never_passes_and_never_exits(Script {
        get: vec![Answer::Outcome(raw(db::KeyIdentityOutcome::Recorded))],
        ..Default::default()
    })
    .await;
    assert!(asked.get.len() > 1, "an unpassed check keeps asking");
}

/// MATCH passes, and that is the ordinary steady state of every pod after the
/// first. Stated as its own test because every assertion above is about NOT
/// passing, and a check that could never pass would satisfy all of them.
#[tokio::test]
async fn a_matching_marker_passes_and_writes_nothing() {
    let (client, asked) = twin(Script {
        get: vec![Answer::Outcome(raw(db::KeyIdentityOutcome::Match))],
        ..Default::default()
    })
    .await;
    let outcome = tokio::time::timeout(WINDOW, watch(client, identity(), brisk())).await;
    assert!(outcome.is_err(), "a passed check never ends the serve");
    let asked = asked.lock().expect("asked");
    assert_eq!(asked.get.len(), 1, "a passed check stops calling");
    assert!(asked.set.is_empty(), "a MATCH has nothing to record");
}

// ---------------------------------------------------------------------------
// THE TRANSPORT AND THE FIFTH MEMBER
// ---------------------------------------------------------------------------

/// An UNAVAILABLE twin retries for ever and NEVER PASSES. Both halves.
///
/// THE ASSERTIONS THAT REDDEN. Passing when the twin cannot be reached — the
/// "gate that skips itself under load" ADR-0764 rejects by name — reddens
/// `get.len() > 1`. Exiting on it reddens `outcome.is_err()` inside the helper.
#[tokio::test]
async fn an_unavailable_twin_retries_for_ever_and_never_passes() {
    let asked = never_passes_and_never_exits(Script {
        get: vec![Answer::Failed(tonic::Code::Unavailable)],
        ..Default::default()
    })
    .await;
    assert!(asked.get.len() > 1, "a transient fault is retried");
    assert!(
        !Unverified::of_status(tonic::Code::Unavailable).is_permanent(),
        "UNAVAILABLE is the transient case"
    );
}

/// DERIVATION_SKEW is NOT-PASSED and NOT-EXITING, and nothing is written.
///
/// THE ASSERTIONS THAT REDDEN. Making a skew exit reddens `outcome.is_err()`
/// inside the helper — the watch would resolve and the timeout would not
/// elapse. Making it pass reddens `get.len() > 1`. Treating it as ABSENT, which
/// the contract names as the worst of the three misreadings, reddens
/// `set.is_empty()`. Demoting it from permanent reddens `is_permanent()`, which
/// is what routes it to an operator rather than only to a retry counter.
#[tokio::test]
async fn a_derivation_skew_neither_passes_nor_exits_and_writes_nothing() {
    let asked = never_passes_and_never_exits(Script {
        get: vec![Answer::Outcome(raw(db::KeyIdentityOutcome::DerivationSkew))],
        ..Default::default()
    })
    .await;
    assert!(asked.get.len() > 1, "a skew is not a pass");
    assert!(
        asked.set.is_empty(),
        "a skew is not an absent marker; recording one would earn the store a second"
    );
    assert!(
        Unverified::SKEW.is_permanent(),
        "no retry mends a skew, so it must reach an operator"
    );
}

/// A skew met on the RECORDING arm is the split rollout the contract describes,
/// and it must not exit the loser.
#[tokio::test]
async fn a_skew_on_the_recording_arm_neither_passes_nor_exits() {
    let asked = never_passes_and_never_exits(Script {
        get: vec![Answer::Outcome(raw(db::KeyIdentityOutcome::Absent))],
        set: vec![Answer::Outcome(raw(db::KeyIdentityOutcome::DerivationSkew))],
    })
    .await;
    assert!(asked.set.len() > 1, "a skew on the write arm is not a pass");
}

/// A MISMATCH met on the RECORDING arm is the split rollout's loser under ONE
/// version, and it is as permanent as one met on the read.
#[tokio::test]
async fn a_mismatch_on_the_recording_arm_ends_the_serve() {
    let (client, _asked) = twin(Script {
        get: vec![Answer::Outcome(raw(db::KeyIdentityOutcome::Absent))],
        set: vec![Answer::Outcome(raw(db::KeyIdentityOutcome::Mismatch))],
    })
    .await;
    let refusal = tokio::time::timeout(WINDOW, watch(client, identity(), brisk())).await;
    assert!(
        refusal.is_ok(),
        "losing a split rollout under one version is still a wrong key"
    );
}

/// A MATCH met on the RECORDING arm passes: somebody else wrote the marker
/// between this pod's read and its write, and it agrees.
#[tokio::test]
async fn a_match_on_the_recording_arm_passes() {
    let (client, asked) = twin(Script {
        get: vec![Answer::Outcome(raw(db::KeyIdentityOutcome::Absent))],
        set: vec![Answer::Outcome(raw(db::KeyIdentityOutcome::Match))],
    })
    .await;
    let outcome = tokio::time::timeout(WINDOW, watch(client, identity(), brisk())).await;
    assert!(outcome.is_err(), "a passed check never ends the serve");
    assert_eq!(asked.lock().expect("asked").set.len(), 1);
}

/// EVERY non-OK status is not-passed, and the PERMANENT ones are told apart from
/// the transient so they can reach an operator.
///
/// UNIMPLEMENTED is an `iam-db` deployed from a tag that predates this arm.
/// FAILED_PRECONDITION is a populated store with no marker. INVALID_ARGUMENT is
/// a request this build should never have sent. Retrying any of them for ever is
/// safe and is NOT sufficient: the pod stays Ready, serving and unverified.
///
/// THE ASSERTION THAT REDDENS if a permanent status is classified transient:
/// `is_permanent()` on that code.
#[tokio::test]
async fn every_non_ok_status_is_not_passed_and_the_permanent_ones_are_named() {
    for code in [
        tonic::Code::Unimplemented,
        tonic::Code::FailedPrecondition,
        tonic::Code::InvalidArgument,
    ] {
        let asked = never_passes_and_never_exits(Script {
            get: vec![Answer::Failed(code)],
            ..Default::default()
        })
        .await;
        assert!(
            asked.get.len() > 1,
            "{code:?} is retried rather than passed"
        );
        assert!(
            Unverified::of_status(code).is_permanent(),
            "{code:?} cannot be mended by a retry, so an operator must be told"
        );
    }
}

// ---------------------------------------------------------------------------
// THE TWO OBLIGATIONS THE REVIEW OF PR 2 FOUND
// ---------------------------------------------------------------------------

/// **D9 BEATS DERIVATION_SKEW WHEN A KEY IS REUSED ACROSS A DERIVATION BUMP**,
/// so the key must not be stable across one.
///
/// `iam-db`'s `replayed_or_compared` checks the idempotency key FIRST: a call
/// replaying a stored key under a different `derivation_version` is answered
/// INVALID_ARGUMENT, not DERIVATION_SKEW — on exactly the migration ADR-0765
/// exists to make survivable. Two defences, and this asserts both.
///
/// THE ASSERTIONS THAT REDDEN. Deriving the key from anything stable — a pod
/// name, an installation id, a constant — reddens `a != b`. Dropping the
/// version from the key reddens the two `contains` assertions.
#[test]
fn the_idempotency_key_is_fresh_and_carries_the_derivation_version() {
    let keys = crate::crypto::tests::keys();
    let a = Identity::of(&keys);
    let b = Identity::of(&keys);
    assert_ne!(
        a.idempotency_key(),
        b.idempotency_key(),
        "a key stable across a derivation bump is answered INVALID_ARGUMENT"
    );
    let marker = format!("v{DERIVATION_VERSION}");
    assert!(a.idempotency_key().contains(&marker));
    assert!(b.idempotency_key().contains(&marker));
}

/// **THE RETRY CARRIES JITTER.** Replicas that started in the same second must
/// not retry in lockstep: three or more concurrent recorders is the shape that
/// deadlocked `iam-db` on PR 2.
///
/// THE ASSERTION THAT REDDENS if the wait becomes a bare fixed interval:
/// `waits.len() > 1` — every seed would draw the same value. Asserting merely
/// that a wait happened would survive that mutation, which is why it is not the
/// assertion here.
#[test]
fn two_pods_do_not_retry_in_lockstep() {
    let retry = Retry::of(Duration::from_secs(1), Duration::from_secs(60));
    let waits: std::collections::BTreeSet<Duration> = (0..16)
        .map(|seed| retry.wait(3, seed * (u64::MAX / 16)))
        .collect();
    assert!(
        waits.len() > 1,
        "sixteen pods drew the same wait, so the retry has no jitter"
    );
}

/// The jitter has a FLOOR, and full jitter is what the floor rules out.
///
/// A wait drawn uniformly from `[0, backoff]` puts a near-zero draw on the
/// table, and a pod that answers an UNAVAILABLE twin by calling again at once is
/// a retry loop with no backoff in it at all. Half the backoff is guaranteed and
/// the other half is drawn.
///
/// THE ASSERTION THAT REDDENS under full jitter: the lower bound, which a seed
/// of 0 would violate.
#[test]
fn the_jitter_never_drops_the_wait_below_half_the_backoff() {
    let retry = Retry::of(Duration::from_secs(1), Duration::from_secs(60));
    for attempt in 0..12 {
        for seed in [0, 1, u64::MAX / 3, u64::MAX / 2, u64::MAX] {
            let waited = retry.wait(attempt, seed);
            let backoff = retry.backoff(attempt);
            assert!(waited >= backoff / 2, "{attempt}/{seed} had no floor");
            assert!(waited <= backoff, "{attempt}/{seed} overshot its backoff");
        }
    }
}

/// The backoff grows and then stops at the cap, so a twin that is down for a day
/// is asked once a minute rather than once a fortnight.
#[test]
fn the_backoff_is_bounded_by_its_cap() {
    let retry = Retry::of(Duration::from_secs(1), Duration::from_secs(60));
    assert_eq!(retry.backoff(0), Duration::from_secs(1));
    assert_eq!(retry.backoff(1), Duration::from_secs(2));
    assert!(retry.backoff(6) > retry.backoff(5));
    for attempt in 6..4096 {
        assert!(retry.backoff(attempt) <= Duration::from_secs(60));
    }
    assert_eq!(retry.backoff(4095), Duration::from_secs(60));
}

// ---------------------------------------------------------------------------
// WHAT AN OPERATOR IS TOLD, AND WHAT ENDS THE SERVE
// ---------------------------------------------------------------------------

/// A permanent fault is RE-STATED on a bounded cadence rather than once.
///
/// Reporting a permanent fault once and then retrying quietly rebuilds the
/// "indefinitely and silently" state the whole arm exists to delete: the pod
/// stays Ready, serving and unverified, and the one line that said so has
/// scrolled away.
///
/// THE ASSERTIONS THAT REDDEN. A report that fires only the first time reddens
/// `restate(Some(RESTATE_AFTER))`. A report on every attempt reddens the
/// `!restate` pair. A changed reason that waits out the interval reddens
/// `restate(None)`.
#[test]
fn a_standing_fault_is_restated_rather_than_reported_once() {
    assert!(
        restate(None),
        "a new or changed reason is always reported at once"
    );
    assert!(!restate(Some(Duration::ZERO)));
    assert!(!restate(Some(RESTATE_AFTER - Duration::from_secs(1))));
    assert!(
        restate(Some(RESTATE_AFTER)),
        "a standing fault is re-stated"
    );
    assert!(restate(Some(RESTATE_AFTER * 7)));
}

/// **AND IT REACHES THE OPERATOR IN MINUTES AT THE SHIPPED BACKOFF**, which is
/// the property the cadence exists for and is NOT the same claim as the
/// arithmetic above.
///
/// This replays the loop's own accumulation against [`Retry::standard`]. THE
/// ASSERTION THAT REDDENS if the cadence is ever keyed on an attempt COUNT
/// again: `worst`. Measured under "one line in every twenty attempts", which
/// was this module's first shape, the gap between two lines about a fault no
/// retry mends was about eleven minutes, because the backoff saturates at a
/// minute long before the twentieth attempt — the counter and the wall clock
/// stop agreeing exactly where it matters.
#[test]
fn a_permanent_fault_reaches_an_operator_within_minutes() {
    let retry = Retry::standard();
    let mut since = Duration::ZERO;
    let mut gaps: Vec<Duration> = Vec::new();
    for attempt in 0..600u32 {
        since += retry.wait(attempt, 0x5eed_5eed_5eed_5eed);
        if restate(Some(since)) {
            gaps.push(since);
            since = Duration::ZERO;
        }
    }
    assert!(gaps.len() > 20, "an operator is told repeatedly, not once");
    let worst = gaps.into_iter().max().expect("at least one line");
    assert!(
        worst <= RESTATE_AFTER + Duration::from_secs(60),
        "an operator waited {worst:?} between two lines about a fault no retry mends"
    );
}

/// An ordinary stop — a signal, or a rotation — exits zero, and the key-identity
/// arm is the ONLY one that does not.
///
/// THE ASSERTION THAT REDDENS if the refusal is folded into the ordinary arm:
/// the `is_err()` in `a_wrong_key_ends_the_serve_and_exits_non_zero`. THE ONE
/// THAT REDDENS if an ordinary stop starts failing: `is_ok()` here, which is
/// what keeps a rollout from turning into a CrashLoopBackOff.
#[tokio::test]
async fn a_signal_and_a_rotation_both_exit_zero() {
    let by_signal = until_stopped(
        std::future::ready(()),
        std::future::pending(),
        std::future::pending(),
    )
    .await;
    assert!(matches!(by_signal, Ended::Ordinary));
    assert!(by_signal.into_exit(false).is_ok());

    let by_rotation = until_stopped(
        std::future::pending(),
        std::future::ready(()),
        std::future::pending(),
    )
    .await;
    assert!(matches!(by_rotation, Ended::Ordinary));
    assert!(by_rotation.into_exit(true).is_ok());
}

/// The fingerprint covers BOTH keys, and the domain string carries the version.
///
/// THE ASSERTIONS THAT REDDEN. Dropping either key from the derivation reddens
/// the corresponding `assert_ne!` — the fingerprint would stop moving when that
/// key changed, and a pod holding half the right key set would pass. Bumping
/// [`DERIVATION_VERSION`] without changing the domain string reddens
/// `ends_with`, which is what makes a bump produce different bytes even against
/// a server that ignored the version.
#[test]
fn the_fingerprint_covers_both_keys_and_the_domain_names_the_version() {
    let base = crate::crypto::tests::keys_of([7u8; 32], [9u8; 32]);
    let other_encryption = crate::crypto::tests::keys_of([8u8; 32], [9u8; 32]);
    let other_blind_index = crate::crypto::tests::keys_of([7u8; 32], [1u8; 32]);

    assert_ne!(
        Identity::of(&base).fingerprint(),
        Identity::of(&other_encryption).fingerprint()
    );
    assert_ne!(
        Identity::of(&base).fingerprint(),
        Identity::of(&other_blind_index).fingerprint()
    );
    assert_eq!(
        Identity::of(&base).fingerprint(),
        Identity::of(&crate::crypto::tests::keys_of([7u8; 32], [9u8; 32])).fingerprint(),
        "the same key set derives the same fingerprint, or no pod ever passes twice"
    );
    assert!(DOMAIN.ends_with(&format!("v{DERIVATION_VERSION}")));
}

/// The fingerprint is never the key, and never a value already on the wire.
///
/// A marker that WAS the key would put the key in the database the keys
/// deliberately do not live in; one that equalled a blind index would let a
/// stolen store confirm a guess about a username against the marker column.
#[test]
fn the_fingerprint_is_neither_the_key_nor_a_blind_index() {
    let keys = crate::crypto::tests::keys_of([7u8; 32], [9u8; 32]);
    let fingerprint = Identity::of(&keys).fingerprint();
    assert_eq!(fingerprint.len(), 32);
    assert_ne!(fingerprint, vec![7u8; 32]);
    assert_ne!(fingerprint, vec![9u8; 32]);
    assert_ne!(fingerprint, keys.blind_index(DOMAIN));
    assert_ne!(fingerprint, crate::crypto::Keys::token_hash(DOMAIN));
}

/// A refusal whose drain ALSO overran still exits non-zero.
///
/// The drain's own ruling is exit 0, and it must not rescue a refusal. THE
/// ASSERTION THAT REDDENS if the two verdicts are ever nested so that the
/// overrun swallows the refusal: `is_err()` below.
#[test]
fn an_overrun_drain_does_not_rescue_a_refusal() {
    let refused = Ended::KeyIdentityRefused(Mismatch {
        arm: "GetKeyIdentity",
    });
    assert!(refused.into_exit(true).is_err());
    assert!(Ended::Ordinary.into_exit(true).is_ok());
}

// ---------------------------------------------------------------------------
// THE CADENCE THROUGH THE REAL LOOP, AND THE WIRING THE BINARY HANDS OVER
// ---------------------------------------------------------------------------

/// One line an operator was told, as the two things these assertions are about.
///
/// Parsed out of [`crate::service::tests`]'s rendered form, which is
/// `LEVEL "message" field=value …`.
#[derive(Clone, Debug)]
struct Line {
    error: bool,
    standing_for_secs: u64,
}

/// The lines about ONE reason, in order.
///
/// **THROUGH THIS BINARY'S ONE GLOBAL SUBSCRIBER, and a thread-local one is NOT
/// an equivalent shortcut.** `tracing` caches a callsite's `Interest` globally
/// and lazily: a callsite first reached by another test, on another thread,
/// while no subscriber existed is cached as NEVER, and a `set_default` installed
/// afterwards captures nothing at all from it. Measured on this file — green
/// under `--test-threads=1`, zero lines captured in parallel. The global tap is
/// registered for every callsite, so this one is enabled whoever gets there
/// first.
fn told_about(reason: &str) -> Vec<Line> {
    crate::service::tests::warnings()
        .into_iter()
        .filter(|line| line.contains(&format!("reason={reason}")))
        .map(|line| Line {
            error: line.starts_with("ERROR"),
            standing_for_secs: line
                .split("standing_for_secs=")
                .nth(1)
                .and_then(|rest| rest.split(' ').next())
                .and_then(|n| n.parse().ok())
                .unwrap_or_default(),
        })
        .collect()
}

const UNIMPLEMENTED: &str = "UNIMPLEMENTED: this iam-db predates the key-identity arm";

/// **THE CADENCE IS PRODUCED BY THE LOOP, and this asserts it THROUGH the loop.**
///
/// `a_standing_fault_is_restated_rather_than_reported_once` calls [`restate`]
/// with hand-built `Duration`s and
/// `a_permanent_fault_reaches_an_operator_within_minutes` RE-IMPLEMENTS the
/// production accumulation in its own body. Both assert the arithmetic. NEITHER
/// touches the two lines in [`watch_with_seed`] and [`report`] that compute the
/// arithmetic's input, so both stayed green while an operator got one line and
/// never another — which is the failure this module's own documentation names by
/// hand. This test runs the real loop against a real twin and reads the real log.
///
/// THE MUTATIONS THAT REDDEN, each measured one at a time:
/// deleting the `*since = since.saturating_add(waited)` accumulation in
/// [`watch_with_seed`] leaves `restate(Some(ZERO))` false for ever, so exactly
/// one line is ever emitted — `lines.len() > 1` and the `standing_for_secs`
/// assertion both go red. Deleting `*standing = Some((reason, ZERO))` in
/// [`report`] leaves `since` `None` for ever, so EVERY attempt reports — the
/// `lines.len() < attempts / 2` bound and the same `standing_for_secs` assertion
/// go red. Demoting a permanent fault to WARN reddens the level assertion.
///
/// THE CLOCK IS PAUSED AFTER THE CONNECT AND NOT BEFORE IT. [`twin_channel`]
/// polls for its listener with `tokio::time::sleep`, and a paused clock
/// auto-advances those five seconds of polling into no real time at all — so the
/// poll would exhaust before the server bound. The loop is bounded by the SCRIPT
/// rather than by a `tokio::time::timeout`, for the same reason: an outer timer
/// is something auto-advance can fire while a round trip is in flight.
#[tokio::test]
async fn the_cadence_an_operator_gets_is_produced_by_the_loop() {
    // Forty permanent answers and then a MISMATCH, which is what ends the loop.
    // `answer` repeats the LAST entry for ever, so the MISMATCH also makes the
    // attempt count exact rather than a race with a timer.
    const ATTEMPTS: usize = 40;
    let mut get = vec![Answer::Failed(tonic::Code::Unimplemented); ATTEMPTS];
    get.push(Answer::Outcome(raw(db::KeyIdentityOutcome::Mismatch)));

    let (channel, asked) = twin_channel(Script {
        get,
        ..Default::default()
    })
    .await;

    // INSTALLED BEFORE THE LOOP AND DRAINING THIS THREAD'S LIST, which is what
    // keeps the tap's own setup noise out of an assertion about a count.
    crate::service::tests::warnings_from_here();

    // A FLAT HUNDRED-SECOND BACKOFF, so each wait is between fifty and a hundred
    // seconds and the cumulative crosses `RESTATE_AFTER` every three to six of
    // them. The production cadence would need an hour of virtual time to say the
    // same thing; the property under test is the accumulation, not the numbers.
    tokio::time::pause();
    let refusal = watch_with_seed(
        IamDbServiceClient::new(channel),
        identity(),
        Retry::of(Duration::from_secs(100), Duration::from_secs(100)),
        0x5eed_5eed_5eed_5eed,
    )
    .await;
    tokio::time::resume();

    assert!(refusal.to_string().contains("MISMATCH"));
    let attempts = asked.lock().expect("asked").get.len();
    assert_eq!(attempts, ATTEMPTS + 1, "the script bounds the loop exactly");

    let lines = told_about(UNIMPLEMENTED);

    // M6: an operator is told MORE THAN ONCE about a fault no retry mends.
    assert!(
        lines.len() > 1,
        "a standing fault reported once is the failure this arm exists to delete; \
         got {} line(s) over {attempts} attempts",
        lines.len()
    );

    // M7: and NOT on every attempt, which trains a reader to skip it.
    assert!(
        lines.len() < attempts / 2,
        "a line per retry is the opposite failure; got {} lines over {attempts} attempts",
        lines.len()
    );

    // AND THE INTERVAL IS THE ONE THE CONSTANT NAMES. Neither mutation above can
    // produce a line carrying a non-zero `standing_for_secs` at all.
    assert!(
        lines
            .iter()
            .any(|line| line.standing_for_secs >= RESTATE_AFTER.as_secs()),
        "no line reported a reason that had stood for {RESTATE_AFTER:?}: {lines:?}"
    );

    // A PERMANENT FAULT REACHES AN OPERATOR AT ERROR, every time it is stated.
    assert!(
        lines.iter().all(|line| line.error),
        "a fault no retry mends is an ERROR, not a retry counter: {lines:?}"
    );
}

/// **THE WIRING SEAM: the check `main` hands over is BUILT IN THE LIBRARY.**
///
/// While `serve_and_drain` took the check as a FUTURE, its call site in
/// `main.rs` could say `{ drop(key_check); std::future::pending() }` — measured
/// on this branch: it compiles, inference gives `Pending<Mismatch>`, all of this
/// suite passes and so does `cargo clippy --all-targets --all-features -D
/// warnings`. The check was constructed and thrown away and nothing anywhere
/// failed, because `src/main.rs` has no reachable test by this repository's
/// standing decision. [`Check`] removes the future from that call site, and this
/// test is what reddens if the same mutation is written where it is still
/// writable — replacing [`watch`] inside [`until_stopped_with`] with
/// `std::future::pending()` elapses the window below.
///
/// It starts from a [`Channel`] and not a client, because a `Channel` is what
/// `main` holds and passes to [`Check::new`].
#[tokio::test]
async fn the_check_main_hands_over_is_the_one_that_ends_the_serve() {
    let (channel, asked) = twin_channel(Script {
        get: vec![Answer::Outcome(raw(db::KeyIdentityOutcome::Mismatch))],
        ..Default::default()
    })
    .await;

    let ended = tokio::time::timeout(
        WINDOW,
        until_stopped_with(
            std::future::pending(),
            std::future::pending(),
            Check::new(channel, identity(), brisk()),
        ),
    )
    .await
    .expect("the check main hands over must reach the select and end the serve");

    assert!(matches!(ended, Ended::KeyIdentityRefused(_)));
    assert!(
        ended.into_exit(false).is_err(),
        "and it is the arm that makes the exit non-zero"
    );
    assert_eq!(
        asked.lock().expect("asked").get.len(),
        1,
        "one round trip settled it, over the channel the binary supplied"
    );
}

/// The refusal an operator reads NAMES THE ARM THAT ANSWERED IT.
///
/// The distinction is diagnostic and the field's own documentation states it: a
/// MISMATCH on the read means a marker was already stored, and one on the write
/// means this pod lost a split rollout. It reached nobody while the `#[error]`
/// string interpolated `DERIVATION_VERSION` and not `arm` — the message is the
/// only thing the process prints on its way out.
///
/// THE ASSERTION THAT REDDENS if `{arm}` is dropped from that string again:
/// `assert_ne!`, which is the one that cannot be satisfied by a sentence naming
/// both arms in prose.
#[test]
fn the_refusal_names_the_arm_that_answered_it() {
    let read = Mismatch { arm: READ }.to_string();
    let write = Mismatch { arm: WRITE }.to_string();
    assert!(read.contains(READ), "{read}");
    assert!(write.contains(WRITE), "{write}");
    assert_ne!(
        read, write,
        "the two arms must not render to the same sentence"
    );
}
