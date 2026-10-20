//! The caller gate (ADR-0972 (1), ledger 1629), driven over all fourteen
//! `IamService` RPCs.
//!
//! **THE THREE LOOPS PROVE EACH OTHER.** The refusal loops assert that the
//! fake twin recorded ZERO calls, which is only an oracle if each request would
//! have reached the twin had it been admitted. The positive loop is what proves
//! that: the same requests, from the gateway's name, reach the twin on every
//! RPC that has an upstream hop. A refusal loop alone would pass for a gate
//! that refused everyone, and for requests that failed validation first.
//!
//! **THE GATE TESTS ARE THE ONLY ONES THAT DRIVE THE TRAIT METHODS.** Every
//! other test in [`super`] calls the `_as` seam with `Some(GATEWAY_CALLER)`.
//! A bare `Request::new(..)` on a trait method has no peer certificates, so it
//! is the "no client certificate name" case, and the `None` loop drives it.

use metrics_util::debugging::{DebugValue, DebuggingRecorder};
use metrics_util::MetricKind;

use super::super::caller::NO_CALLER;
use super::*;

/// A LITERAL, never `caller::CALLER_REFUSED` (ADR-0599): a series name
/// asserted through the constant that produced it passes straight through a
/// rename, and the probe text and dashboards query this exact name. `_total`
/// is the estate's counter convention (`yadgar_calls_total`,
/// `yadgar_iamdb_caller_refused_total`).
const CALLER_REFUSED_SERIES: &str = "yadgar_iam_caller_refused_total";

/// A real leaf name `platform` issues under the same internal authority, so it
/// verifies at the handshake and reaches the gate. Not the gateway's.
const NOT_THE_GATEWAY: &str = "task-caller";

/// The RPCs this build answers `UNIMPLEMENTED` without a hop to the twin.
const NO_UPSTREAM: [&str; 1] = ["SetRateLimitOverride"];

/// How a loop reaches the RPC.
#[derive(Clone, Copy)]
enum Via<'a> {
    /// The `_as` seam, with this caller.
    As(Option<&'a str>),
    /// The `IamService` trait method, with a bare request: no peer chain.
    Trait,
}

/// What one RPC answered, and how many twin calls it made.
struct Answer {
    rpc: &'static str,
    status: Result<(), Status>,
    upstream: usize,
}

fn twin_calls(rec: &Arc<Mutex<Recorded>>) -> usize {
    rec.lock().expect("recorded").calls
}

/// A twin that answers every arm the requests below reach.
async fn gated_iam(password: &str) -> (Iam, Arc<Mutex<Recorded>>) {
    let (iam, rec, _inv) = iam_with(FakeDb {
        password: known_user(password),
        resolves_to: Some("yadgar:user:1".into()),
        redeem: redeemed("alice"),
        ..Default::default()
    })
    .await;
    (iam, rec)
}

/// Ask one RPC through `$via`, and count the twin calls it made.
macro_rules! ask {
    ($iam:ident, $rec:ident, $via:ident, $rpc:literal, $method:ident, $method_as:ident, $req:expr) => {{
        let before = twin_calls($rec);
        let status = match $via {
            Via::As(caller) => $iam.$method_as(caller, $req).await.map(drop),
            Via::Trait => IamService::$method($iam, $req).await.map(drop),
        };
        Answer {
            rpc: $rpc,
            status,
            upstream: twin_calls($rec) - before,
        }
    }};
}

/// Ask every one of the fourteen RPCs once, with a request that reaches the
/// twin when admitted. Three groups only so that no one function passes
/// clippy's cognitive-complexity ceiling.
async fn every_rpc(
    iam: &Iam,
    rec: &Arc<Mutex<Recorded>>,
    via: Via<'_>,
    password: &str,
) -> Vec<Answer> {
    let mut answers = sign_in_rpcs(iam, rec, via, password).await;
    answers.extend(credential_rpcs(iam, rec, via).await);
    answers.extend(admin_rpcs(iam, rec, via).await);
    answers
}

async fn sign_in_rpcs(
    iam: &Iam,
    rec: &Arc<Mutex<Recorded>>,
    via: Via<'_>,
    password: &str,
) -> Vec<Answer> {
    vec![
        ask!(
            iam,
            rec,
            via,
            "ResolveCredential",
            resolve_credential,
            resolve_credential_as,
            Request::new(ResolveCredentialRequest {
                token: "a-bearer-token".into(),
            })
        ),
        ask!(
            iam,
            rec,
            via,
            "Login",
            login,
            login_as,
            login("alice", password)
        ),
        ask!(
            iam,
            rec,
            via,
            "RedeemEnrolment",
            redeem_enrolment,
            redeem_enrolment_as,
            redeem(&fixture_secret(), password, "01J0000000000000000000000G")
        ),
        ask!(
            iam,
            rec,
            via,
            "IssueEnrolment",
            issue_enrolment,
            issue_enrolment_as,
            issue("01J0000000000000000000000E")
        ),
        ask!(
            iam,
            rec,
            via,
            "ListCredentials",
            list_credentials,
            list_credentials_as,
            Request::new(ListCredentialsRequest {
                user_id: "yadgar:user:1".into(),
                ..Default::default()
            })
        ),
    ]
}

async fn credential_rpcs(iam: &Iam, rec: &Arc<Mutex<Recorded>>, via: Via<'_>) -> Vec<Answer> {
    vec![
        ask!(
            iam,
            rec,
            via,
            "SetUserAdmin",
            set_user_admin,
            set_user_admin_as,
            promote(true, None)
        ),
        ask!(
            iam,
            rec,
            via,
            "SetRateLimitOverride",
            set_rate_limit_override,
            set_rate_limit_override_as,
            Request::new(SetRateLimitOverrideRequest::default())
        ),
        ask!(
            iam,
            rec,
            via,
            "SetInheritedSetting",
            set_inherited_setting,
            set_inherited_setting_as,
            Request::new(org_write())
        ),
        ask!(
            iam,
            rec,
            via,
            "IssueCredential",
            issue_credential,
            issue_credential_as,
            Request::new(IssueCredentialRequest {
                idempotency: None,
                user_id: "yadgar:user:1".into(),
                label: "a laptop".into(),
                expires_in_seconds: 3600,
                ..Default::default()
            })
        ),
        ask!(
            iam,
            rec,
            via,
            "RevokeCredential",
            revoke_credential,
            revoke_credential_as,
            Request::new(RevokeCredentialRequest {
                credential_id: "yadgar:credential:fake".into(),
                ..Default::default()
            })
        ),
    ]
}

async fn admin_rpcs(iam: &Iam, rec: &Arc<Mutex<Recorded>>, via: Via<'_>) -> Vec<Answer> {
    vec![
        ask!(
            iam,
            rec,
            via,
            "RevokeAllCredentials",
            revoke_all_credentials,
            revoke_all_credentials_as,
            revoke_all(REVOKE_ALL_USER, None)
        ),
        ask!(
            iam,
            rec,
            via,
            "CreateUser",
            create_user,
            create_user_as,
            Request::new(CreateUserRequest {
                external_id: "someone".into(),
                display_name: "Some One".into(),
                ..Default::default()
            })
        ),
        ask!(
            iam,
            rec,
            via,
            "AddTeamMember",
            add_team_member,
            add_team_member_as,
            Request::new(AddTeamMemberRequest {
                team_id: "yadgar:team:t1".into(),
                user_id: "yadgar:user:1".into(),
                ..Default::default()
            })
        ),
        ask!(
            iam,
            rec,
            via,
            "RemoveTeamMember",
            remove_team_member,
            remove_team_member_as,
            Request::new(RemoveTeamMemberRequest {
                team_id: "yadgar:team:t1".into(),
                user_id: "yadgar:user:1".into(),
                ..Default::default()
            })
        ),
    ]
}

/// Every answer is the gate's refusal, and the twin was never asked.
fn assert_all_refused(answers: &[Answer], rec: &Arc<Mutex<Recorded>>, presented: &str) {
    assert_eq!(answers.len(), 14, "every IamService RPC is asked");
    for a in answers {
        let refusal = a
            .status
            .as_ref()
            .expect_err(&format!("{} must refuse {presented}", a.rpc));
        assert_eq!(
            refusal.code(),
            tonic::Code::PermissionDenied,
            "{} must refuse {presented} with PERMISSION_DENIED, not {:?}",
            a.rpc,
            refusal.code()
        );
        assert!(
            refusal.message().contains(GATEWAY_CALLER),
            "{}: the refusal names the one caller iam admits: {:?}",
            a.rpc,
            refusal.message()
        );
    }
    assert_eq!(
        twin_calls(rec),
        0,
        "a refused call reaches no store: the gate runs before every upstream hop"
    );
}

/// A pod holding a valid leaf that is not the gateway's is refused on every
/// verb, before any upstream call.
///
/// MUTATIONS THAT REDDEN: an `admit` that admits everyone (every `expect_err`);
/// the gate moved after `_inner`'s first hop on any RPC (`twin_calls == 0`); a
/// trait method left calling its `_inner` directly does not redden here —
/// `every_rpc_with_no_client_certificate_name_is_refused` is the loop that
/// drives the trait methods.
#[tokio::test]
async fn every_rpc_from_a_non_gateway_leaf_is_refused_before_any_upstream_call() {
    let password = fixture_password();
    let (iam, rec) = gated_iam(&password).await;

    let answers = every_rpc(&iam, &rec, Via::As(Some(NOT_THE_GATEWAY)), &password).await;

    assert_all_refused(&answers, &rec, NOT_THE_GATEWAY);
    for a in &answers {
        let message = a.status.as_ref().unwrap_err().message().to_string();
        assert!(
            message.contains(NOT_THE_GATEWAY),
            "{}: the refusal names what was presented: {message:?}",
            a.rpc
        );
    }
}

/// No client-certificate name — `clientAuth: "off"`, no leaf, a cleartext
/// listener — is a refusal: fail closed (ADR-0972 Q3).
///
/// BOTH PATHS. `Via::As(None)` is the gate's own `None` arm. `Via::Trait` is
/// the trait method with a bare request, which proves each handler hands the
/// name it read to the gate rather than calling the work directly.
#[tokio::test]
async fn every_rpc_with_no_client_certificate_name_is_refused() {
    let password = fixture_password();
    for via in [Via::As(None), Via::Trait] {
        let (iam, rec) = gated_iam(&password).await;
        let answers = every_rpc(&iam, &rec, via, &password).await;
        assert_all_refused(&answers, &rec, "no caller");
    }
}

/// THE POSITIVE CONTROL: the gateway's name is admitted on every verb, and
/// the requests the refusal loops send do reach the twin when admitted.
///
/// Without it, a gate that refused everyone would pass both refusal loops,
/// and so would requests that failed validation before their first hop.
#[tokio::test]
async fn the_gateway_leaf_is_admitted_on_every_rpc() {
    let password = fixture_password();
    let (iam, rec) = gated_iam(&password).await;

    let answers = every_rpc(&iam, &rec, Via::As(Some(GATEWAY_CALLER)), &password).await;

    assert_eq!(answers.len(), 14);
    for a in &answers {
        if NO_UPSTREAM.contains(&a.rpc) {
            assert_eq!(
                a.status.as_ref().map_err(Status::code),
                Err(tonic::Code::Unimplemented),
                "{}: admitted, and answered as this build answers it",
                a.rpc
            );
            assert_eq!(a.upstream, 0, "{} has no upstream hop", a.rpc);
            continue;
        }
        assert!(
            a.status.is_ok(),
            "{}: the gateway is admitted and the request is well formed: {:?}",
            a.rpc,
            a.status
        );
        assert!(
            a.upstream >= 1,
            "{}: admitted, the request reaches the twin — which is what makes the \
             refusal loops' zero-call assertion an oracle",
            a.rpc
        );
    }
}

/// **A REFUSED `Login` OR `RedeemEnrolment` STILL COSTS THE FLOOR.**
///
/// The gate runs inside the floored span. A refusal answered at once would
/// let a caller tell the gate from a wrong password by the response time.
///
/// MUTATION THAT REDDENS: the gate moved above the clock in `login_as` or
/// `redeem_enrolment_as` — the refusal then answers in microseconds.
#[tokio::test]
async fn a_refused_login_still_costs_the_floor() {
    const FLOOR: Duration = Duration::from_millis(300);

    let (iam, _rec, _inv) = iam_with_floor(FakeDb::default(), FLOOR).await;
    let started = Instant::now();
    let refused = iam
        .login_as(Some(NOT_THE_GATEWAY), login("alice", &fixture_password()))
        .await
        .expect_err("the gate refuses a non-gateway Login");
    assert_eq!(refused.code(), tonic::Code::PermissionDenied);
    assert!(
        started.elapsed() >= FLOOR,
        "a refused Login answered in {:?}, under its {FLOOR:?} floor",
        started.elapsed()
    );

    let (iam, _rec, _inv) = iam_with_redeem_floor(FakeDb::default(), FLOOR).await;
    let started = Instant::now();
    let refused = iam
        .redeem_enrolment_as(
            None,
            redeem(
                &fixture_secret(),
                &fixture_password(),
                "01J0000000000000000000000F",
            ),
        )
        .await
        .expect_err("the gate refuses a RedeemEnrolment with no caller");
    assert_eq!(refused.code(), tonic::Code::PermissionDenied);
    assert!(
        started.elapsed() >= FLOOR,
        "a refused RedeemEnrolment answered in {:?}, under its {FLOOR:?} floor",
        started.elapsed()
    );
}

/// The `caller_refused` value for one `caller` label, or `None` if no such
/// series was ever registered.
fn refused_count(
    snapshot: &[(metrics_util::CompositeKey, DebugValue)],
    caller: &str,
) -> Option<u64> {
    snapshot.iter().find_map(|(key, value)| {
        let named = key.kind() == MetricKind::Counter
            && key.key().name() == CALLER_REFUSED_SERIES
            && key
                .key()
                .labels()
                .any(|l| l.key() == "caller" && l.value() == caller);
        match (named, value) {
            (true, DebugValue::Counter(n)) => Some(*n),
            _ => None,
        }
    })
}

/// **THE GATE'S OWN COUNTER RISES, LABELLED WITH THE PRESENTED NAME.**
/// `PERMISSION_DENIED` on the call metrics is not this signal: iam-db already
/// returns it on the bootstrap-demand path and iam relays upstream codes.
///
/// A LOCAL RECORDER, NEVER `install()`: this binary's tests run in parallel
/// and a global recorder is process-wide. Plain `#[tokio::test]` is a
/// current-thread runtime, so every increment happens on the guarded thread.
/// ONE snapshot at the end, because a `DebuggingRecorder` snapshot drains.
///
/// MUTATIONS THAT REDDEN: the increment deleted (both `Some(1)`); the label
/// fixed to one value (the other `Some(1)`); an admitted call that also
/// increments (the gateway's series is `None`).
#[tokio::test]
async fn a_gate_refusal_increments_caller_refused_with_the_presented_name() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let _guard = metrics::set_default_local_recorder(&recorder);

    let (iam, _rec, _inv) = iam_with(FakeDb::default()).await;
    let user = || {
        Request::new(CreateUserRequest {
            external_id: "someone".into(),
            display_name: "Some One".into(),
            ..Default::default()
        })
    };
    iam.create_user_as(Some(NOT_THE_GATEWAY), user())
        .await
        .expect_err("refused");
    IamService::create_user(&iam, user())
        .await
        .expect_err("refused: a bare request has no caller");
    iam.create_user_as(Some(GATEWAY_CALLER), user())
        .await
        .expect("admitted");

    let snapshot = snapshotter.snapshot().into_vec();
    let snapshot: Vec<_> = snapshot.into_iter().map(|(k, _, _, v)| (k, v)).collect();
    assert_eq!(refused_count(&snapshot, NOT_THE_GATEWAY), Some(1));
    assert_eq!(refused_count(&snapshot, NO_CALLER), Some(1));
    assert_eq!(
        refused_count(&snapshot, GATEWAY_CALLER),
        None,
        "an admitted call is not a refusal"
    );
}
