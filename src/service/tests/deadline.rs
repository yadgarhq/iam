//! ADR-1019: every `iam-db` call is bounded by the caller's remaining time.
//!
//! The caller's deadline arrives as `grpc-timeout` on the incoming request.
//! These tests set it by hand on the request handed to the `_as` seam, exactly
//! where tonic's server leaves it, and read what the fake twin was TOLD from
//! [`Recorded::told`]. The ceiling is [`TEST_CEILING`], the chart default.
//!
//! **THE ACCEPTANCE NUMBER IS THE GATEWAY'S.** The gateway gives
//! `ResolveCredential` and `Login` a 10 s `AUTH_DEADLINE`; before this change
//! `iam-db` was told nothing and worked on for up to `iam`'s 14 s ceiling.

use super::*;

/// The gateway's `AUTH_DEADLINE`.
const AUTH_DEADLINE: Duration = Duration::from_secs(10);

/// How long a test waits for an answer before calling the hop wedged. Far above
/// every budget below, so it reddens only a hop that never answers.
const WEDGED: Duration = Duration::from_secs(5);

/// `req` as tonic's server hands it on when the caller said it waits `budget`.
fn with_deadline<T>(mut req: Request<T>, budget: Duration) -> Request<T> {
    let value = format!("{}m", budget.as_millis());
    req.metadata_mut()
        .insert(yadgar_dial::GRPC_TIMEOUT, value.parse().expect("ASCII"));
    req
}

/// A `grpc-timeout` value as a duration: at most eight digits and one unit
/// (PROTOCOL-HTTP2.md). tonic picks the unit, so the test never compares text.
pub(crate) fn told(raw: &str) -> Duration {
    let (digits, unit) = raw.split_at(raw.len() - 1);
    let n: u64 = digits.parse().expect("digits");
    match unit {
        "H" => Duration::from_secs(n * 3600),
        "M" => Duration::from_secs(n * 60),
        "S" => Duration::from_secs(n),
        "m" => Duration::from_millis(n),
        "u" => Duration::from_micros(n),
        "n" => Duration::from_nanos(n),
        other => panic!("{other:?} is not a grpc-timeout unit"),
    }
}

/// Every `grpc-timeout` the twin was told, in call order.
fn everything_told(rec: &Arc<Mutex<Recorded>>) -> Vec<Duration> {
    rec.lock()
        .expect("recorded")
        .told
        .iter()
        .map(|t| {
            told(
                t.as_deref()
                    .expect("every iam-db call carries a grpc-timeout"),
            )
        })
        .collect()
}

fn resolve() -> Request<ResolveCredentialRequest> {
    Request::new(ResolveCredentialRequest {
        token: "a-bearer-token".into(),
    })
}

fn wedged_store() -> FakeDb {
    FakeDb {
        resolves_to: Some("yadgar:user:1".into()),
        resolves_hangs: true,
        ..Default::default()
    }
}

/// Red case (1): a store that never answers is cut off BEFORE the caller's
/// deadline. `iam` answers `DEADLINE_EXCEEDED` itself, the store was told at
/// most remaining - 50 ms, and the store's handler is dropped.
#[tokio::test]
async fn a_wedged_store_is_cut_off_before_the_callers_deadline() {
    let (iam, rec, _inv) = iam_with(wedged_store()).await;
    let budget = Duration::from_millis(300);

    let started = Instant::now();
    let answered = tokio::time::timeout(
        WEDGED,
        iam.resolve_credential_as(Some(GATEWAY_CALLER), with_deadline(resolve(), budget)),
    )
    .await
    .expect("iam must answer on its own; it waited on a wedged store past its caller");
    let elapsed = started.elapsed();

    let refused = answered.expect_err("the store never answered");
    assert_eq!(
        refused.code(),
        tonic::Code::DeadlineExceeded,
        "a cut-off call is DEADLINE_EXCEEDED, not CANCELLED and not an outage: {refused:?}"
    );
    assert!(
        elapsed < budget,
        "iam answered after {elapsed:?}, which is past its caller's {budget:?}: the \
         caller had already given up and tonic would have dropped the handler"
    );
    let all = everything_told(&rec);
    assert_eq!(all.len(), 1, "one call to the store: {all:?}");
    assert!(
        all[0] <= budget - yadgar_dial::DEADLINE_MARGIN,
        "the store was told {:?}; the caller left at most {budget:?} - 50 ms",
        all[0]
    );

    // The twin's server drops its handler asynchronously, once the stream is
    // reset or its own copy of the deadline fires.
    let dropped = tokio::time::timeout(WEDGED, async {
        while !rec.lock().expect("recorded").hung_handler_dropped {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(
        dropped.is_ok(),
        "the store's handler is still running on a request nobody waits for"
    );
}

/// A caller whose deadline leaves no more than the margin gets
/// `DEADLINE_EXCEEDED` and the store is never asked.
#[tokio::test]
async fn a_deadline_inside_the_margin_never_reaches_the_store() {
    let (iam, rec, _inv) = iam_with(wedged_store()).await;

    let refused = tokio::time::timeout(
        WEDGED,
        iam.resolve_credential_as(
            Some(GATEWAY_CALLER),
            with_deadline(resolve(), yadgar_dial::DEADLINE_MARGIN),
        ),
    )
    .await
    .expect("iam must answer on its own; it asked a wedged store")
    .expect_err("no time is left for an inner call");

    assert_eq!(refused.code(), tonic::Code::DeadlineExceeded, "{refused:?}");
    assert_eq!(
        rec.lock().expect("recorded").calls,
        0,
        "the store was asked"
    );
}

/// Red case (2): a request with no deadline is bounded by the ceiling, and the
/// store is TOLD the ceiling, on every call of both auth RPCs.
#[tokio::test]
async fn no_deadline_falls_back_to_the_ceiling() {
    let password = fixture_password();
    let (iam, rec, _inv) = iam_with(FakeDb {
        password: known_user(&password),
        resolves_to: Some("yadgar:user:1".into()),
        ..Default::default()
    })
    .await;

    iam.resolve_credential_as(Some(GATEWAY_CALLER), resolve())
        .await
        .expect("resolves");
    iam.login_as(Some(GATEWAY_CALLER), login("max", &password))
        .await
        .expect("signs in");

    let all = everything_told(&rec);
    assert_eq!(all.len(), 3, "resolve, then lookup and mint: {all:?}");
    for (n, bound) in all.iter().enumerate() {
        assert_eq!(*bound, TEST_CEILING, "call {n} was told {bound:?}");
    }
}

/// Red case (3), and the acceptance number: the gateway's 10 s reaches the
/// store as at most 9.95 s, never as `iam`'s 14 s ceiling. `Login`'s second
/// call shares the first call's deadline, so it is told strictly less.
#[tokio::test]
async fn the_gateways_auth_deadline_reaches_the_store_below_it() {
    let password = fixture_password();
    let (iam, rec, _inv) = iam_with(FakeDb {
        password: known_user(&password),
        resolves_to: Some("yadgar:user:1".into()),
        ..Default::default()
    })
    .await;
    let most = AUTH_DEADLINE - yadgar_dial::DEADLINE_MARGIN;

    iam.resolve_credential_as(
        Some(GATEWAY_CALLER),
        with_deadline(resolve(), AUTH_DEADLINE),
    )
    .await
    .expect("resolves");
    iam.login_as(
        Some(GATEWAY_CALLER),
        with_deadline(login("max", &password), AUTH_DEADLINE),
    )
    .await
    .expect("signs in");

    let all = everything_told(&rec);
    assert_eq!(all.len(), 3, "resolve, then lookup and mint: {all:?}");
    for (n, bound) in all.iter().enumerate() {
        assert!(
            *bound <= most,
            "call {n} was told {bound:?}; the gateway left at most {most:?}"
        );
    }
    let (lookup, mint) = (all[1], all[2]);
    assert!(
        mint < lookup,
        "the mint was told {mint:?} and the lookup {lookup:?}: the second call of \
         one request gets only what the first left"
    );
}

/// D67: the cut-off call is RECORDED as `DEADLINE_EXCEEDED`. A dropped `Call`
/// records `UNRECORDED`, which is what every upstream refusal did before.
#[test]
fn a_cut_off_call_is_recorded_as_deadline_exceeded() {
    // A LOCAL recorder on a CURRENT-THREAD runtime, for the reasons
    // `the_outcome_of_a_label_refusal_is_one_the_shared_mapping_produces` gives.
    let recorder = metrics_util::debugging::DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");

    metrics::with_local_recorder(&recorder, || {
        rt.block_on(async {
            let (iam, _rec, _inv) = iam_with(wedged_store()).await;
            let answered = tokio::time::timeout(
                WEDGED,
                iam.resolve_credential_as(
                    Some(GATEWAY_CALLER),
                    with_deadline(resolve(), Duration::from_millis(300)),
                ),
            )
            .await
            .expect("iam must answer on its own");
            answered.expect_err("the store never answered");
        });
    });

    let outcomes: Vec<String> = snapshotter
        .snapshot()
        .into_vec()
        .into_iter()
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
        outcomes,
        vec!["DEADLINE_EXCEEDED".to_string()],
        "one call, recorded with the code it answered"
    );
}

// ---------------------------------------------------------------------------
// No oracle from the caller's deadline (security review of this change).
//
// RULE: on an unauthenticated path, until the credential or secret is
// confirmed AND the answer is decided, the caller's deadline must not change
// which status comes back. Each test below cuts one inner call off at the
// caller's deadline and compares the answer with what a WRONG credential gets
// at the same point: same code, same message.

/// `(code, message)` of a refusal, the two things a caller can read.
fn seen<T: std::fmt::Debug>(answered: Result<T, Status>) -> (tonic::Code, String) {
    let refused = answered.expect_err("refused");
    (refused.code(), refused.message().to_string())
}

/// What a wrong password gets from `Login`.
async fn wrong_password_login() -> (tonic::Code, String) {
    let (iam, _rec, _inv) = iam_with(FakeDb {
        password: known_user(&fixture_password()),
        ..Default::default()
    })
    .await;
    seen(
        iam.login_as(Some(GATEWAY_CALLER), login("max", &fixture_password()))
            .await,
    )
}

#[tokio::test]
async fn a_login_lookup_cut_off_answers_exactly_as_a_wrong_password() {
    let password = fixture_password();
    let (iam, _rec, _inv) = iam_with(FakeDb {
        password: known_user(&password),
        lookup_delay: Duration::from_secs(30),
        ..Default::default()
    })
    .await;

    let answered = tokio::time::timeout(
        WEDGED,
        iam.login_as(
            Some(GATEWAY_CALLER),
            with_deadline(login("max", &password), Duration::from_millis(300)),
        ),
    )
    .await
    .expect("iam must answer on its own");

    assert_eq!(seen(answered), wrong_password_login().await);
}

#[tokio::test]
async fn a_login_mint_cut_off_answers_exactly_as_a_wrong_password() {
    let password = fixture_password();
    let (iam, rec, _inv) = iam_with(FakeDb {
        password: known_user(&password),
        mint_delay: Duration::from_secs(30),
        ..Default::default()
    })
    .await;

    // Long enough for the lookup and the Argon2 verification of a debug
    // build, so the cut lands on the mint.
    let answered = iam
        .login_as(
            Some(GATEWAY_CALLER),
            with_deadline(login("max", &password), Duration::from_secs(3)),
        )
        .await;

    assert_eq!(
        rec.lock().expect("recorded").create_credential.len(),
        1,
        "the password verified and the mint was asked"
    );
    assert_eq!(seen(answered), wrong_password_login().await);
}

#[tokio::test]
async fn a_spend_cut_off_answers_exactly_as_an_unknown_secret() {
    let password = fixture_password();
    let (iam, rec, _inv) = iam_with(FakeDb {
        redeem: redeemed("ada"),
        spend_delay: Duration::from_secs(30),
        ..Default::default()
    })
    .await;
    let answered = iam
        .redeem_enrolment_as(
            Some(GATEWAY_CALLER),
            with_deadline(redeem("s3cret", &password, "k1"), Duration::from_secs(3)),
        )
        .await;
    assert_eq!(
        rec.lock().expect("recorded").redeem_enrolment.len(),
        1,
        "the spend was asked"
    );

    let (unknown, _rec, _inv) = iam_with(FakeDb::default()).await;
    let refused = unknown
        .redeem_enrolment_as(Some(GATEWAY_CALLER), redeem("s3cret", &password, "k1"))
        .await;
    assert_eq!(seen(answered), seen(refused));
}

#[tokio::test]
async fn a_redemption_mint_cut_off_answers_as_a_different_password_replay() {
    let password = fixture_password();
    let (iam, rec, _inv) = iam_with(FakeDb {
        redeem: redeemed("ada"),
        password: known_user(&password),
        mint_delay: Duration::from_secs(30),
        ..Default::default()
    })
    .await;
    // The spend hashes and the replay check verifies: two Argon2 runs first.
    let answered = iam
        .redeem_enrolment_as(
            Some(GATEWAY_CALLER),
            with_deadline(redeem("s3cret", &password, "k1"), Duration::from_secs(5)),
        )
        .await;
    assert_eq!(
        rec.lock().expect("recorded").create_credential.len(),
        1,
        "the replay check passed and the mint was asked"
    );

    let (replay, _rec, _inv) = iam_with(FakeDb {
        redeem: redeemed("ada"),
        password: known_user(&fixture_password()),
        ..Default::default()
    })
    .await;
    let refused = replay
        .redeem_enrolment_as(Some(GATEWAY_CALLER), redeem("s3cret", &password, "k1"))
        .await;
    assert_eq!(seen(answered), seen(refused));
}

/// THROUGH A SERVED `iam`: a real tonic server behind the gate, called by a
/// gateway-leaf client that sets its own deadline. tonic's server drops the
/// handler at that deadline, so this is what a caller can actually observe.
///
/// For every deadline, a RIGHT password either signs in (it had the time) or
/// is refused with exactly the code a WRONG password gets at the same
/// deadline. The deadlines sit below the floor, around it, and around the
/// floor plus the slow mint.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn through_a_served_iam_a_short_deadline_never_tells_a_right_password_from_a_wrong_one() {
    use super::gate_transport::{leaf, pki, serve_iam_with, SERVED_NAME};
    use crate::pb::yadgar::iam::v1::iam_service_client::IamServiceClient;
    use tonic::transport::{Certificate, ClientTlsConfig};

    let floor = Duration::from_secs(2);
    let mint = Duration::from_secs(3);
    let password = fixture_password();
    let (iam, _rec, _inv) = iam_with_floor(
        FakeDb {
            password: known_user(&password),
            mint_delay: mint,
            ..Default::default()
        },
        floor,
    )
    .await;
    let p = pki();
    let port = serve_iam_with(&p, "required", iam).await;
    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(&p.ca_pem))
        .domain_name(SERVED_NAME)
        .identity(leaf(&p, GATEWAY_CALLER));
    let channel = Endpoint::from_shared(format!("https://127.0.0.1:{port}"))
        .expect("endpoint")
        .tls_config(tls)
        .expect("tls")
        .connect()
        .await
        .expect("connect to the served iam");

    let attempt = |pw: String, budget: Duration| {
        let mut client = IamServiceClient::new(channel.clone());
        async move {
            let mut req = Request::new(LoginRequest {
                username: "max".into(),
                password: pw,
                label: "laptop".into(),
            });
            req.set_timeout(budget);
            tokio::time::timeout(budget + WEDGED, client.login(req))
                .await
                .expect("the caller's own deadline ends every call")
                .map(drop)
                .map_err(|s| s.code())
        }
    };

    let mut masked = 0;
    for millis in [500, 1_900, 2_300, 3_400, 7_000] {
        let budget = Duration::from_millis(millis);
        let (right, wrong) = tokio::join!(
            attempt(password.clone(), budget),
            attempt(fixture_password(), budget)
        );
        let wrong = wrong.expect_err("a wrong password never signs in");
        match right {
            Ok(()) => {}
            Err(code) => {
                assert_eq!(
                    code, wrong,
                    "at {budget:?} a right password got {code:?} and a wrong one {wrong:?}"
                );
                if code == tonic::Code::Unauthenticated {
                    masked += 1;
                }
            }
        }
    }
    assert!(
        masked > 0,
        "no deadline cut a right password's mint off after the floor, so the \
         masking path was never exercised"
    );
}
