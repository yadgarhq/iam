//! The credential epoch on `Login` and `RedeemEnrolment` (ADR-0972 (4), ledger
//! 1578, train step I1c), and the voided outcome (ADR-0972 (5), ledger 1630).
//!
//! **THE TWIN'S RECORDED MINT IS THE ORACLE.** A mint sent without the epoch is
//! answered `Ok` exactly like one sent with it, so the carry tests read what the
//! fake `iam-db` was asked. The refusal tests compare against a REAL wrong
//! password's answer rather than against literals, so a change to `refused()`
//! cannot leave the two drifting apart.

use super::*;

/// What `iam-db` says when the epoch moved. Its words never reach the caller.
const EPOCH_MOVED: &str = "the account changed since this credential was asked for";

/// The fixed answer to a redemption whose mint lost the race (`iam.proto`).
const PASSWORD_SET_RUN_LOGIN: &str = "your password is set, but the account changed before a \
     credential could be issued; run `yaadgaar login`";

/// A floor long enough to measure and short enough to pay in a test.
const FLOOR: Duration = Duration::from_millis(150);

/// A redemption answer carrying the epoch the store returned.
fn redeemed_at(epoch: u64) -> Option<db::RedeemEnrolmentResponse> {
    redeemed("ada").map(|mut r| {
        r.credential_epoch = epoch;
        r
    })
}

fn minted(rec: &Arc<Mutex<Recorded>>) -> Vec<db::CreateCredentialRequest> {
    rec.lock().expect("recorded").create_credential.clone()
}

// ---- Login -----------------------------------------------------------------

#[tokio::test]
async fn login_carries_the_epoch_it_read_into_the_mint() {
    // BOTH VALUES. 7 catches a constant; 0 catches `(e != 0).then_some(e)`,
    // which reads 0 as "no epoch" — but 0 is a real epoch (every user starts
    // there), and dropping it leaves the race open for every user never reset.
    for epoch in [7, 0] {
        let password = fixture_password();
        let (iam, rec, _inv) = iam_with(FakeDb {
            password: known_user(&password),
            epoch,
            ..Default::default()
        })
        .await;

        iam.login_as(Some(GATEWAY_CALLER), login("ada", &password))
            .await
            .expect("a login");

        let mints = minted(&rec);
        assert_eq!(mints.len(), 1);
        assert_eq!(
            mints[0].expected_credential_epoch,
            Some(epoch),
            "the epoch read with the hash is the one the mint is checked against"
        );
    }
}

#[tokio::test]
async fn a_stale_login_answers_the_same_refusal_as_a_wrong_password() {
    // THE RACE OPENS NO ORACLE. A login that verified the old password and then
    // lost the mint to a reset must be indistinguishable from a wrong password:
    // same code, same message, same floor.
    let password = fixture_password();
    let (iam, rec, _inv) = iam_with_floor(
        FakeDb {
            password: known_user(&password),
            epoch: 3,
            create_credential_fails: Some((tonic::Code::FailedPrecondition, EPOCH_MOVED)),
            ..Default::default()
        },
        FLOOR,
    )
    .await;

    let started = tokio::time::Instant::now();
    let stale = iam
        .login_as(Some(GATEWAY_CALLER), login("ada", &password))
        .await
        .expect_err("the epoch moved");
    let elapsed = started.elapsed();

    let wrong = iam
        .login_as(Some(GATEWAY_CALLER), login("ada", &fixture_password()))
        .await
        .expect_err("a wrong password");

    assert_eq!(stale.code(), wrong.code());
    assert_eq!(stale.message(), wrong.message());
    assert_eq!(stale.code(), tonic::Code::Unauthenticated);
    assert!(
        elapsed >= FLOOR,
        "the stale answer is held to the floor: {elapsed:?} < {FLOOR:?}"
    );
    assert_eq!(minted(&rec).len(), 1, "the mint WAS asked, and refused");
}

// ---- RedeemEnrolment -------------------------------------------------------

#[tokio::test]
async fn redemption_carries_the_epoch_the_store_returned_into_the_mint() {
    let password = fixture_password();
    let (iam, rec, _inv) = iam_with(FakeDb {
        redeem: redeemed_at(9),
        password: known_user(&password),
        ..Default::default()
    })
    .await;

    iam.redeem_enrolment_as(
        Some(GATEWAY_CALLER),
        redeem(&fixture_secret(), &password, "k1"),
    )
    .await
    .expect("a redemption");

    let mints = minted(&rec);
    assert_eq!(mints.len(), 1);
    assert_eq!(mints[0].expected_credential_epoch, Some(9));
}

#[tokio::test]
async fn a_redemption_whose_mint_lost_the_epoch_race_says_password_set_run_login() {
    // The redemption committed: the secret is spent and the password is set.
    // So the answer must not say spent or expired, and must not be the single
    // refusal, which sends the person for an enrolment they do not need.
    let password = fixture_password();
    let (iam, _rec, _inv) = iam_with_redeem_floor(
        FakeDb {
            redeem: redeemed_at(4),
            password: known_user(&password),
            create_credential_fails: Some((tonic::Code::FailedPrecondition, EPOCH_MOVED)),
            ..Default::default()
        },
        FLOOR,
    )
    .await;

    let started = tokio::time::Instant::now();
    let refused = iam
        .redeem_enrolment_as(
            Some(GATEWAY_CALLER),
            redeem(&fixture_secret(), &password, "k1"),
        )
        .await
        .expect_err("the epoch moved");
    let elapsed = started.elapsed();

    assert_eq!(refused.code(), tonic::Code::FailedPrecondition);
    assert_eq!(refused.message(), PASSWORD_SET_RUN_LOGIN);
    let words = refused.message().to_lowercase();
    assert!(!words.contains("spent") && !words.contains("expired"));
    assert_ne!(refused.message(), enrolment_refused().message());
    assert!(
        elapsed >= FLOOR,
        "held to the redeem floor: {elapsed:?} < {FLOOR:?}"
    );
}

#[tokio::test]
async fn a_replay_after_a_bump_rechecks_the_password_then_says_run_login() {
    // ACCEPTED DEVIATION (iam-db#98): a REPLAYED redemption returns the epoch
    // its first delivery recorded, so after any bump the replay's mint is
    // refused. `iam` must still have re-checked the password first — `iam-db`
    // cannot, because it is handed a fresh salted hash on every attempt.
    let password = fixture_password();
    let (iam, rec, _inv) = iam_with(FakeDb {
        redeem: redeemed_at(2),
        password: known_user(&password),
        create_credential_fails: Some((tonic::Code::FailedPrecondition, EPOCH_MOVED)),
        ..Default::default()
    })
    .await;

    let refused = iam
        .redeem_enrolment_as(
            Some(GATEWAY_CALLER),
            redeem(&fixture_secret(), &password, "k1"),
        )
        .await
        .expect_err("a replay after a bump mints nothing");

    assert_eq!(refused.code(), tonic::Code::FailedPrecondition);
    assert_eq!(refused.message(), PASSWORD_SET_RUN_LOGIN);
    let seen = rec.lock().expect("recorded");
    assert_eq!(
        seen.get_password_hash.len(),
        1,
        "the password was re-checked"
    );
    assert_eq!(seen.create_credential[0].expected_credential_epoch, Some(2));
}

#[tokio::test]
async fn a_replay_with_a_different_password_mints_nothing_whatever_epoch_it_carries() {
    // REGRESSION GUARD, green before I1c: the replay check runs before the mint,
    // so the epoch the store returned never reaches a mint for a password that
    // does not match. Pinned with a NONZERO epoch so a reorder that minted first
    // and checked after would be caught.
    let (iam, rec, _inv) = iam_with(FakeDb {
        redeem: redeemed_at(5),
        password: known_user(&fixture_password()),
        ..Default::default()
    })
    .await;

    let refused = iam
        .redeem_enrolment_as(
            Some(GATEWAY_CALLER),
            redeem(&fixture_secret(), &fixture_password(), "k1"),
        )
        .await
        .expect_err("a different password");

    assert_eq!(refused.code(), tonic::Code::InvalidArgument);
    let seen = rec.lock().expect("recorded");
    assert_eq!(seen.get_password_hash.len(), 1, "the password was checked");
    assert!(seen.create_credential.is_empty(), "nothing was minted");
}

#[tokio::test]
async fn a_voided_enrolment_answers_the_same_refusal_as_a_spent_one() {
    // REGRESSION GUARD (ADR-0972 (5)): every outcome but REDEEMED is refused
    // already. Pinned so a future arm for VOIDED cannot give it its own words.
    let mut answers = Vec::new();
    for outcome in [db::RedeemOutcome::Voided, db::RedeemOutcome::Spent] {
        let (iam, rec, _inv) = iam_with(FakeDb {
            redeem: refusal(outcome),
            ..Default::default()
        })
        .await;
        let refused = iam
            .redeem_enrolment_as(
                Some(GATEWAY_CALLER),
                redeem(&fixture_secret(), &fixture_password(), "k1"),
            )
            .await
            .expect_err("refused");
        assert!(minted(&rec).is_empty(), "{outcome:?} mints nothing");
        answers.push((refused.code(), refused.message().to_string()));
    }
    assert_eq!(answers[0], answers[1]);
    assert_eq!(answers[0].0, tonic::Code::Unauthenticated);
}

// ---- IssueCredential -------------------------------------------------------

#[tokio::test]
async fn issue_credential_sends_no_expected_epoch() {
    // An administrative mint reads no epoch, so it checks none (ADR-0972 (4)).
    let (iam, rec, _inv) = iam_with(FakeDb::default()).await;

    iam.issue_credential_as(
        Some(GATEWAY_CALLER),
        Request::new(IssueCredentialRequest {
            user_id: "yadgar:user:1".into(),
            label: "ci".into(),
            ..Default::default()
        }),
    )
    .await
    .expect("an issue");

    assert_eq!(minted(&rec)[0].expected_credential_epoch, None);
}

#[tokio::test]
async fn a_revoking_redemption_whose_mint_lost_the_race_still_evicts() {
    // GUARD (security review of I1c): the store revoked the old credentials in
    // the redemption's transaction, which committed before the mint was
    // refused. The eviction must not depend on the mint landing.
    let password = fixture_password();
    let mut spent = redeemed_at(6);
    if let Some(r) = spent.as_mut() {
        r.revoked_existing_credentials = true;
    }
    let (iam, _rec, inv) = iam_with(FakeDb {
        redeem: spent,
        password: known_user(&password),
        create_credential_fails: Some((tonic::Code::FailedPrecondition, EPOCH_MOVED)),
        ..Default::default()
    })
    .await;

    iam.redeem_enrolment_as(
        Some(GATEWAY_CALLER),
        redeem(&fixture_secret(), &password, "k1"),
    )
    .await
    .expect_err("the epoch moved");

    assert_eq!(
        inv.published(),
        vec![(subject::CREDENTIAL_REVOKED, "yadgar:user:1".to_string())]
    );
}
