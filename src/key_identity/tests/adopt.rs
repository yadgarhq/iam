//! The adoption proof and `KEY_IDENTITY_ADOPT` (ADR-1085, ADR-1089), against
//! the same scripted twin as [`super`].
//!
//! Every case reaches the proof the one way production does: `GetKeyIdentity`
//! answers `ABSENT` and `SetKeyIdentity` answers `FAILED_PRECONDITION`.

use super::*;
use crate::crypto::tests::keys_of;
use crate::crypto::Keys;
use crate::key_identity::adopt::{
    proven, Failure, Proof, ADOPTION_UNIMPLEMENTED, NO_EVIDENCE, OBSERVED_FAILED, OBSERVED_PASSED,
    PROOF,
};

const RIGHT: ([u8; 32], [u8; 32]) = ([7u8; 32], [9u8; 32]);

fn right() -> Keys {
    keys_of(RIGHT.0, RIGHT.1)
}

/// One stored row, encrypted and indexed under `keys` exactly as
/// `CreateUser` writes it (`service/admin.rs`).
fn row(keys: &Keys, n: usize) -> db::KeyIdentityEvidence {
    let external_id = format!("Operator-{n}@Example.org");
    db::KeyIdentityEvidence {
        user_id: format!("yadgar:user:{n:04}"),
        external_id_ciphertext: keys.encrypt(&external_id).expect("encrypt"),
        display_name_ciphertext: keys.encrypt(&format!("Operator {n}")).expect("encrypt"),
        external_id_blind_index: keys.blind_index(&external_id),
    }
}

fn rows(keys: &Keys, n: usize) -> Vec<db::KeyIdentityEvidence> {
    (0..n).map(|i| row(keys, i)).collect()
}

fn ids(n: usize) -> Vec<String> {
    (0..n).map(|i| format!("yadgar:user:{i:04}")).collect()
}

/// A populated store with no marker, holding `evidence`, answering Adopt with
/// `adopt`.
fn pre_marker(evidence: Vec<db::KeyIdentityEvidence>, adopt: Vec<Answer>) -> Script {
    Script {
        get: vec![Answer::Outcome(raw(db::KeyIdentityOutcome::Absent))],
        set: vec![Answer::Failed(tonic::Code::FailedPrecondition)],
        evidence,
        adopt,
        ..Default::default()
    }
}

fn identity_in(adoption: Adoption) -> Identity {
    Identity::of(Arc::new(right()), adoption)
}

/// Run the check for [`WINDOW`]: `Ok` is the serve ending, `Err` is a check
/// that is still running — passed and silent, or not passed and asking.
async fn run(script: Script, identity: Identity) -> (Option<Mismatch>, Asked) {
    let (client, asked) = twin(script).await;
    let ended = tokio::time::timeout(WINDOW, watch(client, TEST_CEILING, identity, brisk()))
        .await
        .ok();
    let asked = Arc::try_unwrap(asked)
        .map(|m| m.into_inner().expect("asked"))
        .unwrap_or_else(|m| std::mem::take(&mut *m.lock().expect("asked")));
    (ended, asked)
}

// ---------------------------------------------------------------------------
// THE PROOF ITSELF: A WHITELIST OVER EVERY ROW
// ---------------------------------------------------------------------------

/// Zero rows is no proof, whatever the keys.
#[test]
fn no_rows_is_no_evidence() {
    assert_eq!(proven(&right(), &[]), Proof::NoEvidence);
}

/// Every row passing is `Passed`, carrying every id in the order read.
#[test]
fn every_row_passing_is_passed_with_the_ids_in_order() {
    let keys = right();
    assert_eq!(proven(&keys, &rows(&keys, 5)), Proof::Passed(ids(5)));
}

/// THE ENCRYPTION KEY: rows written under another one fail GCM's tag.
#[test]
fn rows_under_another_encryption_key_fail() {
    let stored = rows(&keys_of([1u8; 32], RIGHT.1), 3);
    let Proof::Failed(failed) = proven(&right(), &stored) else {
        panic!("a wrong encryption key must fail the proof");
    };
    assert_eq!(failed.len(), 3);
    assert!(failed
        .iter()
        .all(|f| f.check == "external_id_ciphertext does not decrypt"));
}

/// **THE BLIND-INDEX KEY, AND ONLY THIS TEST COVERS IT.** The right encryption
/// key decrypts every row; only the recomputed index tells the keys apart.
#[test]
fn the_right_encryption_key_with_another_blind_index_key_fails() {
    let stored = rows(&keys_of(RIGHT.0, [2u8; 32]), 3);
    let Proof::Failed(failed) = proven(&right(), &stored) else {
        panic!("a wrong blind-index key must fail the proof");
    };
    assert_eq!(failed.len(), 3);
    assert!(failed.iter().all(|f| f.check.contains("blind_index")));
}

/// The display name is checked too: a row whose ONLY fault is that ciphertext
/// fails.
#[test]
fn a_bad_display_name_alone_fails() {
    let keys = right();
    let mut stored = rows(&keys, 2);
    let last = stored[1].display_name_ciphertext.len() - 1;
    stored[1].display_name_ciphertext[last] ^= 1;
    assert_eq!(
        proven(&keys, &stored),
        Proof::Failed(vec![Failure {
            user_id: "yadgar:user:0001".into(),
            check: "display_name_ciphertext does not decrypt",
        }])
    );
}

/// **ONE BAD ROW AMONG GOOD ONES FAILS THE WHOLE PROOF**, and is the one
/// named. Reddens under `any` read for `all`.
#[test]
fn one_bad_row_among_good_ones_fails_and_is_named() {
    let keys = right();
    let mut stored = rows(&keys, 10);
    stored[7] = row(&keys_of([3u8; 32], [4u8; 32]), 7);
    let Proof::Failed(failed) = proven(&keys, &stored) else {
        panic!("one bad row must fail the proof");
    };
    assert_eq!(failed.len(), 1);
    assert_eq!(failed[0].user_id, "yadgar:user:0007");
}

/// A ciphertext too short to hold a nonce is a failed row, never a skipped one.
#[test]
fn an_empty_ciphertext_fails() {
    let keys = right();
    let mut stored = rows(&keys, 1);
    stored[0].external_id_ciphertext.clear();
    assert!(matches!(proven(&keys, &stored), Proof::Failed(_)));
}

// ---------------------------------------------------------------------------
// ADOPT MODE THROUGH THE LOOP
// ---------------------------------------------------------------------------

/// **A PROVED STORE IS ADOPTED, AND THEN THE CHECK PASSES.** The ids sent are
/// every row read, in order, under the fingerprint and version asked about,
/// and the D9 key is the adoption arm's own.
#[tokio::test]
async fn a_proved_store_is_adopted_and_then_passes() {
    let keys = right();
    let id = identity_in(Adoption::Adopt);
    let (ended, asked) = run(
        pre_marker(
            rows(&keys, 3),
            vec![Answer::Outcome(raw(db::KeyIdentityOutcome::Recorded))],
        ),
        id.clone(),
    )
    .await;
    assert!(ended.is_none(), "a passed check never ends the serve");
    assert_eq!(asked.get.len(), 1, "a passed check stops asking");
    assert_eq!(asked.adopt.len(), 1);
    let adopt = &asked.adopt[0];
    assert_eq!(adopt.evidence_user_ids, ids(3));
    assert_eq!(adopt.key_fingerprint, id.fingerprint());
    assert_eq!(adopt.derivation_version, DERIVATION_VERSION);
    let key = adopt.idempotency.as_ref().expect("D9 key").key.clone();
    assert_ne!(key, asked.set[0].idempotency.as_ref().expect("D9 key").key);
    assert!(key.starts_with(&format!("iam:key-identity-adopt:v{DERIVATION_VERSION}:")));
}

/// `MATCH` from the adoption arm passes: another replica adopted first.
#[tokio::test]
async fn a_match_from_the_adoption_arm_passes() {
    let keys = right();
    let (ended, asked) = run(
        pre_marker(
            rows(&keys, 2),
            vec![Answer::Outcome(raw(db::KeyIdentityOutcome::Match))],
        ),
        identity_in(Adoption::Adopt),
    )
    .await;
    assert!(ended.is_none());
    assert_eq!(asked.get.len(), 1, "a passed check stops asking");
}

/// **A FAILED PROOF IN ADOPT MODE ENDS THE SERVE AND EXITS NON-ZERO**, and
/// nothing is adopted.
#[tokio::test]
async fn a_failed_proof_in_adopt_mode_ends_the_serve() {
    let (ended, asked) = run(
        pre_marker(rows(&keys_of([1u8; 32], [2u8; 32]), 3), Vec::new()),
        identity_in(Adoption::Adopt),
    )
    .await;
    let refusal = ended.expect("a failed proof has MISMATCH's disposition");
    assert_eq!(refusal.arm, PROOF);
    assert!(refusal.to_string().contains("adoption proof"));
    assert!(Ended::KeyIdentityRefused(refusal).into_exit(false).is_err());
    assert!(asked.adopt.is_empty(), "a failed proof is never adopted");
}

/// `MISMATCH` from the adoption arm ends the serve, as on `SetKeyIdentity`.
#[tokio::test]
async fn a_mismatch_from_the_adoption_arm_ends_the_serve() {
    let keys = right();
    let (ended, _) = run(
        pre_marker(
            rows(&keys, 2),
            vec![Answer::Outcome(raw(db::KeyIdentityOutcome::Mismatch))],
        ),
        identity_in(Adoption::Adopt),
    )
    .await;
    assert_eq!(
        ended.expect("MISMATCH ends the serve").arm,
        "AdoptKeyIdentity"
    );
}

/// `DERIVATION_SKEW`, the zero value, `ABSENT` and an unknown member neither
/// pass nor exit: the check keeps asking.
#[tokio::test]
async fn no_other_adoption_answer_passes_or_exits() {
    let keys = right();
    for outcome in [
        raw(db::KeyIdentityOutcome::DerivationSkew),
        raw(db::KeyIdentityOutcome::Unspecified),
        raw(db::KeyIdentityOutcome::Absent),
        99,
    ] {
        let (ended, asked) = run(
            pre_marker(rows(&keys, 2), vec![Answer::Outcome(outcome)]),
            identity_in(Adoption::Adopt),
        )
        .await;
        assert!(ended.is_none(), "{outcome}: must not end the serve");
        assert!(asked.adopt.len() > 1, "{outcome}: must not pass");
    }
}

/// **ZERO ROWS IS NO PROOF**: never adopted, never passed, never exited, and
/// permanent.
#[tokio::test]
async fn an_empty_evidence_read_is_never_adopted() {
    let (ended, asked) = run(
        pre_marker(Vec::new(), Vec::new()),
        identity_in(Adoption::Adopt),
    )
    .await;
    assert!(ended.is_none());
    assert!(asked.list.len() > 1, "not passed: it keeps asking");
    assert!(asked.adopt.is_empty());
    assert!(NO_EVIDENCE.is_permanent());
}

/// **MORE THAN 64 ROWS: EXACTLY THE 64 OLDEST**, read over several pages, and
/// no page asks for more than the cap.
#[tokio::test]
async fn more_than_the_cap_sends_exactly_the_oldest_cap() {
    let keys = right();
    let mut script = pre_marker(
        rows(&keys, 100),
        vec![Answer::Outcome(raw(db::KeyIdentityOutcome::Recorded))],
    );
    script.page_cap = 30;
    let (_, asked) = run(script, identity_in(Adoption::Adopt)).await;
    assert_eq!(asked.adopt[0].evidence_user_ids, ids(EVIDENCE_CAP));
    assert!(asked.list.len() >= 3, "three pages at thirty a page");
    assert!(asked
        .list
        .iter()
        .all(|r| r.page_size > 0 && r.page_size as usize <= EVIDENCE_CAP));
    assert_eq!(asked.list[0].page_size as usize, EVIDENCE_CAP);
}

/// A PEER THAT SERVES MORE THAN ASKED still yields exactly the 64 oldest:
/// iam-db refuses more than 64 ids, so the cap is this side's to hold.
#[tokio::test]
async fn a_peer_that_over_serves_still_sends_exactly_the_cap() {
    let keys = right();
    let mut script = pre_marker(
        rows(&keys, 100),
        vec![Answer::Outcome(raw(db::KeyIdentityOutcome::Recorded))],
    );
    script.page_fixed = 50;
    let (_, asked) = run(script, identity_in(Adoption::Adopt)).await;
    assert_eq!(asked.adopt[0].evidence_user_ids, ids(EVIDENCE_CAP));
}

/// **AT MOST 64 ROWS: EVERY ROW**, over several pages.
#[tokio::test]
async fn fewer_than_the_cap_over_several_pages_sends_every_row() {
    let keys = right();
    let mut script = pre_marker(
        rows(&keys, 40),
        vec![Answer::Outcome(raw(db::KeyIdentityOutcome::Recorded))],
    );
    script.page_cap = 16;
    let (_, asked) = run(script, identity_in(Adoption::Adopt)).await;
    assert_eq!(asked.adopt[0].evidence_user_ids, ids(40));
    assert_eq!(asked.list.len(), 3);
}

/// **A STATUS ON THE EVIDENCE READ IS NEVER A PROOF FAILURE.**
#[tokio::test]
async fn a_status_on_the_evidence_read_neither_adopts_nor_exits() {
    for code in [tonic::Code::Unavailable, tonic::Code::Unimplemented] {
        let mut script = pre_marker(rows(&right(), 2), Vec::new());
        script.list_fails = Some(code);
        let (ended, asked) = run(script, identity_in(Adoption::Adopt)).await;
        assert!(ended.is_none(), "{code:?}: not a proof failure");
        assert!(asked.list.len() > 1, "{code:?}: retried");
        assert!(asked.adopt.is_empty());
    }
}

/// **A STATUS ON THE ADOPTION ARM IS NOT-PASSED, NEVER A REFUSAL.**
#[tokio::test]
async fn a_status_on_the_adoption_arm_neither_passes_nor_exits() {
    for code in [
        tonic::Code::Unimplemented,
        tonic::Code::FailedPrecondition,
        tonic::Code::Unavailable,
    ] {
        let (ended, asked) = run(
            pre_marker(rows(&right(), 2), vec![Answer::Failed(code)]),
            identity_in(Adoption::Adopt),
        )
        .await;
        assert!(ended.is_none(), "{code:?}: not a refusal");
        assert!(asked.adopt.len() > 1, "{code:?}: not passed");
    }
}

/// `UNIMPLEMENTED` on either adoption RPC names the ADOPTION arm — not the
/// key-identity arm the twin evidently has — and is TRANSIENT, at WARN: it is
/// what every pod sees while `iam-db` is still rolling onto the adoption arm.
#[tokio::test]
async fn unimplemented_names_the_adoption_arm() {
    crate::service::tests::warnings_from_here();
    let mut script = pre_marker(rows(&right(), 2), Vec::new());
    script.list_fails = Some(tonic::Code::Unimplemented);
    let _ = run(script, identity_in(Adoption::Adopt)).await;
    let lines = told_about(ADOPTION_UNIMPLEMENTED.reason);
    assert!(!lines.is_empty(), "an operator is told");
    assert!(lines.iter().all(|line| !line.error), "{lines:?}");
    assert!(!ADOPTION_UNIMPLEMENTED.is_permanent());
    assert!(ADOPTION_UNIMPLEMENTED.reason.contains("adoption RPCs"));
}

/// The adoption-arm lines on this thread, as rendered — level, message and
/// fields.
fn adoption_unimplemented_lines() -> Vec<String> {
    crate::service::tests::warnings()
        .into_iter()
        .filter(|l| l.contains(&format!("reason={}", ADOPTION_UNIMPLEMENTED.reason)))
        .collect()
}

/// **AN `iam-db` STILL ROLLING IS NOT AN INCIDENT (yaadgaar 499).** Seen live:
/// each iam pod's first `ListKeyIdentityEvidence` reached an `iam-db` pod that
/// predated the adoption arm and logged ERROR "no retry will mend it"; the
/// retry 10-12 s later reached a new pod and the dry run PASSED. The loop
/// always retried; only the log claimed it would not help.
///
/// THE ASSERTIONS THAT REDDEN: classifying `ADOPTION_UNIMPLEMENTED` permanent
/// again (the lines become ERROR and carry the permanent sentence); a check
/// that stops at the first answer (`list.len() > 1`).
#[tokio::test]
async fn unimplemented_then_a_passed_dry_run_claims_no_permanence() {
    crate::service::tests::warnings_from_here();
    let mut script = pre_marker(rows(&right(), 2), Vec::new());
    script.list_fails = Some(tonic::Code::Unimplemented);
    script.list_fails_first = 1;
    let (ended, asked) = run(script, identity_in(Adoption::Observe)).await;
    assert!(ended.is_none());
    assert!(asked.list.len() > 1, "the retry reached the evidence");
    let lines = adoption_unimplemented_lines();
    assert!(!lines.is_empty(), "the transient condition is still told");
    for line in &lines {
        assert!(line.starts_with("WARN"), "{line}");
        assert!(!line.contains("no retry will mend"), "{line}");
    }
}

/// The same rollout in `adopt` mode: `AdoptKeyIdentity` answers
/// `UNIMPLEMENTED`, then `RECORDED`, and the check PASSES — it stops asking.
#[tokio::test]
async fn unimplemented_then_an_adoption_passes_and_claims_no_permanence() {
    crate::service::tests::warnings_from_here();
    let (ended, asked) = run(
        pre_marker(
            rows(&right(), 2),
            vec![
                Answer::Failed(tonic::Code::Unimplemented),
                Answer::Outcome(raw(db::KeyIdentityOutcome::Recorded)),
            ],
        ),
        identity_in(Adoption::Adopt),
    )
    .await;
    assert!(ended.is_none());
    assert_eq!(
        asked.adopt.len(),
        2,
        "passed on the retry and stopped asking"
    );
    assert_eq!(asked.get.len(), 2);
    let lines = adoption_unimplemented_lines();
    assert!(!lines.is_empty(), "the transient condition is still told");
    for line in lines {
        assert!(line.starts_with("WARN"), "{line}");
        assert!(!line.contains("no retry will mend"), "{line}");
    }
}

/// **A STANDING `ADOPTION_UNIMPLEMENTED` ESCALATES TO ERROR ON ITS FIRST
/// RESTATEMENT.** An `iam-db` with the key-identity arm and without the adoption
/// arm is a permanent state, and a WARN for ever would hide it. A rollout clears
/// in seconds and never reaches [`RESTATE_AFTER`]; a reason that has stood that
/// long is not a rollout.
///
/// Forty `UNIMPLEMENTED` answers, then evidence under ANOTHER key in `adopt`
/// mode: the failed proof ends the loop, so the script bounds it exactly.
///
/// THE ASSERTIONS THAT REDDEN: no escalation (no ERROR line); escalation
/// without the elapsed guard (the first line is ERROR).
#[tokio::test]
async fn a_standing_adoption_unimplemented_escalates_to_error_on_restatement() {
    const ATTEMPTS: usize = 40;
    let mut script = pre_marker(rows(&keys_of([3u8; 32], [4u8; 32]), 2), Vec::new());
    script.list_fails = Some(tonic::Code::Unimplemented);
    script.list_fails_first = ATTEMPTS;
    let (channel, asked) = twin_channel(script).await;
    crate::service::tests::warnings_from_here();
    tokio::time::pause();
    let refusal = watch_with_seed(
        IamDbServiceClient::new(channel),
        TEST_CEILING,
        identity_in(Adoption::Adopt),
        Retry::of(Duration::from_secs(100), Duration::from_secs(100)),
        0x5eed_5eed_5eed_5eed,
    )
    .await;
    tokio::time::resume();
    assert_eq!(refusal.arm, PROOF);
    assert_eq!(asked.lock().expect("asked").list.len(), ATTEMPTS + 1);

    let lines = told_about(ADOPTION_UNIMPLEMENTED.reason);
    assert!(lines.len() > 1, "restated: {lines:?}");
    assert!(
        !lines[0].error,
        "the first line is a rollout until shown otherwise"
    );
    assert!(lines[1..].iter().all(|l| l.error), "{lines:?}");
    assert!(
        lines[1..]
            .iter()
            .all(|l| l.standing_for_secs >= RESTATE_AFTER.as_secs()),
        "{lines:?}"
    );
}

/// **THE ESCALATION IS `ADOPTION_UNIMPLEMENTED`'s ALONE.** An unreachable twin
/// that stands just as long stays WARN on every restatement: it is an outage
/// the dial already reports, not a version gap.
///
/// THE ASSERTION THAT REDDENS: escalating every transient reason that stands.
#[tokio::test]
async fn a_standing_unavailable_twin_is_never_escalated() {
    const ATTEMPTS: usize = 40;
    let mut get = vec![Answer::Failed(tonic::Code::Unavailable); ATTEMPTS];
    get.push(Answer::Outcome(raw(db::KeyIdentityOutcome::Mismatch)));
    let (channel, _) = twin_channel(Script {
        get,
        ..Default::default()
    })
    .await;
    crate::service::tests::warnings_from_here();
    tokio::time::pause();
    let _ = watch_with_seed(
        IamDbServiceClient::new(channel),
        TEST_CEILING,
        identity_in(Adoption::Adopt),
        Retry::of(Duration::from_secs(100), Duration::from_secs(100)),
        0x5eed_5eed_5eed_5eed,
    )
    .await;
    tokio::time::resume();
    let lines = told_about(Unverified::of_status(tonic::Code::Unavailable).reason);
    assert!(lines.len() > 1, "restated: {lines:?}");
    assert!(lines.iter().all(|l| !l.error), "{lines:?}");
}

/// Only `SetKeyIdentity`'s `FAILED_PRECONDITION` leads to the proof: the same
/// code on the read arm never lists evidence.
#[tokio::test]
async fn failed_precondition_on_the_read_never_lists_evidence() {
    let (ended, asked) = run(
        Script {
            get: vec![Answer::Failed(tonic::Code::FailedPrecondition)],
            evidence: rows(&right(), 2),
            ..Default::default()
        },
        identity_in(Adoption::Adopt),
    )
    .await;
    assert!(ended.is_none());
    assert!(asked.list.is_empty());
    assert!(asked.adopt.is_empty());
}

// ---------------------------------------------------------------------------
// OBSERVE MODE: THE DRY RUN NEVER WRITES AND NEVER EXITS
// ---------------------------------------------------------------------------

/// **OBSERVE NEVER CALLS ADOPT, EVEN ON A PASSED PROOF**, and the pod stays
/// UNVERIFIED — still asking. The outcome is INFO, never the ERROR of an
/// incident.
#[tokio::test]
async fn observe_never_adopts_on_a_passed_proof() {
    crate::service::tests::warnings_from_here();
    let keys = right();
    let (ended, asked) = run(
        pre_marker(
            rows(&keys, 3),
            vec![Answer::Outcome(raw(db::KeyIdentityOutcome::Recorded))],
        ),
        identity_in(Adoption::Observe),
    )
    .await;
    assert!(ended.is_none());
    assert!(asked.adopt.is_empty(), "observe never adopts");
    assert!(
        asked.get.len() > 1,
        "observe stays UNVERIFIED and keeps asking"
    );
    assert!(asked.list.len() > 1);
    assert!(
        told_about(OBSERVED_PASSED).is_empty(),
        "a passed dry run is INFO, below the WARN tap"
    );
}

/// **OBSERVE NEVER EXITS ON A FAILED PROOF**, never adopts, and WARNs naming
/// the failing row.
#[tokio::test]
async fn observe_never_exits_on_a_failed_proof() {
    crate::service::tests::warnings_from_here();
    let keys = right();
    let mut stored = rows(&keys, 3);
    stored[1] = row(&keys_of([3u8; 32], [4u8; 32]), 1);
    let (ended, asked) = run(
        pre_marker(stored, Vec::new()),
        identity_in(Adoption::Observe),
    )
    .await;
    assert!(ended.is_none(), "observe never ends the serve");
    assert!(asked.adopt.is_empty());
    let lines: Vec<String> = crate::service::tests::warnings()
        .into_iter()
        .filter(|l| l.contains(&format!("reason={OBSERVED_FAILED}")))
        .collect();
    assert!(!lines.is_empty(), "an operator is told");
    assert!(lines.iter().all(|l| l.starts_with("WARN")), "{lines:?}");
    assert!(lines[0].contains("yadgar:user:0001") && lines[0].contains("rows=3"));
    assert!(!lines[0].contains("yadgar:user:0000"));
}

// ---------------------------------------------------------------------------
// THE KNOB
// ---------------------------------------------------------------------------

/// Exactly `observe` or `adopt`; every other spelling names the variable and
/// the chart key.
#[test]
fn the_mode_parses_only_observe_and_adopt() {
    assert_eq!(Adoption::parse("observe"), Ok(Adoption::Observe));
    assert_eq!(Adoption::parse("adopt"), Ok(Adoption::Adopt));
    for bad in ["", "Observe", "ADOPT", "true", "dry-run", " adopt"] {
        let refusal = Adoption::parse(bad).expect_err(bad);
        assert!(refusal.contains("KEY_IDENTITY_ADOPT") && refusal.contains("keyIdentity.adopt"));
    }
}
