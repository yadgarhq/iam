//! `ListCredentials` and the actor on `RevokeCredential` (ledger 1627, train
//! step I1b).
//!
//! **THE TWIN'S RECORDED REQUEST IS THE ORACLE.** A relay that moves the wrong
//! field, or none, answers `Ok` exactly like a working one, so every test here
//! reads what the fake `iam-db` was asked rather than only what `iam` answered.

use super::*;

const LISTED_USER: &str = "yadgar:user:listed";

fn listing(user_id: &str) -> Request<ListCredentialsRequest> {
    Request::new(ListCredentialsRequest {
        user_id: user_id.into(),
        ..Default::default()
    })
}

fn stored(id: &str, label: &str, expires_at: Option<i64>) -> db::Credential {
    db::Credential {
        id: id.into(),
        user_id: LISTED_USER.into(),
        label: label.into(),
        created_at: Some(prost_types::Timestamp {
            seconds: 1_700_000_000,
            nanos: 0,
        }),
        expires_at: expires_at.map(|seconds| prost_types::Timestamp { seconds, nanos: 0 }),
        revoked_at: None,
    }
}

fn twin_listed(rec: &Arc<Mutex<Recorded>>) -> Vec<db::ListCredentialsRequest> {
    rec.lock().expect("recorded").list_credentials.clone()
}

#[tokio::test]
async fn listing_relays_the_request_and_projects_each_row() {
    let (iam, rec, _inv) = iam_with(FakeDb {
        list_answer: db::ListCredentialsResponse {
            credentials: vec![
                stored("yadgar:credential:a", "laptop", None),
                // EXPIRED rows are returned: `expires_at` is what says so.
                stored("yadgar:credential:b", "phone", Some(1_700_000_100)),
            ],
            next_page_token: "yadgar:credential:b".into(),
        },
        ..Default::default()
    })
    .await;

    let got = iam
        .list_credentials_as(
            Some(GATEWAY_CALLER),
            Request::new(ListCredentialsRequest {
                user_id: LISTED_USER.into(),
                page_size: 2,
                page_token: "yadgar:credential:0".into(),
                unverified_actor: Some(UnverifiedActor {
                    user_id: "yadgar:user:admin".into(),
                }),
            }),
        )
        .await
        .expect("a listing")
        .into_inner();

    assert_eq!(
        twin_listed(&rec),
        vec![db::ListCredentialsRequest {
            user_id: LISTED_USER.into(),
            page_size: 2,
            page_token: "yadgar:credential:0".into(),
            // RELAYED (proto v1.21.0 added the field on the iam-db side):
            // exactly as received, never fabricated.
            unverified_actor: Some(UnverifiedActor {
                user_id: "yadgar:user:admin".into(),
            }),
        }],
        "the store must be asked what the caller asked for"
    );
    // `iam.Credential` has no user id, token, hash or revoked_at, so the
    // projection can only carry these four fields.
    assert_eq!(
        got.credentials,
        vec![
            Credential {
                id: "yadgar:credential:a".into(),
                label: "laptop".into(),
                created_at: Some(prost_types::Timestamp {
                    seconds: 1_700_000_000,
                    nanos: 0
                }),
                expires_at: None,
            },
            Credential {
                id: "yadgar:credential:b".into(),
                label: "phone".into(),
                created_at: Some(prost_types::Timestamp {
                    seconds: 1_700_000_000,
                    nanos: 0
                }),
                expires_at: Some(prost_types::Timestamp {
                    seconds: 1_700_000_100,
                    nanos: 0
                }),
            },
        ]
    );
    assert_eq!(got.next_page_token, "yadgar:credential:b");
}

#[tokio::test]
async fn an_empty_list_is_an_ok_with_no_rows_and_no_token() {
    let (iam, rec, _inv) = iam_with(FakeDb::default()).await;

    let got = iam
        .list_credentials_as(Some(GATEWAY_CALLER), listing(LISTED_USER))
        .await
        .expect("an empty listing is an answer")
        .into_inner();

    assert!(got.credentials.is_empty());
    assert_eq!(got.next_page_token, "");
    assert_eq!(twin_listed(&rec).len(), 1, "the store WAS asked");
}

#[tokio::test]
async fn a_revoked_row_the_store_should_have_omitted_is_not_listed() {
    // The contract omits revoked rows. A store that broke that must not turn a
    // tombstone into a live-looking entry here: an entry leaving the list is
    // how a caller sees that a revocation landed.
    let mut revoked = stored("yadgar:credential:gone", "old", None);
    revoked.revoked_at = Some(prost_types::Timestamp {
        seconds: 1_700_000_050,
        nanos: 0,
    });
    let (iam, _rec, _inv) = iam_with(FakeDb {
        list_answer: db::ListCredentialsResponse {
            credentials: vec![revoked, stored("yadgar:credential:live", "new", None)],
            next_page_token: String::new(),
        },
        ..Default::default()
    })
    .await;

    let got = iam
        .list_credentials_as(Some(GATEWAY_CALLER), listing(LISTED_USER))
        .await
        .expect("a listing")
        .into_inner();

    let ids: Vec<_> = got.credentials.iter().map(|c| c.id.as_str()).collect();
    assert_eq!(ids, vec!["yadgar:credential:live"]);
}

#[tokio::test]
async fn a_store_failure_keeps_its_code_and_loses_its_words() {
    for (code, message) in [
        (tonic::Code::Unavailable, "storage unavailable"),
        (tonic::Code::Internal, "table iam_credential is corrupt"),
    ] {
        let (iam, _rec, _inv) = iam_with(FakeDb {
            list_fails: Some((code, message)),
            ..Default::default()
        })
        .await;

        let refused = iam
            .list_credentials_as(Some(GATEWAY_CALLER), listing(LISTED_USER))
            .await
            .expect_err("the store failed");

        assert_eq!(refused.code(), code, "the code survives");
        assert!(
            !refused.message().contains("iam_credential"),
            "storage detail must not reach the caller: {}",
            refused.message()
        );
    }
}

#[tokio::test]
async fn a_refused_listing_request_never_reaches_the_store() {
    let long = "x".repeat(97);
    let cases = [
        ("empty user id", listing("")),
        ("over-long user id", listing(&long)),
        (
            "negative page size",
            Request::new(ListCredentialsRequest {
                user_id: LISTED_USER.into(),
                page_size: -1,
                ..Default::default()
            }),
        ),
        (
            "over-long page token",
            Request::new(ListCredentialsRequest {
                user_id: LISTED_USER.into(),
                page_token: long.clone(),
                ..Default::default()
            }),
        ),
    ];
    for (name, req) in cases {
        let (iam, rec, _inv) = iam_with(FakeDb::default()).await;

        let refused = iam
            .list_credentials_as(Some(GATEWAY_CALLER), req)
            .await
            .expect_err(name);

        assert_eq!(refused.code(), tonic::Code::InvalidArgument, "{name}");
        assert!(
            twin_listed(&rec).is_empty(),
            "{name}: the store was never asked"
        );
    }
}

#[tokio::test]
async fn listing_forwards_the_request_id() {
    let (iam, rec, _inv) = iam_with(FakeDb::default()).await;

    iam.list_credentials_as(
        Some(GATEWAY_CALLER),
        with_request_id(
            ListCredentialsRequest {
                user_id: LISTED_USER.into(),
                ..Default::default()
            },
            "req-list-1",
        ),
    )
    .await
    .expect("a listing");

    assert_eq!(
        rec.lock().expect("recorded").list_request_ids,
        vec![Some("req-list-1".to_string())]
    );
}

#[tokio::test]
async fn a_refused_caller_makes_no_listing_call() {
    let (iam, rec, _inv) = iam_with(FakeDb::default()).await;

    let refused = iam
        .list_credentials_as(Some("task-caller"), listing(LISTED_USER))
        .await
        .expect_err("not the gateway");

    assert_eq!(refused.code(), tonic::Code::PermissionDenied);
    assert!(twin_listed(&rec).is_empty());
    assert_eq!(rec.lock().expect("recorded").calls, 0);
}

#[tokio::test]
async fn revoking_one_credential_relays_the_actor_and_an_absent_one_stays_absent() {
    // MUTATION THIS CATCHES: `unverified_actor: None` on the relay. It answers
    // `Ok` and publishes, so the forwarded request is the only oracle. BOTH ARMS,
    // because fabricating `Some(UnverifiedActor { user_id: "" })` for a caller
    // that named nobody hides an id that was dropped.
    for actor in [
        Some(UnverifiedActor {
            user_id: "yadgar:user:admin".into(),
        }),
        None,
    ] {
        let (iam, rec, _inv) = iam_with(FakeDb::default()).await;

        iam.revoke_credential_as(
            Some(GATEWAY_CALLER),
            Request::new(RevokeCredentialRequest {
                credential_id: "yadgar:credential:fake".into(),
                user_id: "yadgar:user:1".into(),
                unverified_actor: actor.clone(),
                ..Default::default()
            }),
        )
        .await
        .expect("a revocation");

        let seen = rec.lock().expect("recorded");
        assert_eq!(seen.revoke_credential.len(), 1);
        assert_eq!(seen.revoke_credential[0].unverified_actor, actor);
        assert_eq!(
            seen.revoke_credential[0].credential_id,
            "yadgar:credential:fake"
        );
    }
}

// ---------------------------------------------------------------------------
// Ownership on RevokeCredential (ADR-0972 (2), train step I1c).
// ---------------------------------------------------------------------------

/// The owner every ownership test names. NOT the fake's `RevokeCredential` echo
/// `"yadgar:user:1"`, so a handler that published the store's id instead of the
/// one it validated cannot pass by coincidence.
const OWNER: &str = "yadgar:user:owner";

fn revoking(user_id: &str) -> Request<RevokeCredentialRequest> {
    Request::new(RevokeCredentialRequest {
        credential_id: "yadgar:credential:fake".into(),
        user_id: user_id.into(),
        ..Default::default()
    })
}

#[tokio::test]
async fn revoke_credential_refuses_an_empty_user_id_before_any_upstream_call() {
    // MUTATION THIS CATCHES: relaying the request without checking `user_id`.
    // A store that implements the pair check refuses it too, but an `iam-db`
    // too old to read the field would revoke by id alone — the refusal has to
    // be here. Over-long is refused for `check_entity_id`'s column reason.
    let long = "x".repeat(97);
    for (name, user_id) in [("empty", ""), ("over-long", long.as_str())] {
        let (iam, rec, inv) = iam_with(FakeDb::default()).await;

        let refused = iam
            .revoke_credential_as(Some(GATEWAY_CALLER), revoking(user_id))
            .await
            .expect_err(name);

        assert_eq!(refused.code(), tonic::Code::InvalidArgument, "{name}");
        assert_eq!(
            rec.lock().expect("recorded").calls,
            0,
            "{name}: the store must never be asked"
        );
        assert!(inv.published().is_empty(), "{name}: nothing to evict");
    }
}

#[tokio::test]
async fn revoke_credential_relays_the_owner_and_publishes_for_it() {
    let (iam, rec, inv) = iam_with(FakeDb::default()).await;

    iam.revoke_credential_as(Some(GATEWAY_CALLER), revoking(OWNER))
        .await
        .expect("a revocation");

    let seen = rec.lock().expect("recorded");
    assert_eq!(seen.revoke_credential.len(), 1);
    assert_eq!(
        seen.revoke_credential[0].user_id, OWNER,
        "the owner travels"
    );
    // The id VALIDATED here, not the store's echo: the store checked the pair
    // against exactly this value.
    assert_eq!(
        inv.published(),
        vec![(subject::CREDENTIAL_REVOKED, OWNER.to_string())]
    );
}

#[tokio::test]
async fn a_credential_of_another_user_is_not_found_and_nothing_is_published() {
    // The store's NOT_FOUND passes through as NOT_FOUND, with this service's
    // fixed sentence and none of the store's words: the answer for "not yours"
    // and "no such id" is one answer, so the call cannot learn whose a
    // credential is.
    let (iam, rec, inv) = iam_with(FakeDb {
        revoke_fails: Some((
            tonic::Code::NotFound,
            "credential yadgar:credential:fake belongs to yadgar:user:other",
        )),
        ..Default::default()
    })
    .await;

    let refused = iam
        .revoke_credential_as(Some(GATEWAY_CALLER), revoking(OWNER))
        .await
        .expect_err("not the owner's");

    assert_eq!(refused.code(), tonic::Code::NotFound);
    assert_eq!(refused.message(), "no such record");
    assert_eq!(rec.lock().expect("recorded").revoke_credential.len(), 1);
    assert!(
        inv.published().is_empty(),
        "a refused revoke evicts nothing"
    );
}

#[tokio::test]
async fn revoke_all_relays_the_void_count() {
    // ADR-0972 (5). NONZERO, because 0 is prost's default and a handler that
    // dropped the store's number would still answer it.
    let (iam, _rec, _inv) = iam_with(FakeDb {
        revoke_all_answer: 2,
        revoke_all_voided: 3,
        ..Default::default()
    })
    .await;

    let got = iam
        .revoke_all_credentials_as(Some(GATEWAY_CALLER), revoke_all(REVOKE_ALL_USER, None))
        .await
        .expect("a revoke-all")
        .into_inner();

    assert_eq!(got.revoked, 2);
    assert_eq!(got.voided_enrolments, 3, "the store's void count travels");
}
