//! Team access stage 3 (plans/team-access.md): `IAM_ADMIN_FROM_TEAM` and what
//! it changes on the verbs that already exist. The F2 `CreateUser` arm, the
//! retired admin and team verbs, and the setting relayed to `iam-db`.
//!
//! Messages and the subject are LITERALS (ADR-0599). The setting-off refusal
//! of a `user_id` is pinned BYTE FOR BYTE: stage 10's VM gate 8 reads it from
//! the gateway's warn line, which carries iam's own refusal unchanged.

use super::*;

const TEAMS_CHANGED: &str = "yadgar.iam.user.teams-changed";

/// A lowercase canonical uuidv7, as the operator mints it.
const DECLARED: &str = "yadgar:user:01920000-0000-7abc-8def-0123456789ab";

/// iam's own refusal for a well-formed `user_id` with the setting false.
const USER_ID_NEEDS_THE_SETTING: &str = "CreateUser with a user_id is the first-administrator \
     arm (ADR-0963 (5)), and IAM_ADMIN_FROM_TEAM is false. With it false, admin comes from \
     the is_admin column, which this arm leaves false, so the user it creates could never \
     enrol as administrator. Set the iam chart's adminFromTeam to true";

fn create(user_id: &str, is_admin: bool) -> Request<CreateUserRequest> {
    Request::new(CreateUserRequest {
        external_id: "first-admin".into(),
        display_name: "First Admin".into(),
        is_admin,
        user_id: user_id.into(),
        ..Default::default()
    })
}

fn calls(rec: &Arc<Mutex<Recorded>>) -> usize {
    rec.lock().expect("recorded").calls
}

/// Stage 2 red 13's malformed ids, one each, plus the empty prefix.
const MALFORMED: [&str; 7] = [
    // uppercase hex
    "yadgar:user:01920000-0000-7ABC-8DEF-0123456789AB",
    // a uuidv4: version nibble 4
    "yadgar:user:01920000-0000-4abc-8def-0123456789ab",
    // variant nibble c
    "yadgar:user:01920000-0000-7abc-cdef-0123456789ab",
    // missing `yadgar:user:` prefix
    "01920000-0000-7abc-8def-0123456789ab",
    // the nil uuid
    "yadgar:user:00000000-0000-0000-0000-000000000000",
    // 35 characters
    "yadgar:user:01920000-0000-7abc-8def-0123456789a",
    // dashes moved
    "yadgar:user:019200000-000-7abc-8def-0123456789ab",
];

/// Red: each malformed `user_id` is `INVALID_ARGUMENT` with no store call,
/// whatever the setting: the format check runs first.
#[tokio::test]
async fn red_06_a_malformed_user_id_is_refused_with_no_store_call() {
    for on in [false, true] {
        for id in MALFORMED {
            let (iam, rec, inv) = iam_admin_from_team(FakeDb::default(), on).await;
            let refused = iam
                .create_user_as(Some(GATEWAY_CALLER), create(id, false))
                .await
                .expect_err(id);
            assert_eq!(refused.code(), tonic::Code::InvalidArgument, "{on} {id}");
            assert!(refused.message().contains("user_id"), "{refused:?}");
            assert_eq!(calls(&rec), 0, "{on} {id}: no store call");
            assert!(inv.published().is_empty());
        }
    }
}

/// Red: a well-formed `user_id` with the setting off is refused
/// `FAILED_PRECONDITION`, no store call, the message pinned byte for byte and
/// naming `IAM_ADMIN_FROM_TEAM`.
#[tokio::test]
async fn red_07_a_user_id_with_the_setting_off_is_refused_byte_for_byte() {
    let (iam, rec, inv) = iam_admin_from_team(FakeDb::default(), false).await;
    let refused = iam
        .create_user_as(Some(GATEWAY_CALLER), create(DECLARED, false))
        .await
        .expect_err("the F2 arm needs the setting");
    assert_eq!(refused.code(), tonic::Code::FailedPrecondition);
    assert_eq!(refused.message(), USER_ID_NEEDS_THE_SETTING);
    assert!(refused.message().contains("IAM_ADMIN_FROM_TEAM"));
    assert_eq!(calls(&rec), 0);
    assert!(inv.published().is_empty());
}

/// Red: with the setting on, the `user_id` reaches the store byte-identical,
/// and one `teams-changed` event follows the create, for that user.
#[tokio::test]
async fn red_08_09_with_the_setting_on_the_user_id_is_relayed_and_one_event_follows() {
    let (iam, rec, inv) = iam_admin_from_team(
        FakeDb {
            create_user_id: Some(DECLARED.into()),
            ..Default::default()
        },
        true,
    )
    .await;
    let made = iam
        .create_user_as(Some(GATEWAY_CALLER), create(DECLARED, false))
        .await
        .expect("relayed")
        .into_inner();
    assert_eq!(made.meta.map(|m| m.id), Some(DECLARED.to_string()));
    let sent = rec.lock().expect("recorded").create_user.clone();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].user_id, DECLARED, "byte-identical");
    assert!(!sent[0].is_admin);
    assert_eq!(inv.published(), vec![(TEAMS_CHANGED, DECLARED.to_string())]);
}

/// Red: no event after a create the store refused.
#[tokio::test]
async fn red_09_no_event_after_a_refused_f2_create() {
    let (iam, rec, inv) = iam_admin_from_team(
        FakeDb {
            create_user_fails: Some((tonic::Code::PermissionDenied, "predicate refused")),
            ..Default::default()
        },
        true,
    )
    .await;
    let refused = iam
        .create_user_as(Some(GATEWAY_CALLER), create(DECLARED, false))
        .await
        .expect_err("the store refused");
    assert_eq!(refused.code(), tonic::Code::PermissionDenied);
    assert_eq!(rec.lock().expect("recorded").create_user.len(), 1);
    assert!(inv.published().is_empty(), "{:?}", inv.published());
}

/// Red: an empty `user_id` relays empty, in both settings, and publishes no
/// team event: an ordinary create joins no team.
#[tokio::test]
async fn red_10_an_empty_user_id_relays_empty() {
    for on in [false, true] {
        let (iam, rec, inv) = iam_admin_from_team(FakeDb::default(), on).await;
        iam.create_user_as(Some(GATEWAY_CALLER), create("", false))
            .await
            .expect("relayed");
        let sent = rec.lock().expect("recorded").create_user.clone();
        assert_eq!(sent.len(), 1, "{on}");
        assert_eq!(sent[0].user_id, "", "{on}");
        assert!(inv.published().is_empty(), "{on}");
    }
}

/// Red: `is_admin: true` with the setting on is `FAILED_PRECONDITION` with no
/// store call; with the setting off it is relayed as today.
#[tokio::test]
async fn red_11_is_admin_true_is_refused_with_the_setting_on_and_relayed_with_it_off() {
    let (iam, rec, _inv) = iam_admin_from_team(FakeDb::default(), true).await;
    let refused = iam
        .create_user_as(Some(GATEWAY_CALLER), create("", true))
        .await
        .expect_err("a second source of admin truth");
    assert_eq!(refused.code(), tonic::Code::FailedPrecondition);
    assert!(
        refused.message().contains("IAM_ADMIN_FROM_TEAM"),
        "{refused:?}"
    );
    assert_eq!(calls(&rec), 0);

    let (iam, rec, _inv) = iam_admin_from_team(FakeDb::default(), false).await;
    iam.create_user_as(Some(GATEWAY_CALLER), create("", true))
        .await
        .expect("relayed as today");
    let sent = rec.lock().expect("recorded").create_user.clone();
    assert_eq!(sent.len(), 1);
    assert!(sent[0].is_admin);
}

/// Red: `SetUserAdmin` works with the setting off and is refused
/// `FAILED_PRECONDITION`, no store call, no event, with it on.
#[tokio::test]
async fn red_05_set_user_admin_works_off_and_is_refused_on() {
    let promote = || {
        Request::new(SetUserAdminRequest {
            user_id: "yadgar:user:1".into(),
            is_admin: true,
            ..Default::default()
        })
    };
    let (iam, rec, inv) = iam_admin_from_team(FakeDb::default(), false).await;
    iam.set_user_admin_as(Some(GATEWAY_CALLER), promote())
        .await
        .expect("off: today's verb");
    assert_eq!(rec.lock().expect("recorded").set_user_admin.len(), 1);
    assert_eq!(inv.published().len(), 1);

    let (iam, rec, inv) = iam_admin_from_team(FakeDb::default(), true).await;
    let refused = iam
        .set_user_admin_as(Some(GATEWAY_CALLER), promote())
        .await
        .expect_err("on: retired");
    assert_eq!(refused.code(), tonic::Code::FailedPrecondition);
    assert!(
        refused.message().contains("IAM_ADMIN_FROM_TEAM"),
        "{refused:?}"
    );
    assert_eq!(calls(&rec), 0);
    assert!(inv.published().is_empty());
}

/// Red: `AddTeamMember` and `RemoveTeamMember` answer `FAILED_PRECONDITION`
/// naming "teams are declared in GitOps", with no store call and no event, in
/// both settings (ADR-0963 (7)).
#[tokio::test]
async fn red_12_the_runtime_team_verbs_are_refused_with_no_store_call() {
    for on in [false, true] {
        let (iam, rec, inv) = iam_admin_from_team(FakeDb::default(), on).await;
        let add = iam
            .add_team_member_as(
                Some(GATEWAY_CALLER),
                Request::new(AddTeamMemberRequest {
                    team_id: "yadgar:team:t1".into(),
                    user_id: "yadgar:user:1".into(),
                    ..Default::default()
                }),
            )
            .await
            .expect_err("retired");
        let remove = iam
            .remove_team_member_as(
                Some(GATEWAY_CALLER),
                Request::new(RemoveTeamMemberRequest {
                    team_id: "yadgar:team:t1".into(),
                    user_id: "yadgar:user:1".into(),
                    ..Default::default()
                }),
            )
            .await
            .expect_err("retired");
        for refused in [add, remove] {
            assert_eq!(refused.code(), tonic::Code::FailedPrecondition, "{on}");
            assert!(
                refused.message().contains("teams are declared in GitOps"),
                "{refused:?}"
            );
        }
        assert_eq!(calls(&rec), 0, "{on}");
        assert!(inv.published().is_empty(), "{on}");
    }
}

/// Red: the setting reaches the store as `admin_from_team` on every
/// `ResolveCredential` and `CreateEnrolment`, `true` when on and `false` when
/// off.
#[tokio::test]
async fn red_13_the_setting_is_relayed_on_resolve_and_on_create_enrolment() {
    for on in [false, true] {
        let (iam, rec, _inv) = iam_admin_from_team(
            FakeDb {
                resolves_to: Some("yadgar:user:1".into()),
                ..Default::default()
            },
            on,
        )
        .await;
        iam.resolve_credential_as(
            Some(GATEWAY_CALLER),
            Request::new(ResolveCredentialRequest {
                token: "a-bearer-token".into(),
            }),
        )
        .await
        .expect("resolve");
        iam.issue_enrolment_as(Some(GATEWAY_CALLER), issue("k-1"))
            .await
            .expect("issue");
        let seen = rec.lock().expect("recorded");
        assert_eq!(seen.resolve_credential.len(), 1);
        assert_eq!(seen.resolve_credential[0].admin_from_team, on);
        assert_eq!(seen.create_enrolment.len(), 1);
        assert_eq!(seen.create_enrolment[0].admin_from_team, on);
    }
}

/// Red: the bootstrap demand AND the revoke instruction reach the store with
/// both fields unchanged, in both settings: iam-db decides the pair by the
/// setting (ADR-0966), iam does not refuse it itself.
#[tokio::test]
async fn red_14_the_demand_and_the_revoke_instruction_travel_together_unchanged() {
    for on in [false, true] {
        let (iam, rec, _inv) = iam_admin_from_team(FakeDb::default(), on).await;
        iam.issue_enrolment_as(
            Some(GATEWAY_CALLER),
            Request::new(IssueEnrolmentRequest {
                user_id: "yadgar:user:1".into(),
                require_zero_credential_admin: true,
                revoke_existing_credentials: true,
                ..Default::default()
            }),
        )
        .await
        .expect("relayed, not refused here");
        let sent = rec.lock().expect("recorded").create_enrolment.clone();
        assert_eq!(sent.len(), 1, "{on}");
        assert!(sent[0].require_zero_credential_admin, "{on}");
        assert!(sent[0].revoke_existing_credentials, "{on}");
        assert_eq!(sent[0].admin_from_team, on);
    }
}

/// The setting is `true` or `false`, exactly as the chart renders it. Any
/// other spelling refuses the boot naming the variable and the chart key.
#[test]
fn the_setting_parses_only_true_and_false() {
    assert_eq!(parse_admin_from_team("true"), Ok(true));
    assert_eq!(parse_admin_from_team("false"), Ok(false));
    for raw in ["", "1", "0", "TRUE", "True", "yes", " true", "on"] {
        let refused = parse_admin_from_team(raw).expect_err(raw);
        assert!(refused.contains("IAM_ADMIN_FROM_TEAM"), "{refused}");
        assert!(refused.contains("adminFromTeam"), "{refused}");
    }
}
