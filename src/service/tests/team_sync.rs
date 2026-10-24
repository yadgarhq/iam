//! Team access stage 3 (plans/team-access.md): `SyncTeams`, its seeder gate,
//! the relay, and the `yadgar.iam.user.teams-changed` events after it.
//!
//! The plan's red cases are numbered here as the PR body lists them. The
//! subject and the principal are LITERALS (ADR-0599): asserted through the
//! constants that produce them, a rename would pass straight through.

use super::*;
use crate::pb::yadgar::common::v1::Scope;

/// The subject the gateway subscribes to, as the broker permits it.
const TEAMS_CHANGED: &str = "yadgar.iam.user.teams-changed";

const SEEDER_LEAF: &str = "seeder-caller";
const SEEDER_USER: &str = "yadgar:system:seeder";

const ALICE: &str = "yadgar:user:01920000-0000-7000-8000-000000000001";
const BOB: &str = "yadgar:user:01920000-0000-7000-8000-000000000002";
const CAROL: &str = "yadgar:user:01920000-0000-7000-8000-000000000003";
const PENDING: &str = "yadgar:user:01920000-0000-7000-8000-00000000000a";
const UNKNOWN: &str = "yadgar:user:01920000-0000-7000-8000-00000000000b";

fn scope(user_id: &str) -> Option<Scope> {
    Some(Scope {
        user_id: user_id.into(),
        request_id: "01920000-0000-7000-8000-0000000000ff".into(),
        ..Default::default()
    })
}

fn team(name: &str, members: &[&str]) -> DeclaredTeam {
    DeclaredTeam {
        name: name.into(),
        member_user_ids: members.iter().map(|m| m.to_string()).collect(),
    }
}

fn declaration(scope: Option<Scope>) -> Request<SyncTeamsRequest> {
    Request::new(SyncTeamsRequest {
        scope,
        teams: vec![
            team("administrators", &[ALICE, PENDING]),
            team("estate-runners", &[BOB, ALICE, UNKNOWN]),
            team("empty", &[]),
        ],
    })
}

fn calls(rec: &Arc<Mutex<Recorded>>) -> usize {
    rec.lock().expect("recorded").calls
}

/// Red 1: every caller but the seeder's leaf is refused, the gateway's leaf
/// included, before any store call. `None` is the trait method's bare request
/// (no peer chain) and the gate's own `None` arm.
#[tokio::test]
async fn red_01_a_non_seeder_leaf_is_refused_before_any_store_call() {
    for caller in [Some(GATEWAY_CALLER), Some("task-caller"), None] {
        let (iam, rec, inv) = iam_with(FakeDb::default()).await;
        let refused = iam
            .sync_teams_as(caller, declaration(scope(SEEDER_USER)))
            .await
            .expect_err("only the seeder's leaf is admitted");
        assert_eq!(refused.code(), tonic::Code::PermissionDenied, "{caller:?}");
        assert!(refused.message().contains(SEEDER_LEAF), "{refused:?}");
        assert_eq!(calls(&rec), 0, "{caller:?}: refused before the store");
        assert!(inv.published().is_empty());
    }
    let (iam, rec, _inv) = iam_with(FakeDb::default()).await;
    let refused = IamService::sync_teams(&iam, declaration(scope(SEEDER_USER)))
        .await
        .expect_err("a bare request carries no leaf");
    assert_eq!(refused.code(), tonic::Code::PermissionDenied);
    assert_eq!(calls(&rec), 0);
}

/// Red 2: the seeder's leaf with any other scope user, or no scope, is
/// refused: neither check is trusted alone (ADR-0936, ADR-0942).
#[tokio::test]
async fn red_02_the_seeder_leaf_with_a_non_seeder_scope_user_is_refused() {
    for scope in [scope("yadgar:user:1"), scope(""), None] {
        let (iam, rec, _inv) = iam_with(FakeDb::default()).await;
        let refused = iam
            .sync_teams_as(Some(SEEDER_LEAF), declaration(scope.clone()))
            .await
            .expect_err("the seeder's principal is required");
        assert_eq!(refused.code(), tonic::Code::PermissionDenied, "{scope:?}");
        assert!(refused.message().contains(SEEDER_USER), "{refused:?}");
        assert_eq!(calls(&rec), 0, "{scope:?}: refused before the store");
    }
}

/// THE POSITIVE CONTROL for reds 1 and 2, and the relay: the seeder is
/// admitted, the declaration and the scope reach the store unchanged, and
/// every count of the answer comes back.
#[tokio::test]
async fn the_seeder_is_admitted_and_the_sync_is_relayed_field_for_field() {
    let answer = db::SyncTeamsResponse {
        teams_inserted: 1,
        teams_archived: 2,
        teams_reactivated: 3,
        members_added: 4,
        members_removed: 5,
        unknown_member_user_ids: vec![UNKNOWN.into()],
        pending_administrator_user_ids: vec![PENDING.into()],
        administrators_live_members: 6,
        changed_user_ids: vec![ALICE.into()],
    };
    let (iam, rec, _inv) = iam_with(FakeDb {
        sync_answer: answer,
        ..Default::default()
    })
    .await;
    let got = iam
        .sync_teams_as(Some(SEEDER_LEAF), declaration(scope(SEEDER_USER)))
        .await
        .expect("the seeder is admitted")
        .into_inner();
    assert_eq!(
        got,
        SyncTeamsResponse {
            teams_inserted: 1,
            teams_archived: 2,
            teams_reactivated: 3,
            members_added: 4,
            members_removed: 5,
            unknown_member_user_ids: vec![UNKNOWN.into()],
            pending_administrator_user_ids: vec![PENDING.into()],
            administrators_live_members: 6,
        }
    );
    let sent = rec.lock().expect("recorded").sync_teams.clone();
    assert_eq!(sent.len(), 1);
    assert_eq!(
        sent[0].scope,
        scope(SEEDER_USER),
        "the seeder's scope, as received"
    );
    let teams: Vec<(String, Vec<String>)> = sent[0]
        .teams
        .iter()
        .map(|t| (t.name.clone(), t.member_user_ids.clone()))
        .collect();
    assert_eq!(
        teams,
        vec![
            ("administrators".into(), vec![ALICE.into(), PENDING.into()]),
            (
                "estate-runners".into(),
                vec![BOB.into(), ALICE.into(), UNKNOWN.into()]
            ),
            ("empty".into(), vec![]),
        ]
    );
}

/// Red 3: one event per id in the store's `changed_user_ids`, on the literal
/// subject, and none for anyone else. CAROL is in no declared team (a removed
/// member, or a member of an archived team): she is evicted because the store
/// names her. BOB is declared and unchanged: no event.
#[tokio::test]
async fn red_03_one_event_per_changed_user_and_none_for_any_other() {
    let (iam, _rec, inv) = iam_with(FakeDb {
        sync_answer: db::SyncTeamsResponse {
            members_added: 1,
            members_removed: 1,
            changed_user_ids: vec![ALICE.into(), CAROL.into()],
            unknown_member_user_ids: vec![UNKNOWN.into()],
            pending_administrator_user_ids: vec![PENDING.into()],
            ..Default::default()
        },
        ..Default::default()
    })
    .await;
    iam.sync_teams_as(Some(SEEDER_LEAF), declaration(scope(SEEDER_USER)))
        .await
        .expect("admitted");
    assert_eq!(
        inv.published(),
        vec![
            (TEAMS_CHANGED, ALICE.to_string()),
            (TEAMS_CHANGED, CAROL.to_string()),
        ],
        "exactly the store's changed set, in its order"
    );
}

/// Red 3, the other half: the counts say nothing about whom to evict. A sync
/// whose store names no changed user publishes nothing, whatever the counts.
#[tokio::test]
async fn red_03_no_event_when_the_store_names_no_changed_user() {
    let (iam, _rec, inv) = iam_with(FakeDb {
        sync_answer: db::SyncTeamsResponse {
            teams_inserted: 1,
            teams_archived: 1,
            teams_reactivated: 1,
            members_added: 1,
            members_removed: 1,
            administrators_live_members: 1,
            ..Default::default()
        },
        ..Default::default()
    })
    .await;
    iam.sync_teams_as(Some(SEEDER_LEAF), declaration(scope(SEEDER_USER)))
        .await
        .expect("admitted");
    assert!(inv.published().is_empty(), "{:?}", inv.published());
}

/// D67's join (ADR-0942): iam's `CallRecord` for `SyncTeams` carries the
/// seeder's `scope.request_id` and principal, with no header on the call.
#[tokio::test]
async fn sync_teams_records_the_seeders_scope_request_id() {
    let (iam, _rec, _inv) = iam_with(FakeDb::default()).await;
    let record =
        the_call_record(iam.sync_teams_as(Some(SEEDER_LEAF), declaration(scope(SEEDER_USER))))
            .await;
    assert!(
        carries(&record, "01920000-0000-7000-8000-0000000000ff"),
        "the seeder's request id: {record}"
    );
    assert!(
        record.contains(r#""user_id":"yadgar:system:seeder""#),
        "{record}"
    );
}

/// Red 4: no event when the store refuses, and the store's refusal reaches
/// the seeder with its code AND its message: the lockout guard's sentence is
/// the operator's only view of why the sync was refused.
#[tokio::test]
async fn red_04_no_event_when_the_store_refuses_and_the_refusal_is_relayed() {
    let (iam, rec, inv) = iam_with(FakeDb {
        sync_fails: Some((
            tonic::Code::FailedPrecondition,
            "the sync would leave administrators with zero live members",
        )),
        sync_answer: db::SyncTeamsResponse {
            members_added: 1,
            changed_user_ids: vec![ALICE.into()],
            ..Default::default()
        },
        ..Default::default()
    })
    .await;
    let refused = iam
        .sync_teams_as(Some(SEEDER_LEAF), declaration(scope(SEEDER_USER)))
        .await
        .expect_err("the store refused");
    assert_eq!(refused.code(), tonic::Code::FailedPrecondition);
    assert_eq!(
        refused.message(),
        "the sync would leave administrators with zero live members"
    );
    assert_eq!(rec.lock().expect("recorded").sync_teams.len(), 1);
    assert!(inv.published().is_empty(), "{:?}", inv.published());
}

/// An `iam-db` built from a contract WITHOUT `SyncTeams` (iam-db origin/main
/// before team access stage 2). The fake twin behind it implements the verb,
/// so the wrapper sends a `SyncTeams` call to a method name the generated
/// server does not know. The answer is then tonic-build's own unknown-method
/// arm, the code an older `iam-db` runs for `SyncTeams`, and not a scripted
/// refusal from a trait method.
#[derive(Clone)]
struct StoreWithoutSyncTeams(IamDbServiceServer<FakeDb>);

impl tonic::server::NamedService for StoreWithoutSyncTeams {
    const NAME: &'static str = "yadgar.iamdb.v1.IamDbService";
}

impl tonic::codegen::Service<http::Request<tonic::body::Body>> for StoreWithoutSyncTeams {
    type Response = http::Response<tonic::body::Body>;
    type Error = std::convert::Infallible;
    type Future = tonic::codegen::BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        tonic::codegen::Service::<http::Request<tonic::body::Body>>::poll_ready(&mut self.0, cx)
    }

    fn call(&mut self, mut req: http::Request<tonic::body::Body>) -> Self::Future {
        if req.uri().path() == "/yadgar.iamdb.v1.IamDbService/SyncTeams" {
            *req.uri_mut() =
                http::Uri::from_static("/yadgar.iamdb.v1.IamDbService/NotInThisContract");
        }
        self.0.call(req)
    }
}

/// Red 15 (merge order, iam#118 ahead of iam-db#104): against a store whose
/// contract has no `SyncTeams`, the seeder is answered `UNIMPLEMENTED`, the
/// store's own code relayed, and nobody is evicted. The fake is never asked.
#[tokio::test]
async fn red_15_a_store_without_sync_teams_answers_unimplemented_and_nobody_is_evicted() {
    let fake = FakeDb {
        sync_answer: db::SyncTeamsResponse {
            members_added: 1,
            changed_user_ids: vec![ALICE.into()],
            ..Default::default()
        },
        ..Default::default()
    };
    let rec = fake.recorded.clone();
    let addr = free_port();
    tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(StoreWithoutSyncTeams(IamDbServiceServer::new(fake)))
            .serve(addr)
            .await;
    });
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
        .expect("connect");
    let inv = Invalidator::connect(None, None, None).await;
    let iam = Iam::new(
        crate::crypto::tests::keys(),
        channel,
        inv.clone(),
        ResponseFloors {
            login: NOMINAL_FLOOR,
            redeem: NOMINAL_FLOOR,
        },
        enrolment_config(),
        test_lifetime(),
        false,
    );

    let refused = iam
        .sync_teams_as(Some(SEEDER_LEAF), declaration(scope(SEEDER_USER)))
        .await
        .expect_err("a store without the verb cannot sync");
    assert_eq!(refused.code(), tonic::Code::Unimplemented, "{refused:?}");
    assert_eq!(
        calls(&rec),
        0,
        "the generated server answered, not the fake"
    );
    assert!(inv.published().is_empty(), "{:?}", inv.published());
}
