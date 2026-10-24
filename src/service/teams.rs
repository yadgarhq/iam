//! Team access, stage 3 (ADR-0962, ADR-0963, ADR-0966; `docs`
//! `plans/team-access.md`): `SyncTeams`, its seeder gate, and the setting
//! `IAM_ADMIN_FROM_TEAM`.
//!
//! **`SyncTeams` IS THE ONE VERB THE GATEWAY MAY NOT CALL.** Every other verb
//! admits `gateway-caller` only ([`super::caller`], ADR-0972 (1)). This one
//! admits `seeder-caller` only, together with the scope user
//! `yadgar:system:seeder`: ADR-0936's check, the shape `project` gives
//! `SyncProjects`. Neither check is trusted alone (ADR-0942).
//!
//! **`IAM_ADMIN_FROM_TEAM`** says where `is_admin` comes from. False (the
//! chart's shipped value): the `iam_user.is_admin` column, as before. True:
//! membership of the live `yadgar:team:administrators`, which `iam-db`
//! computes. `iam-db` holds no iam setting, so iam relays it as
//! `admin_from_team` on every `ResolveCredential` and `CreateEnrolment`. With
//! it true, `SetUserAdmin` and `CreateUser` with `is_admin: true` are refused
//! here, because a true column would be a second source of admin truth; and
//! `CreateUser` with a `user_id` (F2, the pre-minted first administrator) is
//! admitted to the store. With it false that `user_id` is refused, because the
//! user F2 creates has a false column and could never enrol.

use super::*;
use crate::pb::yadgar::common::v1::Scope;

/// The variable the setting is read from, and the chart key that renders it.
pub const ADMIN_FROM_TEAM_ENV: &str = "IAM_ADMIN_FROM_TEAM";
pub const ADMIN_FROM_TEAM_CHART_KEY: &str = "adminFromTeam";

/// The ONE caller `SyncTeams` admits: the common name on the seeder's client
/// leaf, as `platform` issues it. Compared EXACTLY.
pub const SEEDER_CALLER: &str = "seeder-caller";

/// The seeder's fixed system principal (ADR-0942), the `scope.user_id` a
/// `SyncTeams` call must carry. The literal `project` pins for `SyncProjects`.
pub const SEEDER_PRINCIPAL: &str = "yadgar:system:seeder";

/// What every runtime team verb answers (ADR-0963 (7)).
const TEAMS_DECLARED: &str = "teams are declared in GitOps: AddTeamMember and RemoveTeamMember \
     are retired (ADR-0963 (7)), and SyncTeams from the seeder is the one writer of team \
     membership. Change the seeder's teams declaration instead";

/// `IAM_ADMIN_FROM_TEAM`, exactly as the chart renders it: `true` or `false`.
/// Any other spelling refuses the boot rather than guessing which was meant.
pub fn parse_admin_from_team(raw: &str) -> Result<bool, String> {
    match raw {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(format!(
            "{ADMIN_FROM_TEAM_ENV} is {other:?}, and it must be exactly \"true\" or \"false\". \
             Set the iam chart's {ADMIN_FROM_TEAM_CHART_KEY}"
        )),
    }
}

/// `"yadgar:user:"` followed by a lowercase canonical uuidv7: 36 characters,
/// 8-4-4-4-12 lowercase hex, version nibble `7`, variant `8`, `9`, `a` or `b`
/// (plans/team-access.md §2, §6 step 1). `iam-db` checks the same rule again,
/// because it is the store.
fn is_declared_user_id(id: &str) -> bool {
    let Some(uuid) = id.strip_prefix("yadgar:user:") else {
        return false;
    };
    let b = uuid.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_digit() || (b'a'..=b'f').contains(c),
        })
        && b[14] == b'7'
        && matches!(b[19], b'8' | b'9' | b'a' | b'b')
}

/// ADR-0936's check, for `SyncTeams`. Both refusals are `PERMISSION_DENIED`
/// and both run before the store is asked.
fn admit_seeder(caller: Option<&str>, scope: Option<&Scope>) -> Result<(), Status> {
    if caller != Some(SEEDER_CALLER) {
        return Err(Status::permission_denied(format!(
            "SyncTeams is callable by the seeder only (ADR-0936, ADR-0963 (1)): the client \
             certificate must name {SEEDER_CALLER:?}, and this one names {}",
            caller.map_or_else(|| "no caller".to_string(), |c| format!("{c:?}"))
        )));
    }
    let principal = scope.map(|s| s.user_id.as_str());
    if principal != Some(SEEDER_PRINCIPAL) {
        return Err(Status::permission_denied(format!(
            "SyncTeams from the seeder's leaf must carry scope.user_id {SEEDER_PRINCIPAL:?} \
             (ADR-0942), and this call carries {}",
            principal.map_or_else(|| "no scope".to_string(), |p| format!("{p:?}"))
        )));
    }
    Ok(())
}

/// The telemetry scope of a `SyncTeams` call.
///
/// D67'S JOIN KEY IS THE SEEDER'S `scope.request_id` (ADR-0942), as `project`
/// records `SyncProjects`; the header stands in only when the scope carries
/// none. Capped at this read point, as `request_id_of` caps the header
/// (ledger 1248). The user is the scope's principal, as received.
fn seeder_tel(req: &Request<SyncTeamsRequest>) -> yadgar_telemetry::observe::Scope {
    let scope = req.get_ref().scope.as_ref();
    let request_id = match scope.map(|s| s.request_id.as_str()) {
        Some(id) if !id.is_empty() => capped(id).into_owned(),
        _ => request_id_of(req),
    };
    tel(
        request_id,
        scope.map(|s| s.user_id.as_str()).unwrap_or_default(),
    )
}

impl Iam {
    /// The seeder's gate, then the relay. Gated here and NOT through
    /// [`super::caller`]'s `admitted`, which admits the gateway only.
    pub(super) async fn sync_teams_as(
        &self,
        caller: Option<&str>,
        req: Request<SyncTeamsRequest>,
    ) -> Result<Response<SyncTeamsResponse>, Status> {
        let call = Call::start(SERVICE, "SyncTeams", Kind::Write, seeder_tel(&req));
        if let Err(refusal) = admit_seeder(caller, req.get_ref().scope.as_ref()) {
            metrics::counter!(
                caller::CALLER_REFUSED,
                "caller" => caller.unwrap_or(caller::NO_CALLER).to_string()
            )
            .increment(1);
            tracing::warn!(
                caller = caller.unwrap_or(caller::NO_CALLER),
                "refused a SyncTeams call that is not the seeder's (ADR-0936)"
            );
            call.fail("PERMISSION_DENIED");
            return Err(refusal);
        }
        self.sync_teams_inner(req, call).await
    }

    async fn sync_teams_inner(
        &self,
        req: Request<SyncTeamsRequest>,
        call: Call,
    ) -> Result<Response<SyncTeamsResponse>, Status> {
        // The header first: `into_inner` drops the metadata it is read from.
        let mut upstream = Request::new(db::SyncTeamsRequest::default());
        forward_request_id(&req, &mut upstream);
        // EXHAUSTIVE, so a field added to the contract fails to compile here
        // rather than being dropped on the relay without a word.
        let SyncTeamsRequest { scope, teams } = req.into_inner();
        let teams: Vec<db::DeclaredTeam> = teams
            .into_iter()
            .map(
                |DeclaredTeam {
                     name,
                     member_user_ids,
                 }| db::DeclaredTeam {
                    name,
                    member_user_ids,
                },
            )
            .collect();
        // THE SEEDER'S SCOPE, AS RECEIVED: its `request_id` joins D67's
        // records across the hops (ADR-0942).
        *upstream.get_mut() = db::SyncTeamsRequest { scope, teams };

        // THE STORE'S REFUSAL IS RELAYED WITH ITS MESSAGE, unlike
        // `upstream_failed`. The caller is the seeder, an internal Job: its log
        // line is the operator's only view of WHY a sync was refused (the
        // lockout guard names `administrators`), and a fixed sentence would
        // hide it. `project` relays `SyncProjects` refusals the same way.
        let answer = match self.client().sync_teams(upstream).await {
            Ok(answer) => answer.into_inner(),
            Err(status) => {
                tracing::warn!(
                    code = ?status.code(),
                    db_message = status.message(),
                    "iam-db refused the team sync"
                );
                // The `Call` drops here, as every other upstream refusal's does.
                drop(call);
                return Err(Status::new(status.code(), status.message().to_owned()));
            }
        };

        // EXHAUSTIVE for the same reason as the request.
        let db::SyncTeamsResponse {
            teams_inserted,
            teams_archived,
            teams_reactivated,
            members_added,
            members_removed,
            unknown_member_user_ids,
            pending_administrator_user_ids,
            administrators_live_members,
            changed_user_ids,
        } = answer;

        // AFTER THE COMMIT, ONE EVENT PER USER THE STORE NAMES, and nobody
        // else. Only iam-db knows whom the sync touched: the members it added
        // and removed, and every member of a team it archived or reactivated.
        // A removed member is in no declared team, so the declaration cannot
        // say who to evict; the store's answer can. A failed publish does not
        // fail the sync: the TTL bounds it.
        for user_id in &changed_user_ids {
            self.invalidator.teams_changed(user_id).await;
        }
        call.finish(Outcome {
            status: "OK",
            ..Default::default()
        });
        Ok(Response::new(SyncTeamsResponse {
            teams_inserted,
            teams_archived,
            teams_reactivated,
            members_added,
            members_removed,
            unknown_member_user_ids,
            pending_administrator_user_ids,
            administrators_live_members,
        }))
    }

    /// `SetUserAdmin` while the setting is true: retired, no store call.
    pub(super) fn set_user_admin_retired(&self) -> Option<Status> {
        self.admin_from_team.then(|| {
            Status::failed_precondition(
                "SetUserAdmin is retired while IAM_ADMIN_FROM_TEAM is true: admin is \
                 membership of the declared administrators team (ADR-0962). Declare the \
                 user in the seeder's administrators team instead",
            )
        })
    }

    /// What `CreateUser` refuses for team access, before anything else is
    /// checked and before the store is asked. In this order:
    ///
    /// 1. a non-empty `user_id` that is not a declared user id:
    ///    `INVALID_ARGUMENT`, whatever the setting;
    /// 2. a non-empty `user_id` while the setting is false:
    ///    `FAILED_PRECONDITION`, the message stage 10's VM gate reads;
    /// 3. `is_admin: true` while the setting is true: `FAILED_PRECONDITION`.
    pub(super) fn create_user_refusal(
        &self,
        r: &CreateUserRequest,
    ) -> Option<(Status, &'static str)> {
        if !r.user_id.is_empty() && !is_declared_user_id(&r.user_id) {
            return Some((
                Status::invalid_argument(
                    "user_id must be \"yadgar:user:\" followed by a lowercase canonical \
                     uuidv7 (36 characters, 8-4-4-4-12 hex, version 7, variant 8, 9, a or \
                     b), or empty to mint one",
                ),
                "INVALID_ARGUMENT",
            ));
        }
        if !r.user_id.is_empty() && !self.admin_from_team {
            return Some((
                Status::failed_precondition(
                    "CreateUser with a user_id is the first-administrator arm (ADR-0963 \
                     (5)), and IAM_ADMIN_FROM_TEAM is false. With it false, admin comes \
                     from the is_admin column, which this arm leaves false, so the user it \
                     creates could never enrol as administrator. Set the iam chart's \
                     adminFromTeam to true",
                ),
                "FAILED_PRECONDITION",
            ));
        }
        if r.is_admin && self.admin_from_team {
            return Some((
                Status::failed_precondition(
                    "CreateUser with is_admin true is refused while IAM_ADMIN_FROM_TEAM is \
                     true: admin is then membership of the declared administrators team, \
                     and a true is_admin column would be a second source of admin truth \
                     (ADR-0962). Create the user plainly and declare it in administrators",
                ),
                "FAILED_PRECONDITION",
            ));
        }
        None
    }

    /// `AddTeamMember` and `RemoveTeamMember`, in either setting: retired
    /// (ADR-0963 (7)), no store call, no event.
    pub(super) fn team_verb_retired(call: Call) -> Status {
        call.fail("FAILED_PRECONDITION");
        Status::failed_precondition(TEAMS_DECLARED)
    }

    /// The setting, for the relays on `ResolveCredential` and
    /// `CreateEnrolment`.
    pub(super) fn admin_from_team(&self) -> bool {
        self.admin_from_team
    }
}
