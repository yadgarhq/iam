//! The two settings an administrator writes: an inherited setting and a
//! rate-limit override.

use super::validate::*;
use super::*;

/// The one member of the setting vocabulary (ADR-0522).
///
/// A CLOSED SET, ENFORCED RATHER THAN DOCUMENTED. A store that accepted free
/// text would accrete settings nothing reads, and a typo would be persisted as a
/// new setting instead of being refused at the call that made it. Adding a
/// member is a contract release, never a data change.
const OWNER_READS_OWN_RECORD: &str = "owner_reads_own_record";

/// Every clause `yadgar.common.v1.SettingScope` states, applied HERE.
///
/// **THE VALIDATION IS THE CONTRACT'S AND IS STATED ONCE, THERE.** This function
/// applies it and deliberately does not restate the reasoning: two normative
/// copies in two files must stay in step for ever, and the copy that drifts is
/// the one a reader happens to open. Each refusal below names the clause it
/// enforces so a reader can find it, and every one is `INVALID_ARGUMENT`.
///
/// **IT RUNS BEFORE THE STORE IS CALLED**, which is what makes `iam` refuse
/// these itself rather than forward them. A refused request leaves no row and
/// burns no idempotency key.
///
/// **WHAT IT DELIBERATELY DOES NOT REFUSE: a `value` holding a number this
/// contract does not name.** The clause list is closed, and it names non-member
/// refusal for `scope` ALONE — because a `switch` on the scope whose `default:`
/// falls through writes the ORGANISATION's policy for a request that named
/// neither level. `iam` does not interpret `value` at all, so it has no such
/// fall-through, and adding a refusal `iam-db` does not share would make the two
/// boundaries disagree about one request. The number is copied through and the
/// store applies its own check (D5: one RPC is one transaction, so a refusal
/// there changes nothing).
fn check_inherited_setting(r: &SetInheritedSettingRequest) -> Result<(), Status> {
    // `scope` IS NOT ONE OF THE MEMBERS THIS ENUM DECLARES. proto3 enums are
    // open, so an unrecognised number arrives intact rather than collapsing to
    // the zero — and it must not be treated as either level.
    let scope = SettingScope::try_from(r.scope).map_err(|_| {
        Status::invalid_argument(
            "scope names no level this contract declares; there are two, an \
             organisation and a team",
        )
    })?;

    match scope {
        SettingScope::Unspecified => {
            return Err(Status::invalid_argument(
                "scope is required: a write addresses the organisation's level \
                 or one team's, and neither is the default",
            ));
        }
        SettingScope::Org => {
            // There is ONE organisation (D27), so a team id here is a caller
            // that meant TEAM.
            if r.team_id.is_some() {
                return Err(Status::invalid_argument(
                    "a team id at organisation scope is a request that meant \
                     team scope; there is one organisation and it is not named",
                ));
            }
            // Every default is wrong: false is the unsafe direction, true locks
            // a deployment that never asked, and keeping the stored value stops
            // the verb from stating a wanted result.
            if r.locked.is_none() {
                return Err(Status::invalid_argument(
                    "locked is required at organisation scope: it has no safe \
                     default, and an unstated lock is the permissive half of a \
                     policy nobody chose",
                ));
            }
            // The organisation always holds a value — the resolution's first
            // step refuses an unset one — so there is nothing there to clear.
            if r.clear {
                return Err(Status::invalid_argument(
                    "the organisation's value cannot be cleared: it always \
                     holds one, and a deployment changes it by stating the \
                     other value",
                ));
            }
        }
        SettingScope::Team => {
            // Nothing names the row to write. ABSENT and PRESENT-AND-EMPTY are
            // two cases, and this boundary has to refuse the second.
            if !r.team_id.as_deref().is_some_and(|t| !t.is_empty()) {
                return Err(Status::invalid_argument(
                    "a team id is required at team scope: nothing else names \
                     the override to write",
                ));
            }
            // The lock is meaningful at organisation scope only, and `false`
            // silently discarded is exactly the case this refusal exists for.
            if r.locked.is_some() {
                return Err(Status::invalid_argument(
                    "locked is meaningful at organisation scope only: a team \
                     cannot state whether teams may override",
                ));
            }
        }
    }

    // SENT EXPLICITLY, THE ZERO IS STILL A REFUSAL AND NEVER A CLEAR — at either
    // scope. It is what a caller that populated nothing sends.
    if r.value == Some(SettingValue::Unspecified as i32) {
        return Err(Status::invalid_argument(
            "value was sent unspecified: that is what an unpopulated field \
             looks like, and it is never read as a value or as a withdrawal",
        ));
    }

    // AN OMITTED VALUE CAN NEVER BE READ AS A DELETION (ADR-0524).
    if r.value.is_none() && !r.clear {
        return Err(Status::invalid_argument(
            "value is required unless clear is set: a request that states \
             neither says nothing at all",
        ));
    }

    // Two contradicting instructions, and neither is the obvious one to discard.
    if r.clear && r.value.is_some() {
        return Err(Status::invalid_argument(
            "clear and value contradict each other: withdraw the override or \
             state one, never both in the same request",
        ));
    }

    if r.name != OWNER_READS_OWN_RECORD {
        return Err(Status::invalid_argument(
            "name is not a setting this contract declares; the vocabulary is \
             closed and adding to it is a contract release",
        ));
    }
    check_inherited_setting_widths(r)
}

/// The two widths `iam_inherited_setting_write` is declared to hold.
///
/// SEPARATE FROM [`check_inherited_setting`] BECAUSE ITS OWN COMMENT ALREADY
/// SAYS THEY ARE SEPARATE — everything above is a clause
/// `yadgar.common.v1.SettingScope` states and this service applies, and these
/// two are neither the contract's nor that scope's. Keeping them in a function
/// of their own is the same argument as keeping them last, made once more.
fn check_inherited_setting_widths(r: &SetInheritedSettingRequest) -> Result<(), Status> {
    // THE STORE'S WIDTHS, AND DELIBERATELY LAST. Everything above is a clause
    // `yadgar.common.v1.SettingScope` states and this service applies; the two
    // below are neither the contract's nor this scope's, they are what
    // `iam_inherited_setting_write` is declared to hold. Keeping them apart is
    // what stops a reader from taking a column width for a contract rule.
    //
    // `name` NEEDS NO SUCH CHECK: the closed vocabulary above already pins it to
    // one 22-character value, well inside its `VARCHAR(64)`.
    check_idempotency_key(r.idempotency.as_ref().map_or("", |i| i.key.as_str()))?;
    // THE WITHDRAWAL IS THE REACHABLE ARM, and both arms are checked anyway. On
    // the SETTING arm `iam-db` consults `live_team` first, so an over-long id is
    // already `NOT_FOUND`; a WITHDRAWAL is a `DELETE` that matches nothing, and
    // the ledger INSERT after it is where the id meets `team_id VARCHAR(96)` and
    // the call comes back as a storage outage. Refusing both makes the answer
    // independent of `clear`, and `INVALID_ARGUMENT` is the truer of the two: a
    // 97-character string is not a team that is missing, it is not a team id.
    if let Some(team_id) = r.team_id.as_deref() {
        check_entity_id("team_id", team_id)?;
    }

    Ok(())
}

impl Iam {
    pub(super) async fn set_inherited_setting_inner(
        &self,
        req: Request<SetInheritedSettingRequest>,
        call: Call,
    ) -> Result<Response<SetInheritedSettingResponse>, Status> {
        if let Err(refusal) = check_inherited_setting(req.get_ref()) {
            call.fail("INVALID_ARGUMENT");
            return Err(refusal);
        }

        let r = req.get_ref();
        // FIELD BY FIELD ONLY BECAUSE THE TWO REQUEST TYPES ARE DIFFERENT — one
        // per boundary, as every other forwarded write here is. `value` and
        // `locked` are copied with their PRESENCE intact: absence is a distinct
        // instruction from any value, and collapsing it would make `clear` the
        // only way this service can express a withdrawal (ADR-0524).
        let mut upstream = Request::new(db::SetInheritedSettingRequest {
            idempotency: r.idempotency.clone(),
            scope: r.scope,
            team_id: r.team_id.clone(),
            name: r.name.clone(),
            value: r.value,
            locked: r.locked,
            clear: r.clear,
            // NOT FORWARDED, for the reason given at IssueEnrolment above: the
            // field is new in proto v1.10.0, no caller sets it, and the
            // upstream this forwards to still vendors v1.8.0 and has no field
            // to receive it. See the follow-up task on ADR-0534's relay.
            unverified_actor: None,
        });
        forward_request_id(&req, &mut upstream);

        let set = self
            .client()
            .set_inherited_setting(upstream)
            .await
            .map_err(upstream_failed)?
            .into_inner();

        call.finish(Outcome {
            status: "OK",
            ..Default::default()
        });
        // MOVED WHOLE. The store's answer carries the OTHER level and every
        // OTHER team's override, which the caller did not send — rebuilding it
        // here is how a field goes missing from a policy an operator is reading
        // back.
        Ok(Response::new(SetInheritedSettingResponse {
            setting: set.setting,
        }))
    }

    /// TAKES ONLY THE `Call`, because it reads nothing from the request: it
    /// refuses every one of them. The parameter list says so rather than
    /// leaving a reader to check.
    pub(super) async fn set_rate_limit_override_inner(
        &self,
        call: Call,
    ) -> Result<Response<SetRateLimitOverrideResponse>, Status> {
        call.fail("UNIMPLEMENTED");
        Err(Status::unimplemented(
            "SetRateLimitOverride is not implemented yet",
        ))
    }
}
