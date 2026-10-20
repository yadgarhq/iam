//! **THE CALLER GATE (ADR-0972 (1), ledger 1629): iam admits the gateway, and
//! nobody else, on every verb.**
//!
//! mTLS says "one of ours", not "which one". Every module's client leaf
//! verifies against the same internal authority, so before this gate any pod
//! holding a leaf and passing a NetworkPolicy could call `SetUserAdmin`,
//! `CreateUser`, `IssueEnrolment` or `RevokeAllCredentials` here — and
//! `unverified_actor` is audit-only (ADR-0534), so nothing else stopped it.
//! The NetworkPolicy (`clients: [gateway]`) selects pods by a label, which is
//! not an identity. The verified leaf's common name is.
//!
//! **EVERY VERB, `ResolveCredential`, `Login` AND `RedeemEnrolment` INCLUDED.**
//! The gateway is the only workload that dials iam (`docs`
//! `plans/admin-and-client-gaps.md` §9.1), and operator probes reach iam
//! through the gateway's HTTP routes, never directly.
//!
//! **NO NAME IS A REFUSAL.** `caller_common_name` answers `None` for a
//! cleartext listener, a listener running `clientAuth: "off"` or `optional`
//! with no certificate presented, and a leaf whose subject carries no single
//! common name. Each of those is refused: fail closed.
//!
//! **THE SEAM IS `<rpc>_as(caller, req)`, AND IT IS THE ONLY PATH.** Each
//! `IamService` trait method reads the name off the request — before anything
//! consumes it, because the peer chain lives on its extensions — and hands it
//! to the `_as` method here. The `_as` method opens the RPC's `Call`, gates,
//! and only then reaches the RPC's `_inner` work. A unit test drives `_as`
//! with `Some(GATEWAY_CALLER)`; only the gate tests drive the trait method.
//! There is no test-only bypass in the gate itself.
//!
//! **`Call::start` IS THE FIRST STATEMENT OF EVERY `_as`**, before the request
//! id is bound and before any clock starts. `observe-coverage` credits a trait
//! method whose whole result is a call to a function that opens its `Call`
//! unconditionally as its first statement — and that is the truth here, not a
//! shape chosen to satisfy the hook: no path through an `_as` avoids its
//! `Call`, the refusal included.

use super::*;

/// The one client-certificate common name iam admits (ADR-0972 (1)).
///
/// **A CONSTANT, NOT A KNOB.** Which workload may call iam is a decision the
/// ADR records, not a deployment's choice. `platform` issues the gateway's
/// leaf as `gateway-client-tls` with `commonName: gateway-caller`, and the
/// gateway presents it on every upstream hop. A wrong name on that leaf is an
/// authentication outage, which is why the deploy path checks the live leaf's
/// CN before the roll.
pub const GATEWAY_CALLER: &str = "gateway-caller";

/// The counter every gate refusal increments, labelled `caller` with the
/// presented common name or [`NO_CALLER`].
///
/// **ITS OWN SERIES, BECAUSE `PERMISSION_DENIED` IS NOT A USABLE SIGNAL.**
/// `iam-db` already returns that code on the bootstrap-demand path, and
/// `upstream_failed` relays an upstream code unchanged, so the call metrics'
/// `PERMISSION_DENIED` label is not zero today and cannot say "the gate
/// refused somebody". This series rises only when THIS gate refuses.
///
/// **THE LABEL IS BOUNDED (D67).** A presented name reaches this label only
/// after the handshake verified its leaf against the internal authority, so
/// its values are the leaves `platform` issued, plus `none`.
pub const CALLER_REFUSED: &str = "yadgar_iam_caller_refused";

/// The `caller` label value for a call that presented no common name.
pub const NO_CALLER: &str = "none";

/// Admit [`GATEWAY_CALLER`] and refuse everything else, `None` included.
///
/// A copy of `project`'s `admit` without the principal half: iam's verbs
/// carry no `Scope`, and the actor on them is audit-only (ADR-0534). The name
/// is compared EXACTLY — no prefix, no case folding — because `platform`
/// issues it exactly.
///
/// **`PERMISSION_DENIED`**, as `project`'s gate answers. The caller is
/// authenticated — its leaf verified — and is not allowed here. The message
/// names the gate and both names, because the one reader who sees it is an
/// operator chasing a misissued leaf: the gateway maps this code on
/// `/admin/issue-enrolment` to its bootstrap-predicate body, so the counter
/// and this log are where the real cause shows.
pub(super) fn admit(caller: Option<&str>) -> Result<(), Status> {
    if caller == Some(GATEWAY_CALLER) {
        return Ok(());
    }
    Err(Status::permission_denied(format!(
        "iam admits the gateway only (ADR-0972): the client certificate must name \
         {GATEWAY_CALLER:?}, and this one names {}. Every module's leaf verifies against \
         the same authority, so verification alone admits nobody here",
        caller.map_or_else(|| "no caller".to_string(), |c| format!("{c:?}"))
    )))
}

/// [`admit`], with the refusal recorded where an operator reads it.
///
/// **ORDER: COUNTER, THEN `fail`, THEN RETURN.** `Call::fail` consumes the
/// `Call`, so a refusal that forgot it would drop the `Call` and record the
/// call as `UNRECORDED` rather than `PERMISSION_DENIED` (D67).
fn admitted(caller: Option<&str>, call: Call) -> Result<Call, Status> {
    match admit(caller) {
        Ok(()) => Ok(call),
        Err(refusal) => {
            metrics::counter!(
                CALLER_REFUSED,
                "caller" => caller.unwrap_or(NO_CALLER).to_string()
            )
            .increment(1);
            tracing::warn!(
                caller = caller.unwrap_or(NO_CALLER),
                "refused a call from a client certificate that is not the gateway's (ADR-0972)"
            );
            call.fail("PERMISSION_DENIED");
            Err(refusal)
        }
    }
}

impl Iam {
    pub(super) async fn resolve_credential_as(
        &self,
        caller: Option<&str>,
        req: Request<ResolveCredentialRequest>,
    ) -> Result<Response<ResolveCredentialResponse>, Status> {
        let call = Call::start(
            SERVICE,
            "ResolveCredential",
            Kind::Read,
            tel(request_id_of(&req), ""),
        );
        let call = admitted(caller, call)?;
        self.resolve_credential_inner(req, call).await
    }

    /// **THE GATE RUNS INSIDE THE FLOORED SPAN**, so a refusal costs the floor
    /// exactly as a wrong password does. Otherwise the refusal's timing would
    /// tell a caller the gate from a password check.
    ///
    /// THE CLOCK STARTS ON THE LINE AFTER `Call::start`, not before it, and
    /// that moves nothing the floor hides: `Call::start` is the same constant
    /// work on every path, so it carries no difference between paths for a
    /// response time to reveal. Everything that can differ — the gate, the
    /// validation and every round trip to `iam-db` — is after the clock.
    pub(super) async fn login_as(
        &self,
        caller: Option<&str>,
        req: Request<LoginRequest>,
    ) -> Result<Response<LoginResponse>, Status> {
        let call = Call::start(SERVICE, "Login", Kind::Write, tel(request_id_of(&req), ""));
        let started = Instant::now();
        let answered = match admitted(caller, call) {
            Ok(call) => self.login_inner(req, call).await,
            Err(refused) => Err(refused),
        };
        self.hold_until_floor(self.login_floor, started.elapsed())
            .await;
        answered
    }

    /// Floored like [`Self::login_as`], for the same reason.
    pub(super) async fn redeem_enrolment_as(
        &self,
        caller: Option<&str>,
        req: Request<RedeemEnrolmentRequest>,
    ) -> Result<Response<RedeemEnrolmentResponse>, Status> {
        let call = Call::start(
            SERVICE,
            "RedeemEnrolment",
            Kind::Write,
            tel(request_id_of(&req), ""),
        );
        let started = Instant::now();
        let answered = match admitted(caller, call) {
            Ok(call) => self.redeem_inner(req, call).await,
            Err(refused) => Err(refused),
        };
        self.hold_until_floor(self.redeem_floor, started.elapsed())
            .await;
        answered
    }

    pub(super) async fn issue_enrolment_as(
        &self,
        caller: Option<&str>,
        req: Request<IssueEnrolmentRequest>,
    ) -> Result<Response<IssueEnrolmentResponse>, Status> {
        let call = Call::start(
            SERVICE,
            "IssueEnrolment",
            Kind::Write,
            tel(request_id_of(&req), &req.get_ref().user_id),
        );
        let call = admitted(caller, call)?;
        self.issue_enrolment_inner(req, call).await
    }

    /// GATED BEFORE THE `UNIMPLEMENTED` ANSWER: a refused caller learns that it
    /// is refused, not which verbs this build serves.
    ///
    /// INSTRUMENTED EVEN THOUGH IT REFUSES (D67). A handler that emits nothing
    /// is indistinguishable from one nobody called, so an operator asking
    /// whether anything has needed this RPC yet would read silence as an
    /// answer. `fail` is what makes "asked for, and refused" countable.
    pub(super) async fn list_credentials_as(
        &self,
        caller: Option<&str>,
        req: Request<ListCredentialsRequest>,
    ) -> Result<Response<ListCredentialsResponse>, Status> {
        let call = Call::start(
            SERVICE,
            "ListCredentials",
            Kind::Read,
            tel(request_id_of(&req), &req.get_ref().user_id),
        );
        let call = admitted(caller, call)?;
        self.list_credentials_inner(call).await
    }

    pub(super) async fn set_user_admin_as(
        &self,
        caller: Option<&str>,
        req: Request<SetUserAdminRequest>,
    ) -> Result<Response<SetUserAdminResponse>, Status> {
        let call = Call::start(
            SERVICE,
            "SetUserAdmin",
            Kind::Write,
            tel(request_id_of(&req), &req.get_ref().user_id),
        );
        let call = admitted(caller, call)?;
        self.set_user_admin_inner(req, call).await
    }

    /// Gated before the `UNIMPLEMENTED` answer, as [`Self::list_credentials_as`].
    pub(super) async fn set_rate_limit_override_as(
        &self,
        caller: Option<&str>,
        req: Request<SetRateLimitOverrideRequest>,
    ) -> Result<Response<SetRateLimitOverrideResponse>, Status> {
        let call = Call::start(
            SERVICE,
            "SetRateLimitOverride",
            Kind::Write,
            tel(request_id_of(&req), &req.get_ref().user_id),
        );
        let call = admitted(caller, call)?;
        self.set_rate_limit_override_inner(call).await
    }

    pub(super) async fn set_inherited_setting_as(
        &self,
        caller: Option<&str>,
        req: Request<SetInheritedSettingRequest>,
    ) -> Result<Response<SetInheritedSettingResponse>, Status> {
        let call = Call::start(
            SERVICE,
            "SetInheritedSetting",
            Kind::Write,
            tel(request_id_of(&req), ""),
        );
        let call = admitted(caller, call)?;
        self.set_inherited_setting_inner(req, call).await
    }

    pub(super) async fn issue_credential_as(
        &self,
        caller: Option<&str>,
        req: Request<IssueCredentialRequest>,
    ) -> Result<Response<IssueCredentialResponse>, Status> {
        let call = Call::start(
            SERVICE,
            "IssueCredential",
            Kind::Write,
            tel(request_id_of(&req), &req.get_ref().user_id),
        );
        let call = admitted(caller, call)?;
        self.issue_credential_inner(req, call).await
    }

    pub(super) async fn revoke_credential_as(
        &self,
        caller: Option<&str>,
        req: Request<RevokeCredentialRequest>,
    ) -> Result<Response<RevokeCredentialResponse>, Status> {
        let call = Call::start(
            SERVICE,
            "RevokeCredential",
            Kind::Write,
            tel(request_id_of(&req), ""),
        );
        let call = admitted(caller, call)?;
        self.revoke_credential_inner(req, call).await
    }

    pub(super) async fn revoke_all_credentials_as(
        &self,
        caller: Option<&str>,
        req: Request<RevokeAllCredentialsRequest>,
    ) -> Result<Response<RevokeAllCredentialsResponse>, Status> {
        let call = Call::start(
            SERVICE,
            "RevokeAllCredentials",
            Kind::Write,
            tel(request_id_of(&req), ""),
        );
        let call = admitted(caller, call)?;
        self.revoke_all_credentials_inner(req, call).await
    }

    pub(super) async fn create_user_as(
        &self,
        caller: Option<&str>,
        req: Request<CreateUserRequest>,
    ) -> Result<Response<CreateUserResponse>, Status> {
        let call = Call::start(
            SERVICE,
            "CreateUser",
            Kind::Write,
            tel(request_id_of(&req), ""),
        );
        let call = admitted(caller, call)?;
        self.create_user_inner(req, call).await
    }

    pub(super) async fn add_team_member_as(
        &self,
        caller: Option<&str>,
        req: Request<AddTeamMemberRequest>,
    ) -> Result<Response<AddTeamMemberResponse>, Status> {
        let call = Call::start(
            SERVICE,
            "AddTeamMember",
            Kind::Write,
            tel(request_id_of(&req), &req.get_ref().user_id),
        );
        let call = admitted(caller, call)?;
        self.add_team_member_inner(req, call).await
    }

    pub(super) async fn remove_team_member_as(
        &self,
        caller: Option<&str>,
        req: Request<RemoveTeamMemberRequest>,
    ) -> Result<Response<RemoveTeamMemberResponse>, Status> {
        let call = Call::start(
            SERVICE,
            "RemoveTeamMember",
            Kind::Write,
            tel(request_id_of(&req), &req.get_ref().user_id),
        );
        let call = admitted(caller, call)?;
        self.remove_team_member_inner(req, call).await
    }
}
