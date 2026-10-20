//! The gRPC surface: [`IamService`] as `iam` implements it.
//!
//! **THE CONTRACT DOCS ARE HERE AND THE WORK IS NOT**, and that division is
//! forced rather than chosen. A trait impl cannot be split across files, and
//! this one does not fit under the file-size ceiling: the handlers therefore
//! call inherent `_inner` methods that live beside the validation and the
//! bounds each RPC is subject to. `Login` and `RedeemEnrolment` already had
//! that shape for a different reason — their wrappers hold the response-time
//! floor — and every other handler now takes it too, uniformly, so that
//! which RPC delegates says nothing about the RPC.
//!
//! **EVERY HANDLER IS ONE LINE NOW, AND THE LINE IS THE CALLER GATE'S SEAM**
//! (ADR-0972 (1), ledger 1629). It reads the verified client leaf's common name
//! BEFORE anything consumes the request — the peer chain lives on its
//! extensions — and hands it to the RPC's `_as` method in [`super::caller`],
//! which opens the `Call`, admits only the gateway, and then does the work.
//! The `Call`, the telemetry scope and the response floors moved there with it.

use yadgar_lifecycle::serve_tls::caller_common_name;

use super::*;

#[tonic::async_trait]
impl IamService for Iam {
    /// The hot path: a bearer token to an identity.
    ///
    /// Hashes and forwards. `iam` does not cache — the GATEWAY does (D72), because
    /// a cache here would still cost a network round trip per request and defeat
    /// the point.
    async fn resolve_credential(
        &self,
        req: Request<ResolveCredentialRequest>,
    ) -> Result<Response<ResolveCredentialResponse>, Status> {
        self.resolve_credential_as(caller_common_name(&req).as_deref(), req)
            .await
    }

    /// Username and password to a long-lived token. The one sign-in a person
    /// performs (D72).
    ///
    /// **The whole call is held to a response-time floor**, both the success and
    /// the failure path — see `Iam::hold_until_floor` for why it is one rule with
    /// no branch, and `crypto::Keys::verify_password` for the leak it closes.
    async fn login(&self, req: Request<LoginRequest>) -> Result<Response<LoginResponse>, Status> {
        self.login_as(caller_common_name(&req).as_deref(), req)
            .await
    }

    /// An enrolment secret and a chosen password to a credential (D73).
    ///
    /// **UNAUTHENTICATED BY CONSTRUCTION** — the secret is all the caller has —
    /// so this carries `Login`'s enumeration problem in a sharper form, and it
    /// takes the same two precautions plus one. `Self::redeem_inner` holds the
    /// order that makes constant work and validation-before-lookup true; this
    /// handler holds it to a response-time floor.
    ///
    /// **THE FLOOR IS NOT `Login`'s ARGUMENT RECYCLED.** `Login` needs one
    /// because the Argon2id cost of a stored hash is a property of the ROW, and
    /// `iam` can equalise its own work but not what a row costs. Here the three
    /// refusals — unknown, spent, expired — are decided INSIDE `iam-db`, by a
    /// `RedeemOutcome` this service only reads. A miss, a row found spent and a
    /// row found expired need not cost the store the same, and NO amount of
    /// constant work in this process can equalise a difference that arises in
    /// another one. Collapsing the three into one status code and then letting
    /// the response time separate them again would leave the contract's "ONE
    /// FAILURE, NOT THREE" true of the code and false of the endpoint. A floor
    /// over the WHOLE handler is the only thing that covers an upstream
    /// difference, which is why it is here and why it is not optional.
    async fn redeem_enrolment(
        &self,
        req: Request<RedeemEnrolmentRequest>,
    ) -> Result<Response<RedeemEnrolmentResponse>, Status> {
        self.redeem_enrolment_as(caller_common_name(&req).as_deref(), req)
            .await
    }

    /// Mint the enrolment an admin hands to a person (D73).
    ///
    /// Administrative, and the ONLY path that sets a password on an account
    /// which already has one: a fresh enrolment, redeemed, sets it
    /// unconditionally. That is the recovery for a forgotten password and for a
    /// redemption that spent its secret without leaving a usable credential.
    ///
    /// **THE ADMIN NEVER LEARNS THE PASSWORD**, which is the whole of D73 — but
    /// an admin may mint an enrolment for any existing user and redeem it
    /// themselves. The literal guarantee survives and its rationale is MITIGATED
    /// RATHER THAN ELIMINATED: the issuance is recorded and the victim's old
    /// password stops working, so the act is loud rather than silent.
    ///
    /// **A REPLAYED KEY MINTS A SECOND, LIVE ENROLMENT — NOT A DEDUPLICATED
    /// NO-OP, AND NOT A DEAD TOKEN.** The key is forwarded to `CreateEnrolment`
    /// unchanged, because D9 applies to every mutating RPC and D4 says
    /// deduplication belongs in the store. But `iam_enrolment` carries no
    /// idempotency column, and `CreateEnrolment` discards the key it is
    /// handed: a retry, arriving with a secret this call minted FRESH, inserts
    /// a SECOND row under a SECOND `enrolment_id`, redeemable exactly like the
    /// first.
    ///
    /// **THAT IS A KNOWN GAP IN THE CONTRACT, TRACKED AS LEDGER 668, RATHER
    /// THAN AN OVERSIGHT HERE.** ADR-0519 decided this RPC refuses a replayed
    /// key instead of minting a second one; the refusal has to live in
    /// `iam-db`, because `iam` holds no store to recognise a key it has seen
    /// (D4) — deriving the secret from the key instead, so `iam` itself could
    /// refuse, is rejected: it would make a caller-chosen string the entropy
    /// of an unauthenticated endpoint's whole authenticator. Not forwarding
    /// the key would trade the gap for `iam` unilaterally disabling a
    /// mechanism the contract mandates, which is worse, so the key travels
    /// and the gap stays open until ledger 668 closes it.
    ///
    /// **UNCONFIGURED ENROLMENT REFUSES HERE RATHER THAN AT BOOT.** The contract
    /// rule is about the TOKEN — never mint one carrying an empty `gateway` —
    /// and refusing to mint keeps it whole. Refusing to start would also stop
    /// `ResolveCredential`, which is the authentication plane for the whole
    /// estate; see [`EnrolmentConfig::from_env`].
    async fn issue_enrolment(
        &self,
        req: Request<IssueEnrolmentRequest>,
    ) -> Result<Response<IssueEnrolmentResponse>, Status> {
        self.issue_enrolment_as(caller_common_name(&req).as_deref(), req)
            .await
    }

    /// List one user's live credentials, so the orphan a lost redemption
    /// response leaves can be found and withdrawn. See
    /// `list_credentials_inner` in `credential.rs` for the relay and its rules.
    async fn list_credentials(
        &self,
        req: Request<ListCredentialsRequest>,
    ) -> Result<Response<ListCredentialsResponse>, Status> {
        self.list_credentials_as(caller_common_name(&req).as_deref(), req)
            .await
    }

    /// Set or clear D73's admin flag, and publish the invalidation.
    ///
    /// **ONE HOP, AND IT ADDS NO RULE OF ITS OWN.** `iamdb.v1.SetUserAdmin`
    /// performs the write, refuses an id it cannot promote — an unknown or
    /// soft-deleted person is `NOT_FOUND` rather than a silent `OK` — and is
    /// idempotent by assigning rather than toggling. Re-deciding any of that here
    /// would be a second place for it to be wrong.
    ///
    /// **THE ACTOR IS RELAYED, AND THIS WAS THE FIRST SITE ON THIS SERVICE THAT
    /// DID.** `create_user` and `issue_enrolment` relay too since ledger 612, and
    /// `revoke_all_credentials` since ADR-0945, and `revoke_credential` since
    /// ledger 1627, so a reader grepping the field now finds five — this paragraph records which one came first, not which one is
    /// alone. ADR-0534's field is audit-only: it is
    /// asserted by the gateway, verified by nothing on the wire, and MUST NOT be an
    /// authorisation input. So it is forwarded exactly as received, and `None`
    /// stays `None`.
    ///
    /// **THE RELAY HAS A SINK, AND `iam-db` v0.7.31 IS WHERE IT ARRIVED.**
    /// `iamdb.v1.SetUserAdmin` now READS `unverified_actor`
    /// (`iam-db/src/service/policy.rs`, through that crate's single `record_actor`)
    /// and writes it to the structured log beside the RPC name and the target. Four
    /// `iam-db` verbs read the field — `CreateUser`, `CreateEnrolment`,
    /// `SetUserAdmin` and `SetInheritedSetting` — where before v0.7.31 only
    /// `SetInheritedSetting` did. **THIS DOC COMMENT SAID "THE RELAY HAS NO SINK
    /// TODAY" UNTIL LEDGER 612 CLOSED**, which was true when written and is the
    /// kind of claim that outlives its measurement; it is corrected rather than
    /// deleted so the sequence stays legible.
    ///
    /// **`idempotency` IS STILL DISCARDED THERE, AND THAT HALF DID NOT CHANGE.**
    /// The store's UPDATE binds `is_admin` and `user_id` and nothing else, so the
    /// key this hop forwards reaches no ledger. The two fields travelled together
    /// and only one of them landed.
    ///
    /// **THERE IS STILL NO AUDIT STORE ON THIS BOUNDARY** (ADR-0620): the log line
    /// is where an attribution lands today, so a reader must not take the
    /// forwarding for a durable audit record. That, and not the sink, is what is
    /// still missing.
    ///
    /// **AN EMPTY ACTOR IS NEVER FABRICATED TO FILL THE FIELD**, and that rule
    /// never rested on what any reader did. `Some(UnverifiedActor { user_id: "" })`
    /// asserts that somebody was named and their id was empty, which is not what an
    /// absent actor means — and now that the sink exists it is a false record in a
    /// real log, rendered `<unattributed>` exactly as a truly absent actor is. That
    /// is the false green: the right output by the wrong route, making an id this
    /// service DROPPED indistinguishable from one the caller never sent.
    ///
    /// **D73 EXCLUDES ADMIN SELF-DEMOTION AND THIS SERVICE CANNOT ENFORCE IT.**
    /// The only caller identity on this request is that same unverifiable actor,
    /// so a check here would be authorising on it. `iam.proto` puts both
    /// administrative checks at the gateway for that reason; the absence of a
    /// self-demotion rule here is deliberate rather than an oversight.
    async fn set_user_admin(
        &self,
        req: Request<SetUserAdminRequest>,
    ) -> Result<Response<SetUserAdminResponse>, Status> {
        self.set_user_admin_as(caller_common_name(&req).as_deref(), req)
            .await
    }

    /// NOT IMPLEMENTED IN THIS CHANGE. D74's overrides are contract surface this
    /// change does not touch.
    async fn set_rate_limit_override(
        &self,
        req: Request<SetRateLimitOverrideRequest>,
    ) -> Result<Response<SetRateLimitOverrideResponse>, Status> {
        self.set_rate_limit_override_as(caller_common_name(&req).as_deref(), req)
            .await
    }

    /// Write ONE LEVEL of ADR-0522's inheritable setting: validate here, store
    /// there.
    ///
    /// **THIS SERVICE REFUSES THE CONTRACT'S CLAUSES ITSELF RATHER THAN
    /// FORWARDING THEM** — `yadgar.iam.v1`'s comment on this RPC says so, and
    /// [`check_inherited_setting`] is where it happens. Every refusal lands
    /// BEFORE the store is called, so a rejected request leaves no row, no
    /// ledger entry and no idempotency key behind.
    ///
    /// **IT RESOLVES NOTHING.** The response carries the setting whole, exactly
    /// as the store answered. The resolution depends on the team of the ROW
    /// being read and belongs where the reach is computed; see
    /// `yadgar.common.v1.InheritedSetting`, which states it once.
    ///
    /// **THE AUTHORISATION GAP, STATED RATHER THAN LEFT TO BE FOUND.** This
    /// request carries no attested caller identity, in common with every
    /// administrative RPC on this service. So `iam` can neither VERIFY that the
    /// caller is an administrator nor RECORD which one changed a policy that
    /// governs who may read which records. The check belongs at the gateway, on
    /// D73's admin flag, because the gateway is the one place identity is
    /// attested (ADR-0488) — a second authentication path invented here would be
    /// a second place for it to be wrong, holding the same secret twice.
    /// **D73's BOOTSTRAP TOKEN DOES NOT REACH THIS VERB**, and must not be
    /// extended to it: a token that exists to create the FIRST admin would
    /// otherwise rewrite the read policy for the whole deployment before an
    /// admin exists to notice.
    ///
    /// **NOTHING IS INVALIDATED, AND THAT IS THE CONTRACT'S ANSWER RATHER THAN
    /// AN OMISSION.** The setting travels on the credential a gateway caches
    /// (ADR-0491). An organisation-level write touches every cached credential
    /// in the deployment and no event on this contract says so, and the
    /// per-user subjects [`crate::invalidate`] publishes need a `user_id` this
    /// request does not carry. A deployment that tightens this policy WAITS THE
    /// CACHE OUT.
    async fn set_inherited_setting(
        &self,
        req: Request<SetInheritedSettingRequest>,
    ) -> Result<Response<SetInheritedSettingResponse>, Status> {
        self.set_inherited_setting_as(caller_common_name(&req).as_deref(), req)
            .await
    }

    async fn issue_credential(
        &self,
        req: Request<IssueCredentialRequest>,
    ) -> Result<Response<IssueCredentialResponse>, Status> {
        self.issue_credential_as(caller_common_name(&req).as_deref(), req)
            .await
    }

    /// Revoke, and publish the invalidation.
    ///
    /// **Publishing is what makes the gateway's cache safe** (D72). Without it a
    /// revoked credential keeps working until its TTL expires, which turns the
    /// backstop into the mechanism and makes every revocation late by design.
    ///
    /// The publish happens AFTER the store confirms, and its failure does not
    /// fail this call: the revocation has already happened, and returning an
    /// error would tell the caller to retry something that is done.
    async fn revoke_credential(
        &self,
        req: Request<RevokeCredentialRequest>,
    ) -> Result<Response<RevokeCredentialResponse>, Status> {
        self.revoke_credential_as(caller_common_name(&req).as_deref(), req)
            .await
    }

    /// Revoke every live credential one user holds, and publish the eviction
    /// (ADR-0945).
    ///
    /// **ONE HOP.** `iamdb.v1.RevokeAllCredentials` locks the user row and
    /// tombstones every live credential in one transaction; this handler
    /// validates `user_id`, relays the actor and publishes CREDENTIAL_REVOKED
    /// after the commit, whatever the count. See `revoke_all_credentials_inner`.
    async fn revoke_all_credentials(
        &self,
        req: Request<RevokeAllCredentialsRequest>,
    ) -> Result<Response<RevokeAllCredentialsResponse>, Status> {
        self.revoke_all_credentials_as(caller_common_name(&req).as_deref(), req)
            .await
    }

    async fn create_user(
        &self,
        req: Request<CreateUserRequest>,
    ) -> Result<Response<CreateUserResponse>, Status> {
        self.create_user_as(caller_common_name(&req).as_deref(), req)
            .await
    }

    async fn add_team_member(
        &self,
        req: Request<AddTeamMemberRequest>,
    ) -> Result<Response<AddTeamMemberResponse>, Status> {
        self.add_team_member_as(caller_common_name(&req).as_deref(), req)
            .await
    }

    /// Removing a member narrows what that user can see, so the cached identity
    /// has to be invalidated or they keep reading the team's records.
    async fn remove_team_member(
        &self,
        req: Request<RemoveTeamMemberRequest>,
    ) -> Result<Response<RemoveTeamMemberResponse>, Status> {
        self.remove_team_member_as(caller_common_name(&req).as_deref(), req)
            .await
    }
}
