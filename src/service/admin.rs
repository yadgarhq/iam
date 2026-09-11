//! The administrative writes on a user and on a team.
//!
//! Every one of them validates, forwards the request to `iam-db` with the
//! caller's idempotency key untouched (D9), and publishes an invalidation
//! where the write can change a cached identity (D72).

use super::*;

/// The longest `external_id` or `display_name` accepted, IN BYTES, because that
/// is what stores them once they are encrypted.
///
/// **484 = 512 − 12 − 16, AND EVERY TERM IS SOMETHING A READER CAN CHECK.** A
/// magic number nobody can re-derive is how a bound like this rots, so the
/// derivation is written out:
///
/// - **512** is the column. `iam_user.external_id_ciphertext` and
///   `iam_user.display_name_ciphertext` are both `VARBINARY(512)`
///   (`iam-db/src/schema.rs`), and `VARBINARY(n)` bounds BYTES.
/// - **12** is the nonce [`crate::crypto::Keys::encrypt`] prefixes to what it
///   returns (`crypto.rs`, `[0u8; 12]`). It is stored alongside the ciphertext
///   because decryption needs it and there is no second column for it.
/// - **16** is AES-256-GCM's authentication tag, appended by the cipher.
///
/// AES-GCM is CTR mode underneath, so the enciphered bytes number exactly as
/// many as the plaintext's: a byte of name costs a byte of column, which is why
/// this is a subtraction and not a ratio. **THE SUBTRACTION IS CHECKED BY
/// MEASUREMENT rather than by this comment** —
/// `crypto::tests::the_longest_plaintext_the_column_holds_encrypts_to_exactly_the_column_width`
/// encrypts 484 bytes and asserts the result is 512, and encrypts 485 and
/// asserts 513. If the cipher or the framing changes, that test goes red before
/// this number does.
///
/// **BYTES AND NOT CHARACTERS, WHICH IS THE OPPOSITE OF [`MAX_LABEL_CHARS`] AND
/// FOR THE SAME REASON.** That bound counts characters because `VARCHAR(255)` on
/// utf8mb4 does; this one counts bytes because `VARBINARY(512)` does, and
/// because `encrypt` enciphers `plaintext.as_bytes()`. Counting characters here
/// would admit 484 four-byte codepoints — 1936 bytes, 1964 encrypted, nearly
/// four times the column — and hand the caller back the storage error this bound
/// exists to delete.
///
/// **ONE CONSTANT FOR TWO FIELDS, and unlike [`MAX_EXPIRES_IN_SECONDS`] that is
/// not a judgement being shared.** ADR-0565 requires a bound to be re-argued per
/// field, and the argument here comes out identical twice over because it is not
/// an opinion about what a field MEANS: `external_id` and `display_name` are
/// encrypted by the same call in the same RPC and land in two columns declared
/// with the same width. The derivation has no per-field term in it. Two copies
/// of one subtraction is how one of them ends up stale.
///
/// **THE SWEEP, BECAUSE FIXING AN INSTANCE IS NOT CLOSING A CLASS.** `iam`
/// encrypts caller-supplied text in exactly two places and both are checked
/// here: `create_user`'s two `enc(...)` calls are the only uses of
/// `Keys::encrypt` in this binary. Every other ciphertext `iam` handles is READ
/// and decrypted, never written from an input.
///
/// Refusing here makes the outcome this service's own, and independent of a
/// `sql_mode` it neither sets nor checks — the same argument [`MAX_LABEL_CHARS`]
/// makes. Measured against the deployed instance on 2026-09-05, `sql_mode` is
/// `STRICT_TRANS_TABLES`, so an over-long value ERRORS rather than truncating;
/// under `sql_mode = ''` the same write would store a CLIPPED name and report
/// success, and a clipped `external_id` is a username nobody can log in with. If
/// either column widens, this constant is what has to move with it.
const MAX_ENCRYPTED_FIELD_BYTES: usize = 484;

/// Everything [`IamService::create_user`] can refuse WITHOUT reaching the store.
///
/// **THE RPC HAD NO VALIDATION AT ALL, and that is what this closes.** An
/// `external_id` longer than the column encrypted cleanly, travelled to `iam-db`
/// as an over-wide `VARBINARY(512)`, and was refused by MariaDB — which `iam-db`
/// renders as `UNAVAILABLE "storage unavailable"` like every other engine error.
/// So an administrator who typed a long name was told the database was down, and
/// through the gateway that arrives as a 503. A request that was never
/// well-formed reported an outage.
///
/// **NO ORACLE, AND THIS PATH IS NOT WHERE ONE WOULD LIVE ANYWAY.** Both checks
/// are answerable from the request alone: they say nothing about who already
/// exists, and in particular they are decided before the unique blind index is
/// consulted. `CreateUser` is an administrative verb rather than one a stranger
/// can reach, but the request-only rule is what makes the refusal safe to state
/// SHARPLY, and stating it sharply is the whole point.
///
/// **BOUNDS, NOT REQUIREMENTS.** An empty `external_id` and an empty
/// `display_name` are left alone here. They are their own question — an empty
/// `external_id` is a username nobody can type, and a SECOND one collides on
/// `uq_iam_user_blind_index` because `HMAC("")` is a single value — and answering
/// it is a contract decision rather than a length check.
fn check_stored_names(r: &CreateUserRequest) -> Result<(), Status> {
    for (field, value) in [
        ("external_id", &r.external_id),
        ("display_name", &r.display_name),
    ] {
        if value.len() > MAX_ENCRYPTED_FIELD_BYTES {
            // NAMING THE FIELD, because two fields share this refusal and a
            // message that named neither would send an administrator to check
            // both. ADR-0565 requires the field to be named for exactly this.
            return Err(Status::invalid_argument(format!(
                "`{field}` is longer than the store will hold: at most 484 \
                 bytes, counted as bytes and not as characters, because it is \
                 encrypted before it is stored"
            )));
        }
    }
    Ok(())
}

impl Iam {
    pub(super) async fn set_user_admin_inner(
        &self,
        req: Request<SetUserAdminRequest>,
        call: Call,
    ) -> Result<Response<SetUserAdminResponse>, Status> {
        let mut upstream = Request::new(db::SetUserAdminRequest {
            // D9'S KEY TRAVELS AND `iam-db` DISCARDS IT, WHICH IS NOT THE SAME
            // ARGUMENT `revoke_credential` MAKES. There the key is what turns a
            // second delivery into a replay; here the store's own comment says
            // it is "idempotent (D9) without a ledger because it ASSIGNS rather
            // than toggles", so a redelivery reaches the same state without
            // consulting a key. It is still forwarded rather than dropped: the
            // field is the CONTRACT's, and a caller that sent a key must not
            // have it silently removed by a hop that has decided it does not
            // need one. If this RPC ever gains a ledger the key is already
            // arriving, though the ledger itself would be `iam-db`'s to add —
            // its handler discards the key today, so nothing on this side makes
            // that work smaller.
            idempotency: req.get_ref().idempotency.clone(),
            user_id: req.get_ref().user_id.clone(),
            is_admin: req.get_ref().is_admin,
            // FORWARDED, AND `create_user` BELOW NOW DOES THE SAME — the team-member
            // verbs in this file are the two that still send `None`. This was the
            // service's first relay; ledger 612 wired the other two verbs the
            // gateway actually reaches. The comment at `issue_credential` argues
            // that a relay of a field nothing populates reads as a relay that
            // works, and that argument still governs the sites left alone.
            unverified_actor: req.get_ref().unverified_actor.clone(),
        });
        forward_request_id(&req, &mut upstream);

        self.client()
            .set_user_admin(upstream)
            .await
            .map_err(upstream_failed)?;

        // **THE SUBJECT NAMES SOMETHING THAT DID NOT HAPPEN, AND THAT COST IS
        // PAID DELIBERATELY.** No credential was revoked here: a person's
        // authority changed. The broker permits `iam` to publish exactly two
        // subjects (`deploy/infra/nats.yaml`, the `iam` user's `publish.allow`),
        // and a publish to a third one is refused ASYNCHRONOUSLY while
        // `Client::publish` has already returned `Ok(())` — see this module's
        // header. A new subject before its broker permission would therefore
        // leave NO record and NO invalidation, and a mislabelled record beats an
        // absent one.
        //
        // **WHAT IT COSTS, STATED RATHER THAN LEFT TO BE FOUND.** The gateway
        // logs the subject as a field on every eviction
        // (`gateway/src/invalidate.rs`, "cached identity invalidated"), and there
        // is no audit store on this boundary — so today a promotion to
        // administrator leaves a record that says `yadgar.iam.credential.revoked`,
        // on the verb whose record matters most. `Call::start` above names the
        // verb truthfully, which is what keeps this a second and corroborated
        // record rather than the only one. A consumer must NOT read this subject
        // as evidence that a revocation occurred.
        //
        // **UNCONDITIONAL, AND ON THE USER FROM THE REQUEST.** Demotion needs the
        // eviction at least as much as promotion does, and this service cannot
        // tell the two apart anyway: the store assigns the wanted value and
        // answers with an empty message, so there is no prior value to compare
        // and `SetUserAdminResponse` carries no id to publish. Publishing AFTER
        // the upstream `Ok` is what keeps that safe — a `NOT_FOUND` for an
        // unknown or soft-deleted person has already returned above, so nothing
        // is invalidated for a user the store refused to write.
        self.invalidator
            .credential_revoked(&req.get_ref().user_id)
            .await;

        call.finish(Outcome {
            status: "OK",
            ..Default::default()
        });
        Ok(Response::new(SetUserAdminResponse {}))
    }

    pub(super) async fn create_user_inner(
        &self,
        req: Request<CreateUserRequest>,
        call: Call,
    ) -> Result<Response<CreateUserResponse>, Status> {
        let r = req.get_ref();

        // VALIDATION BEFORE ENCRYPTION, and the order is what makes the refusal
        // legible. Encrypting first would spend the work and then refuse on a
        // length nothing in the ciphertext explains; refusing first means the
        // number in the message is the number the caller sent.
        if let Err(refusal) = check_stored_names(r) {
            // WITHOUT THIS THE REFUSAL IS RECORDED AS `UNRECORDED`. `Call::fail`
            // takes `self` by value so the compiler holds it ahead of the `Err`,
            // but a path that never calls it compiles fine and drops the `Call`
            // — and this branch is brand new, so there was nothing to copy.
            call.fail("INVALID_ARGUMENT");
            return Err(refusal);
        }

        let enc = |s: &str| {
            self.keys
                .encrypt(s)
                .map_err(|_| Status::internal("cannot encrypt"))
        };

        let mut upstream = Request::new(db::CreateUserRequest {
            // D9's key travels, on `revoke_credential`'s reasoning.
            idempotency: r.idempotency.clone(),
            // DEAD FIELDS, AND EMPTY IS THE SECURITY PROPERTY. The plaintext name
            // and display name never cross this boundary; the ciphertexts and the
            // blind index below are what the store receives. Written out empty
            // rather than defaulted, so the boundary's own rule is legible here.
            //
            // TWO FIELDS, TWO EXPECTATIONS, for the reason given in `login`: one
            // attribute covering both is satisfied by either, so the day one of
            // them stops being deprecated the lint stays quiet about the other.
            #[expect(
                deprecated,
                reason = "the dead field is written out rather than defaulted: see above"
            )]
            external_id: String::new(),
            #[expect(
                deprecated,
                reason = "the dead field is written out rather than defaulted: see above"
            )]
            display_name: String::new(),
            external_id_ciphertext: enc(&r.external_id)?,
            display_name_ciphertext: enc(&r.display_name)?,
            external_id_blind_index: self.keys.blind_index(&r.external_id),
            // D73'S ADMIN FLAG, AND IT HAS TO ARRIVE. It is settable at creation
            // for exactly one reason the contract states: the FIRST administrator
            // must exist before anyone can log in to promote one. This service
            // does not decide the value and does not authorise on it — it carries
            // what the caller sent, which is what `SetUserAdmin` exists to change
            // afterwards.
            is_admin: r.is_admin,
            // FORWARDED, AND THE SINK IS REAL. `iamdb.v1.CreateUser` records the
            // actor from v0.7.31 on, after generating the new id so one line names
            // both who asked and what was created. ADR-0534's field is audit-only:
            // it is forwarded exactly as received, `None` stays `None`, and nothing
            // here authorises on it.
            unverified_actor: r.unverified_actor.clone(),
        });
        forward_request_id(&req, &mut upstream);

        let created = self
            .client()
            .create_user(upstream)
            .await
            .map_err(upstream_failed)?
            .into_inner();

        call.finish(Outcome {
            status: "OK",
            ..Default::default()
        });
        Ok(Response::new(CreateUserResponse { meta: created.meta }))
    }

    pub(super) async fn add_team_member_inner(
        &self,
        req: Request<AddTeamMemberRequest>,
        call: Call,
    ) -> Result<Response<AddTeamMemberResponse>, Status> {
        let mut upstream = Request::new(db::AddTeamMemberRequest {
            // D9's key travels, on `revoke_credential`'s reasoning.
            idempotency: req.get_ref().idempotency.clone(),
            team_id: req.get_ref().team_id.clone(),
            user_id: req.get_ref().user_id.clone(),
            // NOT FORWARDED, for the reason given at `issue_credential`. One of
            // that comment's five remaining relay sites.
            unverified_actor: None,
        });
        forward_request_id(&req, &mut upstream);

        self.client()
            .add_team_member(upstream)
            .await
            .map_err(upstream_failed)?;

        // ADDING invalidates too, and the subject is named `teams-changed`
        // rather than `teams-removed` precisely so this is not forgotten — see
        // `invalidate::subject::TEAMS_CHANGED`. Granting a team changes what a
        // cached identity says just as removing one does; without this, a newly
        // granted permission arrives up to 300s late and reads as a bug in
        // whatever the person was trying to reach.
        self.invalidator.teams_changed(&req.get_ref().user_id).await;

        call.finish(Outcome {
            status: "OK",
            ..Default::default()
        });
        Ok(Response::new(AddTeamMemberResponse {}))
    }

    pub(super) async fn remove_team_member_inner(
        &self,
        req: Request<RemoveTeamMemberRequest>,
        call: Call,
    ) -> Result<Response<RemoveTeamMemberResponse>, Status> {
        let mut upstream = Request::new(db::RemoveTeamMemberRequest {
            // D9's key travels, on `revoke_credential`'s reasoning.
            idempotency: req.get_ref().idempotency.clone(),
            team_id: req.get_ref().team_id.clone(),
            user_id: req.get_ref().user_id.clone(),
            // NOT FORWARDED, for the reason given at `issue_credential`. One of
            // that comment's five remaining relay sites.
            unverified_actor: None,
        });
        forward_request_id(&req, &mut upstream);

        self.client()
            .remove_team_member(upstream)
            .await
            .map_err(upstream_failed)?;

        self.invalidator.teams_changed(&req.get_ref().user_id).await;

        call.finish(Outcome {
            status: "OK",
            ..Default::default()
        });
        Ok(Response::new(RemoveTeamMemberResponse {}))
    }
}
