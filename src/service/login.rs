//! `Login`, and the response-time floor that hides what it found.
//!
//! The floor is here rather than in [`super`] because it exists for this
//! RPC's enumeration problem; `RedeemEnrolment` holds itself to one for a
//! different reason, stated at its own handler.

use super::validate::*;
use super::*;

impl Iam {
    /// Everything `Login` actually does. Wrapped by the trait method, which is
    /// what holds it to the response-time floor.
    ///
    /// SPLIT SO THE FLOOR CANNOT BE PARTIAL. With the work in its own function
    /// there is one place the elapsed time is read and one place it is paid, and
    /// no `return` inside this body can skip either — the early refusal below is
    /// exactly the path that would otherwise answer fastest.
    ///
    /// D67's `Call` IS OPENED BY THE HANDLER AND FINISHED HERE, so it spans the
    /// work and NOT the wait. An operator sets the floor from the real duration
    /// distribution, and a metric padded to a constant would report the constant
    /// instead — deleting the one signal that says the floor needs raising. The
    /// gap between what this records and what a client observes is deliberate,
    /// and [`Self::hold_until_floor`] is what makes it visible when it closes.
    ///
    /// TAKING `call` AS A PARAMETER IS ALSO WHAT KEEPS `observe-coverage` HONEST.
    /// That hook follows same-file calls to find a `Call::start`, but its
    /// `BARE_CALL` pattern excludes an identifier preceded by `.`, so a
    /// `self.login_inner(…)` hop is invisible to it: opening the `Call` in here
    /// would leave the handler reading as uninstrumented. Opening it in the
    /// handler and passing it down satisfies the check by being true rather than
    /// by an exemption.
    pub(super) async fn login_inner(
        &self,
        req: Request<LoginRequest>,
        call: Call,
    ) -> Result<Response<LoginResponse>, Status> {
        // VALIDATION BEFORE LOOKUP, and this check was ABSENT ENTIRELY. `Login`
        // stores a caller-supplied `label` in the same column `RedeemEnrolment`
        // and `IssueCredential` do, and it was the only one of the three with no
        // bound on it — so an over-long label verified the password, minted a
        // token, and then failed the INSERT, which reaches the caller as
        // `UNAVAILABLE "storage unavailable"`. A sign-in that reports an outage
        // for a request that was never well-formed sends a person to an operator
        // instead of to their own input.
        //
        // **INSIDE `login_inner` AND NOT IN THE HANDLER**, which is the same
        // reason this function exists: the handler is what pays the
        // response-time floor, so a refusal placed above the call to this one
        // would be the fast path the floor exists to close. Here it is floored
        // like every other answer.
        //
        // NO ORACLE. The check is answerable from the request alone and says
        // nothing about whether the username exists — which is exactly the
        // property `iam.proto` states as VALIDATION BEFORE LOOKUP for the
        // sharper case, `RedeemEnrolment`.
        if let Err(refusal) = check_label(&req.get_ref().label) {
            // WITHOUT THIS THE REFUSAL IS RECORDED AS `UNRECORDED`. `Call::fail`
            // takes `self` by value so the compiler holds it ahead of the `Err`,
            // but a path that never calls it compiles fine and drops the `Call`
            // — and this branch is brand new, so there was nothing to copy.
            call.fail("INVALID_ARGUMENT");
            return Err(refusal);
        }

        // The username never leaves this process. What goes to the store is its
        // blind index, so the plaintext reaches no query log and no backup.
        let mut lookup = Request::new(db::GetPasswordHashRequest {
            // DEAD FIELD, AND EMPTY IS THE SECURITY PROPERTY RATHER THAN AN
            // OMISSION. The plaintext username never crosses this boundary — it
            // would otherwise reach a query log and a database backup — so the
            // superseded field is written out empty rather than left to a rest
            // pattern that would say the same thing silently.
            //
            // THE EXPECTATION IS ON THIS FIELD AND NOT ON THE STATEMENT, which
            // is the same distinction the rest of this change is about. On the
            // statement it is satisfied by ANY deprecated field in the literal,
            // so a `#[deprecated]` later landing on `username_blind_index` would
            // be absorbed silently and `unfulfilled_lint_expectations` would
            // never fire. One field, one expectation.
            #[expect(
                deprecated,
                reason = "the dead field is written out rather than defaulted: see above"
            )]
            username: String::new(),
            username_blind_index: self.keys.blind_index(&req.get_ref().username),
        });
        forward_request_id(&req, &mut lookup);

        let found = self
            .client()
            .get_password_hash(lookup)
            .await
            .map_err(upstream_failed)?
            .into_inner();

        // THE ORDER HERE IS THE SECURITY PROPERTY.
        //
        // `verify_password` is called whether or not a user was found, and it
        // does a full Argon2id verification either way — against the real hash if
        // there is one, against a dummy otherwise. Returning early on an unknown
        // username would make it answer in microseconds while a known one takes
        // the ~50ms Argon2id costs, and that difference is measurable over a
        // network. The endpoint would enumerate accounts.
        let stored = (!found.user_id.is_empty()).then_some(found.argon2id_hash.as_str());
        if !self.keys.verify_password(stored, &req.get_ref().password) {
            call.fail("UNAUTHENTICATED");
            return Err(refused());
        }

        let token = Keys::mint_token().map_err(|_| Status::internal("cannot mint a credential"))?;
        let mut create = Request::new(db::CreateCredentialRequest {
            // NOTHING TO SUPPLY: `LoginRequest` carries no idempotency key. D9's
            // key covers mutating RPCs a caller can retry, and a sign-in is not
            // one this contract gives a key to.
            idempotency: None,
            user_id: found.user_id.clone(),
            token_hash: Keys::token_hash(&token),
            label: req.get_ref().label.clone(),
            // NOTHING TO SUPPLY: `LoginRequest` has no field to ask for an
            // expiry, so there is no deadline to carry.
            expires_at: None,
            // NOTHING TO SUPPLY, AND NOT MERELY UNWIRED. `Login` is the person
            // themselves signing in, not an administrator acting on someone —
            // `LoginRequest` carries no actor and ADR-0534's field is for
            // administrative requests.
            unverified_actor: None,
        });
        forward_request_id(&req, &mut create);

        let created = self
            .client()
            .create_credential(create)
            .await
            .map_err(upstream_failed)?
            .into_inner();

        call.finish(Outcome {
            status: "OK",
            ..Default::default()
        });
        Ok(Response::new(LoginResponse {
            // The only time this value is ever returned. The store holds a hash.
            token: token.to_string(),
            credential_id: created.credential_id,
        }))
    }

    /// Wait out whatever is left of the floor, or say that there was nothing left.
    ///
    /// **A FLOOR CLOSES ONLY THE FAST SIDE.** Padding a short call up to a
    /// constant makes every call that is FASTER than the constant look alike; a
    /// call that is SLOWER answers late and still reports how much work it did.
    /// So when `elapsed` exceeds the floor the control is not merely inactive for
    /// that call, it is covering nothing — and the only thing that can be done
    /// about it is to raise the configured value, which needs an operator who
    /// knows. Hence the warning, naming both numbers: the observed duration and
    /// the floor it passed.
    ///
    /// Without it this degrades in silence. The floor keeps being applied, the
    /// tests keep passing, and the property it is supposed to deliver is simply
    /// gone for whichever rows are slow — a check that cannot fail, which is
    /// worse than none.
    ///
    /// **NOT AN ERROR, deliberately.** A verification slower than the floor is
    /// still a CORRECT verification. Refusing it would lock out exactly the
    /// accounts whose unusual cost this exists to hide, turning a leak into an
    /// outage; the same trade is worked through at
    /// [`crate::crypto::Keys::verify_password`], where refusing a cheap stored
    /// hash before verifying it would make every pre-tune account a permanent
    /// lockout.
    ///
    /// `checked_sub` returns `None` ONLY when `elapsed` is STRICTLY greater than
    /// the floor, so answering exactly on it sleeps zero and warns nothing —
    /// "exceeds" means exceeds.
    ///
    /// **ONE MECHANISM FOR BOTH FLOORED RPCs, AND TWO CONFIGURED VALUES.** The
    /// rule is identical for `Login` and `RedeemEnrolment`, so a second copy of
    /// it would be a second place to get it wrong; the VALUES cannot be shared,
    /// because a redemption legitimately costs more and would then warn on every
    /// call. Which RPC is naming its floor travels in the event, so the two do
    /// not merge into one indistinguishable stream of warnings.
    pub(super) async fn hold_until_floor(&self, floor: Floor, elapsed: Duration) {
        let Some(remaining) = floor.value.checked_sub(elapsed) else {
            tracing::warn!(
                rpc = floor.rpc,
                observed_ms = elapsed.as_millis() as u64,
                floor_ms = floor.value.as_millis() as u64,
                floor_env = floor.env,
                "this call took longer than its response-time floor; the floor is \
                 hiding nothing for it. Raise the named variable above the slowest \
                 legitimate call of this RPC on this deployment."
            );
            return;
        };
        tokio::time::sleep(remaining).await;
    }
}
