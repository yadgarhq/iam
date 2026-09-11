//! `IssueEnrolment` and `RedeemEnrolment` — the two unauthenticated-by-
//! construction paths (D73).
//!
//! Together in one file because they are two halves of one mechanism: what
//! `IssueEnrolment` mints is exactly what `RedeemEnrolment` spends, and the
//! lifetime one writes is the one the other is refused by.

use super::validate::*;
use super::*;

/// D73's 24 hours, and NOT configurable.
///
/// The deadline is written into the store at creation rather than recomputed at
/// read time, so a value that moved would silently re-date every live token
/// rather than only the ones minted after the change. A constant is what makes
/// "every enrolment expires 24 hours after it was minted" true of the rows as
/// well as of the code.
const ENROLMENT_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);

/// The longest password `RedeemEnrolment` accepts.
///
/// A BOUND, NOT A POLICY. It is here because the password is hashed BEFORE the
/// enrolment secret is looked up — which is what stops `INVALID_ARGUMENT` from
/// reporting that the secret was good — and an unbounded input on an
/// unauthenticated path is then work anyone can ask for without presenting
/// anything. Nothing about strength is asserted; that belongs to whatever sets
/// policy, and this file is not it.
const MAX_PASSWORD_BYTES: usize = 1024;

/// Everything that can be refused WITHOUT looking the secret up.
///
/// **THIS IS THE LIST, AND ITS SHORTNESS IS THE POINT.** Any check added here
/// must be answerable from the request alone; a check that needs to know whether
/// the secret exists belongs after the lookup and must refuse with
/// `UNAUTHENTICATED` like every other outcome there, or the status code becomes
/// the oracle constant work was meant to close.
///
/// THE SECRET IS DELIBERATELY NOT VALIDATED. An empty or malformed one is left
/// to fall through to the lookup and be refused as unknown, which is what it is.
/// A shape check on it would be a second way for this endpoint to answer, told
/// apart from the first by its status code.
fn validate_redemption(r: &RedeemEnrolmentRequest) -> Result<(), Status> {
    // REQUIRED, and this is the field the whole retry-safety story rests on. A
    // redemption spends the secret and mints the credential, so a lost response
    // with no key leaves the person holding a password they chose, a spent
    // secret, no credential and no username — and a bare retry answers
    // UNAUTHENTICATED. The key is what makes the retry reach the store as the
    // same write.
    if r.idempotency.as_ref().is_none_or(|i| i.key.is_empty()) {
        return Err(Status::invalid_argument(
            "an idempotency key is required: without one a retry spends the \
             secret a second time instead of replaying the first attempt, and a \
             lost response locks the person out",
        ));
    }
    // **THE SHARPEST INSTANCE OF THE BOUNDED-COLUMN CLASS, AND IT IS ON THIS
    // PATH.** The ledger INSERT is the LAST statement of the store's spend
    // transaction, so an over-long key made the whole transaction roll back:
    // `UNAVAILABLE "storage unavailable"` to the caller, the secret still
    // unspent, and every retry under that same key repeating it for ever. A
    // permanent 503 no retry escapes, on an unauthenticated endpoint, for a
    // request that was never well formed.
    //
    // ANSWERABLE FROM THE REQUEST ALONE, which is what this function's own
    // header requires of anything added to it. The key's length says nothing
    // about whether the secret exists or has been spent, so it opens no oracle.
    check_idempotency_key(r.idempotency.as_ref().map_or("", |i| i.key.as_str()))?;
    // A password nobody typed is not a password. The only strength rule stated
    // here, deliberately — see MAX_PASSWORD_BYTES.
    if r.password.is_empty() {
        return Err(Status::invalid_argument("a password is required"));
    }
    if r.password.len() > MAX_PASSWORD_BYTES {
        return Err(Status::invalid_argument(
            "the password is longer than this service will hash",
        ));
    }
    check_label(&r.label)?;
    Ok(())
}

impl Iam {
    /// Everything `RedeemEnrolment` actually does, split from the handler for
    /// the reason [`Self::login_inner`] is split: with the work in its own
    /// function there is one place the elapsed time is read and one place it is
    /// paid, and no `return` in this body can skip either.
    ///
    /// **THE ORDER OF THE FOUR STEPS IS THE WHOLE SECURITY PROPERTY**, and each
    /// is placed against a named leak:
    ///
    /// 1. **VALIDATE FIRST.** Every check that does not need the secret runs
    ///    before the secret is looked up. Otherwise `INVALID_ARGUMENT` comes
    ///    back only once the secret has been confirmed, and the STATUS CODE
    ///    itself says the secret was good — an oracle cleaner than timing, and
    ///    one no amount of constant work touches.
    /// 2. **HASH BEFORE THE LOOKUP.** The Argon2id cost is paid on every path
    ///    because it is paid before anything is known about the secret. An
    ///    implementation that hashed only after a hit would answer an unknown
    ///    secret in microseconds and a valid one in tens of milliseconds.
    /// 3. **ONE REFUSAL FOR THREE OUTCOMES.** Unknown, spent and expired are all
    ///    `UNAUTHENTICATED` with one message. The store tells them apart and
    ///    records which; the caller cannot. The refusal path ALSO pays the
    ///    verification the success path is about to pay, so the two cost the
    ///    same two Argon2id operations rather than two against one. **The
    ///    store's own ERROR is a fourth outcome and is collapsed with them**:
    ///    an idempotency key already recorded against a different secret is
    ///    refused there with `INVALID_ARGUMENT`, before the presented secret is
    ///    looked up, and forwarding that code told a caller holding no secret
    ///    whether the key had been redeemed. See the call site.
    /// 4. **THE REPLAY CHECK, WHICH REMEMBERS NOTHING.** `iam` holds no store
    ///    (D4), so it cannot know whether this key has been seen. It does not
    ///    need to: it verifies the presented password against the hash the store
    ///    already holds — the comparison `Login` makes on every call. A first
    ///    attempt always passes, because the store has just written that very
    ///    hash. A key replayed with a DIFFERENT password fails, and is refused
    ///    rather than answered with the first attempt's outcome — which would
    ///    leave the FIRST password live while the person believed the second had
    ///    taken effect.
    pub(super) async fn redeem_inner(
        &self,
        req: Request<RedeemEnrolmentRequest>,
        call: Call,
    ) -> Result<Response<RedeemEnrolmentResponse>, Status> {
        // 1. VALIDATION BEFORE LOOKUP.
        if let Err(refusal) = validate_redemption(req.get_ref()) {
            call.fail("INVALID_ARGUMENT");
            return Err(refusal);
        }
        // 2-3. THE HASHING AND THE SPEND, in `Self::spend_enrolment`: every
        // refusal reachable before the secret is confirmed lives there, and
        // every one of them is indistinguishable from the others.
        let (spent, call) = self.spend_enrolment(&req, call).await?;

        // The username, decrypted exactly as it was encrypted. A person
        // enrolling on their first machine has no in-band way to learn it, and
        // `iam` holds no store to have remembered it in — so the store returning
        // the ciphertext in the same transaction is the only place a retry can
        // recover it from.
        let username = self
            .keys
            .decrypt(&spent.external_id_ciphertext)
            .map_err(|_| Status::internal("cannot decrypt the stored username"))?;

        // 4. THE REPLAY CHECK. The blind index is computed here from the name
        // just decrypted; the plaintext still crosses no boundary.
        let mut lookup = Request::new(db::GetPasswordHashRequest {
            // DEAD FIELD, EMPTY FOR THE REASON GIVEN IN `login`: the plaintext
            // name just decrypted must not cross this boundary either. The
            // expectation is per-field for the reason given there too.
            #[expect(
                deprecated,
                reason = "the dead field is written out rather than defaulted: see above"
            )]
            username: String::new(),
            username_blind_index: self.keys.blind_index(&username),
        });
        forward_request_id(&req, &mut lookup);
        let held = self
            .client()
            .get_password_hash(lookup)
            .await
            .map_err(upstream_failed)?
            .into_inner();

        let stored = (!held.user_id.is_empty()).then_some(held.argon2id_hash.as_str());
        if !self.keys.verify_password(stored, &req.get_ref().password) {
            call.fail("INVALID_ARGUMENT");
            // NAMED, AND SAFE TO NAME. Reaching this line means the secret was
            // already confirmed and spent under this very key, so the refusal
            // reports nothing the caller did not already know. That is the
            // opposite of the refusals above it, and the reason validation runs
            // before the lookup rather than here.
            return Err(Status::invalid_argument(
                "this idempotency key was used with a different password; a \
                 replay cannot change the password the first attempt set",
            ));
        }

        // A FRESH CREDENTIAL UNDER ITS OWN KEY. The caller's key deliberately
        // does not cover this write: the token is shown once and kept as a hash,
        // so no replay could return the first one, and a store able to hand its
        // own tokens back is a different class of risk. A retry therefore mints
        // a credential the earlier attempt's owner never holds — the orphan the
        // contract accepts, findable through ListCredentials.
        let token = Keys::mint_token().map_err(|_| Status::internal("cannot mint a credential"))?;
        let mut create = Request::new(db::CreateCredentialRequest {
            idempotency: Some(Idempotency {
                key: uuid::Uuid::now_v7().to_string(),
            }),
            user_id: spent.user_id.clone(),
            token_hash: Keys::token_hash(&token),
            label: req.get_ref().label.clone(),
            // NO EXPIRY, because this request has no field to ask for one.
            expires_at: None,
            // NOT STAMPED. This credential is minted by RedeemEnrolment, whose
            // request carries no actor to record — the holder of the enrolment
            // secret is the subject, not an administrator acting on one. The
            // field exists on the boundary from v1.10.0 and is left absent
            // rather than filled with a value nothing supplied.
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
        Ok(Response::new(RedeemEnrolmentResponse {
            token: token.to_string(),
            credential_id: created.credential_id,
            username,
        }))
    }

    /// Everything that happens BEFORE the presented secret is known good.
    ///
    /// THE SEAM IS THE ONE [`Self::redeem_inner`] ALREADY NAMES: the comment
    /// on the spend below says the two `upstream_failed` sites after it "run
    /// only after the secret is confirmed and spent, so their codes report
    /// nothing the caller does not already know". Everything on THIS side of
    /// that line has to refuse indistinguishably; everything on the other side
    /// may name its reason. Splitting there rather than at a line count keeps
    /// that distinction visible instead of leaving it to a reader to rediscover.
    ///
    /// TAKES AND RETURNS THE `Call` because `Call::fail` and `Call::finish`
    /// consume it: the refusal paths below mark the call failed and the success
    /// path hands it back for [`Self::redeem_inner`] to finish. Nothing about
    /// the order, the statuses or the equalising verifications changes.
    async fn spend_enrolment(
        &self,
        req: &Request<RedeemEnrolmentRequest>,
        call: Call,
    ) -> Result<(db::RedeemEnrolmentResponse, Call), Status> {
        // 2. THE HASHING, PAID BEFORE ANYTHING IS KNOWN. `iam` does it and the
        // plaintext stops here: the store is given a finished PHC string, so no
        // chosen password reaches a query log, a slow-query log or a backup.
        // Through `crypto`'s single mint point, so this hash and the dummy the
        // equalisation verifies against cannot drift apart in cost.
        let argon2id_hash = self
            .keys
            .hash_password(&req.get_ref().password)
            .map_err(|_| Status::internal("cannot hash the password"))?;

        // SPEND AND SET IN ONE TRANSACTION, at the store. The caller's key goes
        // through UNCHANGED and nothing is remembered against it here (D9 puts
        // the deduplication in the owning module's store, D4 leaves `iam`
        // without one).
        let mut spend = Request::new(db::RedeemEnrolmentRequest {
            idempotency: req.get_ref().idempotency.clone(),
            // Deterministic, because the store looks a secret up by it. SHA-256
            // and not Argon2id: this secret is 256 bits of CSPRNG output and has
            // no entropy problem for a slow hash to solve.
            secret_hash: Keys::token_hash(&req.get_ref().secret),
            argon2id_hash,
        });
        forward_request_id(req, &mut spend);

        // THE STORE'S OWN REFUSALS ARE PART OF "ONE REFUSAL FOR THREE OUTCOMES",
        // and forwarding their status code untouched was an oracle on an
        // unauthenticated endpoint. `upstream_failed` replaces the MESSAGE and
        // keeps the CODE — correct everywhere else, and exactly the leak here.
        //
        // WHAT IT LEAKED, with no secret needed: the store compares a presented
        // `secret_hash` against the one its ledger holds for this key BEFORE it
        // looks the secret up, and refuses a mismatch with INVALID_ARGUMENT. So a
        // caller sending any key with a garbage secret learned whether that key
        // had been redeemed — INVALID_ARGUMENT if it had, UNAUTHENTICATED if it
        // had not. The response-time floor equalises TIME and never STATUS.
        //
        // NOTHING IS LOST BY COLLAPSING IT. The only other INVALID_ARGUMENT that
        // call can produce is the store refusing an `argon2id_hash` too long for
        // its column, and `iam` mints that PHC string itself — its length is
        // fixed and unreachable from the request.
        //
        // THE OTHER CODES STAY. UNAVAILABLE and INTERNAL describe the deployment
        // rather than the secret: every caller sees them at once, so they tell an
        // attacker nothing about the key they presented, and collapsing an outage
        // into "this enrolment cannot be redeemed" would send a person to reissue
        // an enrolment that is fine.
        //
        // THE GENERAL RULE, because one call site is not the lesson: a design
        // promising ONE refusal for N outcomes must audit the status code of
        // EVERY upstream error it forwards, not only its own refusal paths. The
        // two remaining `upstream_failed` sites in this function — the password
        // lookup and the credential mint — are safe for the reason step 4 gives:
        // both run only after the secret is confirmed and spent, so their codes
        // report nothing the caller does not already know.
        let spent = match self.client().redeem_enrolment(spend).await {
            Ok(answered) => answered.into_inner(),
            Err(refused) if refused.code() == tonic::Code::InvalidArgument => {
                // THE VERIFICATION THE SUCCESS PATH PAYS, paid here too — the same
                // reason step 3 below pays it, and this path would otherwise be
                // the one refusal costing a single Argon2id operation.
                let _ = self.keys.verify_password(None, &req.get_ref().password);
                // At INFO beside step 3's refusal and for the same reason: the
                // operator diagnosing a failed enrolment needs the store's own
                // words, and the caller must not have them.
                tracing::info!(
                    upstream = %refused.message(),
                    "enrolment redemption refused by the store"
                );
                call.fail("UNAUTHENTICATED");
                return Err(enrolment_refused());
            }
            Err(other) => return Err(upstream_failed(other)),
        };

        // 3. ONE FAILURE, NOT THREE.
        if spent.outcome() != db::RedeemOutcome::Redeemed {
            // THE VERIFICATION THE SUCCESS PATH IS ABOUT TO PAY, paid here too.
            // Without it a refusal costs one Argon2id operation and a redemption
            // costs two, and the response time says which — the same enumeration
            // `Login` closes with the same call, and the reason this one ignores
            // its answer.
            let _ = self.keys.verify_password(None, &req.get_ref().password);
            // The server tells the three apart and the caller does not. Recorded
            // at INFO because it is an ordinary event on an unauthenticated
            // endpoint; an operator diagnosing a failed enrolment needs to know
            // WHICH of the three it was, and that is the only place it exists.
            tracing::info!(
                outcome = spent.outcome().as_str_name(),
                "enrolment redemption refused"
            );
            call.fail("UNAUTHENTICATED");
            return Err(enrolment_refused());
        }

        Ok((spent, call))
    }

    pub(super) async fn issue_enrolment_inner(
        &self,
        req: Request<IssueEnrolmentRequest>,
        call: Call,
    ) -> Result<Response<IssueEnrolmentResponse>, Status> {
        // BEFORE THE SECRET IS MINTED AND BEFORE THE STORE IS TOUCHED, so a
        // deployment without enrolment configured leaves no enrolment row and
        // no secret behind. FAILED_PRECONDITION rather than INTERNAL: the
        // request is well formed and the service is not broken, it is not
        // configured for this — and the message names the variable, because the
        // operator reading it is the one who can fix it.
        let Some(enrolment) = self.enrolment.as_ref() else {
            call.fail("FAILED_PRECONDITION");
            return Err(Status::failed_precondition(
                "enrolment is not configured on this deployment: ENROLMENT_GATEWAY \
                 is unset or the CA it names could not be read, and a token minted \
                 without them would point a new client at nothing",
            ));
        };

        // 256 bits from the OS CSPRNG, through the same mint point a bearer
        // token uses. This secret IS the whole authenticator of an
        // unauthenticated endpoint, so its entropy is the single property that
        // decides whether that endpoint is brute-forceable — and one mint point
        // is what stops a second, weaker one from appearing beside it.
        let secret =
            Keys::mint_token().map_err(|_| Status::internal("cannot mint an enrolment"))?;

        // WRITTEN DOWN AT CREATION, not recomputed at read time: a policy change
        // must not silently re-date every live token.
        let expires_at = prost_types::Timestamp::from(SystemTime::now() + ENROLMENT_LIFETIME);

        let mut create = Request::new(db::CreateEnrolmentRequest {
            idempotency: req.get_ref().idempotency.clone(),
            user_id: req.get_ref().user_id.clone(),
            // The HASH. The secret itself never crosses this boundary, so it
            // reaches no query log and no backup — and deterministic, because
            // redemption looks an enrolment up by exactly this value.
            secret_hash: Keys::token_hash(&secret),
            expires_at: Some(expires_at),
            // NOT FORWARDED, DELIBERATELY. `IssueEnrolmentRequest` grew this
            // field in proto v1.10.0 and nothing in the estate populates it
            // yet, so copying it across would carry `None` under a different
            // name and read as a relay that works. Wiring the relay is
            // ADR-0534's own change, not this pin bump.
            unverified_actor: None,
            // RELAYED VERBATIM. The gateway sets this iff the caller is the
            // bootstrap token (ADR-0655); `iam` neither sets nor inspects it
            // — `iam-db` is the only tier that evaluates the predicate, inside
            // the same transaction as the insert. Copying `false` here by
            // omission is the false green ADR-0655's own design exists to
            // refuse: the demand would be silently dropped and the ordinary
            // path taken with nobody having checked anything.
            require_zero_credential_admin: req.get_ref().require_zero_credential_admin,
        });
        forward_request_id(&req, &mut create);

        let created = self
            .client()
            .create_enrolment(create)
            .await
            .map_err(upstream_failed)?
            .into_inner();

        // THE TRUST ANCHOR TRAVELS WITH THE SECRET, and not merely the secret. A
        // client that has never met this deployment has nothing to verify the
        // gateway against; the out-of-band channel this token is pasted over is
        // already trusted, so the anchor goes on it. `gateway` and `ca_pem` come
        // from this service's configuration, so an admin assembles neither and
        // can get neither wrong.
        let token = EnrolmentToken {
            secret: secret.to_string(),
            gateway: enrolment.gateway.clone(),
            // ABSENT means system trust applies, which is a legitimate
            // deployment. It is never PRESENT AND EMPTY: `EnrolmentConfig`
            // refuses that at boot, because absence is the whole of "use system
            // trust" and an empty string is a token assembled wrong.
            ca_pem: enrolment.ca_pem.clone(),
            expires_at: Some(expires_at),
        };

        // STANDARD ALPHABET, WITH PADDING (RFC 4648 section 4), and NOT the
        // URL-safe unpadded encoding `Keys::mint_token` uses inside the message.
        // The contract names the alphabet because getting it wrong produces a
        // token that decodes to noise on precisely the machines that have never
        // met this deployment and can least diagnose it.
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(prost::Message::encode_to_vec(&token));

        call.finish(Outcome {
            status: "OK",
            ..Default::default()
        });
        Ok(Response::new(IssueEnrolmentResponse {
            token: encoded,
            enrolment_id: created.enrolment_id,
            expires_at: Some(expires_at),
        }))
    }
}
