//! The credential surface: resolving one, listing them, minting one and
//! revoking one.

use super::validate::*;
use super::*;

/// The longest life [`IamService::issue_credential`] will grant: ten years.
///
/// A BOUND ON THE DURATION ASKED FOR, NOT ON THE INSTANT IT PRODUCES, and that
/// distinction is the whole reason the number is this one. The store writes the
/// deadline into a MariaDB `TIMESTAMP` through `FROM_UNIXTIME`, and that
/// column's ceiling MOVES BETWEEN MINOR VERSIONS of the engine. Measured against
/// `mariadb:11.8.9`, the image `iam-db`'s README stands up, at its stock
/// `sql_mode`: `FROM_UNIXTIME(2147483648)` stores `2038-01-19 03:14:08` without
/// complaint — the classic 32-bit bound is NOT where 11.8 refuses, because 11.5
/// widened the column — while `FROM_UNIXTIME(4294967296)` is NULL and the INSERT
/// is refused outright with `ERROR 1292`. A ceiling copied from that measurement
/// into this file would be `iam` hardcoding a number owned by a version of a
/// database it does not talk to directly and does not deploy.
///
/// SO THE REFUSAL IS ABOUT WHAT THE FIELD MEANS INSTEAD. `expires_in_seconds`
/// asks for a bearer credential's life, and the expiry exists to bound what a
/// leaked token is worth. A token asked to live longer than a decade is asking
/// for no bound at all — which this contract already offers, spelled `0`, and
/// which a caller that wants it should say rather than approximate. Ten years
/// stays under the measured store ceiling until roughly 2096, so the refusal a
/// caller meets here is this service's own and never the store's.
pub(super) const MAX_EXPIRES_IN_SECONDS: i64 = 315_360_000;

/// The two `expires_in_seconds` values `IssueCredential` refuses, and why the
/// refusal belongs on this boundary rather than at the store.
///
/// The contract says of this field exactly one thing — "Zero means no expiry" —
/// so neither value below is one a caller written against it sends, and refusing
/// them is not a refusal such a caller newly meets. What each one did before is
/// different, and only one of them ever reached the database.
///
/// **ABOVE THE BOUND ALREADY FAILED CLOSED, and the fix is the message rather
/// than the outcome.** Measured against `mariadb:11.8.9` — the image `iam-db`'s
/// README stands up — at its stock `sql_mode`, which is strict:
/// `FROM_UNIXTIME(4294967296)` is NULL, and the INSERT is REFUSED with `ERROR
/// 1292 Truncated incorrect unixtime value` rather than storing that NULL. So no
/// credential was ever written with a swallowed deadline. But `iam-db` renders
/// every engine error as "storage unavailable", so a malformed request came back
/// to its caller reading as an outage, implicating a database that was working.
/// Refusing here is ADR-0512's shape: the negative outcome is documented on the
/// boundary the caller compiles against. It also makes the outcome independent
/// of the store's `sql_mode` — the same INSERT stores the NULL under `sql_mode
/// = ''`, which nothing here deploys and nothing here asserts either.
///
/// **A NEGATIVE FAILED OPEN, and never involved the store at all.** The deadline
/// is only sent when the request asks for a positive one, so a negative sent
/// `expires_at: None` — the unlimited life `0` asks for, handed to the request
/// that asked for the shortest one possible. That is the credential that
/// authenticates forever, and it lives in this file rather than in the database.
fn check_issue_credential(r: &IssueCredentialRequest) -> Result<(), Status> {
    // HAD NO BOUND AT ALL, on the same handler that gained a validation function
    // for `expires_in_seconds`. See `check_label`: an over-long one reached the
    // column and came back as `UNAVAILABLE "storage unavailable"`, which
    // implicates a database that is working for a request that was never
    // well-formed — ADR-0512's misattribution, on the administrative path.
    check_label(&r.label)?;
    // HAD NO BOUND EITHER, and this handler is the only one that hands a
    // caller's id to a column with nothing between. `iam-db`'s
    // `create_credential` is the one write in that service with no `live_user`
    // check, so `user_id` was bound straight into `iam_credential.user_id
    // VARCHAR(96)` — and `ERROR 1406` came back as `UNAVAILABLE "storage
    // unavailable"`. See [`MAX_ENTITY_ID_CHARS`] for the half this does not
    // close: a SHORT id naming nobody still fails the foreign key.
    check_entity_id("user_id", &r.user_id)?;
    if r.expires_in_seconds < 0 {
        return Err(Status::invalid_argument(
            "expires_in_seconds cannot be negative: a deadline already past is \
             not a shorter life, and it will not be read as the unlimited one \
             that 0 asks for",
        ));
    }
    if r.expires_in_seconds > MAX_EXPIRES_IN_SECONDS {
        return Err(Status::invalid_argument(
            "expires_in_seconds is longer than this service will grant a \
             credential; send 0 to ask for no expiry at all",
        ));
    }
    Ok(())
}

impl Iam {
    pub(super) async fn resolve_credential_inner(
        &self,
        req: Request<ResolveCredentialRequest>,
        call: Call,
    ) -> Result<Response<ResolveCredentialResponse>, Status> {
        let mut upstream = Request::new(db::ResolveCredentialRequest {
            token_hash: Keys::token_hash(&req.get_ref().token),
        });
        forward_request_id(&req, &mut upstream);

        let got = self
            .client()
            .resolve_credential(upstream)
            .await
            .map_err(upstream_failed)?
            .into_inner();

        // AN EMPTY user_id IS A NEGATIVE ANSWER, and it must not be cacheable.
        //
        // `iam-db` returns an empty response for "no live credential" — unknown,
        // revoked, expired, or belonging to a soft-deleted person. Copying that
        // through with the ordinary TTL tells the gateway to remember, for five
        // minutes, that a token resolves to user_id "". Nothing consumes this
        // field yet, which is exactly why the shape is pinned now: the consumer
        // that caches on it has not been written, and by the time it is, a
        // `valid_for_seconds: 300` beside an empty user id looks deliberate.
        //
        // Zero, not a shorter TTL: there is no interval over which "this token
        // belongs to nobody" is worth remembering, and a revoked credential's
        // negative answer is the one thing that must never be served from a
        // cache.
        let resolved = !got.user_id.is_empty();
        let resp = ResolveCredentialResponse {
            user_id: got.user_id,
            team_ids: got.team_ids,
            // The gateway's cache TTL. A BACKSTOP, not the invalidation
            // mechanism — revocation and team changes arrive as broker events
            // (D72). Five minutes bounds how long a missed event can leave a
            // revoked credential working.
            valid_for_seconds: if resolved { 300 } else { 0 },
            // D73's flag, read in the same transaction as the credential and
            // passed straight through. FALSE IS THE SAFE DEFAULT — an `iam` that
            // did not set it denies administration rather than granting it —
            // which is why it is forwarded rather than left to that default: the
            // safe reading of an absent value is not a reason to make every
            // admin absent.
            is_admin: got.is_admin,
            // DELIBERATELY LEFT EMPTY IN THIS CHANGE, and empty is a defined
            // answer rather than a missing one: no override for any bucket, so
            // the gateway's configured defaults apply unmodified. It is NOT
            // "deny everything". D74's overrides need a mapping between the
            // storage and API shapes of `RateLimitOverride` and are not part of
            // enrolment; forwarding them is the follow-up this line marks.
            rate_limit_overrides: Vec::new(),
            // ADR-0522's setting, MOVED WHOLE AND NEVER REBUILT.
            //
            // **THE INPUTS, NEVER THE ANSWER.** `iam` resolves none of this. The
            // resolution depends on the team of the ROW being read, which no
            // caller upstream of the query knows, so it happens where the reach
            // is computed. `yadgar.common.v1.InheritedSetting` states the rule
            // once; writing a second copy of it here is the mistake that
            // comment exists to prevent.
            //
            // **NO DEFAULT IS SUBSTITUTED FOR AN ABSENT ONE, AND THAT IS THE
            // WHOLE POINT.** `iam-db` answers with the message ABSENT when the
            // organisation row is not there, and with `org_locked` FALSE — and
            // false is the PERMISSIVE half of a policy the deployment never
            // stated. An `unwrap_or_default()` here, or any field-by-field
            // reconstruction, would hand a -db a policy nobody chose. Absent and
            // present-holding-UNSPECIFIED are ONE case, which a -db that reads
            // this setting REFUSES rather than reading as OFF. A single move is
            // what makes substituting a default unwritable rather than merely
            // discouraged.
            //
            // NOT BRANCHED ON `resolved`, unlike `valid_for_seconds` above. That
            // TTL is zeroed on the negative path because a negative answer is
            // worth caching for no interval. This setting is DEPLOYMENT-WIDE
            // rather than credential-scoped, and no rule in the contract makes
            // it conditional on a credential matching.
            owner_reads_own_record: got.owner_reads_own_record,
        };
        call.finish(Outcome {
            status: "OK",
            ..Default::default()
        });
        Ok(Response::new(resp))
    }

    /// TAKES ONLY THE `Call`, because it reads nothing from the request: it
    /// refuses every one of them. The parameter list says so rather than
    /// leaving a reader to check.
    pub(super) async fn list_credentials_inner(
        &self,
        call: Call,
    ) -> Result<Response<ListCredentialsResponse>, Status> {
        call.fail("UNIMPLEMENTED");
        Err(Status::unimplemented(
            "ListCredentials is not implemented yet; an orphaned credential is \
             currently findable only in the store",
        ))
    }

    pub(super) async fn issue_credential_inner(
        &self,
        req: Request<IssueCredentialRequest>,
        call: Call,
    ) -> Result<Response<IssueCredentialResponse>, Status> {
        let r = req.get_ref();
        // BEFORE THE MINT, so a refused request leaves no token in existence.
        if let Err(refusal) = check_issue_credential(r) {
            call.fail("INVALID_ARGUMENT");
            return Err(refusal);
        }

        let token = Keys::mint_token().map_err(|_| Status::internal("cannot mint a credential"))?;
        let mut create = Request::new(db::CreateCredentialRequest {
            // NOT FORWARDED, AND THIS IS THE ONE PLACE THAT SILENCE WAS A
            // DECISION RATHER THAN AN OVERSIGHT. `yadgar.common.v1.Idempotency`
            // names `IssueCredential` as the case ADR-0519's single-use-secret
            // carve-out "would reach", and says moving it "is its own decision
            // and its own contract release, and it is not made here". Handing
            // the caller's key to the store would decide it from this file: the
            // store would replay the key and answer with a credential whose
            // token was minted in the first call and kept only as a hash, so the
            // second caller receives a token that authenticates nobody — the
            // dead-token failure ADR-0519 exists to name. `RedeemEnrolment` puts
            // its own mint outside the caller's key for exactly this reason.
            //
            // **AND THE OTHER HALF, BECAUSE NOT FORWARDING IT IS NOT FREE.**
            // That same comment enumerates the carve-out's members and says "AN
            // RPC NOT NAMED HERE IS NOT A MEMBER, however well it fits the
            // description" — and today the list is one, `IssueEnrolment`. So as
            // published, `IssueCredential` is governed by D9's ORDINARY rule,
            // under which a retry of the same key returns the first answer. It
            // does not: `iam` accepts a key it then discards, so a caller
            // retrying a lost response mints a SECOND live credential and the
            // first is orphaned — a token nobody holds, revocable by nobody who
            // knows it exists, live until its expiry. Forwarding the key here
            // would trade that for the dead-token failure above, which is worse
            // and is not this file's to choose. The resolution is a contract
            // release that classifies this RPC, not a change on this line.
            idempotency: None,
            user_id: r.user_id.clone(),
            token_hash: Keys::token_hash(&token),
            label: r.label.clone(),
            // THE DEADLINE THE CALLER ASKED FOR. Zero means no expiry, which the
            // contract states in as many words, and it is the ONLY remaining way
            // to reach `None` here: a negative and an absurd value are both
            // refused above, by `check_issue_credential`, which carries the
            // measurement that argues for each refusal.
            //
            // ADDED IN SECONDS ON THE WIRE TYPE. Kept SATURATING although the
            // bound makes the saturation unreachable — a ten-year offset cannot
            // carry an epoch second past `i64::MAX` — because `SystemTime +
            // Duration` aborts the process on overflow and nothing about this
            // handler should depend on a bound staying where it is today.
            expires_at: (r.expires_in_seconds > 0).then(|| {
                let now = prost_types::Timestamp::from(SystemTime::now());
                prost_types::Timestamp {
                    seconds: now.seconds.saturating_add(r.expires_in_seconds),
                    nanos: now.nanos,
                }
            }),
            // NOT FORWARDED, AND THE FIELD IS ON BOTH SIDES OF THIS HOP.
            // `IssueCredentialRequest` grew ADR-0534's actor in proto v1.10.0 and
            // nothing populates it: the gateway reaches three RPCs and this is
            // not one of them, so there is no administrative path for an actor to
            // arrive on. Relaying `r.unverified_actor` today would move `None`
            // and READ AS A RELAY THAT WORKS.
            //
            // **THE RELAY HAS EIGHT SITES AND FIVE OF THEM STILL SEND `None`**:
            // here, `revoke_credential`, `add_team_member`, `remove_team_member` and
            // `set_inherited_setting`. Five sites were invisible until this file
            // stopped using a rest pattern, so whoever wires the path by grepping
            // for the field would have found two.
            //
            // **THREE RELAY FOR REAL — `set_user_admin`, `create_user` and
            // `issue_enrolment`** — so "nothing populates the field" is not true of
            // this service as a whole. It stays true here: those three are exactly
            // the RPCs the gateway's administrative route reaches, and this is not
            // one of them. The five above wait on a caller each, not on a sink;
            // `iam-db` v0.7.31 reads the field on four verbs and would need the
            // same additive change for `CreateCredential`, `RevokeCredential`,
            // `AddTeamMember` and `RemoveTeamMember`.
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
        Ok(Response::new(IssueCredentialResponse {
            token: token.to_string(),
            credential_id: created.credential_id,
        }))
    }

    pub(super) async fn revoke_credential_inner(
        &self,
        req: Request<RevokeCredentialRequest>,
        call: Call,
    ) -> Result<Response<RevokeCredentialResponse>, Status> {
        let mut upstream = Request::new(db::RevokeCredentialRequest {
            // D9's key travels. A revocation is a mutating RPC a retrying load
            // balancer will deliver twice, and the key is what makes the second
            // delivery a replay rather than a second write.
            idempotency: req.get_ref().idempotency.clone(),
            credential_id: req.get_ref().credential_id.clone(),
            // NOT FORWARDED, for the reason given at `issue_credential`: nothing
            // populates the field, so a relay would move `None` and read as one
            // that works. One of that comment's five remaining relay sites.
            unverified_actor: None,
        });
        forward_request_id(&req, &mut upstream);

        let done = self
            .client()
            .revoke_credential(upstream)
            .await
            .map_err(upstream_failed)?
            .into_inner();

        // The USER, not the credential — the gateway's cache is keyed on a token
        // hash this service never sees, so the person is the addressable unit.
        // This is why RevokeCredential returns user_id at all.
        self.invalidator.credential_revoked(&done.user_id).await;

        call.finish(Outcome {
            status: "OK",
            ..Default::default()
        });
        Ok(Response::new(RevokeCredentialResponse {}))
    }
}
