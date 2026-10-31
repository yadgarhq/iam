//! Adoption: how a POPULATED store with NO marker acquires one, on this
//! process's cryptographic proof that it holds the key set the rows were
//! encrypted under (ADR-1085, as amended by ADR-1089).
//!
//! **A SIBLING FILE, for [`super::stop`]'s reason.** `mod.rs` reaches this from
//! one place — `SetKeyIdentity` answering `FAILED_PRECONDITION` — and
//! everything after that point lives here.
//!
//! # The proof, and it is a whitelist
//!
//! Read the store's OLDEST rows from `ListKeyIdentityEvidence` — every row when
//! it holds [`EVIDENCE_CAP`] or fewer, else the [`EVIDENCE_CAP`] oldest. For
//! EVERY row, AES-256-GCM-decrypt both ciphertexts and recompute the blind index
//! from the decrypted `external_id`. GCM's tag fails under any other encryption
//! key, and the blind index matches under no other blind-index key, so the pair
//! covers both keys in the fingerprint. [`Proof::Passed`] is built only from
//! rows that each passed all three checks; "no row failed" is never a pass, and
//! zero rows read is [`Proof::NoEvidence`], which is no proof at all.
//!
//! # `KEY_IDENTITY_ADOPT`: what a proof may do
//!
//! | mode | `Passed` | `Failed` | `NoEvidence` |
//! | --- | --- | --- | --- |
//! | `observe` | INFO, no `AdoptKeyIdentity`, stays UNVERIFIED | WARN, keeps serving, stays UNVERIFIED | stays UNVERIFIED |
//! | `adopt` | `AdoptKeyIdentity`; passes on `RECORDED` or `MATCH` | ends the serve, exit non-zero | stays UNVERIFIED |
//!
//! `observe` is the read-only dry run ADR-1085 requires before automatic
//! adoption is deployed: one foreign or old-scheme row among the sampled rows
//! exits EVERY pod in `adopt` mode, by design, and `observe` is how an operator
//! finds that row first.
//!
//! **A STATUS ON EITHER RPC IS NEVER A PROOF FAILURE.** It is not-passed, and it
//! is classified as every other status in this module is; `UNIMPLEMENTED` names
//! an `iam-db` that predates the adoption arm.

use std::time::Duration;

use tonic::transport::Channel;
use tonic::Request;
use yadgar_dial::Deadline;

use super::{Identity, Step, Unverified, DERIVATION_VERSION};
use crate::crypto::Keys;
use crate::pb::yadgar::common::v1::Idempotency;
use crate::pb::yadgar::iamdb::v1 as db;
use crate::pb::yadgar::iamdb::v1::iam_db_service_client::IamDbServiceClient;

/// The variable the mode is read from, and the chart key that renders it.
pub const ADOPT_ENV: &str = "KEY_IDENTITY_ADOPT";
pub const ADOPT_CHART_KEY: &str = "keyIdentity.adopt";

/// The most rows the proof reads, and the most ids `AdoptKeyIdentity` accepts.
/// A CONTRACT NUMBER (proto `AdoptKeyIdentityRequest`, ADR-1089), not a knob.
pub const EVIDENCE_CAP: usize = 64;

/// The arm name a FAILED PROOF ends the serve under. Not an RPC: the proof is
/// this process's own, so [`super::Mismatch`] prints its own sentence for it.
pub(super) const PROOF: &str = "the adoption proof";

const ADOPT: &str = "AdoptKeyIdentity";

/// What a passed proof may do (`KEY_IDENTITY_ADOPT`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Adoption {
    /// Run the proof and log its outcome. NEVER call `AdoptKeyIdentity` and
    /// never end the serve on a failed proof.
    Observe,
    /// Adopt on a passed proof; end the serve on a failed one.
    Adopt,
}

impl Adoption {
    /// `KEY_IDENTITY_ADOPT`, exactly as the chart renders it: `observe` or
    /// `adopt`. Any other spelling refuses the boot rather than guessing.
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw {
            "observe" => Ok(Self::Observe),
            "adopt" => Ok(Self::Adopt),
            other => Err(format!(
                "{ADOPT_ENV} is {other:?}, and it must be exactly \"observe\" or \"adopt\" \
                 (ADR-1085). Set the iam chart's {ADOPT_CHART_KEY}"
            )),
        }
    }
}

/// D9's key for `AdoptKeyIdentity`: fresh per process and carrying the
/// derivation version, for [`super::mint_idempotency_key`]'s reasons. A KEY OF
/// ITS OWN, never `SetKeyIdentity`'s, so the two arms can never be read as a
/// replay of each other.
pub(super) fn mint_idempotency_key() -> String {
    format!(
        "iam:key-identity-adopt:v{DERIVATION_VERSION}:{}",
        uuid::Uuid::now_v7()
    )
}

/// One row that did not pass, and the first check it failed. NEVER a
/// plaintext (D72): the id and the name of the check, nothing decrypted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Failure {
    pub(super) user_id: String,
    pub(super) check: &'static str,
}

/// What the evidence proves.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Proof {
    /// Zero rows read. No proof, so never an adoption.
    NoEvidence,
    /// EVERY row read passed; the ids, in the order they were read.
    Passed(Vec<String>),
    /// At least one row failed. Every failing row, in the order read.
    Failed(Vec<Failure>),
}

/// The proof over `rows`. THE WHITELIST: `Passed` only when every row was
/// individually seen to pass.
pub(super) fn proven(keys: &Keys, rows: &[db::KeyIdentityEvidence]) -> Proof {
    if rows.is_empty() {
        return Proof::NoEvidence;
    }
    let mut passed = Vec::with_capacity(rows.len());
    let mut failed = Vec::new();
    for row in rows {
        match verdict(keys, row) {
            Ok(()) => passed.push(row.user_id.clone()),
            Err(check) => failed.push(Failure {
                user_id: row.user_id.clone(),
                check,
            }),
        }
    }
    match failed.is_empty() && passed.len() == rows.len() {
        true => Proof::Passed(passed),
        false => Proof::Failed(failed),
    }
}

/// One row's three checks. `Ok` only when all three passed.
fn verdict(keys: &Keys, row: &db::KeyIdentityEvidence) -> Result<(), &'static str> {
    let external_id = keys
        .decrypt(&row.external_id_ciphertext)
        .map_err(|_| "external_id_ciphertext does not decrypt")?;
    keys.decrypt(&row.display_name_ciphertext)
        .map_err(|_| "display_name_ciphertext does not decrypt")?;
    match keys.blind_index(&external_id) == row.external_id_blind_index {
        true => Ok(()),
        false => Err("external_id_blind_index does not match the decrypted external_id"),
    }
}

/// The oldest rows, at most [`EVIDENCE_CAP`], in the order the store served
/// them. Pages until the cap or the last page; a page with no rows ends the
/// read, so a peer that never stops handing out tokens cannot spin this.
async fn evidence(
    client: &mut IamDbServiceClient<Channel>,
    ceiling: Duration,
) -> Result<Vec<db::KeyIdentityEvidence>, tonic::Status> {
    let mut rows = Vec::new();
    let mut page_token = String::new();
    loop {
        let want = EVIDENCE_CAP - rows.len();
        let ask = Request::new(db::ListKeyIdentityEvidenceRequest {
            page_size: i32::try_from(want).unwrap_or(i32::MAX),
            page_token,
        });
        let page = Deadline::none()
            .call(ceiling, ask, |r| client.list_key_identity_evidence(r))
            .await?
            .into_inner();
        let served = page.evidence.len();
        rows.extend(page.evidence);
        if rows.len() >= EVIDENCE_CAP || page.next_page_token.is_empty() || served == 0 {
            break;
        }
        page_token = page.next_page_token;
    }
    rows.truncate(EVIDENCE_CAP);
    Ok(rows)
}

/// Read the evidence, prove it, and act on the proof under the mode.
pub(super) async fn attempt(
    client: &mut IamDbServiceClient<Channel>,
    ceiling: Duration,
    identity: &Identity,
) -> Step {
    let rows = match evidence(client, ceiling).await {
        Ok(rows) => rows,
        Err(status) => return Step::NotYet(of_status(status.code())),
    };
    match (proven(&identity.keys, &rows), identity.adoption) {
        (Proof::NoEvidence, _) => Step::NotYet(NO_EVIDENCE),
        (Proof::Passed(ids), Adoption::Observe) => Step::NotYet(observed(ids.len(), Vec::new())),
        (Proof::Failed(failed), Adoption::Observe) => Step::NotYet(observed(rows.len(), failed)),
        (Proof::Failed(failed), Adoption::Adopt) => {
            tracing::error!(
                rows = rows.len(),
                failing = ?failed,
                "the adoption proof FAILED: these oldest rows of iam_user do not decrypt, or \
                 their blind index does not match, under the key set this process loaded. \
                 KEY_IDENTITY_ADOPT is adopt, so the serve ends (ADR-1085)"
            );
            Step::Refused(PROOF)
        }
        (Proof::Passed(ids), Adoption::Adopt) => {
            tracing::info!(
                rows = ids.len(),
                "the adoption proof PASSED over the oldest rows of iam_user; asking iam-db to \
                 adopt the marker (ADR-1085)"
            );
            adopt(client, ceiling, identity, ids).await
        }
    }
}

async fn adopt(
    client: &mut IamDbServiceClient<Channel>,
    ceiling: Duration,
    identity: &Identity,
    evidence_user_ids: Vec<String>,
) -> Step {
    let write = Request::new(db::AdoptKeyIdentityRequest {
        idempotency: Some(Idempotency {
            key: identity.adopt_idempotency_key.clone(),
        }),
        key_fingerprint: identity.fingerprint(),
        derivation_version: DERIVATION_VERSION,
        evidence_user_ids,
    });
    let asked = Deadline::none()
        .call(ceiling, write, |r| client.adopt_key_identity(r))
        .await;
    match asked {
        Err(status) => Step::NotYet(of_status(status.code())),
        Ok(response) => outcome_of_adopt(response.into_inner().outcome),
    }
}

/// **THE WHITELIST ON THE ADOPTION ARM: `RECORDED` OR `MATCH`**, with
/// `MISMATCH` and `DERIVATION_SKEW` taking `SetKeyIdentity`'s dispositions, as
/// the contract states.
fn outcome_of_adopt(raw: i32) -> Step {
    match db::KeyIdentityOutcome::try_from(raw) {
        Ok(db::KeyIdentityOutcome::Recorded | db::KeyIdentityOutcome::Match) => Step::Passed(ADOPT),
        Ok(db::KeyIdentityOutcome::Mismatch) => Step::Refused(ADOPT),
        Ok(db::KeyIdentityOutcome::DerivationSkew) => Step::NotYet(Unverified::SKEW),
        // UNSPECIFIED, ABSENT — which this arm never sends — and later members.
        _ => Step::NotYet(Unverified::UNREADABLE),
    }
}

/// A status on either adoption RPC: [`Unverified::of_status`], except that
/// `UNIMPLEMENTED` names the ADOPTION arm, which is newer than the key-identity
/// arm an `iam-db` that answered `SetKeyIdentity` already has.
fn of_status(code: tonic::Code) -> Unverified {
    match code {
        tonic::Code::Unimplemented => ADOPTION_UNIMPLEMENTED,
        other => Unverified::of_status(other),
    }
}

pub(super) const ADOPTION_UNIMPLEMENTED: Unverified = Unverified::of(
    "UNIMPLEMENTED: this iam-db predates the adoption arm (ListKeyIdentityEvidence, \
     AdoptKeyIdentity)",
    true,
);

/// Zero rows read: no proof, and no retry makes one (ADR-1085).
pub(super) const NO_EVIDENCE: Unverified = Unverified::of(
    "NO_EVIDENCE: SetKeyIdentity says the store holds rows, and ListKeyIdentityEvidence \
     returned none, so there is nothing to prove the key set against",
    true,
);

pub(super) const OBSERVED_PASSED: &str = "OBSERVE: the adoption proof PASSED; \
     KEY_IDENTITY_ADOPT is observe, so nothing was adopted";
pub(super) const OBSERVED_FAILED: &str = "OBSERVE: the adoption proof FAILED; \
     KEY_IDENTITY_ADOPT is observe, so the serve goes on";

/// What a dry run found, carried to [`super::report`] so it rides the same
/// cadence as every other standing reason rather than logging per retry.
#[derive(Clone, Debug)]
pub(super) struct Observed {
    rows: usize,
    failed: Vec<Failure>,
}

fn observed(rows: usize, failed: Vec<Failure>) -> Unverified {
    let reason = match failed.is_empty() {
        true => OBSERVED_PASSED,
        false => OBSERVED_FAILED,
    };
    Unverified {
        observed: Some(Observed { rows, failed }),
        ..Unverified::of(reason, true)
    }
}

/// Tell an operator what the dry run found: INFO on a pass, WARN on a failure.
pub(super) fn tell(observed: &Observed, reason: &'static str, stood_for: Duration) {
    match observed.failed.is_empty() {
        true => tracing::info!(
            reason,
            rows = observed.rows,
            standing_for_secs = stood_for.as_secs(),
            "dry run: every one of the oldest rows of iam_user read decrypts and matches its \
             blind index under the key set this process loaded. This pod stays UNVERIFIED; \
             set keyIdentity.adopt to adopt to record the marker (ADR-1085)"
        ),
        false => tracing::warn!(
            reason,
            rows = observed.rows,
            failing = ?observed.failed,
            standing_for_secs = stood_for.as_secs(),
            "dry run: some of the oldest rows of iam_user do NOT decrypt, or do not match their \
             blind index, under the key set this process loaded. With keyIdentity.adopt set to \
             adopt, every pod would end its serve and exit non-zero. Nothing was written and \
             this pod keeps serving UNVERIFIED (ADR-1085)"
        ),
    }
}
