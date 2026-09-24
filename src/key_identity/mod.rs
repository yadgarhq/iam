//! Whether the key set this process holds is the one this store's rows were
//! encrypted under — ADR-0764, as amended by ADR-0765.
//!
//! # It refuses to KEEP RUNNING, and never to boot
//!
//! ADR-0532 keeps the dial to `iam-db` lazy, and `main.rs`'s own module
//! documentation argues at length why: blocking this service's startup on the
//! twin turns one module's slow migration into a cascading outage across
//! everything that depends on it. So nothing here gates boot. The check runs as
//! a TASK afterwards, in the same `select!` arm shape [`crate::rotate`] already
//! uses to end the serve on a permanent fault, and the ONLY thing it can do to
//! the process is end the serve and make the exit non-zero.
//!
//! **THE COST IS ACCEPTED AND STATED IN ADR-0764**: between boot and the twin's
//! first answer a pod holding the WRONG key is Ready and serving. Every such
//! request already fails on decrypt, so the window leaks no plaintext and
//! corrupts no data. Anyone later tempted to "fix" that by failing boot must
//! re-read ADR-0532 first.
//!
//! # The four dispositions, and they are not symmetric
//!
//! | answer | passes | ends the serve | an operator is told |
//! | --- | --- | --- | --- |
//! | `MATCH`, or `RECORDED` from the write | yes | no | no |
//! | `MISMATCH` | no | YES, exit non-zero | yes |
//! | `DERIVATION_SKEW` | no | no | YES |
//! | anything else, including every non-OK status | no | no | when permanent |
//!
//! **THE PASS IS A WHITELIST AND NEVER A BLACKLIST OF `MISMATCH`.** A caller
//! reading "not MISMATCH" as a pass would pass on the zero value, on
//! `DERIVATION_SKEW`, on a member added after this tag, and on every transport
//! failure besides — a gate that skips itself when it cannot reach its answer,
//! which ADR-0764 rejects by name. `Step` is the whitelist and
//! `outcome_of_read` and `outcome_of_write` are the only two places that
//! decide it.
//!
//! **AN UNAVAILABLE TWIN RETRIES FOR EVER AND NEVER PASSES.** That is the arm
//! ADR-0764 chose over failing boot and over passing on unreachability, and its
//! revisit trigger is the only thing that would change it.
//!
//! # Changing the derivation is a MIGRATION, not a release
//!
//! [`DERIVATION_VERSION`] is 1 and the bytes are derived by
//! [`crate::crypto::Keys::key_identity_fingerprint`] under [`DOMAIN`]. Changing
//! either — a different domain string, a different input, another primitive —
//! means bumping the version AND rewriting every installation's stored marker,
//! or every pod reads `DERIVATION_SKEW` and never passes. ADR-0765 exists
//! because that hazard has no mechanism behind it otherwise.

use std::time::Duration;

use tonic::transport::Channel;

use crate::crypto::Keys;
use crate::pb::yadgar::common::v1::Idempotency;
use crate::pb::yadgar::iamdb::v1 as db;
use crate::pb::yadgar::iamdb::v1::iam_db_service_client::IamDbServiceClient;

mod retry;
mod stop;

pub use retry::Retry;
pub use stop::{until_stopped, until_stopped_with, Check, Ended};

/// Which function produced the fingerprint. Versions start at 1 (ADR-0765);
/// zero is refused by both arms, because `uint32` has no presence in proto3.
pub const DERIVATION_VERSION: u32 = 1;

/// The domain-separation string the fingerprint is derived under.
///
/// **IT CARRIES THE VERSION, AND THAT IS BELT AND BRACES.** The stored marker is
/// the PAIR, so `iam-db` already refuses to compare across versions. Putting the
/// number in the string as well means a bump produces DIFFERENT BYTES even
/// against a peer that ignored the field — so the worst case of a half-deployed
/// version bump is `MISMATCH` on a comparison that at least happened, rather
/// than two derivations silently agreeing.
///
/// `the_fingerprint_covers_both_keys_and_the_domain_names_the_version` asserts
/// the two are spelled consistently; a bump that edits one and not the other is
/// red rather than subtle.
pub const DOMAIN: &str = "yadgar:iam:key-identity:v1";

/// How long ONE unchanged reason may stand before it is re-stated.
///
/// **NOT A CONFIGURATION KNOB (ADR-0569).** Nothing else reads it, no chart
/// renders it, and there is no second source for it to disagree with: it is the
/// cadence of a log line, which is a property of this mechanism rather than a
/// setting of this deployment.
pub const RESTATE_AFTER: Duration = Duration::from_secs(300);

/// Whether a reason that has stood for `since` the last line is re-stated.
///
/// **A STANDING CONDITION REPORTED ONCE IS THE FAILURE, NOT THE FIX.** The
/// contract's own words about a permanent status are that retrying it for ever
/// is safe and is NOT SUFFICIENT — the pod stays Ready, serving and unverified,
/// indefinitely and silently. One line at the top of a pod's life scrolls away
/// and leaves exactly that state. A line per retry is the opposite failure and
/// trains a reader to skip it, which is [`crate::rotate`]'s own rule about a
/// standing condition.
///
/// **KEYED ON ELAPSED TIME AND NOT ON AN ATTEMPT COUNT, and the difference is
/// measured rather than stylistic.** [`Retry`] backs off to a minute, so "one
/// line in every twenty attempts" — the first shape of this function — put
/// roughly eleven minutes between two lines about a fault no retry mends. The
/// property an operator has is a line every five minutes; the property a counter
/// gives is a line every twenty waits, and the two stop agreeing the moment the
/// backoff saturates. `a_permanent_fault_reaches_an_operator_within_minutes`
/// asserts the first of those and reddens under the second.
///
/// **THIS FUNCTION IS THE ARITHMETIC AND NOT THE CADENCE.** Its input is
/// accumulated by [`watch_with_seed`] and reset by [`report`], and neither of
/// those two lines is touched by any assertion over this function — both were
/// deletable, green, while an operator got one line and never another.
/// `the_cadence_an_operator_gets_is_produced_by_the_loop` runs the real loop
/// against a real twin and reads the real log, which is what closes them.
///
/// `None` is a reason that has not been reported at all — the first attempt, or
/// the first under a CHANGED reason — and it is always reported.
fn restate(since: Option<Duration>) -> bool {
    match since {
        None => true,
        Some(standing) => standing >= RESTATE_AFTER,
    }
}

/// What this process claims about its key set, computed once at boot.
#[derive(Clone, Debug)]
pub struct Identity {
    fingerprint: Vec<u8>,
    idempotency_key: String,
}

impl Identity {
    /// Derive it from the keys this process loaded.
    ///
    /// Takes `&Keys` and NOT the key bytes: the material never leaves
    /// [`crate::crypto`], which is the one module that holds it.
    pub fn of(keys: &Keys) -> Self {
        Self {
            fingerprint: keys.key_identity_fingerprint(DOMAIN),
            idempotency_key: mint_idempotency_key(),
        }
    }

    fn fingerprint(&self) -> Vec<u8> {
        self.fingerprint.clone()
    }

    fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }
}

/// D9's key, MINTED FRESH PER PROCESS AND CARRYING THE DERIVATION VERSION.
///
/// **A KEY STABLE ACROSS A DERIVATION BUMP IS ANSWERED `INVALID_ARGUMENT`, NOT
/// `DERIVATION_SKEW`**, and that is the contract's own ordering rather than a
/// bug to route around: `iam-db`'s `replayed_or_compared` checks the key FIRST,
/// so a call replaying a stored key under a different `derivation_version` is
/// refused as a replay carrying a different payload. The consequence lands here.
/// A key derived from a pod name, an installation id or a constant would turn
/// the one migration ADR-0765 exists to make survivable into the one answer an
/// operator cannot act on.
///
/// TWO DEFENCES AND NOT ONE, because either alone is an argument about the
/// future. The version is folded in, so two derivations can never collide on a
/// key; and a fresh UUIDv7 per process means two derivations are not the only
/// thing that separates them.
///
/// **WHAT THE KEY STILL BUYS, so nobody deletes it as decoration.** Within one
/// process, a `SetKeyIdentity` whose response was lost is replayed under the
/// SAME key and the SAME payload, and answers `RECORDED` — the original outcome.
/// A fresh key per ATTEMPT would answer `MATCH` instead, and the contract
/// requires an implementation to preserve that distinction.
fn mint_idempotency_key() -> String {
    format!(
        "iam:key-identity:v{DERIVATION_VERSION}:{}",
        uuid::Uuid::now_v7()
    )
}

/// The key set this process holds is NOT the one these rows were encrypted
/// under. Permanent: no restart, no retry and no wait changes it.
#[derive(Debug, thiserror::Error)]
#[error(
    "the key-identity marker in iam-db does NOT match the key set this process loaded: {arm} \
     answered MISMATCH under derivation version {DERIVATION_VERSION}. A MISMATCH on \
     GetKeyIdentity means a marker was ALREADY stored and disagrees; one on SetKeyIdentity \
     means another replica recorded a different marker between this pod's read and its write, \
     so this pod lost a split rollout. Every name and every credential already stored was \
     encrypted under a different key set, so this process cannot read its own rows and will \
     not go on serving as though it could (ADR-0764). Nothing has been written. Mount the key \
     Secret this installation was provisioned with; if it is lost, the rows are not \
     recoverable and no key in the world makes them so."
)]
pub struct Mismatch {
    /// Which arm answered it, and it is INTERPOLATED INTO THE MESSAGE ABOVE
    /// rather than held for a reader of this struct. This message is the only
    /// thing the process prints on its way out, so a field the operator never
    /// sees states its distinction where nobody reads it.
    arm: &'static str,
}

/// Run the check until it passes, or until it must end the serve.
///
/// **RESOLVES ONLY ON A DEFINITE `MISMATCH`, and never otherwise** — the shape
/// `yadgar_lifecycle::rotate::watch` already has, so [`until_stopped`]'s arm
/// fires for one reason and one reason only. A check that has PASSED stops
/// asking and never resolves; a check that has not passed keeps asking for ever
/// and never resolves either.
pub async fn watch(
    client: IamDbServiceClient<Channel>,
    identity: Identity,
    retry: Retry,
) -> Mismatch {
    watch_with_seed(client, identity, retry, retry::seed()).await
}

/// [`watch`] with the jitter's seed supplied, so a test can assert an exact wait
/// rather than a distribution.
pub async fn watch_with_seed(
    mut client: IamDbServiceClient<Channel>,
    identity: Identity,
    retry: Retry,
    seed: u64,
) -> Mismatch {
    let mut attempt: u32 = 0;
    // The reason standing right now, and how long it has stood SINCE THE LAST
    // LINE about it. Accumulated from the waits below rather than read off a
    // clock, so what an operator gets is what a test can assert.
    let mut standing: Option<(&'static str, Duration)> = None;

    loop {
        match step(&mut client, &identity).await {
            Step::Passed(arm) => {
                tracing::info!(
                    arm,
                    derivation_version = DERIVATION_VERSION,
                    "the key set this process holds is the one iam-db's rows were encrypted \
                     under (ADR-0764)"
                );
                never().await
            }
            Step::Refused(arm) => return Mismatch { arm },
            Step::NotYet(unverified) => report(&unverified, &mut standing),
        }
        let waited = retry.wait(attempt, seed);
        if let Some((_, since)) = standing.as_mut() {
            *since = since.saturating_add(waited);
        }
        tokio::time::sleep(waited).await;
        attempt = attempt.saturating_add(1);
    }
}

/// Tell an operator, on the cadence [`restate`] sets.
fn report(unverified: &Unverified, standing: &mut Option<(&'static str, Duration)>) {
    // A CHANGE OF REASON IS ALWAYS REPORTED, whatever the cadence says. An
    // UNAVAILABLE twin that comes back answering UNIMPLEMENTED is a different
    // fact about the deployment, and waiting out the interval to say so would
    // leave the old one standing as the last thing anybody was told.
    let since = standing
        .as_ref()
        .and_then(|(reason, since)| (*reason == unverified.reason).then_some(*since));
    if !restate(since) {
        // THE CLOCK IS NOT RESET HERE. Leaving `standing` alone is what lets the
        // waits keep accumulating towards the next line; resetting it on every
        // quiet attempt would mean no line is ever due again.
        return;
    }
    let stood_for = since.unwrap_or_default();
    *standing = Some((unverified.reason, Duration::ZERO));
    match unverified.permanent {
        // NO RETRY MENDS THIS, so the pod stays Ready, serving and unverified
        // until somebody acts. ERROR is the level that says a human is needed.
        true => tracing::error!(
            reason = unverified.reason,
            standing_for_secs = stood_for.as_secs(),
            derivation_version = DERIVATION_VERSION,
            "the key identity is UNVERIFIED and no retry will mend it. This pod is Ready and \
             serving and has NOT proved it holds the key set its rows were encrypted under. \
             Deploy an iam-db carrying the key-identity arm, or resolve the marker this store \
             holds (ADR-0764, ADR-0765)"
        ),
        false => tracing::warn!(
            reason = unverified.reason,
            standing_for_secs = stood_for.as_secs(),
            "the key identity is not yet verified; retrying. This pod is Ready and serving in \
             the meantime (ADR-0532)"
        ),
    }
}

/// Why the check has not passed, and whether any retry can mend it.
#[derive(Clone, Copy, Debug)]
pub struct Unverified {
    reason: &'static str,
    permanent: bool,
}

impl Unverified {
    /// A marker produced by a function this build does not speak.
    pub const SKEW: Self = Self {
        reason: "DERIVATION_SKEW",
        permanent: true,
    };

    /// An answer this build cannot read as a pass: the zero value, a member
    /// added after this tag, or `RECORDED` from the arm that writes nothing.
    ///
    /// **PERMANENT, FOR `UNIMPLEMENTED`'s REASON AND NOT A DIFFERENT ONE.** All
    /// three things this covers are a version disagreement between the two
    /// binaries: a peer sending a member this tag does not know, or sending one
    /// on an arm its own contract says never sends it. None of them is mended by
    /// waiting, and every one of them is mended by a DEPLOY — which is exactly
    /// what [`Self::of_status`] classifies `UNIMPLEMENTED` permanent for. Left
    /// transient it warns for ever, and this module's own table says an operator
    /// is told when no retry will mend it.
    const UNREADABLE: Self = Self {
        reason: "an outcome this build cannot read as a pass",
        permanent: true,
    };

    /// A non-OK status. EVERY one of them is not-passed; the question this
    /// answers is only whether a retry could ever mend it.
    ///
    /// `UNIMPLEMENTED` is an `iam-db` deployed from a tag that predates the arm.
    /// `FAILED_PRECONDITION` is a populated store with no marker — an incident,
    /// and the only refusal about the stored marker on that arm.
    /// `INVALID_ARGUMENT` is a request this build should never have sent, which
    /// includes D9's refusal of a key replayed under a different payload.
    pub fn of_status(code: tonic::Code) -> Self {
        match code {
            tonic::Code::Unimplemented => Self {
                reason: "UNIMPLEMENTED: this iam-db predates the key-identity arm",
                permanent: true,
            },
            tonic::Code::FailedPrecondition => Self {
                reason: "FAILED_PRECONDITION: the store holds rows and no marker",
                permanent: true,
            },
            tonic::Code::InvalidArgument => Self {
                reason: "INVALID_ARGUMENT: iam-db refused the request this build sent",
                permanent: true,
            },
            _ => Self {
                reason: "the twin did not answer",
                permanent: false,
            },
        }
    }

    /// Whether an operator must be told rather than a retry counter.
    pub fn is_permanent(self) -> bool {
        self.permanent
    }
}

/// What one round trip settled. The whitelist, and the only thing that passes.
enum Step {
    Passed(&'static str),
    Refused(&'static str),
    NotYet(Unverified),
}

const READ: &str = "GetKeyIdentity";
const WRITE: &str = "SetKeyIdentity";

async fn step(client: &mut IamDbServiceClient<Channel>, identity: &Identity) -> Step {
    let asked = client
        .get_key_identity(db::GetKeyIdentityRequest {
            key_fingerprint: identity.fingerprint(),
            derivation_version: DERIVATION_VERSION,
        })
        .await;
    match asked {
        Err(status) => Step::NotYet(Unverified::of_status(status.code())),
        Ok(response) => match outcome_of_read(response.into_inner().outcome) {
            // THE ONLY BRANCH THAT WRITES, and it is reached from `ABSENT`
            // alone. `ABSENT` does NOT say the installation is empty — only
            // `iam-db` can tell that, and its `SetKeyIdentity` refuses to record
            // over a store that already holds rows. This service asks; it never
            // concludes.
            Read::Absent => record(client, identity).await,
            Read::Settled(step) => step,
        },
    }
}

/// What `GetKeyIdentity` answered, as a disposition.
enum Read {
    Absent,
    Settled(Step),
}

/// **THE WHITELIST ON THE READ ARM: `MATCH` AND NOTHING ELSE.**
///
/// `RECORDED` is deliberately NOT a pass here, and that is a narrowing of the
/// rule rather than a departure from it. The contract states that this arm
/// writes nothing and never sends `RECORDED`, so a twin that sends it has
/// contradicted the rule its claim rests on — and a gate does not take a
/// positive answer from a peer that just broke its own contract.
/// `recorded_from_the_read_arm_never_passes` is the assertion that reddens if
/// the whitelist is ever applied to the two arms jointly.
fn outcome_of_read(raw: i32) -> Read {
    match db::KeyIdentityOutcome::try_from(raw) {
        Ok(db::KeyIdentityOutcome::Match) => Read::Settled(Step::Passed(READ)),
        Ok(db::KeyIdentityOutcome::Mismatch) => Read::Settled(Step::Refused(READ)),
        Ok(db::KeyIdentityOutcome::Absent) => Read::Absent,
        Ok(db::KeyIdentityOutcome::DerivationSkew) => Read::Settled(Step::NotYet(Unverified::SKEW)),
        // UNSPECIFIED, RECORDED, and every member added after this tag.
        _ => Read::Settled(Step::NotYet(Unverified::UNREADABLE)),
    }
}

/// **THE WHITELIST ON THE WRITE ARM: `RECORDED` OR `MATCH`.**
///
/// `RECORDED` says THIS call wrote the marker. `MATCH` says somebody else did
/// between this pod's read and its write — the replica that won a split rollout,
/// or this pod's own earlier attempt under the same idempotency key. Both are
/// positive answers about the same stored pair.
fn outcome_of_write(raw: i32) -> Step {
    match db::KeyIdentityOutcome::try_from(raw) {
        Ok(db::KeyIdentityOutcome::Recorded | db::KeyIdentityOutcome::Match) => Step::Passed(WRITE),
        Ok(db::KeyIdentityOutcome::Mismatch) => Step::Refused(WRITE),
        Ok(db::KeyIdentityOutcome::DerivationSkew) => Step::NotYet(Unverified::SKEW),
        // UNSPECIFIED, ABSENT — which this arm never sends, since once it has
        // answered OK a marker exists either way — and every later member.
        _ => Step::NotYet(Unverified::UNREADABLE),
    }
}

async fn record(client: &mut IamDbServiceClient<Channel>, identity: &Identity) -> Step {
    let asked = client
        .set_key_identity(db::SetKeyIdentityRequest {
            idempotency: Some(Idempotency {
                key: identity.idempotency_key().to_string(),
            }),
            key_fingerprint: identity.fingerprint(),
            derivation_version: DERIVATION_VERSION,
        })
        .await;
    match asked {
        Err(status) => Step::NotYet(Unverified::of_status(status.code())),
        Ok(response) => outcome_of_write(response.into_inner().outcome),
    }
}

async fn never() -> ! {
    let never: std::convert::Infallible = std::future::pending().await;
    match never {}
}

#[cfg(test)]
mod tests;
