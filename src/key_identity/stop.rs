//! What ends the serve, which arm did it, and what the exit code owes it.
//!
//! **A SIBLING FILE BESIDE [`super::retry`], AND THE REASON IS THE SAME SHAPE.**
//! `mod.rs` holds the round trip and the classification of its answers; this
//! holds the process's stop. Splitting them is also what leaves `mod.rs` room
//! under the `complexity` hook's 500-line ceiling, which it was within thirteen
//! lines of.

use std::time::Duration;

use tonic::transport::Channel;

use super::{watch, Identity, Retry};
use crate::pb::yadgar::iamdb::v1::iam_db_service_client::IamDbServiceClient;

/// The key set this process holds is NOT the one these rows were encrypted
/// under. Permanent: no restart, no retry and no wait changes it.
///
/// Reached two ways: an arm of `iam-db` ANSWERED `MISMATCH`, or this process's
/// own adoption proof FAILED over the store's oldest rows ([`super::adopt`]).
/// The two get different sentences, because only the first is an answer.
#[derive(Debug, thiserror::Error)]
#[error("{}", sentence(self.arm))]
pub struct Mismatch {
    /// Which arm answered it, and it is INTERPOLATED INTO THE MESSAGE ABOVE
    /// rather than held for a reader of this struct. This message is the only
    /// thing the process prints on its way out, so a field the operator never
    /// sees states its distinction where nobody reads it.
    pub(super) arm: &'static str,
}

/// What the process prints on its way out, by the way the refusal was reached.
fn sentence(arm: &'static str) -> String {
    if arm == super::adopt::PROOF {
        return String::from(
            "the key set this process loaded did NOT pass the adoption proof (ADR-1085): at \
             least one of the oldest rows of iam_user failed to decrypt under it, or its blind \
             index did not match. KEY_IDENTITY_ADOPT is adopt, so this is MISMATCH's \
             disposition and the serve ends. Nothing has been written; the log line before \
             this one names the failing user ids. Mount the key Secret this installation \
             was provisioned with, or set keyIdentity.adopt to observe to keep serving \
             UNVERIFIED while the rows are examined.",
        );
    }
    format!(
        "the key-identity marker in iam-db does NOT match the key set this process loaded: {arm} \
         answered MISMATCH under derivation version {DERIVATION_VERSION}. A MISMATCH on \
         GetKeyIdentity means a marker was ALREADY stored and disagrees; one on SetKeyIdentity \
         means another replica recorded a different marker between this pod's read and its write, \
         so this pod lost a split rollout. Every name and every credential already stored was \
         encrypted under a different key set, so this process cannot read its own rows and will \
         not go on serving as though it could (ADR-0764). Nothing has been written. Mount the key \
         Secret this installation was provisioned with; if it is lost, the rows are not \
         recoverable and no key in the world makes them so.",
        DERIVATION_VERSION = super::DERIVATION_VERSION
    )
}

/// What ended the serve, and what the process owes the exit code afterwards.
#[derive(Debug)]
pub enum Ended {
    /// A signal, or a rotation. The restart is the point, so the exit is 0.
    Ordinary,
    /// The key-identity check refused. The exit is NON-ZERO.
    KeyIdentityRefused(Mismatch),
}

impl Ended {
    /// What the process owes the exit code once BOTH verdicts are in. `Err` is
    /// the non-zero exit: `run` returns it and `main` exits `ExitCode::FAILURE`
    /// (1).
    ///
    /// **THE TWO VERDICTS COMBINE RATHER THAN NEST, and that is the whole reason
    /// this takes an argument it never branches on.** `drain_overran` is
    /// `yadgar_lifecycle::Drain::Overran`, whose own ruling is exit 0 — the
    /// restart is the point, and a CrashLoopBackOff on top of a slow drain helps
    /// nobody. Reading the refusal only inside the drain's SUCCESS arm is a
    /// one-line change that silently exits 0 on exactly the pod that most needs
    /// to stop, and a signature that never saw the overrun could not state the
    /// rule at all.
    ///
    /// # Errors
    ///
    /// Only [`Ended::KeyIdentityRefused`]. Everything else is an ordinary stop.
    pub fn into_exit(self, drain_overran: bool) -> Result<(), Mismatch> {
        let _ = drain_overran;
        match self {
            Self::Ordinary => Ok(()),
            Self::KeyIdentityRefused(mismatch) => Err(mismatch),
        }
    }
}

/// What ends the serve, and which of the three arms did it.
///
/// **IN THE LIBRARY RATHER THAN IN `main`, AND `main` CALLS IT RATHER THAN
/// REPEATING IT** — [`crate::rotate::watch_set`]'s argument, applied to the stop
/// select. The exit code is the only thing this whole check produces, and a
/// `select!` written inline in a binary entry point is reachable from no test:
/// deleting an arm there compiles and passes the entire suite, which is the
/// defect `watch_set` exists to close. Three REQUIRED futures and no `Option`,
/// so an arm cannot be dropped silently.
///
/// **`main` DOES NOT CALL THIS ONE.** It calls [`until_stopped_with`], which is
/// the same select with the key-identity arm BUILT here rather than handed in —
/// see that function for the mutation the distinction closes. This one stays
/// public because it is where the three arms are decided, and because the
/// arithmetic of "which arm, which exit code" is assertable over
/// `ready`/`pending` without a socket.
pub async fn until_stopped(
    signals: impl std::future::Future<Output = ()>,
    rotation: impl std::future::Future<Output = ()>,
    key_identity: impl std::future::Future<Output = Mismatch>,
) -> Ended {
    tokio::select! {
        () = signals => Ended::Ordinary,
        () = rotation => Ended::Ordinary,
        refusal = key_identity => Ended::KeyIdentityRefused(refusal),
    }
}

/// Everything the key-identity arm needs, as ONE value rather than three.
///
/// **A STRUCT AND NOT THREE PARAMETERS, for a reason clippy enforces.**
/// `serve_and_drain` in `main.rs` already carries seven arguments, which is
/// `clippy::too_many_arguments`' limit, and this repository denies
/// `clippy::all`. Threading a channel, an identity and a cadence through it
/// separately is one lint away from being pushed back into a future parameter,
/// which is the shape [`until_stopped_with`] exists to remove.
pub struct Check {
    client: IamDbServiceClient<Channel>,
    /// The request timeout `channel` was dialled with; see [`watch`].
    ceiling: Duration,
    identity: Identity,
    retry: Retry,
}

impl Check {
    /// Build it from the SAME lazy channel every RPC uses — a clone, not a
    /// second dial. `Channel` is cheap to clone and reconnects nowhere, so
    /// nothing new is opened and nothing new is waited on.
    pub fn new(channel: Channel, ceiling: Duration, identity: Identity, retry: Retry) -> Self {
        Self {
            client: IamDbServiceClient::new(channel),
            ceiling,
            identity,
            retry,
        }
    }
}

/// [`until_stopped`] with the key-identity arm BUILT HERE RATHER THAN PASSED IN,
/// and **that difference is the whole point of this function.**
///
/// **THE MUTATION IT MAKES UNWRITABLE.** While `main` received the check as a
/// FUTURE, the call site could say `{ drop(key_check); std::future::pending() }`
/// — measured: it compiles, inference gives `Pending<Mismatch>`, the whole suite
/// passes and so does `clippy -D warnings`. The check is then constructed and
/// thrown away, and the binary's only job here is gone. `main.rs` has no
/// reachable test by this repository's standing decision, so nothing there could
/// ever have caught it. Taking the CHANNEL instead means there is no future at
/// that call site to replace: the only way to write that mutation now is inside
/// this function, where `the_check_main_hands_over_is_the_one_that_ends_the_serve`
/// calls it against a scripted twin and reddens.
///
/// This is [`crate::rotate::watch_set`]'s argument carried one step further than
/// [`until_stopped`] carried it. That function moved the SELECT into the
/// library; this moves the ARGUMENTS fed to the select in beside it, which is
/// where the surviving mutation actually lived.
///
/// What is left in `main` is the choice of channel, identity and cadence, and
/// none of the three can silently disable the check: the first round trip
/// happens before any wait, so even an absurd [`Retry`] still asks once.
pub async fn until_stopped_with(
    signals: impl std::future::Future<Output = ()>,
    rotation: impl std::future::Future<Output = ()>,
    check: Check,
) -> Ended {
    until_stopped(
        signals,
        rotation,
        watch(check.client, check.ceiling, check.identity, check.retry),
    )
    .await
}
