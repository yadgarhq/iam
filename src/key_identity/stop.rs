//! What ends the serve, which arm did it, and what the exit code owes it.
//!
//! **A SIBLING FILE BESIDE [`super::retry`], AND THE REASON IS THE SAME SHAPE.**
//! `mod.rs` holds the round trip and the classification of its answers; this
//! holds the process's stop. Splitting them is also what leaves `mod.rs` room
//! under the `complexity` hook's 500-line ceiling, which it was within thirteen
//! lines of.

use tonic::transport::Channel;

use super::{watch, Identity, Mismatch, Retry};
use crate::pb::yadgar::iamdb::v1::iam_db_service_client::IamDbServiceClient;

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
    /// the non-zero exit: `main` returns it and the process exits 1.
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
    identity: Identity,
    retry: Retry,
}

impl Check {
    /// Build it from the SAME lazy channel every RPC uses — a clone, not a
    /// second dial. `Channel` is cheap to clone and reconnects nowhere, so
    /// nothing new is opened and nothing new is waited on.
    pub fn new(channel: Channel, identity: Identity, retry: Retry) -> Self {
        Self {
            client: IamDbServiceClient::new(channel),
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
        watch(check.client, check.identity, check.retry),
    )
    .await
}
