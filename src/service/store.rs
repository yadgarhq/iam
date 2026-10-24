//! The `iam-db` hop, bounded by the caller's deadline (ADR-1019).
//!
//! **EVERY `iam-db` CALL A HANDLER MAKES GOES THROUGH [`Iam::ask`]**, or
//! through [`Iam::ask_recorded`] when every failure is answered alike. The
//! handler captures [`Deadline::of`] ONCE, as its first statement, before the
//! request is consumed. Each call it then makes is stamped with
//! min(ceiling, remaining - [`yadgar_dial::DEADLINE_MARGIN`]) as its
//! `grpc-timeout`, and is cut off at that bound here as well as by tonic. A
//! handler that makes two calls (`Login`: lookup, then mint) hands the SAME
//! `Deadline` to both, so the second is told only what is left.
//!
//! Without this, `iam` built each `iam-db` request fresh, with no deadline on
//! it. The gateway gives up on `ResolveCredential` and `Login` at its 10 s
//! `AUTH_DEADLINE`; the store kept working for up to this hop's 14 s ceiling on
//! a request nobody was waiting for. That is the inverted chain of yaadgaar
//! #337.
//!
//! **A CALL CUT OFF AT ITS BOUND IS `DEADLINE_EXCEEDED`, ON THE WIRE AND IN
//! TELEMETRY.** [`upstream_failed`] keeps the code, so the gateway reads
//! `DEADLINE_EXCEEDED` rather than an outage. [`store_failed`] records the same
//! code on the handler's `Call` before the `Err` returns. Before this change
//! every upstream refusal dropped the `Call`, which records `UNRECORDED` (D67).
//! The 50 ms margin is what lets this hop answer at all: its own bound fires
//! before tonic's server drops the handler at the caller's deadline.

use std::future::Future;
use std::time::Duration;

use tonic::transport::Channel;
use tonic::{Request, Response, Status};
use yadgar_dial::Deadline;
use yadgar_telemetry::observe::Call;

use super::{upstream_failed, Iam};
use crate::pb::yadgar::iamdb::v1::iam_db_service_client::IamDbServiceClient;

/// The `iam-db` hop: the channel, and the request timeout it was dialled with.
///
/// **ONE VALUE, BECAUSE THE TWO ARE ONE FACT.** `upstream::connect` dials the
/// channel with `IAM_DB_REQUEST_TIMEOUT_SECONDS` as tonic's per-request timer.
/// ADR-1019 makes the same number the CEILING that every `iam-db` call is
/// stamped with. Carried apart, a caller could hand `Iam` a channel dialled
/// with one timeout and a ceiling that names another. The header the store
/// reads would then stop describing the timer that actually cuts the call.
pub struct IamDb {
    pub(super) channel: Channel,
    pub(super) ceiling: Duration,
}

impl IamDb {
    /// `ceiling` is the request timeout `channel` was dialled with: the value
    /// `upstream::request_timeout_from_env` read and `upstream::connect` used.
    pub fn new(channel: Channel, ceiling: Duration) -> Self {
        Self { channel, ceiling }
    }
}

impl Iam {
    /// One `iam-db` call under `deadline`, answered with the response's body.
    ///
    /// `f` gets a fresh client and the stamped request. It is written
    /// `|mut c, r| async move { c.<verb>(r).await }`, because a tonic client
    /// method borrows the client for the life of its future.
    ///
    /// # Errors
    ///
    /// `DEADLINE_EXCEEDED` without asking the store when the caller's deadline
    /// leaves no time; `DEADLINE_EXCEEDED` when the call was cut off at its
    /// bound; otherwise whatever the store answered. Not redacted: the caller
    /// passes it to [`store_failed`] or reads its code first.
    pub(super) async fn ask<U, T, F, Fut>(
        &self,
        deadline: Deadline,
        request: Request<U>,
        f: F,
    ) -> Result<T, Status>
    where
        F: FnOnce(IamDbServiceClient<Channel>, Request<U>) -> Fut,
        Fut: Future<Output = Result<Response<T>, Status>>,
    {
        let client = self.client();
        deadline
            .call(self.ceiling, request, |r| f(client, r))
            .await
            .map(Response::into_inner)
    }
}

impl Iam {
    /// [`Iam::ask`] for a call whose every failure is answered as
    /// [`store_failed`] answers it: redacted, and recorded on `call` with its
    /// code. `call` comes back with the answer, for the handler to finish.
    ///
    /// # Errors
    ///
    /// What [`Iam::ask`] returns, redacted, with `call` already failed.
    pub(super) async fn ask_recorded<U, T, F, Fut>(
        &self,
        deadline: Deadline,
        call: Call,
        request: Request<U>,
        f: F,
    ) -> Result<(T, Call), Status>
    where
        F: FnOnce(IamDbServiceClient<Channel>, Request<U>) -> Fut,
        Fut: Future<Output = Result<Response<T>, Status>>,
    {
        match self.ask(deadline, request, f).await {
            Ok(answered) => Ok((answered, call)),
            Err(failed) => Err(store_failed(call, failed)),
        }
    }
}

/// Whether `failed` is a call cut off at the caller's deadline: by this hop's
/// bound, or by `iam-db` bounding its own work by the time this hop told it.
///
/// **ON AN UNAUTHENTICATED PATH THIS IS NEVER ANSWERED AS ITSELF** before the
/// credential or secret is confirmed and the answer decided. The caller CHOSE
/// the deadline, so a `DEADLINE_EXCEEDED` there would turn store latency, or
/// a right password's mint, into a status the caller can read: an oracle the
/// response floor cannot close, because the floor equalises time and never
/// status. Those sites answer as a wrong credential at the same point does,
/// and record `DEADLINE_EXCEEDED` on the `Call`, which only an operator reads.
pub(super) fn cut_off(failed: &Status) -> bool {
    let cut = failed.code() == tonic::Code::DeadlineExceeded;
    if cut {
        tracing::info!(
            upstream = %failed.message(),
            "an iam-db call was cut off at the caller's deadline; answered as a refusal"
        );
    }
    cut
}

/// An `iam-db` call failed: redact it as [`upstream_failed`] does, and record
/// its code on `call`.
///
/// **THE CODE RECORDED IS THE CODE ANSWERED.** It is read off the redacted
/// status, so telemetry and the caller cannot disagree. A cut-off call records
/// `DEADLINE_EXCEEDED`, not `UNRECORDED`. The one exception is [`cut_off`]'s.
pub(super) fn store_failed(call: Call, failed: Status) -> Status {
    recorded(call, upstream_failed(failed))
}

/// Record `answered`'s code on `call`, and hand `answered` back. For a status
/// already redacted, such as [`super::login::MintRefused::Failed`]'s.
pub(super) fn recorded(call: Call, answered: Status) -> Status {
    call.fail(yadgar_telemetry::grpc::status_name(&answered));
    answered
}
