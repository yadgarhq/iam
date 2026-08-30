//! Connecting to `iam-db`, this module's twin.
//!
//! Kept separate from [`crate::balance`] deliberately: `balance` is the generic
//! channel-balancing mechanism (D23) — it knows about `SocketAddr`s and DNS, and
//! nothing about which module it is balancing for. This is the thin,
//! module-specific wiring on top: `iam-db`'s env-configured host and port,
//! named the way `service.rs` and `main.rs` expect. `Iam` builds its own typed
//! `IamDbServiceClient` from the `Channel` this returns, the same way `task`'s
//! `Task` builds `TaskDbServiceClient` from the channel it is given — the twin
//! is cheap to clone and reconnects nowhere, so there is no reason to hand
//! around a pre-typed client instead of the channel itself.

use tonic::transport::Channel;

use crate::balance::{self, BalanceError};

/// Connect to `iam-db` and return a load-balanced [`Channel`].
///
/// `iam-db`'s Service is headless, same as `task-db` (D23), so this goes through
/// `balance::connect` — one long-lived HTTP/2 connection per pod, re-resolved
/// every 5s — rather than a plain single-endpoint `Endpoint::connect`.
pub async fn connect(host: &str, port: u16) -> Result<Channel, BalanceError> {
    balance::connect(host, port).await
}
