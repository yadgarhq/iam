//! The transport this service LISTENS on.
//!
//! The mirror image of [`crate::upstream`]: `upstream` decides how this service
//! VERIFIES `iam-db`, and its prefix names that upstream; this module decides
//! which certificate this service PRESENTS to its own callers and whether it
//! verifies THEIRS. Its prefix is `LISTEN`, already the variable naming the
//! address it binds.
//!
//! # ONE IMPLEMENTATION, ADOPTED (ADR-0846, B-U5)
//!
//! This module used to hold its own `ServerTls`: the switch, two paths, and a
//! PEM check per file. Five other gRPC servers held near-identical copies, and
//! none verified a client certificate. The type is
//! [`yadgar_lifecycle::serve_tls::ServerTls`] now, adopted rather than copied,
//! so a security control cannot drift six ways. What stays here is what is
//! THIS service's: the prefix, the chart key, and the one call site.
//!
//! | variable | chart value | values |
//! | --- | --- | --- |
//! | `LISTEN_TLS_ENABLED` | `tls.enabled` | exactly `1` or `0` |
//! | `LISTEN_TLS_CERT_FILE`, `LISTEN_TLS_KEY_FILE` | `tls.certSecret` | paths |
//! | `LISTEN_TLS_CLIENT_AUTH` | `tls.clientAuth` | exactly `off`, `optional`, `required` |
//! | `LISTEN_TLS_CLIENT_CA_FILE` | `tls.clientCaSecret` | a path |
//!
//! # NO COMPILED-IN DEFAULT (ADR-0845, ADR-0854)
//!
//! The switch and the client-auth mode are REQUIRED. Absent, empty or any
//! value outside the listed ones refuses the boot, naming the variable AND the
//! chart key — whether TLS is on or off. `off` is the value that turns client
//! verification off; deleting the variable is a boot refusal, not a way to
//! get there. `optional` and `required` verify against
//! `LISTEN_TLS_CLIENT_CA_FILE`, and a verifying mode with no CA file refuses.
//!
//! # A misconfiguration is an error, never a downgrade
//!
//! A path that names nothing, a file that cannot be read, a key that does not
//! match its certificate and a CA file holding no certificate all stop
//! [`builder`] with a message naming the file. None of them returns a server:
//! the only server that could be returned is a PLAINTEXT one, and an operator
//! who asked for encryption would then have an unencrypted listener nobody
//! could see was unencrypted.
//!
//! # ALPN
//!
//! tonic pushes `h2` onto the acceptor's ALPN list itself, and its client
//! REFUSES a connection that did not negotiate `h2` — so a gRPC request that
//! crosses the transport in `tests/serve_tls.rs` is the proof.
//!
//! # Shutdown lives in `yadgar-lifecycle`
//!
//! [`yadgar_lifecycle::shutdown`], [`yadgar_lifecycle::DRAIN_BUDGET`] and
//! [`yadgar_lifecycle::drain_within`] were three items in this module. The one
//! test that stays here compares the budget with
//! [`crate::service::MEASURED_REDEEM_RESPONSE_FLOOR`], because both numbers
//! it needs are this repository's or the crate's, not either alone's.

use tonic::transport::Server;

pub use yadgar_lifecycle::serve_tls::{ServeTlsError, ServerTls, LISTEN};

/// The values block this listener's keys render from: `tls.enabled`,
/// `tls.clientAuth` and the rest. Every refusal names `<CHART_KEY>.<leaf>`, so
/// the operator reads the variable in the crash log and edits this key.
pub const CHART_KEY: &str = "tls";

/// Read the listener's transport from the process environment.
///
/// `Ok(None)` is the cleartext listener, and it is only ever the answer to an
/// EXPLICIT `LISTEN_TLS_ENABLED=0` with `LISTEN_TLS_CLIENT_AUTH=off`.
pub fn from_env() -> Result<Option<ServerTls>, ServeTlsError> {
    ServerTls::from_env(LISTEN, CHART_KEY)
}

/// The same decision, over an injected lookup.
///
/// **A seam, because environment variables are process-global.** A test that
/// sets one steers every other test in the same binary. It reads under THIS
/// service's prefix and chart key, so a test through it proves what this
/// service passes the crate, not only what the crate does.
pub fn from_lookup(
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<Option<ServerTls>, ServeTlsError> {
    ServerTls::from_lookup(LISTEN, CHART_KEY, lookup)
}

/// The server this service listens with, encrypted or not.
///
/// `None` is the cleartext listener; `Some` is TLS — with the client verifier
/// the mode asks for — or an ERROR, never a cleartext server. The acceptor is
/// built HERE, eagerly, so a bad mount refuses at boot rather than failing a
/// stranger's first handshake.
///
/// The caller adds its own services to what comes back, which is what lets
/// `tests/serve_tls.rs` stand the real thing up on a port it chose.
pub fn builder(tls: Option<&ServerTls>) -> Result<Server, ServeTlsError> {
    yadgar_lifecycle::serve_tls::server(tls)
}

#[cfg(test)]
mod tests;
