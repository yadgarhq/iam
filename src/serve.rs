//! The transport this service LISTENS on.
//!
//! The mirror image of [`crate::upstream`], and deliberately the same shape: a
//! `<PREFIX>_TLS_*` triple read through an injected lookup, a flag that must be
//! exactly `"1"`, and a misconfiguration that is an error rather than a
//! downgrade. **The two configure opposite directions and must not be
//! confused:** `upstream` decides how this service VERIFIES `iam-db`, and its
//! prefix names that upstream; this module decides which certificate this
//! service PRESENTS to its own callers, and its prefix is `LISTEN`, already the
//! variable naming the address it binds.
//!
//! # It is OPT-IN, and OFF unless a deployment asks for it
//!
//! With nothing configured this binds exactly the plaintext listener it always
//! has. That is deliberate rather than timid: the certificates do not exist yet,
//! and this service's callers — the gateway among them — carry their own
//! matching flag, also shipped off. The cut-over turns both ends on together and
//! is a separate change that can be reverted on its own.
//!
//! # Configuration is file paths and a flag, never an issuer-specific resource
//!
//! D80. A certificate and a private key on disk are written by cert-manager in
//! the reference deployment and by a hand-assembled Secret anywhere else, and
//! this module cannot tell the difference — which is the point. Nothing here
//! names an issuer, a mesh or an ingress implementation.
//!
//! # A misconfiguration is an error, never a downgrade
//!
//! **This is the entire defect the change exists to remove.** A flag that is on
//! with a path that names nothing, a file that cannot be read, a PEM that
//! decodes to no certificate, or a key that does not match its certificate — all
//! of them stop [`builder`] with a message naming the file. None of them returns
//! a server, because the only server that could be returned is a PLAINTEXT one
//! carrying a TLS configuration that failed, and an operator who asked for
//! encryption would then have an unencrypted listener nobody could see was
//! unencrypted.
//!
//! # ALPN
//!
//! A TLS gRPC listener that does not negotiate `h2` answers nothing useful.
//! tonic pushes `h2` onto the acceptor's ALPN list itself — see
//! `tonic/src/transport/server/service/tls.rs` — so this module adds nothing,
//! and `tests/serve_tls.rs` proves it rather than assuming it: tonic's own
//! client REFUSES a connection that did not negotiate `h2`, so a gRPC request
//! that crosses the transport is the proof.
//!
//! # Shutdown moved to `yadgar-lifecycle`
//!
//! [`yadgar_lifecycle::shutdown`], [`yadgar_lifecycle::DRAIN_BUDGET`] and
//! [`yadgar_lifecycle::drain_within`] were three items in this module, and the
//! same three in `task` and in `gateway`. They are one decision rather than
//! three: `terminationGracePeriodSeconds` bounds a drain KUBELET started, the
//! rotation watcher ends the serve on its own, so kubelet's clock never runs and
//! a budget this process holds is the only thing bounding what follows.
//!
//! Why they were in a library rather than in `main` is unchanged, and is the
//! same reason [`crate::serve::builder`] is: a decision inside a binary entry
//! point is one no test can reach, and which signals end this process is exactly
//! the kind that fails silently. This binary listened for SIGINT alone while Kubernetes sends
//! SIGTERM.
//!
//! **The one test that stays here is the one whose numbers are both here.** The
//! budget must outlast the slowest legitimate call, and
//! [`crate::service::DEFAULT_REDEEM_RESPONSE_FLOOR`] is the estate's only real
//! lower bound for that — so `a_drain_budget_must_outlast_the_slowest_legitimate_call`
//! compares two production constants in this repository against the crate's.
//!
//! # What is deliberately NOT here
//!
//! **Mutual TLS.** Verifying a CLIENT certificate is `ServerTlsConfig`'s
//! `client_ca_root` plus one more path, and the seam is left open by taking a
//! struct rather than a list of arguments — the same way `yadgar_dial`'s
//! `TlsOptions` leaves room for `ClientTlsConfig::identity`. It is a later
//! decision, not an omission from this one.

use std::path::{Path, PathBuf};

use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tonic::transport::{Identity, Server, ServerTlsConfig};
// THE ONE ERROR-CHAIN FLATTENER FOR THE ESTATE (ADR-0591). The body that used to
// sit below `builder` in this file was one of five — `iam-db`, `task`, `task-db`,
// `project-db` and here — byte-identical apart from local names, under TWO
// names: `chain` here and in `iam-db`, `describe` in the other three. It is
// deleted rather than left beside the shared one, because a consolidation that
// adds a sixth copy without removing the five is worse than none. The call site
// is unchanged: the published signature is the PERMISSIVE `&dyn Error`, which
// accepts everything the `&(dyn Error + 'static)` written here did.
use yadgar_telemetry::diagnose::chain;

/// The prefix the listener's transport is configured from:
/// `LISTEN_TLS_ENABLED`, `LISTEN_TLS_CERT_FILE` and `LISTEN_TLS_KEY_FILE`.
///
/// `LISTEN` because that is already the variable naming what is being
/// configured — the address this service binds. A client's prefix names the
/// upstream it dials for the same reason.
pub const LISTEN: &str = "LISTEN";

/// What a deployment got wrong about the listener's transport.
///
/// Every variant is a BOOT FAILURE. None of them has a fallback, and the absence
/// of one is the point: the only fallback available is a plaintext listener, and
/// that is what an operator who set the flag was trying to stop.
#[derive(Debug, thiserror::Error)]
pub enum ServerTlsError {
    #[error(
        "{0}_TLS_ENABLED is set but {0}_TLS_CERT_FILE names no certificate. TLS was \
         asked for, so this is a deployment mistake rather than a reason to listen in \
         cleartext — and it is NOT the same as leaving TLS off, which is the supported \
         way to run without one. Point {0}_TLS_CERT_FILE at the PEM certificate this \
         service should present."
    )]
    NoCertFile(&'static str),

    #[error(
        "{0}_TLS_ENABLED is set but {0}_TLS_KEY_FILE names no private key. A \
         certificate without its key serves nothing, and listening in cleartext is not \
         the answer to a half-finished configuration. Point {0}_TLS_KEY_FILE at the PEM \
         private key belonging to the certificate at {0}_TLS_CERT_FILE."
    )]
    NoKeyFile(&'static str),

    #[error(
        "the certificate at {path} could not be read ({source}). TLS was asked for, so \
         this service refuses to start rather than fall back to a cleartext listener. \
         The usual cause is a Secret that was never mounted, so check that the volume \
         exists and that this path is inside it."
    )]
    CertUnreadable {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error(
        "the private key at {path} could not be read ({source}). TLS was asked for, so \
         this service refuses to start rather than fall back to a cleartext listener. \
         The usual cause is a mount that selected the certificate and not the key."
    )]
    KeyUnreadable {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error(
        "the certificate at {path} is not valid PEM ({source}). A file that cannot be \
         decoded cannot be served, and a cleartext listener is not what was asked for."
    )]
    CertUnparsable {
        path: PathBuf,
        source: rustls_pki_types::pem::Error,
    },

    #[error(
        "the file at {path} holds no certificate. It was read and decoded without \
         error, and it contained no CERTIFICATE section at all — which the PEM reader \
         reports as an empty list rather than as a failure, so it looks like a file \
         that parsed fine. A listener with no certificate is not a listener, and \
         cleartext is not the fallback."
    )]
    CertEmpty { path: PathBuf },

    #[error(
        "the file at {path} holds no usable private key ({source}). Only PKCS#8, PKCS#1 \
         and SEC1 PEM keys are understood. A cleartext listener is not the answer."
    )]
    KeyUnparsable {
        path: PathBuf,
        source: rustls_pki_types::pem::Error,
    },

    #[error(
        "the certificate at {cert} and the private key at {key} were both decoded and \
         then refused together: {detail}. The usual cause is a key that belongs to a \
         DIFFERENT certificate, which no check of either file on its own can see. This \
         service refuses to start rather than bind a cleartext listener."
    )]
    Rejected {
        cert: PathBuf,
        key: PathBuf,
        detail: String,
    },
}

/// The certificate and key this service presents to its callers.
///
/// **Two paths, and nothing else.** No issuer, no Secret name, no namespace —
/// see the module documentation for why D80 makes that the whole of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerTls {
    cert_file: PathBuf,
    key_file: PathBuf,
}

impl ServerTls {
    /// Read the listener's transport configuration from the environment.
    ///
    /// `Ok(None)` is the ordinary answer today: TLS is opt-in, so an
    /// unconfigured deployment binds the plaintext listener exactly as before.
    pub fn from_env(prefix: &'static str) -> Result<Option<Self>, ServerTlsError> {
        Self::from_lookup(prefix, |key| std::env::var(key).ok())
    }

    /// The same decision, over an injected lookup.
    ///
    /// **A seam, because environment variables are process-global.** A test that
    /// sets one steers every other test running in the same binary, so the
    /// decision that picks between an encrypted listener and a cleartext one
    /// could not be tested at all without this.
    pub fn from_lookup(
        prefix: &'static str,
        lookup: impl Fn(&str) -> Option<String>,
    ) -> Result<Option<Self>, ServerTlsError> {
        let get = |suffix: &str| {
            lookup(&format!("{prefix}_{suffix}"))
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };

        // Exactly "1". A permissive parse here — "0", "false" and "no" all
        // enabling it — is how a setting meant to be off ends up on, and the
        // reverse mistake is worse: this flag is the revert lever for the
        // cut-over, and a lever that does not move is not one. It is the same
        // rule the client side applies to its own flag.
        if get("TLS_ENABLED").as_deref() != Some("1") {
            if get("TLS_CERT_FILE").is_some() || get("TLS_KEY_FILE").is_some() {
                // NOT an error. Leaving the paths in place while the flag is off
                // is exactly how the cut-over gets reverted, so refusing it would
                // make the lever unusable. It is still worth a line: a deployment
                // that believes it is encrypted and is not should be able to see
                // that from the boot log.
                tracing::warn!(
                    prefix,
                    "a certificate is configured but {prefix}_TLS_ENABLED is not \"1\", so \
                     this service listens in CLEARTEXT"
                );
            }
            return Ok(None);
        }

        Ok(Some(Self {
            cert_file: PathBuf::from(
                get("TLS_CERT_FILE").ok_or(ServerTlsError::NoCertFile(prefix))?,
            ),
            key_file: PathBuf::from(get("TLS_KEY_FILE").ok_or(ServerTlsError::NoKeyFile(prefix))?),
        }))
    }

    /// The PEM certificate this service presents.
    pub fn cert_file(&self) -> &Path {
        &self.cert_file
    }

    /// The PEM private key belonging to that certificate.
    pub fn key_file(&self) -> &Path {
        &self.key_file
    }

    /// Read and CHECK both files, and build the acceptor's settings.
    ///
    /// Everything that can be wrong is wrong HERE, once, before a listener
    /// exists — so a bad path is a startup error naming a file rather than a
    /// handshake failure much later, and never a quiet downgrade.
    fn tls_config(&self) -> Result<ServerTlsConfig, ServerTlsError> {
        // ADR-0523-WATCHED: ServerTls
        let cert =
            std::fs::read(&self.cert_file).map_err(|source| ServerTlsError::CertUnreadable {
                path: self.cert_file.clone(),
                source,
            })?;
        // ADR-0523-WATCHED: ServerTls
        let key =
            std::fs::read(&self.key_file).map_err(|source| ServerTlsError::KeyUnreadable {
                path: self.key_file.clone(),
                source,
            })?;

        // THE ASSERTION THIS FUNCTION EXISTS FOR. The PEM reader yields nothing
        // — rather than an error — for input that contains no certificate
        // section, so "parsed successfully" can mean "parsed nothing". Left
        // unchecked it surfaces from inside the acceptor as a sentence about a
        // certificate chain, naming neither file.
        let certificates = CertificateDer::pem_slice_iter(&cert)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| ServerTlsError::CertUnparsable {
                path: self.cert_file.clone(),
                source,
            })?;
        if certificates.is_empty() {
            return Err(ServerTlsError::CertEmpty {
                path: self.cert_file.clone(),
            });
        }

        // Decoded and DISCARDED, deliberately: the point is to find out which
        // file is wrong while both paths are still in hand. tonic decodes them
        // again from the `Identity` below, and its error names neither.
        PrivateKeyDer::from_pem_slice(&key).map_err(|source| ServerTlsError::KeyUnparsable {
            path: self.key_file.clone(),
            source,
        })?;

        Ok(ServerTlsConfig::new().identity(Identity::from_pem(&cert, &key)))
    }
}

/// The server this service listens with, encrypted or not.
///
/// **`tls` decides the transport, and there is no third state.** `None` is the
/// plaintext listener this service has always bound; `Some` is the same server
/// with the connection encrypted, and it returns an ERROR rather than a
/// plaintext server if the certificate or key is unusable.
///
/// The caller adds its own services to what comes back. Returning the builder
/// rather than serving from here is what lets `tests/serve_tls.rs` stand the
/// real thing up on a port it chose.
pub fn builder(tls: Option<&ServerTls>) -> Result<Server, ServerTlsError> {
    let Some(tls) = tls else {
        return Ok(Server::builder());
    };

    let config = tls.tls_config()?;
    // The acceptor is built HERE, eagerly, and that is why a mismatched key is a
    // boot failure: `tls_config` checks each file on its own, and only rustls
    // comparing the certificate's public key against the private one catches a
    // pair that is individually valid and jointly wrong.
    //
    // `chain` on the way out is NOT decoration, and it is the SHARED one
    // (ADR-0591). tonic's transport error renders as the two words "transport
    // error" and keeps everything useful in its `source` chain, so a message
    // that did not walk that chain would tell an operator nothing at all.
    Server::builder()
        .tls_config(config)
        .map_err(|e| ServerTlsError::Rejected {
            cert: tls.cert_file.clone(),
            key: tls.key_file.clone(),
            detail: chain(&e),
        })
}

#[cfg(test)]
mod tests;
