//! How the broker hop is ENCRYPTED (B-N3, ADR-0852, ADR-0845): the
//! `NATS_TLS_*` contract, the boot-time checks of its files, and the
//! `async-nats` options built from it.
//!
//! Split out of [`super`] for the file-size ceiling, along the seam the hop
//! already has: that module is WHERE the broker is and what credential this
//! service presents to it; this one is how the connection is verified and
//! who this service says it is at the TLS layer. `gateway#105` (B-N3
//! gateway) took the same split for the same reason; this file mirrors its
//! `src/invalidate/transport.rs`.
//!
//! # The client certificate's OWN key, not `iam-db`'s mount (ADR-0885)
//!
//! The B-N3 plan card assumed this service already has a
//! `/var/run/secrets/client-cert` directory every upstream's client identity
//! shares, the way `gateway` does. It does not: `iam`'s only client leaf
//! mount today is `iam-db-client-cert`, rendered only when
//! `iamDb.tls.clientCertSecret` is set, under `iamDb.tls.enabled`. Coupling
//! the broker's identity to that mount would mean turning `iamDb.tls`'s
//! identity off also turned the broker's off, silently. ADR-0885 rules
//! against it: `nats.tls.clientCertSecret` is this service's OWN chart key,
//! with its OWN mount, read here through [`upstream::NATS`] — independent of
//! every `iamDb.tls` key.

use std::path::Path;

use async_nats::rustls::pki_types::pem::PemObject;
use async_nats::rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::upstream::{self, UpstreamTls};

use super::Credentials;

/// The one `UpstreamTls` variable the broker hop cannot honour.
const TLS_DOMAIN: &str = "NATS_TLS_DOMAIN";

/// The broker hop's transport, resolved and CHECKED, or `None` for
/// cleartext (`NATS_TLS_ENABLED="0"`).
///
/// **THE SAME PARSER [`crate::upstream::UpstreamTls::from_lookup`] THE
/// `IAM_DB` HOP USES**, under [`upstream::NATS`], rather than a second copy
/// of it. So the switch has the same contract: ADR-0845's exactly `"1"` or
/// `"0"`, an absence or an empty value refusing the boot naming the variable
/// and [`upstream::NATS_CHART_KEY`], and the client identity both-or-neither.
///
/// **CHECKED HERE, AT BOOT, because `async-nats` does not check these files
/// until the dial.** It reads them inside every connection attempt, and its
/// failures there are a connect error [`super::Invalidator::connect`]'s
/// redial-free boot would simply report as "cannot reach the broker" for
/// ever. Two of them are worse than a retry loop:
///
/// - **A CA file holding no certificate is ZERO trust anchors and NO
///   error** (`async-nats`'s `tls.rs`: an empty iterator is not an error).
///   Every handshake then fails as an unknown issuer, which reads as a
///   broker fault rather than a deployment one.
/// - **The chart's CA and client-cert volumes are `optional: true`**, the
///   same as every other mount in this service, so a missing Secret is an
///   EMPTY DIRECTORY rather than a stuck pod. The process must exit naming
///   the path, as the `iam-db` hop does — not boot into a retry loop that
///   never says what is actually wrong.
///
/// So each file is read once here and refused unless it holds what it must.
/// Each read is marked `ADR-0523-WATCHED` even though it is never folded
/// through [`crate::upstream::UpstreamTls`]'s own `Material` impl: see
/// `crate::rotate::watch_set`'s own doc for why this hop's client leaf is
/// watched by path rather than by that impl.
///
/// **`NATS_TLS_DOMAIN` IS REFUSED**, unlike `IAM_DB`'s and the gRPC hops'
/// own domain override. `async-nats` verifies the broker's certificate
/// against the host in `NATS_URL` and has no override for it — gateway#105
/// measured the same thing against the same library.
pub fn broker_tls(lookup: &impl Fn(&str) -> Option<String>) -> Result<Option<UpstreamTls>, String> {
    let Some(tls) = UpstreamTls::from_lookup(upstream::NATS, upstream::NATS_CHART_KEY, lookup)
        .map_err(|e| e.to_string())?
    else {
        return Ok(None);
    };
    if tls.domain().is_some() {
        return Err(format!(
            "{TLS_DOMAIN} is set, and the broker hop cannot honour it: async-nats verifies the \
             broker's certificate against the host in NATS_URL and has no override. Unset \
             {TLS_DOMAIN} and point NATS_URL at a name the broker's certificate carries."
        ));
    }
    let ca = tls.ca_file();
    if certificates_in(ca, "NATS_TLS_CA_FILE")? == 0 {
        return Err(format!(
            "NATS_TLS_CA_FILE names {}, which holds no PEM certificate. That is zero trust \
             anchors, so every handshake with the broker would fail as an unknown issuer. \
             Point it at the bundle holding the authority that signed the broker's \
             certificate.",
            ca.display()
        ));
    }
    if let (Some(certificate), Some(key)) = (tls.client_certificate_file(), tls.client_key_file()) {
        if certificates_in(certificate, "NATS_TLS_CLIENT_CERT_FILE")? == 0 {
            return Err(format!(
                "NATS_TLS_CLIENT_CERT_FILE names {}, which holds no PEM certificate, so this \
                 service has no identity to present to the broker.",
                certificate.display()
            ));
        }
        private_key_in(key)?;
    }
    Ok(Some(tls))
}

/// How many PEM certificates `path` holds, refusing the boot naming
/// `variable` and the path when it cannot be read or parsed.
fn certificates_in(path: &Path, variable: &str) -> Result<usize, String> {
    // ADR-0523-WATCHED: nats_tls
    let bytes = std::fs::read(path).map_err(|e| {
        format!(
            "{variable} names {}, which cannot be read: {e}. TLS to the broker was asked for, \
             so this refuses to start rather than dialling without it.",
            path.display()
        )
    })?;
    CertificateDer::pem_slice_iter(&bytes)
        .collect::<Result<Vec<_>, _>>()
        .map(|certificates| certificates.len())
        .map_err(|e| {
            format!(
                "{variable} names {}, which is not valid PEM: {e}",
                path.display()
            )
        })
}

/// Refuse the boot unless `path` holds a PEM private key.
fn private_key_in(path: &Path) -> Result<(), String> {
    // ADR-0523-WATCHED: nats_tls
    let bytes = std::fs::read(path).map_err(|e| {
        format!(
            "NATS_TLS_CLIENT_KEY_FILE names {}, which cannot be read: {e}. A client \
             certificate cannot be presented without its key.",
            path.display()
        )
    })?;
    PrivateKeyDer::from_pem_slice(&bytes)
        .map(drop)
        .map_err(|e| {
            format!(
                "NATS_TLS_CLIENT_KEY_FILE names {}, which holds no PEM private key: {e}",
                path.display()
            )
        })
}

/// What this service presents to the broker and how it verifies it: the
/// credential and the transport, and nothing about what is done with the
/// connection once it exists.
///
/// **THE TRUST STORE IS THE CA FILE AND NOTHING ELSE, on the first dial and
/// on every reconnect.** `async-nats` 0.50 builds its rustls config on
/// EVERY connection attempt and loads the platform store only when no root
/// file was given. A root file is always given when TLS is on, so no
/// platform or public root ever joins it — the "no public roots" rule
/// `iam-db`'s own hop keeps. `tls_client_config` is deliberately NOT used:
/// on that path the library loads the platform store anyway, and a
/// distroless image has none to load.
///
/// **`require_tls` IS CALLED EXPLICITLY IN BOTH DIRECTIONS.** `async-nats`
/// upgrades whenever the SERVER asks for TLS, so against a TLS broker
/// everything else here works without it. What it adds is the refusal of a
/// broker that does NOT ask — a cleartext listener, or one serving
/// `allow_non_tls` — so a configuration that says TLS never dials in the
/// clear; and, with `tls` absent, an explicit `false` rather than leaving
/// the option at whatever `async-nats` defaults to.
pub(super) fn connect_options(
    credentials: &Option<Credentials>,
    tls: &Option<UpstreamTls>,
) -> async_nats::ConnectOptions {
    // BUILT FROM THE PAIR, never spliced into the URL. `nats://user:pass@host`
    // carries a password only URL-encoded, so one containing `@`, `/` or `#`
    // would be silently truncated and a DIFFERENT password sent than the one
    // in the Secret — a failure with no visible cause at any layer.
    let options = match credentials {
        Some(c) => {
            async_nats::ConnectOptions::with_user_and_password(c.user.clone(), c.password.clone())
        }
        None => async_nats::ConnectOptions::new(),
    };
    let Some(tls) = tls else {
        return options.require_tls(false);
    };
    let options = options
        .require_tls(true)
        .add_root_certificates(tls.ca_file().to_path_buf());
    match (tls.client_certificate_file(), tls.client_key_file()) {
        (Some(certificate), Some(key)) => {
            options.add_client_certificate(certificate.to_path_buf(), key.to_path_buf())
        }
        // `UpstreamTls` holds both or neither, so this arm is "neither": the
        // hop is encrypted and presents no identity, which a broker still at
        // `nats.tls.clientAuth: off` accepts.
        _ => options,
    }
}
