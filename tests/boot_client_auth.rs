//! The "iam listening" line's `client_auth` field (ledger 1422, ADR-0854).
//!
//! `src/main.rs` is a binary entry point, so nothing inside `serve_and_drain`
//! is reachable from a unit test (see `tests/boot_message.rs`'s own module
//! doc for the same point about `run`). The only way to prove the field is
//! actually in the line `main` writes — rather than in some helper a test
//! calls on its own — is to run the real binary and read what it printed,
//! the way `tests/exit_chain.rs` already does for `wait_until_listening`.
//!
//! Two cases, because a single one cannot discriminate. A cleartext boot's
//! mode is ALWAYS `off` — `serve::ServerTls::from_lookup` refuses any other
//! value with `LISTEN_TLS_ENABLED=0` — so a case that only booted cleartext
//! would still pass against `client_auth = %ClientAuth::Off` hard-coded with
//! `listen_tls` never consulted at all. The second case boots encrypted with
//! `required`, which only a real read of `ServerTls::client_auth()` can
//! produce.

mod support;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use support::{cleartext_env, fresh_keys_dir, Booted};

/// A file under the system temp directory, deleted on drop — the same shape
/// `src/invalidate/tests.rs`'s own `TempFile` takes, copied rather than
/// shared because that one is private to the library crate and this is a
/// separate compilation unit.
struct TempFile(PathBuf);

impl TempFile {
    fn write(name: &str, contents: &str) -> Self {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "yadgar-iam-boot-client-auth-{}-{}-{name}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, contents).expect("a writable temp directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Replace `key`'s value in `vars` (added if absent) — the same override
/// shape `tests/boot_message.rs` uses inline, named here because this file
/// overrides more than one variable per case.
fn set(vars: &mut Vec<(&'static str, String)>, key: &'static str, value: String) {
    vars.retain(|(k, _)| *k != key);
    vars.push((key, value));
}

#[test]
fn a_cleartext_boot_logs_client_auth_off() {
    let keys_dir = fresh_keys_dir();
    let mut iam = Booted::start(&cleartext_env(&keys_dir));
    let line = iam.wait_until_listening();
    assert!(
        line.contains("\"client_auth\":\"off\""),
        "a cleartext boot must log client_auth as off: {line}"
    );
}

/// MUTATION: `src/main.rs`'s `listen_tls.map_or(serve::ClientAuth::Off, |t|
/// t.client_auth())` replaced with a bare `serve::ClientAuth::Off` turns this
/// red — [`a_cleartext_boot_logs_client_auth_off`] alone cannot see that
/// mutation, because `off` is also what a cleartext boot's real mode is.
#[test]
fn a_tls_boot_with_client_auth_required_logs_it() {
    let keys_dir = fresh_keys_dir();
    let leaf = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("a self-signed serving certificate");
    // A SEPARATE self-signed certificate stands in for the client CA. Nothing
    // in this file dials the listener with a client certificate — the claim
    // under test is what the BOOT LOG says the mode is, not that `required`
    // enforces it (`tests/serve_tls.rs` already proves that) — so the CA file
    // only needs to hold one PEM certificate, which any self-signed leaf does.
    let ca = rcgen::generate_simple_self_signed(vec!["iam-test-ca".to_string()])
        .expect("a self-signed stand-in for the client CA");

    let cert = TempFile::write("cert", &leaf.cert.pem());
    let key = TempFile::write("key", &leaf.signing_key.serialize_pem());
    let ca_file = TempFile::write("ca", &ca.cert.pem());

    let mut vars = cleartext_env(&keys_dir);
    set(&mut vars, "LISTEN_TLS_ENABLED", "1".to_string());
    set(&mut vars, "LISTEN_TLS_CLIENT_AUTH", "required".to_string());
    set(
        &mut vars,
        "LISTEN_TLS_CERT_FILE",
        cert.path().display().to_string(),
    );
    set(
        &mut vars,
        "LISTEN_TLS_KEY_FILE",
        key.path().display().to_string(),
    );
    set(
        &mut vars,
        "LISTEN_TLS_CLIENT_CA_FILE",
        ca_file.path().display().to_string(),
    );

    let mut iam = Booted::start(&vars);
    let line = iam.wait_until_listening();
    assert!(
        line.contains("\"client_auth\":\"required\""),
        "a TLS boot with LISTEN_TLS_CLIENT_AUTH=required must log client_auth as required: {line}"
    );
}
