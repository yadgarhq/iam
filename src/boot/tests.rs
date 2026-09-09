//! Unit tests for [`super`], in their own file.
//!
//! A submodule rather than a `#[cfg(test)]` block at the foot of `boot.rs`, the
//! same seam every other module in this crate takes.

use super::*;

/// An environment stating only what a test cares about.
fn env_of<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
    move |key| {
        pairs
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.to_string())
    }
}

/// A file holding exactly these bytes, at a path this test owns.
fn password_file(name: &str, contents: &str) -> String {
    let dir = std::env::temp_dir().join(format!("yadgar-iam-boot-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create the password directory");
    let path = dir.join("password");
    std::fs::write(&path, contents).expect("write the password");
    path.to_str().expect("a utf-8 path").to_string()
}

/// Deliberately unlike anything the implementation could contain. A fixture
/// equal to a constant in the code under test would pass for a build that
/// used its own idea of a password rather than the configured one.
const PASSWORD: &str = "sentinel-of-the-nats-password-4c17";
const USER: &str = "sentinel-user";

#[test]
fn both_set_is_the_credential_the_files_and_the_environment_describe() {
    let path = password_file("both", PASSWORD);
    let got = nats_credentials(env_of(&[
        ("NATS_PASSWORD_FILE", path.as_str()),
        ("NATS_USER", USER),
    ]))
    .expect("a fully configured broker credential loads")
    .expect("and it is a credential rather than nothing");

    assert_eq!(got.user, USER);
    assert_eq!(got.password, PASSWORD);
}

#[test]
fn neither_set_presents_nothing_rather_than_refusing() {
    // A BROKER WITH NO AUTHORIZATION BLOCK IS A SUPPORTED DEPLOYMENT, and
    // the chart says so. Refusing here would turn every deployment that has
    // not cut over into a CrashLoopBackOff.
    assert!(nats_credentials(env_of(&[]))
        .expect("an unconfigured broker is not an error")
        .is_none());
}

#[test]
fn a_password_with_no_user_refuses_the_boot() {
    let path = password_file("no-user", PASSWORD);
    let err = nats_credentials(env_of(&[("NATS_PASSWORD_FILE", path.as_str())]))
        .expect_err("a password with no account to present it as cannot authenticate");

    assert!(matches!(err, BootError::NatsPasswordWithoutUser), "{err}");
}

#[test]
fn a_user_with_no_password_refuses_the_boot_rather_than_connecting_anonymously() {
    // THE ASYMMETRY THIS CLOSES. The opposite half-configuration refused from
    // the day it was written; this one returned `Ok(None)` and connected with
    // no credential at all, logging a warning nobody reads — the silent fall
    // back the sibling arm's own message calls out.
    //
    // MUTATION THIS CATCHES: returning `Ok(None)` when the path is empty
    // regardless of the user, which is what the code did. Every other test in
    // this file passes under it, including the one above — the two arms are
    // independent and only this one sees the missing half.
    let err = nats_credentials(env_of(&[("NATS_USER", USER)]))
        .expect_err("an account with no password cannot authenticate");

    assert!(matches!(err, BootError::NatsUserWithoutPassword), "{err}");
}

#[test]
fn an_empty_password_file_refuses_the_boot() {
    // A blank password is not one, and a Secret whose key exists and holds
    // nothing is a deployment mistake rather than a request to connect
    // anonymously.
    let path = password_file("empty", "\n");
    let err = nats_credentials(env_of(&[
        ("NATS_PASSWORD_FILE", path.as_str()),
        ("NATS_USER", USER),
    ]))
    .expect_err("a blank password must refuse the boot");

    assert!(matches!(err, BootError::NatsPasswordEmpty { .. }), "{err}");
}

#[test]
fn an_unreadable_password_file_refuses_the_boot_naming_the_path() {
    // NAMING THE PATH IS THE POINT. An optional volume mount that cannot be
    // satisfied mounts an EMPTY directory rather than failing the pod, so the
    // only evidence the operator gets is this message.
    let err = nats_credentials(env_of(&[
        ("NATS_PASSWORD_FILE", "/var/run/secrets/nats/absent"),
        ("NATS_USER", USER),
    ]))
    .expect_err("a path naming no file must refuse the boot");

    assert!(
        matches!(err, BootError::NatsPasswordUnreadable { .. }),
        "{err}"
    );
    assert!(
        err.to_string().contains("/var/run/secrets/nats/absent"),
        "the refusal must name the path it could not read: {err}"
    );
}

#[test]
fn only_the_trailing_newline_is_stripped() {
    // `kubectl create secret --from-file` stores the bytes exactly, editor
    // newline included, and a password with a `\n` on the end is a different
    // password. Inner whitespace is a legitimate part of one and is left
    // alone — stripping it would send a different password than the Secret
    // holds, failing as an authorization violation with no visible cause.
    let path = password_file("newline", "  spaced  password  \r\n");
    let got = nats_credentials(env_of(&[
        ("NATS_PASSWORD_FILE", path.as_str()),
        ("NATS_USER", USER),
    ]))
    .expect("it loads")
    .expect("and it is a credential");

    assert_eq!(got.password, "  spaced  password  ");
}

#[test]
fn an_empty_password_file_variable_is_the_same_as_an_absent_one() {
    // A chart that renders the key with no value must not be a different
    // deployment from one that omits it.
    assert!(nats_credentials(env_of(&[("NATS_PASSWORD_FILE", "")]))
        .expect("an empty path is no path")
        .is_none());
}

// ---------------------------------------------------------------------------
// `env_required` and `refusal`, moved here with the functions themselves.
//
// THEY USED TO LIVE IN `main.rs`, tested through a `#[cfg(test)] mod tests` in
// the BINARY target. That is the arrangement this module's own header argues
// against: `refusal`'s doc says it exists as a named function only because
// nothing inside `main` is reachable from a test. Moving the two decisions into
// the library moves their tests with them, and every assertion below is the one
// that was there before.
// ---------------------------------------------------------------------------

// Each test owns a UNIQUE key. `std::env` is process-global and `cargo test`
// runs these on threads of one process, so tests sharing a variable name
// would pass or fail depending on scheduling.

/// The case a naive test omits, and the only one that proves the value is
/// USED. A test that merely asserts "boot succeeds" passes just as happily
/// with a compiled-in default still in place behind the read.
#[test]
fn a_set_value_is_returned_verbatim() {
    std::env::set_var("YADGAR_TEST_IAM_REQUIRED_PRESENT", "0.0.0.0:50052");
    assert_eq!(
        env_required("YADGAR_TEST_IAM_REQUIRED_PRESENT").as_deref(),
        Ok("0.0.0.0:50052")
    );
}

#[test]
fn an_absent_knob_refuses_and_names_itself() {
    std::env::remove_var("YADGAR_TEST_IAM_REQUIRED_ABSENT");
    let err = env_required("YADGAR_TEST_IAM_REQUIRED_ABSENT").unwrap_err();
    assert!(
        err.contains("YADGAR_TEST_IAM_REQUIRED_ABSENT"),
        "the refusal must name the knob, got: {err}"
    );
    assert!(err.contains("NOT SET"), "got: {err}");
}

/// **THE CASE THAT DISCRIMINATES.** Helm renders an unset value as `""`, so
/// a nulled chart value arrives here as set-but-empty rather than as absent.
/// An implementation that collapses the two into one branch is the defect
/// this estate found three separate times in one week, so the messages are
/// asserted to DIFFER rather than merely to exist.
#[test]
fn an_empty_knob_refuses_with_its_own_message() {
    std::env::set_var("YADGAR_TEST_IAM_REQUIRED_EMPTY", "");
    std::env::remove_var("YADGAR_TEST_IAM_REQUIRED_EMPTY_ABSENT");
    let empty = env_required("YADGAR_TEST_IAM_REQUIRED_EMPTY").unwrap_err();
    let absent = env_required("YADGAR_TEST_IAM_REQUIRED_EMPTY_ABSENT").unwrap_err();
    assert!(empty.contains("set but EMPTY"), "got: {empty}");
    assert!(
        empty.replace("YADGAR_TEST_IAM_REQUIRED_EMPTY", "K")
            != absent.replace("YADGAR_TEST_IAM_REQUIRED_EMPTY_ABSENT", "K"),
        "empty and absent must not share one message"
    );
}

/// THE ONE THING LEDGER 733/740 IS ABOUT, against the REAL error rather
/// than a fixture that could be shaped to pass.
///
/// `tonic::transport::Error`'s whole `Display` is the two words `transport
/// error`, and `BalanceError::Tls` interpolates exactly that — so the
/// sentence `main` used to print for an unusable transport was `TLS could
/// not be configured: transport error`, which names no file, no key and no
/// reason. What went wrong sits one layer BELOW tonic's error and is
/// reachable only by walking `source()`.
///
/// **BOTH RENDERINGS ARE ASSERTED, and the negative one is the point.** A
/// test that only checked `refusal` contains the reason would pass against
/// a `to_string()` that happened to carry it; asserting that `to_string()`
/// does NOT is what shows the layer is genuinely lost, which is the
/// finding rather than a matched absence.
///
/// MUTATION: replace `refusal`'s body with `error.to_string()` and this
/// fails.
///
/// The error is produced by `crate::upstream::connect` — the same
/// call `main` makes — given a bundle that is a real authority and a
/// verification domain `rustls::ServerName` refuses. No dial is involved:
/// the domain is rejected while `yadgar_dial::connect_tls` builds the
/// tonic endpoint, before anything is resolved.
#[tokio::test]
async fn a_refusal_carries_the_layer_below_transport_error() {
    let ca = MintedCa::new();
    let tls = upstream_tls(ca.path(), "not a server name");

    let error = crate::upstream::connect("iam-db", 50051, Some(&tls))
        .await
        .expect_err("a domain rustls cannot parse must refuse before any dial");

    assert!(
        refusal(&error).contains("invalid dns name"),
        "the refusal must carry the layer below tonic's `transport error`; got: {:?}",
        refusal(&error)
    );
    assert!(
        !error.to_string().contains("invalid dns name"),
        "if the head already carried the reason there would be nothing to walk \
         for, and this test would be certifying itself; got: {:?}",
        error.to_string()
    );
}

/// `UpstreamTls` assembled the way a DEPLOYMENT assembles it — through
/// `from_lookup` over the `IAM_DB_TLS_*` names — rather than by hand, so
/// the test cannot configure a shape `main` could never produce.
fn upstream_tls(ca_file: &std::path::Path, domain: &str) -> crate::upstream::UpstreamTls {
    let vars = [
        ("IAM_DB_TLS_ENABLED".to_string(), "1".to_string()),
        (
            "IAM_DB_TLS_CA_FILE".to_string(),
            ca_file.display().to_string(),
        ),
        ("IAM_DB_TLS_DOMAIN".to_string(), domain.to_string()),
    ];
    crate::upstream::UpstreamTls::from_lookup(crate::upstream::IAM_DB, |key| {
        vars.iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.to_string())
    })
    .expect("a flag, a bundle and a domain are a valid configuration")
    .expect("the flag is set, so TLS is on")
}

/// A CA bundle that is a REAL authority, minted per run and deleted after.
///
/// It has to be real: an empty or unparsable bundle is refused by
/// `TlsOptions::prepare` BEFORE the endpoint is built, so it would produce
/// `CaEmpty` and never reach the variant under test. Minted rather than
/// checked in, for the reason every other rig in this repository gives — a
/// fixture key in the repository is a secret in the repository.
///
/// The name carries a COUNTER as well as the pid: `cargo test` runs these
/// on threads of one process, and a clock is a timestamp rather than a
/// nonce (ledger 706, 710, 729).
struct MintedCa(std::path::PathBuf);

impl MintedCa {
    fn new() -> Self {
        use rcgen::{
            BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyPair,
            KeyUsagePurpose,
        };
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

        let key = KeyPair::generate().expect("a key pair");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("parameters");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params
            .distinguished_name
            .push(DnType::CommonName, "yadgar-iam boot-refusal test authority");
        let ca = CertifiedIssuer::self_signed(params, key).expect("a self-signed authority");

        let path = std::env::temp_dir().join(format!(
            "yadgar-iam-refusal-{}-{}.pem",
            std::process::id(),
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::write(&path, ca.pem()).expect("the bundle must be written");
        Self(path)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for MintedCa {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
