//! Unit tests for [`super`], in their own file.
//!
//! A submodule rather than a `#[cfg(test)]` block at the foot of
//! `invalidate.rs`, the same seam `crypto`, `service`, `serve` and `upstream`
//! already take (ADR-0635/ADR-0577's 500-line ceiling, measured against this
//! file, is what made the split due rather than optional).

use super::*;
use crate::upstream;

#[tokio::test]
async fn no_broker_is_a_working_publisher_that_publishes_nothing() {
    // The alternative — refusing to construct — would make a missing broker
    // an authentication outage, which is a worse failure than a late
    // revocation.
    let inv = Invalidator::connect(None, None, None).await;
    inv.credential_revoked("yadgar:user:x").await;
    inv.teams_changed("yadgar:user:x").await;
    assert!(!inv.is_publishing());
}

#[tokio::test]
async fn an_unreachable_broker_does_not_panic_or_block() {
    let inv = Invalidator::connect(Some("nats://127.0.0.1:1"), None, None).await;
    inv.credential_revoked("yadgar:user:y").await;
    assert!(!inv.is_publishing());
}

/// 965 CENSUS ROW M10. `ConnectOptions` publishes no getter for the
/// bound, so this reads its derived `Debug` string — the same technique
/// `upstream/tests.rs` uses for `TlsOptions::identity`, at the pinned
/// `async-nats` tag. A field rename would still show up as
/// `connection_timeout: 3s`, which is the property under test rather
/// than the field's name.
///
/// THROUGH [`connect_options`] ITSELF, the function [`Invalidator::connect`]
/// actually calls — not a second `ConnectOptions::new().connection_timeout(..)`
/// built here independently, which would pass whether or not `connect_options`
/// ever called `.connection_timeout` at all (a review caught this: deleting
/// the call from production left this test green). Both arms, because the
/// anonymous path is a separate branch inside `connect_options` and the
/// bound belongs to both.
#[test]
fn the_connect_options_carry_the_bound() {
    for credentials in [
        None,
        Some(Credentials {
            user: "iam".into(),
            password: "sentinel".into(),
            password_file: "/var/run/secrets/nats/password".into(),
        }),
    ] {
        let options = connect_options(&credentials, &None);
        assert!(
            format!("{options:?}").contains("\"connection_timeout\": 3s"),
            "the bound built into the options sent to `connect` must be {CONNECT_TIMEOUT:?}"
        );
    }
}

/// `require_tls` IS CALLED EXPLICITLY ON BOTH SIDES (B-N3). Dropping the
/// `false` arm would leave `async-nats`'s own default standing in for a
/// deployment that asked for cleartext — passing today, because the
/// default happens to agree, and silently wrong the day it does not.
#[test]
fn require_tls_is_explicit_in_both_directions() {
    let without = transport::connect_options(&None, &None);
    assert!(
        format!("{without:?}").contains("\"tls_required\": false"),
        "cleartext must set require_tls(false) explicitly: {without:?}"
    );

    let tls = sentinel_tls(None);
    let with = transport::connect_options(&None, &Some(tls));
    assert!(
        format!("{with:?}").contains("\"tls_required\": true"),
        "TLS on must set require_tls(true): {with:?}"
    );
}

/// THE CA REACHES THE OPTIONS. Dropping `add_root_certificates` would leave
/// the trust store at whatever `async-nats` defaults to — the platform
/// store on a distroless image has nothing in it, so this is the one check
/// that tells "no roots were added" apart from "the right root was added".
#[test]
fn the_ca_bundle_reaches_connect_options() {
    let without_tls = transport::connect_options(&None, &None);
    assert!(
        format!("{without_tls:?}").contains("\"certificates\": []"),
        "with no TLS configured, no root certificate must be added: {without_tls:?}"
    );

    let tls = sentinel_tls(None);
    let with_tls = transport::connect_options(&None, &Some(tls));
    assert!(
        !format!("{with_tls:?}").contains("\"certificates\": []"),
        "a CA bundle must reach the options as a root certificate: {with_tls:?}"
    );
}

/// THE DEFAULT: no client certificate configured, so the connection is
/// encrypted and presents no identity — exactly `UpstreamTls`'s own default
/// for every other hop.
#[test]
fn with_no_client_identity_the_hop_presents_none() {
    let tls = sentinel_tls(None);
    let options = transport::connect_options(&None, &Some(tls));
    assert!(
        format!("{options:?}").contains("\"client_cert\": None"),
        "no client certificate configured must add no identity to the options"
    );
}

/// THE CLIENT PAIR REACHES THE OPTIONS WHEN CONFIGURED. `UpstreamTls` holds
/// both or neither, so `None`'s absence above and this presence are the
/// only two reachable shapes.
#[test]
fn the_client_pair_reaches_connect_options_when_configured() {
    let tls = sentinel_tls(Some((
        "/var/run/secrets/nats-client-tls/client.pem",
        "/var/run/secrets/nats-client-tls/client-key.pem",
    )));
    let options = transport::connect_options(&None, &Some(tls));
    assert!(
        !format!("{options:?}").contains("\"client_cert\": None"),
        "a configured client certificate must reach the options as an identity: {options:?}"
    );
}

/// A SENTINEL `UpstreamTls`, built the same way `broker_tls` builds a real
/// one — through `from_lookup` — but over made-up paths this test never
/// reads: `connect_options` wires paths into `ConnectOptions` without
/// opening them (`async-nats` reads them at the dial).
fn sentinel_tls(client: Option<(&str, &str)>) -> upstream::UpstreamTls {
    let mut vars = vec![
        ("NATS_TLS_ENABLED".to_string(), "1".to_string()),
        (
            "NATS_TLS_CA_FILE".to_string(),
            "/var/run/config/nats-ca/ca.pem".to_string(),
        ),
    ];
    if let Some((cert, key)) = client {
        vars.push(("NATS_TLS_CLIENT_CERT_FILE".to_string(), cert.to_string()));
        vars.push(("NATS_TLS_CLIENT_KEY_FILE".to_string(), key.to_string()));
    }
    upstream::UpstreamTls::from_lookup(upstream::NATS, upstream::NATS_CHART_KEY, move |k| {
        vars.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone())
    })
    .expect("a complete configuration")
    .expect("the flag is set")
}

/// A name no other case in this run can collide with — `tests/assembly.rs`
/// has its own copy of this helper for the same reason.
fn unique() -> String {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    format!(
        "{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    )
}

/// A file under the system temp directory, deleted when this value drops —
/// so a test that panics mid-case does not leave a fixture beside the next
/// run's.
struct TempFile(std::path::PathBuf);

impl TempFile {
    fn write(name: &str, contents: &str) -> Self {
        let path = std::env::temp_dir().join(format!("yadgar-iam-transport-{}-{name}", unique()));
        std::fs::write(&path, contents).expect("a writable temp directory");
        Self(path)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// A real, self-signed certificate's PEM — enough to satisfy `broker_tls`'s
/// "holds at least one PEM certificate" check. Not a chain and not signed by
/// any authority these tests mint elsewhere: `certificates_in` counts PEM
/// blocks, not trust.
fn a_certificate_pem() -> String {
    let key = rcgen::KeyPair::generate().unwrap();
    let params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.self_signed(&key).unwrap().pem()
}

/// A real PEM private key, for the "holds a PEM private key" check.
fn a_private_key_pem() -> String {
    rcgen::KeyPair::generate().unwrap().serialize_pem()
}

/// `NATS_TLS_DOMAIN` IS REFUSED. `async-nats` verifies the broker's
/// certificate against the host in `NATS_URL` and has no override, unlike
/// the gRPC hops' own `domain` key.
#[test]
fn nats_tls_domain_is_refused() {
    let ca = TempFile::write("ca", &a_certificate_pem());
    let vars = [
        ("NATS_TLS_ENABLED".to_string(), "1".to_string()),
        (
            "NATS_TLS_CA_FILE".to_string(),
            ca.path().display().to_string(),
        ),
        (
            "NATS_TLS_DOMAIN".to_string(),
            "broker.verified-as-this.invalid".to_string(),
        ),
    ];
    let lookup = move |k: &str| vars.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
    let err = transport::broker_tls(&lookup).unwrap_err();
    assert!(err.contains("NATS_TLS_DOMAIN"), "{err}");
}

/// A CA FILE WITH NO CERTIFICATE IS ZERO TRUST ANCHORS, which `async-nats`
/// treats as no error at all — so this check has to run before the dial
/// ever does, or every handshake fails as an unknown issuer with no
/// deployment mistake named anywhere.
#[test]
fn an_empty_ca_file_is_refused_before_any_dial() {
    let ca = TempFile::write("ca", "not a certificate");
    let vars = [
        ("NATS_TLS_ENABLED".to_string(), "1".to_string()),
        (
            "NATS_TLS_CA_FILE".to_string(),
            ca.path().display().to_string(),
        ),
    ];
    let lookup = move |k: &str| vars.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
    let err = transport::broker_tls(&lookup).unwrap_err();
    assert!(err.contains("NATS_TLS_CA_FILE"), "{err}");
    assert!(err.contains("no PEM certificate"), "{err}");
}

/// THE SAME CHECK, ON THE CLIENT CERTIFICATE: a deployment that names a
/// Secret holding no certificate has no identity to present, and the
/// mistake belongs at boot rather than at a handshake that fails for an
/// unrelated reason.
#[test]
fn an_empty_client_certificate_is_refused_before_any_dial() {
    let ca = TempFile::write("ca", &a_certificate_pem());
    let cert = TempFile::write("cert", "not a certificate");
    let key = TempFile::write("key", &a_private_key_pem());
    let vars = [
        ("NATS_TLS_ENABLED".to_string(), "1".to_string()),
        (
            "NATS_TLS_CA_FILE".to_string(),
            ca.path().display().to_string(),
        ),
        (
            "NATS_TLS_CLIENT_CERT_FILE".to_string(),
            cert.path().display().to_string(),
        ),
        (
            "NATS_TLS_CLIENT_KEY_FILE".to_string(),
            key.path().display().to_string(),
        ),
    ];
    let lookup = move |k: &str| vars.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
    let err = transport::broker_tls(&lookup).unwrap_err();
    assert!(err.contains("NATS_TLS_CLIENT_CERT_FILE"), "{err}");
}

/// A KEY FILE HOLDING NO PRIVATE KEY is refused the same way: a certificate
/// cannot be presented without one, and the mistake is caught before the
/// dial names neither variable.
#[test]
fn a_client_key_file_with_no_private_key_is_refused() {
    let ca = TempFile::write("ca", &a_certificate_pem());
    let cert = TempFile::write("cert", &a_certificate_pem());
    let key = TempFile::write("key", "not a private key");
    let vars = [
        ("NATS_TLS_ENABLED".to_string(), "1".to_string()),
        (
            "NATS_TLS_CA_FILE".to_string(),
            ca.path().display().to_string(),
        ),
        (
            "NATS_TLS_CLIENT_CERT_FILE".to_string(),
            cert.path().display().to_string(),
        ),
        (
            "NATS_TLS_CLIENT_KEY_FILE".to_string(),
            key.path().display().to_string(),
        ),
    ];
    let lookup = move |k: &str| vars.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
    let err = transport::broker_tls(&lookup).unwrap_err();
    assert!(err.contains("NATS_TLS_CLIENT_KEY_FILE"), "{err}");
}

/// A COMPLETE, VALID CONFIGURATION IS ACCEPTED, with both files real and
/// non-empty — the green case the four refusals above are measured against.
#[test]
fn a_complete_configuration_is_accepted() {
    let ca = TempFile::write("ca", &a_certificate_pem());
    let cert = TempFile::write("cert", &a_certificate_pem());
    let key = TempFile::write("key", &a_private_key_pem());
    let vars = [
        ("NATS_TLS_ENABLED".to_string(), "1".to_string()),
        (
            "NATS_TLS_CA_FILE".to_string(),
            ca.path().display().to_string(),
        ),
        (
            "NATS_TLS_CLIENT_CERT_FILE".to_string(),
            cert.path().display().to_string(),
        ),
        (
            "NATS_TLS_CLIENT_KEY_FILE".to_string(),
            key.path().display().to_string(),
        ),
    ];
    let lookup = move |k: &str| vars.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
    let tls = transport::broker_tls(&lookup)
        .expect("a real CA and a real client pair")
        .expect("the flag is set");
    assert_eq!(tls.ca_file(), ca.path());
}

/// `NATS_TLS_ENABLED="0"` IS STILL CLEARTEXT, through the SAME parser
/// `IAM_DB` uses — proved here rather than only in `upstream/tests.rs`,
/// because this is the call site that matters: `main` must not refuse a
/// deployment that has not cut over yet.
#[test]
fn nats_tls_enabled_false_is_cleartext() {
    let vars = [("NATS_TLS_ENABLED".to_string(), "0".to_string())];
    let lookup = move |k: &str| vars.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
    assert_eq!(transport::broker_tls(&lookup).unwrap(), None);
}

#[test]
fn a_credential_never_prints_itself() {
    // The one place a password reaches a formatter. A derived `Debug` would
    // put it into every panic message and test failure that touched the
    // struct, which is how a secret ends up in a log nobody meant to write
    // it to.
    let c = Credentials {
        user: "iam".into(),
        password: "sentinel-of-the-nats-password".into(),
        password_file: "/var/run/secrets/nats/password".into(),
    };
    let printed = format!("{c:?}");
    assert!(
        !printed.contains("sentinel-of-the-nats-password"),
        "{printed}"
    );
    assert!(printed.contains("iam"), "{printed}");
}

#[test]
fn subjects_share_a_namespace_so_one_wildcard_can_catch_them() {
    assert!(subject::CREDENTIAL_REVOKED.starts_with("yadgar.iam."));
    assert!(subject::TEAMS_CHANGED.starts_with("yadgar.iam."));
}

#[test]
fn the_subjects_are_pinned_as_literals_because_three_parties_must_agree() {
    // AS LITERALS, never through `subject::*`. An assertion that reads the
    // constant renames both sides at once, so it cannot see a rename — the
    // namespace check above is exactly that shape, and both subjects can be
    // renamed under it with the whole suite still green.
    //
    // Three parties carry these strings and only one of them is this file.
    // `gateway/src/invalidate.rs` keeps its own copy, pinned there the same
    // way, and `deploy/infra/nats.yaml` names both in the broker's publish
    // and subscribe allow-lists. A rename no test can see leaves publisher,
    // subscriber and broker disagreeing while three suites stay green: the
    // broker refuses the publish, nothing subscribes to what is published,
    // and a revoked credential keeps working until the gateway's cache TTL
    // expires. That is a security bound, so the literal is the assertion.
    assert_eq!(subject::CREDENTIAL_REVOKED, "yadgar.iam.credential.revoked");
    assert_eq!(subject::TEAMS_CHANGED, "yadgar.iam.user.teams-changed");
}

/// A broker that refuses every dial and counts them, for the redial's waits.
async fn counting_refuser() -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds");
    let url = format!("nats://{}", listener.local_addr().expect("its address"));
    let dials = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = std::sync::Arc::clone(&dials);
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            tokio::spawn(async move {
                let _ = socket.write_all(b"INFO {\"auth_required\":true}\r\n").await;
                let mut buf = vec![0u8; 4096];
                let _ = socket.read(&mut buf).await;
                let _ = socket
                    .write_all(b"-ERR 'Authorization Violation'\r\n")
                    .await;
                while let Ok(n) = socket.read(&mut buf).await {
                    if n == 0 {
                        return;
                    }
                }
            });
        }
    });
    (url, dials)
}

/// LEDGER 1420 REVIEW: a refused credential is dialled AGAIN, at the refused
/// interval and never at the outage one. The platform broker reads this
/// service's password from its own environment, so a rotation can leave the
/// broker on the old password until it restarts; a terminal refusal would leave
/// the pod publishing nothing after that.
///
/// Run through [`redial::until_connected`] with SCALED waits — the production
/// ones are 5 s and 60 s, and CI does not wait a minute — so this proves the
/// loop's shape; `tests/nats_auth.rs` proves the production outage rate is not
/// used for a refusal.
#[tokio::test]
async fn a_refused_credential_is_redialled_at_the_refused_interval_not_the_outage_one() {
    let (url, dials) = counting_refuser().await;
    let waits = redial::Waits {
        outage: std::time::Duration::from_millis(50),
        refused: std::time::Duration::from_millis(600),
    };
    let task = tokio::spawn(redial::until_connected(
        url,
        None,
        None,
        std::sync::Arc::default(),
        std::time::Duration::ZERO,
        waits,
    ));
    let count = || dials.load(std::sync::atomic::Ordering::SeqCst);

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(count(), 1, "a refusal was redialled at the outage interval");
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    assert!(
        count() >= 2,
        "a refused credential was never dialled again, so a broker that later accepts it \
         would never hear from this pod"
    );
    task.abort();
}

/// The same property through the BOOT path: a credential refused on the first
/// dial is handed to the redial at the refused interval, not dropped.
#[tokio::test]
async fn a_credential_refused_at_boot_is_dialled_again_at_the_refused_interval() {
    let (url, dials) = counting_refuser().await;
    let waits = redial::Waits {
        outage: std::time::Duration::from_millis(50),
        refused: std::time::Duration::from_millis(600),
    };
    let inv = Invalidator::dial(Some(&url), None, None, waits).await;
    assert!(!inv.is_publishing());
    let count = || dials.load(std::sync::atomic::Ordering::SeqCst);

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(
        count(),
        1,
        "a boot refusal was redialled at the outage interval"
    );
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    assert!(
        count() >= 2,
        "a credential refused at boot was never dialled again"
    );
}
