//! The serving TLS seam, proved by real handshakes.
//!
//! **A test that only shows "TLS was configured" passes against the broken
//! version of this change**, so nothing here inspects a `ServerTlsConfig`. Every
//! case stands the real listener up through [`yadgar_iam::serve::builder`],
//! dials it, and asserts on whether a request survived the transport.
//!
//! **The configuration travels the whole way.** Each case builds its
//! [`ServerTls`] through `from_lookup`, so the same reading of
//! `LISTEN_TLS_CERT_FILE` and `LISTEN_TLS_KEY_FILE` that a deployment performs
//! is what ends up on the wire — not a struct assembled by the test.
//!
//! **ALPN is verified by consequence, and that is worth stating plainly.** tonic
//! pushes `h2` onto the server's ALPN list itself
//! (`tonic/src/transport/server/service/tls.rs`), and its channel connector
//! REFUSES a connection whose negotiated protocol is not `h2` unless
//! `assume_http2` was asked for — `tonic/src/transport/channel/service/tls.rs`,
//! the `H2NotNegotiated` arm. Nothing here sets `assume_http2`. So a gRPC
//! request that comes back `Unimplemented` over TLS is proof that `h2` was
//! negotiated: without it the client would have refused the connection. No
//! mutation of THIS repository's code can turn that assertion red, because the
//! server's ALPN list is tonic's; the assertion is a guard against a tonic
//! upgrade that drops it, not against a local mistake.
//!
//! CERTIFICATES ARE MINTED PER RUN. A fixture key committed to the repository is
//! a secret committed to the repository, and it expires on a date nobody is
//! watching.
//!
//! NOTE ON `localhost`: it is the one name that resolves without touching
//! `/etc/hosts`, and on this machine it resolves to BOTH `::1` and `127.0.0.1`.
//! `serve` therefore binds every address the name resolves to, on one port, so a
//! client that picks the other one is not talking to a closed port. That is a
//! property of the test rig, not of the service.

use std::collections::HashSet;
use std::io::Write as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier, OnceLock};
use std::time::Duration;

use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::codegen::{http, Service};
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity};

use yadgar_iam::serve::{self, ServeTlsError, ServerTls};

/// The name the test certificates are issued for, and the name the rig listens
/// on.
const SERVED_NAME: &str = "localhost";

/// A name NOTHING in `serve.rs` could have chosen for itself, used where the
/// question is whether the certificate on the wire came from the configured
/// FILE rather than from somewhere inside the implementation.
const SENTINEL_NAME: &str = "iam-served-this-and-nothing-else.invalid";

/// A certificate authority and one certificate it issued.
///
/// The ISSUER is kept, not only its PEM, so a case can mint a CLIENT leaf
/// under the same authority (B-U5): a listener with `clientAuth: required`
/// verifies a caller against a CA, and the rig has to hold one to sign with.
struct Pki {
    ca: CertifiedIssuer<'static, KeyPair>,
    ca_pem: String,
    cert_pem: String,
    key_pem: String,
}

/// Mint a CA and a server certificate whose ONLY subject alternative name is
/// `san` — a DNS name, with no IP SAN.
fn pki(san: &str) -> Pki {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "yadgar-iam test authority");
    let ca = CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();

    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec![san.to_string()]).unwrap();
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.distinguished_name.push(DnType::CommonName, san);
    let cert = params.signed_by(&key, &ca).unwrap();

    Pki {
        ca_pem: ca.pem(),
        ca,
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
    }
}

/// A CLIENT leaf `ca` issued: the `clientAuth` extended key usage, the name a
/// caller of this service carries (`iam-caller`, as `chart/values.yaml` names
/// it), and its key. Returned as `(certificate, key)` PEM.
fn client_leaf(ca: &CertifiedIssuer<'static, KeyPair>) -> (String, String) {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec!["iam-caller".to_string()]).unwrap();
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    params
        .distinguished_name
        .push(DnType::CommonName, "iam-caller");
    let cert = params.signed_by(&key, ca).unwrap();
    (cert.pem(), key.serialize_pem())
}

/// A file that deletes itself, so a certificate and a key can be handed over as
/// PATHS — which is the only shape [`ServerTls`] accepts, and the reason it
/// accepts it (D80).
struct TempPem(PathBuf);

/// One reading of the clock per PROCESS, so two runs that the OS gave the same
/// recycled pid do not name the same files. It varies per run and never within
/// one, which is what leaves [`unique_name`] with exactly one varying part.
fn run_id() -> u128 {
    static RUN: OnceLock<u128> = OnceLock::new();
    *RUN.get_or_init(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    })
}

/// The name of one temporary PEM, unique within this process by CONSTRUCTION.
///
/// **THE CLOCK IS NOT A UNIQUENESS SOURCE ACROSS THREADS, and this is measured
/// on this tree rather than assumed.** The name used to be `pid` plus a fresh
/// nanosecond reading. Every test in this binary shares the pid and they run on
/// threads, so two concurrent calls collide whenever both readings land on the
/// same nanosecond — and then one `TempPem`'s `Drop` deletes a path a sibling
/// test is still reading. A clock is a timestamp, not a nonce (ledger 629).
///
/// The counter is the ONLY part that varies within a run, which is what makes
/// the property assertable rather than merely likely.
fn unique_name() -> String {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    format!(
        "yadgar-iam-{}-{}-{}.pem",
        std::process::id(),
        run_id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    )
}

/// The SEQUENTIAL property, and it is a mutation guard rather than a
/// reproduction — stated plainly because the distinction was measured. It
/// PASSES against the clock-based name this change replaces: same-thread
/// readings advance by tens of nanoseconds and never repeat, so a sequential
/// assertion cannot see the defect.
///
/// MUTATION: replace `fetch_add(1, ..)` with `load(..)` and this fails on every
/// run.
#[test]
fn two_temporary_names_are_never_the_same_name() {
    assert_ne!(unique_name(), unique_name());

    let many: HashSet<String> = (0..1000).map(|_| unique_name()).collect();
    assert_eq!(many.len(), 1000, "1000 names must be 1000 distinct names");
}

/// THE CONCURRENT PROPERTY, which is the one that reproduces the defect, and it
/// is the failing test this fix was written against. Cross-thread readings of
/// `SystemTime::now()` repeat constantly; same-thread ones do not, which is why
/// only a threaded assertion can see it.
#[test]
fn concurrent_names_are_all_distinct() {
    const THREADS: usize = 16;
    const PER_THREAD: usize = 2000;

    let start = Arc::new(Barrier::new(THREADS));
    let handles: Vec<_> = (0..THREADS)
        .map(|_| {
            let start = Arc::clone(&start);
            std::thread::spawn(move || {
                start.wait();
                (0..PER_THREAD).map(|_| unique_name()).collect::<Vec<_>>()
            })
        })
        .collect();

    let all: Vec<String> = handles
        .into_iter()
        .flat_map(|h| h.join().unwrap())
        .collect();
    let distinct: HashSet<&String> = all.iter().collect();
    assert_eq!(
        distinct.len(),
        THREADS * PER_THREAD,
        "{} of {} names collided across {THREADS} threads",
        THREADS * PER_THREAD - distinct.len(),
        THREADS * PER_THREAD
    );
}

impl TempPem {
    fn with(contents: &str) -> Self {
        let path = std::env::temp_dir().join(unique_name());
        // `create_new`, not `fs::write`. Silence is what made the old collision
        // expensive: two tests shared a path, one deleted it, and the other
        // failed somewhere else entirely — as a missing file, or as a negative
        // fixture that had been overwritten with valid material. If a name is
        // ever reused, this panics and names the file instead.
        let mut file = std::fs::File::options()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap_or_else(|e| panic!("{} already exists or cannot be made: {e}", path.display()));
        file.write_all(contents.as_bytes()).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempPem {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Build the settings the way a DEPLOYMENT builds them — out of the variables
/// the chart renders — rather than by assembling the struct directly. A test
/// that bypassed `serve::from_lookup` would leave the reading of those names,
/// and THIS service's chart key, unproven.
///
/// `LISTEN_TLS_CLIENT_AUTH` is `off` here: every case that is not about client
/// authentication states the value a deployment with mutual TLS off writes,
/// because an absent one refuses the boot (ADR-0854).
fn configured(cert: &Path, key: &Path) -> ServerTls {
    configured_with(cert, key, "off", None)
}

/// [`configured`], with the client-authentication mode and, when it verifies,
/// the client CA file a deployment mounts.
fn configured_with(cert: &Path, key: &Path, mode: &str, client_ca: Option<&Path>) -> ServerTls {
    let mut vars: Vec<(String, String)> = vec![
        ("LISTEN_TLS_ENABLED".to_string(), "1".to_string()),
        (
            "LISTEN_TLS_CERT_FILE".to_string(),
            cert.display().to_string(),
        ),
        ("LISTEN_TLS_KEY_FILE".to_string(), key.display().to_string()),
        ("LISTEN_TLS_CLIENT_AUTH".to_string(), mode.to_string()),
    ];
    if let Some(ca) = client_ca {
        vars.push((
            "LISTEN_TLS_CLIENT_CA_FILE".to_string(),
            ca.display().to_string(),
        ));
    }
    serve::from_lookup(move |k| vars.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()))
        .expect("a flag, a certificate, a key and a mode are a complete configuration")
        .expect("the flag is set, so this is the TLS path")
}

/// Stand the service's own listener up on every address `SERVED_NAME` resolves
/// to, and return the shared port.
///
/// `Routes::default()` answers every method with `Unimplemented`, which is all
/// that is needed: the question each test asks is whether a request reached the
/// server at all.
async fn serve(tls: Option<&ServerTls>) -> u16 {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((SERVED_NAME, 0))
        .await
        .unwrap()
        .collect();
    assert!(!addrs.is_empty(), "{SERVED_NAME} resolved to nothing");

    let (port, listeners) = bind_one_port_on_every_address(&addrs).await;
    for listener in listeners {
        spawn(listener, tls);
    }

    ready(port).await;
    port
}

/// How many ports to try before giving up on finding one free everywhere. The
/// count is NAMED rather than inlined so the panic below can state it; the
/// number is unchanged, because lowering it is a behaviour change with no
/// measurement behind it.
const BIND_ATTEMPTS: usize = 50;

/// One ephemeral port, bound on EVERY address the name resolves to.
///
/// **THE KERNEL PICKS THE PORT FOR ONE ADDRESS AND PROMISES NOTHING ABOUT THE
/// OTHERS.** Asking for an ephemeral port on `127.0.0.1` and then demanding that
/// same number on `::1` fails whenever a concurrently running test in this
/// binary was handed it there first — `EADDRINUSE` on the second bind, which the
/// old code turned into `.expect(..)`. It is a second, independent race in the
/// same rig, and it was measured firing on this tree, so fixing only the filed
/// defect would have left the suite flaky.
///
/// So the whole SET is acquired before anything is spawned, and a partial
/// acquisition is dropped and retried with a fresh port. Retrying is honest
/// here: the failure is another process holding a number, which the next number
/// does not have.
///
/// **RETRYING IS ONLY HONEST FOR A PORT SOMEBODY ELSE HOLDS.** Every other bind
/// error is permanent, so retrying one spends fifty ports to learn nothing and
/// then blames port exhaustion for it. The case that makes this concrete: on a
/// host with IPv6 disabled where `localhost` still resolves `::1`, every bind on
/// `::1` returns `EADDRNOTAVAIL`. So `AddrInUse` is retried and every other
/// error names the address it happened on — the form `yadgar-dial`'s
/// `tests/common/mod.rs` already carries, which this rig cited as its precedent
/// and then did not adopt (ledger 708).
async fn bind_one_port_on_every_address(addrs: &[SocketAddr]) -> (u16, Vec<TcpListener>) {
    for _ in 0..BIND_ATTEMPTS {
        let first = TcpListener::bind(addrs[0])
            .await
            .unwrap_or_else(|e| panic!("no free port on {}: {e}", addrs[0].ip()));
        let port = first.local_addr().unwrap().port();

        let mut listeners = vec![first];
        for addr in &addrs[1..] {
            match TcpListener::bind(SocketAddr::new(addr.ip(), port)).await {
                Ok(listener) => listeners.push(listener),
                // Dropping `listeners` releases the port on every address it was
                // taken on, so the next attempt starts from nothing held.
                Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => break,
                Err(e) => panic!("binding {} on port {port}: {e}", addr.ip()),
            }
        }
        if listeners.len() == addrs.len() {
            return (port, listeners);
        }
    }
    panic!(
        "no ephemeral port was free on all {} addresses in {BIND_ATTEMPTS} attempts",
        addrs.len()
    );
}

/// A PERMANENT bind failure on a LATER address names that address, rather than
/// being spent as one of [`BIND_ATTEMPTS`] retries.
///
/// The failure is a real one rather than a mocked one: `192.0.2.0/24` is
/// TEST-NET-1, reserved for documentation and assigned to no interface, so
/// binding it returns `EADDRNOTAVAIL`. Against the `Err(_) => break` this
/// replaces, the case panicked with "no ephemeral port was free on all 2
/// addresses" — port exhaustion, which is the wrong diagnosis and the whole of
/// ledger 708.
#[tokio::test]
#[should_panic(expected = "binding 192.0.2.1")]
async fn a_permanent_failure_on_a_later_address_is_reported_not_retried() {
    let addrs = [
        SocketAddr::from(([127, 0, 0, 1], 0)),
        SocketAddr::from(([192, 0, 2, 1], 0)),
    ];
    bind_one_port_on_every_address(&addrs).await;
}

/// The same property on the FIRST address, which is a SEPARATE path through the
/// same function and the likelier one to meet a disabled address family:
/// `localhost` resolves `::1` AHEAD of `127.0.0.1` on this machine, so a host
/// with IPv6 off fails on `addrs[0]` before the loop is ever reached. That bind
/// used to carry `.expect("an ephemeral port on the first address")`, which
/// named no address and reported the wrong cause just as the loop did.
#[tokio::test]
#[should_panic(expected = "no free port on 192.0.2.1")]
async fn a_permanent_failure_on_the_first_address_is_reported_not_retried() {
    let addrs = [SocketAddr::from(([192, 0, 2, 1], 0))];
    bind_one_port_on_every_address(&addrs).await;
}

fn spawn(listener: TcpListener, tls: Option<&ServerTls>) {
    let mut server = serve::builder(tls).expect("a usable certificate and key");
    let router = server.add_routes(tonic::service::Routes::default());
    tokio::spawn(async move {
        let _ = router
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await;
    });
}

/// Wait until the port accepts a TCP connection, rather than sleeping a guessed
/// interval.
async fn ready(port: u16) {
    for _ in 0..200 {
        if tokio::net::TcpStream::connect((SERVED_NAME, port))
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the test server never accepted a connection on port {port}");
}

/// Send one gRPC request at `port` and report whether it ARRIVED.
///
/// `Ok` means the transport carried it: the handshake completed and the server
/// answered — with `Unimplemented`, which is a perfectly good answer to this
/// question. `Err` means it never got there, whether the connection or the
/// request is where it stopped.
async fn reach(port: u16, tls: Option<ClientTlsConfig>) -> Result<(), String> {
    let scheme = if tls.is_some() { "https" } else { "http" };
    let mut endpoint = Endpoint::from_shared(format!("{scheme}://{SERVED_NAME}:{port}"))
        .unwrap()
        .connect_timeout(Duration::from_secs(5));
    if let Some(tls) = tls {
        endpoint = endpoint.tls_config(tls).map_err(|e| format!("{e}"))?;
    }
    // LAZY, so there is exactly one place a failure can be observed. An eager
    // `connect` would report a refused handshake from a different call than the
    // one reporting a refused request, and every case here asks the same
    // question of both.
    let mut channel = endpoint.connect_lazy();

    let req = http::Request::builder()
        .version(http::Version::HTTP_2)
        .method("POST")
        .uri(format!(
            "{scheme}://{SERVED_NAME}/yadgar.iam.v1.IamService/Probe"
        ))
        .header("content-type", "application/grpc")
        .body(tonic::body::Body::empty())
        .unwrap();

    std::future::poll_fn(|cx| channel.poll_ready(cx))
        .await
        .map_err(|e| format!("{e}"))?;
    match tokio::time::timeout(Duration::from_secs(10), channel.call(req)).await {
        Err(_) => Err("the request timed out".to_string()),
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(format!("{e}")),
    }
}

fn trusting(ca_pem: &str, domain: &str) -> ClientTlsConfig {
    ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(ca_pem))
        .domain_name(domain)
}

/// THE PROPERTY THE WHOLE CAR EXISTS FOR: the listener speaks TLS, and a gRPC
/// request crosses it.
///
/// It is also the ALPN assertion. The client refuses any connection that does
/// not negotiate `h2` (`H2NotNegotiated`), and nothing here asks it to assume
/// HTTP/2 — so a server that offered no ALPN, or offered something else, would
/// fail this rather than serve a connection that answers nothing useful.
#[tokio::test]
async fn a_tls_client_reaches_a_server_built_with_tls() {
    let p = pki(SERVED_NAME);
    let cert = TempPem::with(&p.cert_pem);
    let key = TempPem::with(&p.key_pem);
    let port = serve(Some(&configured(cert.path(), key.path()))).await;

    assert_eq!(
        reach(port, Some(trusting(&p.ca_pem, SERVED_NAME))).await,
        Ok(())
    );
}

/// THE OTHER HALF of "it really is TLS". A cleartext client must not reach a
/// TLS listener — otherwise the case above could pass while the server had
/// quietly started in the clear and the client had quietly stopped verifying.
#[tokio::test]
async fn a_cleartext_client_cannot_reach_a_tls_server() {
    let p = pki(SERVED_NAME);
    let cert = TempPem::with(&p.cert_pem);
    let key = TempPem::with(&p.key_pem);
    let port = serve(Some(&configured(cert.path(), key.path()))).await;

    assert!(
        reach(port, None).await.is_err(),
        "cleartext against a TLS listener must fail"
    );
}

/// THE DEFAULT, unchanged. Nothing configured means the plaintext listener this
/// service has always had, and a client that expects one still finds it.
#[tokio::test]
async fn a_cleartext_client_reaches_a_server_built_without_tls() {
    let port = serve(None).await;
    assert_eq!(reach(port, None).await, Ok(()));
}

/// And the default really is plaintext, so the pair above cannot both start
/// passing because everything became TLS.
#[tokio::test]
async fn a_tls_client_cannot_reach_a_server_built_without_tls() {
    let p = pki(SERVED_NAME);
    let port = serve(None).await;

    assert!(
        reach(port, Some(trusting(&p.ca_pem, SERVED_NAME)))
            .await
            .is_err(),
        "TLS against a cleartext listener must fail"
    );
}

/// THE CERTIFICATE ON THE WIRE IS THE ONE AT THE CONFIGURED PATH, proved with a
/// name the implementation could not have chosen: the certificate is issued for
/// a sentinel, the client verifies against that sentinel, and only a server
/// presenting THAT FILE can satisfy it.
#[tokio::test]
async fn the_certificate_served_is_the_one_at_the_configured_path() {
    let p = pki(SENTINEL_NAME);
    let cert = TempPem::with(&p.cert_pem);
    let key = TempPem::with(&p.key_pem);
    let port = serve(Some(&configured(cert.path(), key.path()))).await;

    assert_eq!(
        reach(port, Some(trusting(&p.ca_pem, SENTINEL_NAME))).await,
        Ok(())
    );
}

/// A certificate from an authority the caller does not trust is what an impostor
/// presents. The connection has to fail, which is also what proves the client
/// side of every case above is doing real verification.
#[tokio::test]
async fn a_certificate_from_an_untrusted_authority_is_refused() {
    let served = pki(SERVED_NAME);
    let cert = TempPem::with(&served.cert_pem);
    let key = TempPem::with(&served.key_pem);
    let port = serve(Some(&configured(cert.path(), key.path()))).await;

    // A second authority, which issued nothing the server holds.
    let stranger = pki(SERVED_NAME);
    assert!(
        reach(port, Some(trusting(&stranger.ca_pem, SERVED_NAME)))
            .await
            .is_err(),
        "a certificate signed by an authority that is not trusted must be refused"
    );
}

/// THE FAILURE THAT MUST NOT DEGRADE, in the form an operator actually produces:
/// the mount did not happen, so the path names nothing.
///
/// `builder` must return an error naming the file. It must NOT return a server —
/// a server returned here is a PLAINTEXT listener carrying a TLS configuration
/// that failed, which is the whole defect this car removes.
#[tokio::test]
async fn a_certificate_path_that_cannot_be_read_is_an_error() {
    let missing = std::env::temp_dir().join("yadgar-iam-no-such-cert-6a17d4.pem");
    let key = TempPem::with("irrelevant, the certificate is checked first");
    let tls = configured(&missing, key.path());

    let outcome = serve::builder(Some(&tls));
    assert!(
        matches!(outcome, Err(ServeTlsError::Unreadable { .. })),
        "a certificate path that does not exist must be refused, not served in cleartext"
    );
    assert!(
        outcome.err().unwrap().to_string().contains(
            missing
                .to_str()
                .expect("the temporary directory is valid UTF-8")
        ),
        "the message must name the file the operator has to fix"
    );
}

/// The same for the key, and separately — an operator who mounted one and not
/// the other must be told WHICH.
#[tokio::test]
async fn a_key_path_that_cannot_be_read_is_an_error() {
    let p = pki(SERVED_NAME);
    let cert = TempPem::with(&p.cert_pem);
    let missing = std::env::temp_dir().join("yadgar-iam-no-such-key-6a17d4.pem");
    let tls = configured(cert.path(), &missing);

    let outcome = serve::builder(Some(&tls));
    assert!(
        matches!(outcome, Err(ServeTlsError::Unreadable { .. })),
        "a key path that does not exist must be refused, not served in cleartext"
    );
    assert!(
        outcome
            .err()
            .unwrap()
            .to_string()
            .contains(missing.to_str().unwrap()),
        "the message must name the file the operator has to fix"
    );
}

/// A file that exists and holds no certificate — or a key file holding no key.
/// Neither is a listener. The acceptor is built eagerly in `builder`, so both
/// refuse at boot as an unusable identity naming BOTH files, never as a
/// cleartext server.
///
/// THE PER-FILE PEM CHECK THIS REPOSITORY USED TO RUN IS GONE (B-U5): it was
/// part of the local `ServerTls` copy ADR-0846 deletes. The refusal still names
/// both paths, so the operator is told which pair to look at.
#[tokio::test]
async fn a_certificate_or_key_file_with_nothing_in_it_is_an_error() {
    let p = pki(SERVED_NAME);
    for contents in ["", "   ", "\n", "there is no PEM in this file\n"] {
        for empty_side in ["certificate", "key"] {
            let (cert, key) = if empty_side == "certificate" {
                (TempPem::with(contents), TempPem::with(&p.key_pem))
            } else {
                (TempPem::with(&p.cert_pem), TempPem::with(contents))
            };
            let tls = configured(cert.path(), key.path());
            let outcome = serve::builder(Some(&tls));
            assert!(
                matches!(outcome, Err(ServeTlsError::Unusable { .. })),
                "a serving file with nothing usable in it must be refused at boot"
            );
            let message = outcome.err().unwrap().to_string();
            assert!(
                message.contains(cert.path().to_str().unwrap())
                    && message.contains(key.path().to_str().unwrap()),
                "the refusal must name both serving files"
            );
        }
    }
}

/// THE MISMATCH. Two independent authorities, each with its own leaf: the
/// certificate of one paired with the private key of the other. Both files are
/// individually valid PEM, so nothing short of checking them TOGETHER notices —
/// and a listener whose key does not match its certificate completes no
/// handshake at all.
#[tokio::test]
async fn a_certificate_and_a_key_that_do_not_match_are_an_error() {
    let one = pki(SERVED_NAME);
    let other = pki(SERVED_NAME);
    let cert = TempPem::with(&one.cert_pem);
    let key = TempPem::with(&other.key_pem);
    let tls = configured(cert.path(), key.path());

    let outcome = serve::builder(Some(&tls));
    assert!(
        matches!(outcome, Err(ServeTlsError::Unusable { .. })),
        "a key that does not match the certificate must be refused at boot"
    );
    let message = outcome.err().unwrap().to_string();
    assert!(
        message.contains(cert.path().to_str().unwrap())
            && message.contains(key.path().to_str().unwrap()),
        "the message must name BOTH files, because either could be the wrong one"
    );
}

/// THE REFUSAL ABOVE HAS TO SAY WHAT WAS WRONG, and the case above cannot tell.
///
/// `ServeTlsError::Unusable`'s own `Display` names the two paths and stops; the
/// reason is its `#[source]`, tonic's `transport error`, and one more hop below
/// that, `rustls::Error`'s `keys may not be consistent`. The lifecycle crate
/// keeps the source rather than flattening it, so the BINARY's one flattener
/// (ADR-0591) renders it — `boot::refusal`, which `boot::listener` calls on the
/// builder's error. This case asserts that walk reaches the reason;
/// `tests/boot_message.rs` asserts the binary prints it.
///
/// The assertion is on rustls's deliberate `Display` string and NOT on the
/// `Debug` of its `#[non_exhaustive]` `KeyMismatch` enum, which is the least
/// stable text in the chain.
#[tokio::test]
async fn the_refusal_names_the_reason_rather_than_just_transport_error() {
    let one = pki(SERVED_NAME);
    let other = pki(SERVED_NAME);
    let cert = TempPem::with(&one.cert_pem);
    let key = TempPem::with(&other.key_pem);
    let tls = configured(cert.path(), key.path());

    let Err(err) = serve::builder(Some(&tls)) else {
        panic!("a key that does not match the certificate must be refused at boot");
    };
    let rendered = yadgar_iam::boot::refusal(&err);

    assert!(
        rendered.contains("keys may not be consistent"),
        "the refusal must carry the layer UNDER tonic's `transport error`, which is \
         the only part naming what was wrong"
    );
    assert!(
        !err.to_string().contains("keys may not be consistent"),
        "the head alone does not carry the reason, so the walk above is what reached it"
    );
}

// ── B-U5: the contract — client authentication through THIS service's wiring ──
//
// Every case below goes through `serve::from_lookup`, which reads under
// `serve::LISTEN` and `serve::CHART_KEY` — the two arguments this repository
// hands to `yadgar_lifecycle::serve_tls`. A case that called the lifecycle
// crate with its own literals would re-test that crate and prove nothing about
// what this service passes it. The crate's own matrix (`lifecycle/tests/`)
// covers every mode against every kind of leaf; these cases assert that THIS
// listener is wired to it.
//
// ASSERT MESSAGES ARE STATIC. CodeQL's cleartext-logging query reads an error
// enum carrying Key- and Certificate-named variants as sensitive, so no message
// below interpolates a refusal; the `contains` checks are the proof.

/// The refusal `serve::from_lookup` returns for `vars`, as an operator reads it.
fn refusal(vars: &[(&str, &str)]) -> String {
    let owned: Vec<(String, String)> = vars
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    match serve::from_lookup(move |k| owned.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone())) {
        Ok(_) => panic!("this configuration must refuse the boot"),
        Err(e) => e.to_string(),
    }
}

/// ADR-0854 (X-ADR-1, extending ADR-0845): `LISTEN_TLS_CLIENT_AUTH` has no
/// default. Absent refuses whether TLS is on or off, naming the variable an
/// operator reads in the crash log AND the chart key they edit.
///
/// MUTATION: `serve::CHART_KEY` set to anything but `tls` turns this red on the
/// chart key.
#[test]
fn an_absent_client_auth_refuses_naming_the_variable_and_the_chart_key() {
    for enabled in ["1", "0"] {
        let message = refusal(&[
            ("LISTEN_TLS_ENABLED", enabled),
            ("LISTEN_TLS_CERT_FILE", "/nonexistent/tls.pem"),
            ("LISTEN_TLS_KEY_FILE", "/nonexistent/tls-key.pem"),
        ]);
        assert!(
            message.contains("LISTEN_TLS_CLIENT_AUTH"),
            "an absent client-auth mode must be refused naming LISTEN_TLS_CLIENT_AUTH"
        );
        assert!(
            message.contains("`tls.clientAuth`"),
            "an absent client-auth mode must be refused naming the chart key tls.clientAuth"
        );
    }
}

/// ADR-0845, asserted again at adoption (K-1): the switch itself has no
/// default either, and the lifted type names this chart's key for it.
#[test]
fn an_absent_tls_enabled_refuses_naming_the_variable_and_the_chart_key() {
    let message = refusal(&[("LISTEN_TLS_CLIENT_AUTH", "off")]);
    assert!(
        message.contains("LISTEN_TLS_ENABLED"),
        "an absent switch must be refused naming LISTEN_TLS_ENABLED"
    );
    assert!(
        message.contains("`tls.enabled`"),
        "an absent switch must be refused naming the chart key tls.enabled"
    );
}

/// EXACT and case-sensitive: `Required` or `on` meaning something is how a typo
/// becomes a posture.
#[test]
fn a_client_auth_outside_the_three_values_refuses_by_name() {
    for value in ["Required", "on", "true", "mtls"] {
        let message = refusal(&[
            ("LISTEN_TLS_ENABLED", "0"),
            ("LISTEN_TLS_CLIENT_AUTH", value),
        ]);
        assert!(
            message.contains("LISTEN_TLS_CLIENT_AUTH") && message.contains("`tls.clientAuth`"),
            "an unknown client-auth mode must be refused naming the variable and the chart key"
        );
    }
}

/// A verifying mode with no authority to verify against is a deployment
/// mistake, refused at boot naming the CA variable and the chart key that
/// mounts it — never a listener that accepts every caller.
#[test]
fn a_verifying_mode_without_a_client_ca_refuses_naming_it() {
    for mode in ["optional", "required"] {
        let message = refusal(&[
            ("LISTEN_TLS_ENABLED", "1"),
            ("LISTEN_TLS_CERT_FILE", "/nonexistent/tls.pem"),
            ("LISTEN_TLS_KEY_FILE", "/nonexistent/tls-key.pem"),
            ("LISTEN_TLS_CLIENT_AUTH", mode),
        ]);
        assert!(
            message.contains("LISTEN_TLS_CLIENT_CA_FILE"),
            "a verifying mode with no CA must be refused naming LISTEN_TLS_CLIENT_CA_FILE"
        );
        assert!(
            message.contains("`tls.clientCaSecret`"),
            "a verifying mode with no CA must be refused naming tls.clientCaSecret"
        );
    }
}

/// A client that presents `leaf` (certificate, key) and trusts `ca_pem`.
fn presenting(ca_pem: &str, leaf: &(String, String)) -> ClientTlsConfig {
    trusting(ca_pem, SERVED_NAME).identity(Identity::from_pem(&leaf.0, &leaf.1))
}

/// A listener serving `p`'s leaf, verifying callers in `mode` against `p`'s
/// own authority — one CA issuing both sides, as in the reference deployment.
/// The three files are returned so they outlive the listener's boot.
async fn serve_verifying(p: &Pki, mode: &str) -> (u16, [TempPem; 3]) {
    let cert = TempPem::with(&p.cert_pem);
    let key = TempPem::with(&p.key_pem);
    let ca = TempPem::with(&p.ca_pem);
    let tls = configured_with(cert.path(), key.path(), mode, Some(ca.path()));
    let port = serve(Some(&tls)).await;
    (port, [cert, key, ca])
}

/// `off` is what B-P1 states for every server, and it must keep serving a
/// caller that presents no certificate — the behaviour every hop has today.
#[tokio::test]
async fn off_serves_a_client_presenting_no_certificate() {
    let p = pki(SERVED_NAME);
    let cert = TempPem::with(&p.cert_pem);
    let key = TempPem::with(&p.key_pem);
    let port = serve(Some(&configured_with(cert.path(), key.path(), "off", None))).await;

    assert_eq!(
        reach(port, Some(trusting(&p.ca_pem, SERVED_NAME))).await,
        Ok(())
    );
}

/// THE PROPERTY B-U5 EXISTS FOR (ADR-0852): `required` refuses a caller that
/// presents no certificate, at the request.
///
/// MUTATION: the mode below set to `optional` turns this red — the same
/// listener then serves the caller.
#[tokio::test]
async fn required_refuses_a_client_presenting_no_certificate() {
    let p = pki(SERVED_NAME);
    let (port, _files) = serve_verifying(&p, "required").await;

    assert!(
        reach(port, Some(trusting(&p.ca_pem, SERVED_NAME)))
            .await
            .is_err(),
        "a required listener must refuse a caller that presents no certificate"
    );
}

/// And the other half, so the case above cannot pass because the listener
/// refuses everyone: a caller presenting a leaf the authority signed is served.
#[tokio::test]
async fn required_accepts_a_client_presenting_a_certificate_the_ca_signed() {
    let p = pki(SERVED_NAME);
    let (port, _files) = serve_verifying(&p, "required").await;
    let leaf = client_leaf(&p.ca);

    assert_eq!(
        reach(port, Some(presenting(&p.ca_pem, &leaf))).await,
        Ok(())
    );
}

/// A leaf from an authority this listener does not trust is what an impostor
/// presents, and `required` refuses it.
#[tokio::test]
async fn required_refuses_a_client_certificate_another_authority_signed() {
    let p = pki(SERVED_NAME);
    let (port, _files) = serve_verifying(&p, "required").await;
    let stranger = pki(SERVED_NAME);
    let leaf = client_leaf(&stranger.ca);

    assert!(
        reach(port, Some(presenting(&p.ca_pem, &leaf)))
            .await
            .is_err(),
        "a required listener must refuse a leaf its client CA did not sign"
    );
}

/// `optional` is the staging step between `off` and `required`: a caller with
/// no certificate is still served.
#[tokio::test]
async fn optional_serves_a_client_presenting_no_certificate() {
    let p = pki(SERVED_NAME);
    let (port, _files) = serve_verifying(&p, "optional").await;

    assert_eq!(
        reach(port, Some(trusting(&p.ca_pem, SERVED_NAME))).await,
        Ok(())
    );
}
