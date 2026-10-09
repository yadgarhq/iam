//! B-N3 (ledger 925, ADR-0852): the broker hop over TLS, against a REAL
//! nats-server rather than a configuration inspected in-process.
//!
//! **THE TWIN OF `gateway`'s OWN `tests/nats_tls.rs` (gateway#105, bb3ce96).**
//! The `Authority`/`Dir`/`Server` fixtures below are copied from it rather
//! than re-derived — the measurements that got the docker invocation, the
//! readiness wait and the five refusal alerts right took that PR several
//! rounds, and a second derivation risks getting one of them wrong in a new
//! way. What differs is `broker()`, which goes through THIS service's own
//! wiring — `yadgar_iam::invalidate::transport::broker_tls` and
//! `Invalidator::connect`, never `Broker::from_lookup` — and the oracle each
//! case reads, `Invalidator::is_publishing()` rather than
//! `invalidate::start`.
//!
//! **WHY A CONTAINER, AND WHY THIS TEST STARTS IT.** The property under test
//! is what a TLS verifier DOES with the material this service hands it, and
//! only a handshake shows that. A certificate minted per run does not exist
//! before the first step, and nats-server reads its certificate once at
//! startup — so each case mints its own authority with rcgen, writes it to a
//! fresh directory, and starts `nats-server` with `docker run -d -v
//! <dir>:/certs:ro` (the mechanism B-N0 measured). The image is the one the
//! platform chart vendors, pinned by digest (D61).
//!
//! **IT FAILS RATHER THAN SKIPS WITHOUT DOCKER.** A suite that turns green on
//! a machine that cannot run it is coverage that is not there.
//!
//! **EVERY CONTAINER IS REMOVED ON DROP**, including on a panic, and every
//! name is unique per run.
//!
//! **WHAT EACH CASE KILLS.** `require_tls` is killed only by the cleartext
//! broker case: against a TLS broker async-nats upgrades whenever the SERVER
//! asks, so every other case stays green without it. `add_root_certificates`
//! is killed by the accepting case (no root, no trust).
//! `add_client_certificate` is killed by the accepting case too, because the
//! server runs `--tlsverify`.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType,
};
use yadgar_iam::invalidate::{transport, Invalidator};
use yadgar_iam::upstream;

/// The image `yadgarhq/platform` vendors (`nats-2.14.6.tgz`), by index digest
/// — the SAME one `gateway`'s own suite pins.
const IMAGE: &str =
    "nats:2.14.6-alpine@sha256:ad7a43eb7e3337c3c38ce5d784d1461791f95f730f252d2b25eee699752a0ca3";

/// How long a container may take to print `Server is ready`.
const READY: Duration = Duration::from_secs(60);

static SEQUENCE: AtomicU32 = AtomicU32::new(0);

fn unique(label: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("a clock after 1970")
        .as_nanos();
    format!(
        "iam-nats-tls-{label}-{}-{nanos}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    )
}

/// An authority, and the PEM of what it signs.
struct Authority {
    issuer: CertifiedIssuer<'static, KeyPair>,
}

impl Authority {
    fn new(name: &str) -> Self {
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.distinguished_name.push(DnType::CommonName, name);
        let issuer = CertifiedIssuer::self_signed(params, KeyPair::generate().expect("a key"))
            .expect("a self-signed authority");
        Self { issuer }
    }

    fn pem(&self) -> String {
        self.issuer.pem()
    }

    /// The broker's serving leaf. `localhost` AND `127.0.0.1`, because the
    /// client dials `nats://localhost:<port>` and verifies that name.
    fn server_leaf(&self) -> (String, String) {
        let key = KeyPair::generate().expect("a key");
        let mut params = CertificateParams::new(vec!["localhost".to_string()]).expect("params");
        params
            .subject_alt_names
            .push(SanType::IpAddress([127, 0, 0, 1].into()));
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.distinguished_name.push(DnType::CommonName, "nats");
        let cert = params.signed_by(&key, &self.issuer).expect("a server leaf");
        (cert.pem(), key.serialize_pem())
    }

    /// A client leaf, as cert-manager issues `iam-client-tls`.
    fn client_leaf(&self) -> (String, String) {
        let key = KeyPair::generate().expect("a key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params.distinguished_name.push(DnType::CommonName, "iam");
        let cert = params.signed_by(&key, &self.issuer).expect("a client leaf");
        (cert.pem(), key.serialize_pem())
    }
}

/// A directory of PEM files, deleted on drop.
struct Dir(PathBuf);

impl Dir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(unique("certs"));
        std::fs::create_dir_all(&path).expect("the certificate directory");
        Self(path)
    }

    fn write(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, contents).expect("a PEM file");
        path
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// One `nats-server` in a container, removed on drop.
struct Server {
    name: String,
    port: u16,
}

impl Server {
    /// `tls: None` serves cleartext. `Some(dir)` serves TLS from
    /// `dir/server.pem`, `dir/server-key.pem`, and VERIFIES clients against
    /// `dir/ca.pem` (`--tlsverify`, as B-N5 will run the platform broker).
    fn start(tls: Option<&Dir>) -> Self {
        let name = unique("server");
        let mut command = Command::new("docker");
        command.args(["run", "-d", "--name", &name, "-p", "127.0.0.1::4222"]);
        if let Some(dir) = tls {
            command.args(["-v", &format!("{}:/certs:ro", dir.0.display())]);
        }
        command.args([IMAGE, "-p", "4222"]);
        if tls.is_some() {
            command.args([
                "--tlsverify",
                "--tlscert=/certs/server.pem",
                "--tlskey=/certs/server-key.pem",
                "--tlscacert=/certs/ca.pem",
            ]);
        }
        let out = command.output().unwrap_or_else(|e| {
            panic!(
                "docker could not be run ({e}). This suite stands a real nats-server up and \
                 FAILS rather than skips without one; install docker or run it where docker is."
            )
        });
        // Constructed before the status check, so a container that started
        // and then failed to report is still removed.
        let mut server = Self { name, port: 0 };
        assert!(
            out.status.success(),
            "docker run failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        server.port = server.published_port();
        server.wait_until_ready();
        server
    }

    fn published_port(&self) -> u16 {
        let out = Command::new("docker")
            .args(["port", &self.name, "4222/tcp"])
            .output()
            .expect("docker port");
        let text = String::from_utf8_lossy(&out.stdout);
        let line = text.lines().next().unwrap_or_default();
        line.rsplit(':')
            .next()
            .and_then(|p| p.trim().parse().ok())
            .unwrap_or_else(|| panic!("no published port in {text:?}"))
    }

    fn wait_until_ready(&self) {
        let deadline = Instant::now() + READY;
        loop {
            let out = Command::new("docker")
                .args(["logs", &self.name])
                .output()
                .expect("docker logs");
            let log = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            if log.contains("Server is ready") {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "nats-server never became ready:\n{log}"
            );
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    fn url(&self) -> String {
        format!("nats://localhost:{}", self.port)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.name])
            .output();
    }
}

/// The broker's transport as `main` resolves it: through
/// `transport::broker_tls`, from the same `NATS_TLS_*` variables the chart
/// renders — NEVER a sentinel `UpstreamTls` built by hand, which would prove
/// only that this test's own idea of the configuration connects.
fn broker_tls(ca: &Path, identity: Option<(&Path, &Path)>) -> upstream::UpstreamTls {
    let mut vars = vec![
        ("NATS_TLS_ENABLED".to_string(), "1".to_string()),
        ("NATS_TLS_CA_FILE".to_string(), ca.display().to_string()),
    ];
    if let Some((cert, key)) = identity {
        vars.push((
            "NATS_TLS_CLIENT_CERT_FILE".to_string(),
            cert.display().to_string(),
        ));
        vars.push((
            "NATS_TLS_CLIENT_KEY_FILE".to_string(),
            key.display().to_string(),
        ));
    }
    let lookup = move |k: &str| vars.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
    transport::broker_tls(&lookup)
        .expect("a complete TLS configuration")
        .expect("the flag is set")
}

/// The platform's authority, the broker's leaf and iam's own leaf, as
/// cert-manager issues all three from `yadgar-internal-ca`.
struct Estate {
    dir: Dir,
    ca: PathBuf,
    client: PathBuf,
    client_key: PathBuf,
}

fn estate() -> Estate {
    let authority = Authority::new("yadgar-iam nats test authority");
    let dir = Dir::new();
    let ca = dir.write("ca.pem", &authority.pem());
    let (server, server_key) = authority.server_leaf();
    dir.write("server.pem", &server);
    dir.write("server-key.pem", &server_key);
    let (client, client_key) = authority.client_leaf();
    let client = dir.write("client.pem", &client);
    let client_key = dir.write("client-key.pem", &client_key);
    Estate {
        dir,
        ca,
        client,
        client_key,
    }
}

#[tokio::test]
async fn a_verifying_broker_accepts_iams_leaf_and_iam_publishes() {
    let estate = estate();
    let server = Server::start(Some(&estate.dir));
    let tls = broker_tls(&estate.ca, Some((&estate.client, &estate.client_key)));

    // THE SAME CONFIGURATION THROUGH THE PRODUCTION PATH:
    // `Invalidator::connect` dials, and `is_publishing` answers whether this
    // replica holds a live connection.
    let invalidator = Invalidator::connect(Some(&server.url()), None, Some(tls)).await;
    assert!(
        invalidator.is_publishing(),
        "a TLS broker that verified iam's leaf must leave this replica publishing"
    );
}

#[tokio::test]
async fn a_verifying_broker_refuses_iam_presenting_no_leaf() {
    let estate = estate();
    let server = Server::start(Some(&estate.dir));
    let tls = broker_tls(&estate.ca, None);

    let invalidator = Invalidator::connect(Some(&server.url()), None, Some(tls)).await;
    assert!(
        !invalidator.is_publishing(),
        "--tlsverify refuses a client with no certificate"
    );
}

#[tokio::test]
async fn a_verifying_broker_refuses_a_leaf_from_a_foreign_authority() {
    // THE CI TWIN OF THE B-N5 PROBE: a leaf that is well-formed, unexpired
    // and carries ClientAuth, from an authority the broker does not trust.
    let estate = estate();
    let server = Server::start(Some(&estate.dir));
    let (foreign, foreign_key) = Authority::new("a foreign authority").client_leaf();
    let foreign = estate.dir.write("foreign.pem", &foreign);
    let foreign_key = estate.dir.write("foreign-key.pem", &foreign_key);
    let tls = broker_tls(&estate.ca, Some((&foreign, &foreign_key)));

    let invalidator = Invalidator::connect(Some(&server.url()), None, Some(tls)).await;
    assert!(
        !invalidator.is_publishing(),
        "a foreign leaf must be refused by the broker"
    );
}

#[tokio::test]
async fn a_broker_signed_by_another_authority_is_refused_by_iam() {
    // CLIENT-SIDE VERIFICATION, with a trust store of ONE file: the broker's
    // leaf chains to `ca.pem`, and iam is handed a different authority. No
    // platform or public root may rescue the handshake.
    let estate = estate();
    let server = Server::start(Some(&estate.dir));
    let wrong = estate
        .dir
        .write("wrong-ca.pem", &Authority::new("the wrong authority").pem());
    let tls = broker_tls(&wrong, Some((&estate.client, &estate.client_key)));

    let invalidator = Invalidator::connect(Some(&server.url()), None, Some(tls)).await;
    assert!(
        !invalidator.is_publishing(),
        "a broker iam cannot verify must be refused client-side"
    );
}

#[tokio::test]
async fn tls_on_against_a_cleartext_broker_is_refused_rather_than_downgraded() {
    // THE ONLY CASE THAT KILLS A DROPPED `require_tls`. A cleartext server
    // never asks for TLS, so without it async-nats would happily connect in
    // the clear while the configuration says otherwise.
    let estate = estate();
    let server = Server::start(None);
    let tls = broker_tls(&estate.ca, Some((&estate.client, &estate.client_key)));

    let invalidator = Invalidator::connect(Some(&server.url()), None, Some(tls)).await;
    assert!(
        !invalidator.is_publishing(),
        "NATS_TLS_ENABLED=1 must never dial a broker in cleartext"
    );
}
