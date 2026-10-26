//! The caller gate proved through tonic: a real listener, real handshakes, a
//! real `Iam` behind them (ADR-0972 (1), ledger 1629).
//!
//! **WHAT THE `_as` LOOPS IN [`super::gate`] CANNOT SHOW** is that the peer
//! chain a verifying listener accepted actually reaches the handler — that
//! `caller_common_name` reads, in production, the leaf the client presented.
//! Only a handshake can show that, so each case here stands the listener up
//! through [`crate::serve::builder`], exactly as `main` does, and dials it.
//!
//! **HERE AND NOT IN `tests/serve_tls.rs`**, which is where the plan put it.
//! An `Iam` needs `Keys`, and the only fixture for them is the crate-private
//! `crypto::tests::keys()`; an integration test cannot reach it, and a public
//! test constructor would be a second way to build an `Iam` that nothing in
//! production uses. The fake twin is this module's parent's, too.
//!
//! The leaf names are the real ones `platform` issues: `gateway-caller` and
//! `task-caller`, both under one authority, so both verify at the handshake.

use std::io::Write as _;
use std::path::PathBuf;

use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Certificate, ClientTlsConfig, Identity};

use super::*;
use crate::pb::yadgar::iam::v1::iam_service_client::IamServiceClient;
use crate::pb::yadgar::iam::v1::iam_service_server::IamServiceServer;

/// The name the serving leaf is issued for. The client dials an IP and
/// verifies this name, so nothing depends on how `localhost` resolves.
pub(super) const SERVED_NAME: &str = "localhost";

/// One authority, the serving leaf it issued, and the means to issue more.
pub(super) struct Pki {
    ca: CertifiedIssuer<'static, KeyPair>,
    pub(super) ca_pem: String,
    cert_pem: String,
    key_pem: String,
}

pub(super) fn pki() -> Pki {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "yadgar-iam gate test authority");
    let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();

    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec![SERVED_NAME.to_string()]).unwrap();
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params
        .distinguished_name
        .push(DnType::CommonName, SERVED_NAME);
    let cert = params.signed_by(&key, &ca).unwrap();
    Pki {
        ca_pem: ca.pem(),
        ca,
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
    }
}

/// A client leaf the authority issued, with common name `name`.
pub(super) fn leaf(p: &Pki, name: &str) -> Identity {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec![name.to_string()]).unwrap();
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    params.distinguished_name.push(DnType::CommonName, name);
    let cert = params.signed_by(&key, &p.ca).unwrap();
    Identity::from_pem(cert.pem(), key.serialize_pem())
}

/// A file that deletes itself. `ServerTls` takes paths, as a deployment
/// mounts them.
struct TempPem(PathBuf);

impl TempPem {
    fn with(contents: &str) -> Self {
        let path = std::env::temp_dir().join(format!("iam-gate-{}.pem", uuid::Uuid::now_v7()));
        let mut file = std::fs::File::options()
            .write(true)
            .create_new(true)
            .open(&path)
            .expect("a fresh temporary file");
        file.write_all(contents.as_bytes()).unwrap();
        Self(path)
    }
}

impl Drop for TempPem {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// The chart's `server.limits` defaults (ADR-1006), through the same lookup a
/// deployment's environment goes through.
fn limits() -> crate::serve::ServerLimits {
    crate::serve::limits_from_lookup(|key| {
        match key {
            "LISTEN_MAX_CONCURRENT_STREAMS" => Some("256"),
            "LISTEN_KEEPALIVE_INTERVAL_SECS" => Some("30"),
            "LISTEN_KEEPALIVE_TIMEOUT_SECS" => Some("10"),
            "LISTEN_MAX_HEADER_LIST_BYTES" => Some("16384"),
            _ => None,
        }
        .map(str::to_string)
    })
    .expect("the chart defaults are a complete, in-range configuration")
}

/// Serve an `Iam` over TLS in client-auth `mode`, verifying callers against
/// `p`'s authority, and return the port. The files outlive the boot only;
/// `serve::builder` reads them once.
async fn serve_iam(p: &Pki, mode: &str) -> u16 {
    let (iam, _rec, _inv) = iam_with(FakeDb {
        resolves_to: Some("yadgar:user:1".into()),
        ..Default::default()
    })
    .await;
    serve_iam_with(p, mode, iam).await
}

/// [`serve_iam`] serving `iam` as given: the same TLS listener and gate, in
/// front of whatever twin and floors the caller built it with.
pub(super) async fn serve_iam_with(p: &Pki, mode: &str, iam: Iam) -> u16 {
    let cert = TempPem::with(&p.cert_pem);
    let key = TempPem::with(&p.key_pem);
    let ca = TempPem::with(&p.ca_pem);
    let vars: Vec<(&str, String)> = vec![
        ("LISTEN_TLS_ENABLED", "1".into()),
        ("LISTEN_TLS_CERT_FILE", cert.0.display().to_string()),
        ("LISTEN_TLS_KEY_FILE", key.0.display().to_string()),
        ("LISTEN_TLS_CLIENT_AUTH", mode.into()),
        ("LISTEN_TLS_CLIENT_CA_FILE", ca.0.display().to_string()),
    ];
    let tls = crate::serve::from_lookup(move |k| {
        vars.iter().find(|(n, _)| *n == k).map(|(_, v)| v.clone())
    })
    .expect("a complete configuration")
    .expect("the TLS path");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let router = crate::serve::builder(Some(&tls), &limits())
        .expect("a usable certificate and key")
        .add_service(IamServiceServer::new(iam));
    tokio::spawn(async move {
        let _ = router
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await;
    });
    port
}

/// Dial `port` presenting `identity`, and ask `ResolveCredential` once.
async fn resolve(p: &Pki, port: u16, identity: Option<Identity>) -> Result<(), tonic::Code> {
    let mut tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(&p.ca_pem))
        .domain_name(SERVED_NAME);
    if let Some(identity) = identity {
        tls = tls.identity(identity);
    }
    let channel = Endpoint::from_shared(format!("https://127.0.0.1:{port}"))
        .unwrap()
        .connect_timeout(Duration::from_secs(5))
        .tls_config(tls)
        .unwrap()
        .connect_lazy();
    let answered = tokio::time::timeout(
        Duration::from_secs(10),
        IamServiceClient::new(channel).resolve_credential(ResolveCredentialRequest {
            token: "a-bearer-token".into(),
        }),
    )
    .await
    .expect("the call answered in time");
    answered.map(drop).map_err(|s| s.code())
}

/// A real `task-caller` leaf verifies at the handshake and is refused by the
/// gate — the probe Max runs against the live estate after the roll.
#[tokio::test]
async fn a_task_caller_leaf_is_refused_through_tonic() {
    let p = pki();
    let port = serve_iam(&p, "required").await;
    assert_eq!(
        resolve(&p, port, Some(leaf(&p, "task-caller"))).await,
        Err(tonic::Code::PermissionDenied)
    );
}

/// THE POSITIVE CONTROL: the gateway's leaf, through the same listener, is
/// admitted. Without it the case above passes for a gate that refuses all.
#[tokio::test]
async fn the_gateway_caller_leaf_is_admitted_through_tonic() {
    let p = pki();
    let port = serve_iam(&p, "required").await;
    assert_eq!(
        resolve(&p, port, Some(leaf(&p, GATEWAY_CALLER))).await,
        Ok(())
    );
}

/// `clientAuth: "off"` requests no certificate, so no name reaches the
/// handler — even from a client holding the gateway's leaf — and the gate
/// refuses (ADR-0972 Q3). This is why K1 makes the charts refuse `"off"`.
#[tokio::test]
async fn an_off_listener_refuses_even_the_gateway_leaf() {
    let p = pki();
    let port = serve_iam(&p, "off").await;
    assert_eq!(
        resolve(&p, port, Some(leaf(&p, GATEWAY_CALLER))).await,
        Err(tonic::Code::PermissionDenied)
    );
}

/// Dial `port` presenting `identity`, and ask `SyncTeams` once with the
/// seeder's principal.
async fn sync(p: &Pki, port: u16, identity: Option<Identity>) -> Result<(), tonic::Code> {
    let mut tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(&p.ca_pem))
        .domain_name(SERVED_NAME);
    if let Some(identity) = identity {
        tls = tls.identity(identity);
    }
    let channel = Endpoint::from_shared(format!("https://127.0.0.1:{port}"))
        .unwrap()
        .connect_timeout(Duration::from_secs(5))
        .tls_config(tls)
        .unwrap()
        .connect_lazy();
    let answered = tokio::time::timeout(
        Duration::from_secs(10),
        IamServiceClient::new(channel).sync_teams(SyncTeamsRequest {
            scope: Some(crate::pb::yadgar::common::v1::Scope {
                user_id: "yadgar:system:seeder".into(),
                ..Default::default()
            }),
            teams: vec![],
        }),
    )
    .await
    .expect("the call answered in time");
    answered.map(drop).map_err(|s| s.code())
}

/// TEAM ACCESS STAGE 3, GATE ITEM 2: the seeder's client chain reaches the
/// `SyncTeams` handler through `serve_tls` with a client CA set. The gate
/// admits only a parsed leaf naming exactly `seeder-caller`, so an `Ok` here
/// is `peer_certs()` returning `Some` with that leaf, read in the handler.
#[tokio::test]
async fn the_seeder_caller_leaf_reaches_sync_teams_through_tonic() {
    let p = pki();
    let port = serve_iam(&p, "required").await;
    assert_eq!(
        sync(&p, port, Some(leaf(&p, "seeder-caller"))).await,
        Ok(())
    );
}

/// The gateway's leaf, verified at the same handshake, is refused on
/// `SyncTeams`: the one verb it may not call.
#[tokio::test]
async fn the_gateway_leaf_is_refused_on_sync_teams_through_tonic() {
    let p = pki();
    let port = serve_iam(&p, "required").await;
    assert_eq!(
        sync(&p, port, Some(leaf(&p, GATEWAY_CALLER))).await,
        Err(tonic::Code::PermissionDenied)
    );
}

/// A client with no leaf is never admitted: the `required` listener fails
/// the handshake, and an `optional` one hands the handler no name.
#[tokio::test]
async fn a_client_with_no_leaf_is_never_admitted_to_sync_teams() {
    let p = pki();
    let port = serve_iam(&p, "required").await;
    assert!(sync(&p, port, None).await.is_err(), "required: refused");
    let port = serve_iam(&p, "optional").await;
    assert_eq!(
        sync(&p, port, None).await,
        Err(tonic::Code::PermissionDenied),
        "optional: no name, refused by the gate"
    );
}
