//! What actually goes on the wire to the broker, and what happens when it is
//! refused.
//!
//! **Asserting that a credential was CONFIGURED is the check that cannot fail.**
//! It passes identically against a build that reads the Secret and never sends
//! it, and against a broker that demands nothing. So the broker here is a real
//! socket speaking the real NATS protocol: it announces `auth_required`, reads
//! the `CONNECT` line the client sends, and answers `PONG` or
//! `-ERR 'Authorization Violation'` on the strength of what is actually in it.
//!
//! Every test comes in a PAIR against that one server — the credentialled client
//! is served, the credential-less one is REFUSED — because only the pair
//! distinguishes an authenticated broker from an open one.
//!
//! # Why a fake broker rather than a real `nats-server`
//!
//! The shared workflow (`yadgarhq/actions`, `ci-pr.yaml`) supplies MariaDB and a
//! Valkey to every Rust repository and no broker, and this repository cannot add
//! a service to a workflow it does not own. A test that needed one would skip in
//! CI, and a skipped security test is the same green-run-that-measured-nothing
//! these files exist to prevent.
//!
//! What is given up by faking it is worth naming: this proves the client sends
//! the credential and honours a refusal, NOT that a real `nats-server` accepts
//! the password the deployment sets. That second half belongs to the deployment
//! and is in `yadgarhq/deploy`'s MIGRATION_NOTES as a command a person runs.
//! What is NOT given up is the assertion that matters most here — the bytes.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use yadgar_iam::invalidate::{Credentials, Invalidator};

/// Deliberately unlike anything the implementation could contain. A fixture equal
/// to a constant in the code under test would pass for a build that sent its own
/// idea of a password rather than the configured one.
const PASSWORD: &str = "sentinel-of-the-nats-password-4c17";
const USER: &str = "sentinel-user";

fn credentials() -> Credentials {
    Credentials {
        user: USER.to_string(),
        password: PASSWORD.to_string(),
        // WHERE it was read from, which the rotation watch set needs and this
        // file does not exercise: nothing here rotates anything. It is carried
        // because a credential without its provenance cannot be watched — see
        // `Credentials`.
        password_file: std::path::PathBuf::from("/var/run/secrets/nats/password"),
    }
}

/// A socket that speaks enough NATS to accept or refuse ONE client.
///
/// Returns the address to dial and a receiver that yields the `CONNECT` line
/// exactly as it arrived — so a test can assert on the bytes rather than on what
/// this crate believes it put in them.
async fn broker() -> (SocketAddr, oneshot::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("the fake broker binds");
    let addr = listener.local_addr().expect("its address");
    let (tx, rx) = oneshot::channel();

    tokio::spawn(async move {
        let Ok((mut socket, _)) = listener.accept().await else {
            return;
        };
        // `auth_required` is what a real server sets when it has an
        // `authorization` block. Every other field of `ServerInfo` has a serde
        // default, so this is a complete INFO as far as the client is concerned.
        if socket
            .write_all(b"INFO {\"auth_required\":true}\r\n")
            .await
            .is_err()
        {
            return;
        }

        // ONE READ. The client writes `CONNECT {...}\r\nPING\r\n` in a single
        // flush, so both arrive together.
        let mut buf = vec![0u8; 4096];
        let Ok(n) = socket.read(&mut buf).await else {
            return;
        };
        let line = String::from_utf8_lossy(&buf[..n]).to_string();

        // THE DECISION IS MADE ON THE BYTES, which is the whole point of this
        // rig. A client that read the Secret and did not send it lands here
        // indistinguishable from one that was never given a Secret at all — and
        // that is correct, because to a broker those two ARE the same client.
        let authorised = line.contains(&format!("\"user\":\"{USER}\""))
            && line.contains(&format!("\"pass\":\"{PASSWORD}\""));
        let reply: &[u8] = if authorised {
            b"PONG\r\n"
        } else {
            // Verbatim what `nats-server` sends. `async-nats` lowercases and
            // strips the quotes before matching, and maps it to
            // `ConnectErrorKind::AuthorizationViolation`.
            b"-ERR 'Authorization Violation'\r\n"
        };
        let _ = socket.write_all(reply).await;
        let _ = tx.send(line);

        // HELD OPEN. A connection the client established and this task then
        // dropped would look like an immediate disconnect, and the test would be
        // measuring a socket teardown rather than an authorisation decision.
        let mut sink = vec![0u8; 1024];
        while let Ok(n) = socket.read(&mut sink).await {
            if n == 0 {
                return;
            }
        }
    });

    (addr, rx)
}

async fn connect(addr: SocketAddr, credentials: Option<Credentials>) -> Invalidator {
    // A ceiling, so a rig that never answers fails as a test rather than hanging
    // a CI job.
    tokio::time::timeout(
        Duration::from_secs(10),
        Invalidator::connect(Some(&format!("nats://{addr}")), credentials),
    )
    .await
    .expect("the broker answered within the deadline")
}

#[tokio::test]
async fn a_service_with_no_credential_is_refused_by_a_broker_that_demands_one() {
    let (addr, observed) = broker().await;

    // THE HALF THAT CANNOT PASS AGAINST AN OPEN BROKER. A server with no
    // authorization block answers this client and it publishes.
    let inv = connect(addr, None).await;
    assert!(
        !inv.is_publishing(),
        "iam connected to a broker that demands a credential while carrying none. Either the \
         refusal was ignored, or the client fell back to an unauthenticated connection."
    );

    let line = observed.await.expect("the broker saw a CONNECT");
    assert!(
        !line.contains("\"pass\":\"") || line.contains("\"pass\":null"),
        "a connection configured with no credential still put a password on the wire: {line}"
    );
}

#[tokio::test]
async fn the_configured_password_is_what_actually_goes_on_the_wire() {
    let (addr, observed) = broker().await;

    // THE HALF THE MUTATION BITES. Drop the credential on the way into
    // `Invalidator::connect`, or stop it building `ConnectOptions` from the pair,
    // and this goes red — which is what proves the refusal above is about the
    // credential rather than about the rig being broken.
    let inv = connect(addr, Some(credentials())).await;
    assert!(
        inv.is_publishing(),
        "the password iam was configured with was not accepted by the broker that demands it, \
         so it never reached the CONNECT line"
    );

    // THE BYTES, not the configuration. This is the assertion a test that only
    // checked `is_publishing` would be missing: it says the credential in the
    // Secret is the credential on the socket.
    let line = observed.await.expect("the broker saw a CONNECT");
    assert!(
        line.contains(&format!("\"user\":\"{USER}\"")),
        "the configured user never reached the wire: {line}"
    );
    assert!(
        line.contains(&format!("\"pass\":\"{PASSWORD}\"")),
        "the configured password never reached the wire: {line}"
    );
}

#[tokio::test]
async fn a_wrong_password_is_refused_rather_than_silently_accepted() {
    let (addr, _observed) = broker().await;

    let wrong = Credentials {
        user: USER.to_string(),
        password: "not-the-password".to_string(),
        password_file: std::path::PathBuf::from("/var/run/secrets/nats/password"),
    };
    assert!(
        !connect(addr, Some(wrong)).await.is_publishing(),
        "a rejected credential produced a publisher, so a wrong password in the Secret would \
         look exactly like a working deployment"
    );
}

#[tokio::test]
async fn an_unreachable_broker_is_survivable_and_a_refused_one_is_too() {
    // THE AVAILABILITY PROPERTY, unchanged by any of the above: iam is the
    // authentication plane, and neither a broker outage nor a broker that
    // refuses this service may stop it authenticating. Both end in a publisher
    // that publishes nothing rather than in a process that will not run. They
    // are told apart in the LOG, which is where an operator can act on the
    // difference.
    let inv = Invalidator::connect(Some("nats://127.0.0.1:1"), Some(credentials())).await;
    assert!(!inv.is_publishing());
    inv.credential_revoked("yadgar:user:z").await;
    inv.teams_changed("yadgar:user:z").await;
}
