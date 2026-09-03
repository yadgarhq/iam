//! What happens when the broker REFUSES a publish, which is the failure this
//! service cannot see by itself.
//!
//! **`Client::publish` returns `Ok(())` for a publish the broker throws away.**
//! It resolves when the command is queued locally and NATS acknowledges no
//! `PUB`, so the refusal arrives afterwards, asynchronously, on a connection the
//! broker deliberately leaves OPEN. The `Err` arm in `Invalidator::publish`
//! never runs. Without an event callback the only record of it is a `debug!`
//! inside `async-nats`, below the `info` these pods run at.
//!
//! So the property under test is not "does publish fail" — it cannot — but
//! **"does the broker's own `-ERR` text reach an operator's log, AT ERROR, with
//! the remedy beside it"**.
//!
//! **`async-nats` 0.50 already prints something, and that is exactly why the
//! assertions are shaped the way they are.** `lib.rs:1105` logs EVERY event —
//! this one included, with the broker's text — at `info!`, and the connection
//! handler logs it again at `debug!`. Neither is at ERROR, and neither says what
//! to fix. So a test that merely looked for the broker's words would pass
//! against a build with no callback at all; it was measured doing exactly that
//! twice while this file was being written. The line is therefore identified by
//! something only `invalidate::on_event` can produce — the SECOND subject, which
//! the broker never mentioned — and only then checked for its level. Both
//! halves are asserted, because either one alone passes
//! against a build that is broken in the way that matters: a callback that
//! logged at `debug!` would satisfy the text and vanish in production, and a
//! hard-coded ERROR line would satisfy the level while saying nothing about what
//! the broker actually refused.
//!
//! # Why a fake broker rather than a real `nats-server`
//!
//! The same reason `tests/nats_auth.rs` gives, and this file extends that rig's
//! shape: the shared workflow supplies no broker, and a test that needed one
//! would skip in CI. What is proved here is that a `-ERR` on an established
//! connection is carried, verbatim, to an ERROR log naming the remedy. What is
//! NOT proved is that a real `nats-server` emits that exact frame for a publish
//! violation — that half belongs to `yadgarhq/deploy` and to a person running a
//! command against a real broker.

use std::io::Write;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use yadgar_iam::invalidate::{subject, Credentials, Invalidator};

/// Deliberately unlike anything the implementation could contain, and carried
/// only by the BROKER's `-ERR` frame.
///
/// This is what separates "the callback forwarded what the broker said" from
/// "the code printed a sentence it already knew". A canned ERROR line naming the
/// subjects would pass an assertion on the subject names; nothing but a real
/// forward can produce this.
///
/// Lowercase on purpose. `async_nats::ServerError::new` lowercases the frame to
/// decide whether it is an authorization violation, and preserves the original
/// case for everything else — a lowercase sentinel is therefore unaffected by a
/// future version that stops preserving it.
const SENTINEL: &str = "sentinel-refusal-4c17";

const PASSWORD: &str = "sentinel-of-the-nats-password-4c17";
const USER: &str = "sentinel-user";

fn credentials() -> Credentials {
    Credentials {
        user: USER.to_string(),
        password: PASSWORD.to_string(),
        password_file: std::path::PathBuf::from("/var/run/secrets/nats/password"),
    }
}

/// Everything this process logged, as bytes.
///
/// A global subscriber rather than `with_default`: the callback runs on a task
/// `async-nats` spawns, and `with_default` is THREAD-LOCAL — it would capture
/// nothing and the test would fail for a reason unrelated to the code. This file
/// holds exactly one test so that the one-shot global installation is
/// unambiguous.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Captured {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().expect("the capture buffer")).to_string()
    }
}

impl Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .expect("the capture buffer")
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// A socket that authenticates one client and then refuses its publish.
///
/// The `-ERR` is written AFTER the `PONG`, which is the whole point: a frame
/// sent during the handshake becomes a `ConnectError` and is already reported.
/// This one lands on an established connection, where nothing reports it.
async fn refusing_broker() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("the fake broker binds");
    let addr = listener.local_addr().expect("its address");

    tokio::spawn(async move {
        let Ok((mut socket, _)) = listener.accept().await else {
            return;
        };
        if socket
            .write_all(b"INFO {\"auth_required\":true}\r\n")
            .await
            .is_err()
        {
            return;
        }
        // ONE READ: the client writes `CONNECT {...}\r\nPING\r\n` in a single
        // flush.
        let mut buf = vec![0u8; 4096];
        if socket.read(&mut buf).await.is_err() {
            return;
        }
        if socket.write_all(b"PONG\r\n").await.is_err() {
            return;
        }

        // THE REFUSAL, on an open connection, in the shape `nats-server` uses
        // for a publish permission violation — plus a sentinel no code in this
        // crate could produce.
        // THE WORDING IS `Publish`, which is what a real `nats-server` 2.14.6
        // sends on this side; the gateway's subscribe side says `Subscription`.
        // Nothing under test depends on either word — `on_event` discriminates
        // on the SUBJECT — and this says `Publish` so the fixture is not quietly
        // teaching a future reader the wrong frame.
        let refusal = format!(
            "-ERR 'Permissions Violation for Publish to \"{}\" [{SENTINEL}]'\r\n",
            subject::CREDENTIAL_REVOKED
        );
        let _ = socket.write_all(refusal.as_bytes()).await;

        // HELD OPEN, exactly as a real broker holds it. A socket dropped here
        // would make this a disconnect test rather than a refusal one.
        let mut sink = vec![0u8; 1024];
        while let Ok(n) = socket.read(&mut sink).await {
            if n == 0 {
                return;
            }
        }
    });

    addr
}

#[tokio::test]
async fn a_refused_publish_reaches_the_log_at_error_with_the_brokers_own_words() {
    let logs = Captured::default();
    // INFO, WHICH IS WHAT THE PODS RUN AT. It drops `async-nats`'s `debug!` copy
    // of the frame; its `info!` copy (lib.rs:1105) survives, which is what the
    // subject discriminator below exists to see past.
    tracing_subscriber::fmt()
        .with_writer(logs.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::INFO)
        .init();

    let addr = refusing_broker().await;
    let inv = tokio::time::timeout(
        Duration::from_secs(10),
        Invalidator::connect(Some(&format!("nats://{addr}")), Some(credentials())),
    )
    .await
    .expect("the broker answered within the deadline");

    // THE CONNECTION SUCCEEDS. That is the premise, not an aside: a refusal that
    // failed the dial would already be reported by the `AuthorizationViolation`
    // arm, and this whole file would be testing a case that cannot happen.
    assert!(
        inv.is_publishing(),
        "the broker accepted this credential, so the refusal under test is about the \
         PUBLISH rather than about the connection"
    );

    // AND THE PUBLISH REPORTS NOTHING. `publish` resolves on a local queue and
    // NATS acknowledges no `PUB`, so this returns exactly as it would against a
    // broker that delivered the message. It is the reason the callback has to
    // exist at all.
    inv.credential_revoked("yadgar:user:refused").await;

    // The `-ERR` is asynchronous by nature, so this waits for it rather than
    // assuming it has arrived. A bound, so a broken build fails as a test rather
    // than hanging CI.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !logs.text().contains(SENTINEL) && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let text = logs.text();
    // THE DISCRIMINATOR, and the reason it is the second subject. The broker's
    // frame named only `CREDENTIAL_REVOKED`, and `async-nats`'s own `info!` copy
    // of it therefore cannot mention `TEAMS_CHANGED`. A line carrying the
    // broker's sentinel AND a subject the broker never sent can only have been
    // assembled by `invalidate::on_event`. Matching on the sentinel alone finds
    // `async-nats`'s line and passes with no callback installed — measured.
    let line = text
        .lines()
        .find(|l| l.contains(SENTINEL) && l.contains(subject::TEAMS_CHANGED))
        .unwrap_or_else(|| {
            panic!(
                "the broker refused this service's publish and nothing in this process's own \
                 log says so, so a wrong publish allow-list would make every revocation late \
                 and silent. Captured:\n{text}"
            )
        });

    // IT CARRIES WHAT THE BROKER ACTUALLY SAID, rather than a sentence this
    // crate already knew. Implied by the search above and asserted anyway, so
    // that a later edit to the search cannot quietly drop it.
    assert!(
        line.contains(SENTINEL),
        "the log line does not carry the broker's own words: {line}"
    );

    // AND IT NAMES THE OTHER HALF OF THE REMEDY. Both subjects are on the allow
    // list an operator has to fix; naming only the refused one sends them to
    // half of it.
    assert!(
        line.contains(subject::CREDENTIAL_REVOKED),
        "the refusal does not name the subject that was refused: {line}"
    );

    // THE LEVEL IS THE HALF `async-nats` DOES NOT GIVE. Its own copy of this
    // event goes out at `info!` — indistinguishable, in a log these pods ship at
    // `info`, from the ordinary connection chatter beside it. ERROR is what
    // makes it findable, and a callback that logged at any lower level would
    // leave the failure exactly as invisible as it was.
    assert!(
        line.contains("ERROR"),
        "the refusal was logged below ERROR, so it reads as ordinary broker chatter: {line}"
    );
}
