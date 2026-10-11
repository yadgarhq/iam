//! The `PUBLISHING` gauge's transitions (ledger 1424), proved against real
//! sockets rather than by calling [`connected`]/[`refused`]/[`on_event`]
//! directly — a case that only called them would pass for an implementation
//! that never wired the gauge set into the call sites that matter.
//!
//! **A CUSTOM RECORDER, NOT `metrics_util::debugging::DebuggingRecorder`.**
//! Its `Snapshotter::snapshot` reads a gauge with
//! `g.swap(0, Ordering::SeqCst)` (`metrics-util` 0.20.4's `debugging.rs`) —
//! every READ also resets the stored value to `0`. Measured directly: two
//! snapshots taken back to back with no write between them read `Gauge(1.0)`
//! and then `Gauge(0.0)`. `gateway`'s own `tests/credential_invalidation.rs`
//! warns that a snapshot "DRAINS the registry" and takes exactly one,
//! at the end of each case; that shape cannot prove a MIDDLE state —
//! `before_disconnect, during, after_reconnect` — without the drain itself
//! manufacturing the very zero a case is trying to observe. [`GaugeLog`]
//! below is a `Recorder` that keeps a plain, growing `Vec<f64>` of every
//! value this gauge's name was `set` to, in order, so reading the log never
//! changes it.
//!
//! **A LOCAL RECORDER, NEVER `install()`**, for the reason `gateway`'s test
//! gives: a global one is process-wide and this binary's tests run in
//! parallel. Plain `#[tokio::test]` builds a CURRENT-THREAD runtime, so the
//! redial `tokio::spawn`s and `async-nats`'s own connection task are all
//! polled on the one thread the recorder guard covers.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use metrics::{Key, KeyName, Metadata, Recorder, SharedString, Unit};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::*;
use crate::invalidate::Invalidator;

/// A LITERAL, never [`PUBLISHING`] (ADR-0599): a series name asserted through
/// the constant that produced it passes straight through a rename, and a
/// renamed metric is the one change where every consumer still compiles while
/// the dashboard querying the old name goes blank.
const PUBLISHING_GAUGE: &str = "yadgar_iam_invalidation_publishing";

/// Every value `PUBLISHING_GAUGE` was `set` to, in order, non-destructively —
/// see the module doc for why this exists instead of a `DebuggingRecorder`
/// snapshot.
#[derive(Clone, Default)]
struct GaugeLog(Arc<Mutex<Vec<f64>>>);

impl GaugeLog {
    /// Every value logged so far. A clone of the inner `Vec`, so reading it
    /// does not race a write landing mid-read the way inspecting the `Mutex`
    /// by reference would invite.
    fn values(&self) -> Vec<f64> {
        self.0.lock().expect("the gauge log").clone()
    }
}

impl Recorder for GaugeLog {
    fn describe_counter(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
    fn describe_gauge(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
    fn describe_histogram(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}

    fn register_counter(&self, _: &Key, _: &Metadata<'_>) -> metrics::Counter {
        metrics::Counter::noop()
    }

    // ONLY THIS GAUGE'S NAME GETS A LOGGING HANDLE. Any other gauge this
    // process ever registers (there are none today) gets a no-op, so this
    // recorder cannot silently start asserting on the wrong series if one is
    // added beside it later.
    fn register_gauge(&self, key: &Key, _: &Metadata<'_>) -> metrics::Gauge {
        if key.name() == PUBLISHING_GAUGE {
            metrics::Gauge::from_arc(Arc::new(self.clone()))
        } else {
            metrics::Gauge::noop()
        }
    }

    fn register_histogram(&self, _: &Key, _: &Metadata<'_>) -> metrics::Histogram {
        metrics::Histogram::noop()
    }
}

/// `increment`/`decrement` are not this gauge's vocabulary (every call site
/// in `redial` uses `set`), so they panic rather than silently log a value
/// nothing in `redial` ever produces.
impl metrics::GaugeFn for GaugeLog {
    fn increment(&self, value: f64) {
        panic!("{PUBLISHING_GAUGE} was incremented by {value}; `redial` only ever calls `set`");
    }

    fn decrement(&self, value: f64) {
        panic!("{PUBLISHING_GAUGE} was decremented by {value}; `redial` only ever calls `set`");
    }

    fn set(&self, value: f64) {
        self.0.lock().expect("the gauge log").push(value);
    }
}

/// Poll `check` until it is `true`, or panic on `deadline` naming `what`.
async fn until(what: &str, deadline: Duration, mut check: impl FnMut() -> bool) {
    let started = Instant::now();
    loop {
        if check() {
            return;
        }
        assert!(
            started.elapsed() <= deadline,
            "waited {deadline:?} for {what}; it never happened"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// A free loopback port, bound and ready to `accept` — the plumbing every
/// fixture below serves differently.
fn bind_loopback() -> (String, TcpListener) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a free loopback port binds");
    listener.set_nonblocking(true).expect("non-blocking");
    let url = format!("nats://{}", listener.local_addr().expect("its address"));
    let listener = TcpListener::from_std(listener).expect("adopted by tokio");
    (url, listener)
}

async fn serve_one_connection(socket: &mut tokio::net::TcpStream, auth_required: bool) {
    let info = if auth_required {
        &b"INFO {\"auth_required\":true}\r\n"[..]
    } else {
        &b"INFO {}\r\n"[..]
    };
    let _ = socket.write_all(info).await;
    let mut buf = vec![0u8; 4096];
    let _ = socket.read(&mut buf).await;
}

/// Reads until the peer closes, so holding a connection open does not look
/// like the client disconnecting it.
async fn hold_open(mut socket: tokio::net::TcpStream) {
    let mut sink = vec![0u8; 1024];
    while let Ok(n) = socket.read(&mut sink).await {
        if n == 0 {
            return;
        }
    }
}

/// A broker that accepts every connection with no credential required, and
/// holds each one open — enough handshake to make `async-nats` report `Ok`.
async fn always_accepting_broker() -> String {
    let (url, listener) = bind_loopback();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            serve_one_connection(&mut socket, false).await;
            let _ = socket.write_all(b"PONG\r\n").await;
            hold_open(socket).await;
        }
    });
    url
}

/// A broker that REFUSES every connection (ledger 1420's `counting_refuser`
/// shape, copied rather than shared across the two test-only compilation
/// units).
async fn always_refusing_broker() -> String {
    let (url, listener) = bind_loopback();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            serve_one_connection(&mut socket, true).await;
            let _ = socket
                .write_all(b"-ERR 'Authorization Violation'\r\n")
                .await;
            hold_open(socket).await;
        }
    });
    url
}

/// A broker that refuses the FIRST connection and accepts every one after,
/// for [`a_redial_success_after_a_refusal_publishes_the_gauge_as_one`].
async fn refusing_once_then_accepting_broker() -> String {
    let (url, listener) = bind_loopback();
    let refused_already = Arc::new(AtomicBool::new(false));
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            if !refused_already.swap(true, Ordering::SeqCst) {
                serve_one_connection(&mut socket, true).await;
                let _ = socket
                    .write_all(b"-ERR 'Authorization Violation'\r\n")
                    .await;
                // Dropped here: the refused connection closes, and the loop
                // goes back to `accept` for the dial this unblocks.
                continue;
            }
            serve_one_connection(&mut socket, false).await;
            let _ = socket.write_all(b"PONG\r\n").await;
            hold_open(socket).await;
        }
    });
    url
}

/// A broker that accepts, closes almost at once, then accepts again and
/// holds the second connection open — for the disconnect/reconnect case.
async fn disconnecting_then_accepting_broker() -> String {
    let (url, listener) = bind_loopback();
    let closed_already = Arc::new(AtomicBool::new(false));
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            serve_one_connection(&mut socket, false).await;
            let _ = socket.write_all(b"PONG\r\n").await;
            if !closed_already.swap(true, Ordering::SeqCst) {
                // CLOSED SERVER-SIDE, which is what `Event::Disconnected`
                // reports. A graceful `shutdown` (a real FIN) rather than a
                // bare `drop` (which can RST before the kernel has flushed
                // anything unsent), so the client sees a clean EOF rather
                // than a reset it might retry past unreported.
                let _ = socket.shutdown().await;
                drop(socket);
                continue;
            }
            hold_open(socket).await;
        }
    });
    url
}

#[tokio::test]
async fn before_any_dial_the_gauge_is_zero() {
    let recorder = GaugeLog::default();
    let local = metrics::set_default_local_recorder(&recorder);

    let inv = Invalidator::connect(None, None, None).await;
    assert!(!inv.is_publishing(), "no broker was configured");

    drop(local);
    assert_eq!(
        recorder.values(),
        vec![0.0],
        "{PUBLISHING_GAUGE} must read 0 before any dial, with no broker configured"
    );
}

#[tokio::test]
async fn a_successful_dial_publishes_the_gauge_as_one() {
    // THE POSITIVE CONTROL: without it, an implementation that writes `0`
    // unconditionally passes every case below that only checks for zero.
    let recorder = GaugeLog::default();
    let local = metrics::set_default_local_recorder(&recorder);

    let url = always_accepting_broker().await;
    let inv = Invalidator::connect(Some(&url), None, None).await;
    assert!(inv.is_publishing(), "the fixture broker accepts anyone");

    drop(local);
    assert_eq!(
        recorder.values(),
        vec![0.0, 1.0],
        "{PUBLISHING_GAUGE} must read 0 (before the dial) then 1 (once it connects)"
    );
}

#[tokio::test]
async fn a_refused_credential_publishes_the_gauge_as_zero() {
    let recorder = GaugeLog::default();
    let local = metrics::set_default_local_recorder(&recorder);

    let url = always_refusing_broker().await;
    let inv = Invalidator::connect(Some(&url), None, None).await;
    assert!(!inv.is_publishing(), "the fixture broker refuses everyone");

    drop(local);
    assert_eq!(
        recorder.values(),
        vec![0.0, 0.0],
        "{PUBLISHING_GAUGE} must read 0 (before the dial) then 0 again (the boot refusal)"
    );
}

/// Proves the gauge follows a REDIAL, not only the boot dial `connected` also
/// reports. The log's THIRD value is what a mutation deleting `connected`'s
/// `set(1.0)` turns from `1.0` to something else — `on_event`'s
/// `Event::Connected` arm also fires on this same successful redial and
/// would still log a trailing `1.0` of its own, but strictly AFTER whichever
/// value `connected` logs, so the entry at index `2` — asserted here — is
/// `connected`'s alone.
#[tokio::test]
async fn a_redial_success_after_a_refusal_publishes_the_gauge_as_one() {
    let recorder = GaugeLog::default();
    let local = metrics::set_default_local_recorder(&recorder);

    let url = refusing_once_then_accepting_broker().await;
    let waits = Waits {
        outage: Duration::from_millis(30),
        refused: Duration::from_millis(100),
    };
    let inv = Invalidator::dial(Some(&url), None, None, waits).await;
    assert!(
        !inv.is_publishing(),
        "the first dial must be the refused one"
    );

    until("the redial to connect", Duration::from_secs(2), || {
        inv.is_publishing()
    })
    .await;

    drop(local);
    let values = recorder.values();
    assert!(
        values.len() >= 3,
        "expected at least [0 (before dial), 0 (refusal), 1 (redial)], got {values:?}"
    );
    assert_eq!(
        values[..2],
        [0.0, 0.0],
        "the boot dial must log 0 (before) then 0 (refused): {values:?}"
    );
    assert_eq!(
        values[2], 1.0,
        "`connected` must log 1 for the redial that followed the refusal: {values:?}"
    );
}

/// Covers the transition neither `connected` nor `refused` can: once a
/// client exists, `async-nats` owns reconnecting underneath it with no call
/// back through `redial`, so only [`on_event`]'s `Disconnected`/`Connected`
/// arms can report it. MUTATION: dropping either `metrics::gauge!` line from
/// those two arms removes the matching `0.0`/trailing `1.0` this asserts.
#[tokio::test]
async fn a_disconnect_drops_the_gauge_and_a_reconnect_restores_it() {
    let recorder = GaugeLog::default();
    let local = metrics::set_default_local_recorder(&recorder);

    let url = disconnecting_then_accepting_broker().await;
    let inv = Invalidator::connect(Some(&url), None, None).await;
    assert!(inv.is_publishing(), "the first connection must succeed");
    assert_eq!(
        recorder.values(),
        vec![0.0, 1.0],
        "{PUBLISHING_GAUGE} must read 0 then 1 right after the boot dial connects"
    );

    // NOT `.last() == Some(&0.0)`: on loopback, with no real latency, the
    // disconnect and the reconnect that follows it both land inside one
    // `until` poll tick, so the LAST value can already be back at `1.0` by
    // the time this is ever checked. What must hold is that a `0.0` landed
    // SOMEWHERE after the boot connect — proof of an actual disconnect,
    // never merely of the initial reset at index 0 — and that the gauge
    // settles on `1.0` once `is_publishing` has nothing more to wait on
    // (`async-nats` reconnects on its own schedule, so the LAST write seen
    // here may not yet be the truly final one; `is_publishing()` staying
    // `true` throughout cannot tell either, which is why this polls the log
    // itself rather than that flag).
    until(
        "a disconnect, then a reconnect, to both be logged",
        Duration::from_secs(2),
        || {
            let v = recorder.values();
            v.len() >= 4 && v[1..].contains(&0.0) && v.last() == Some(&1.0)
        },
    )
    .await;

    drop(local);
    let values = recorder.values();
    assert!(
        values[0] == 0.0 && values[1] == 1.0,
        "the boot dial's own pair must stay first: {values:?}"
    );
    assert!(
        values[1..].contains(&0.0),
        "a real disconnect must have been logged after the boot connect: {values:?}"
    );
    assert_eq!(
        values.last(),
        Some(&1.0),
        "the gauge must settle back on 1 once async-nats's own reconnect succeeds: {values:?}"
    );
}
