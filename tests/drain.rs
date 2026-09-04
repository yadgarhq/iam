//! RETURNED IS NOT THE SAME AS CLOSED — the one drain property that belongs to
//! tonic rather than to `yadgar-lifecycle`.
//!
//! `yadgar-lifecycle` owns [`yadgar_lifecycle::drain_within`] and tests it
//! thoroughly, but it declares NO TRANSPORT — its own rig is a bare
//! `loop { listener.accept().await }`. Against a bare accept loop "the port
//! stopped accepting after the drain" is trivially true, because dropping the
//! listener binding releases the port. Against tonic it is a property OF THE
//! DEPENDENCY: `serve_with_incoming_shutdown` resolving while the port still
//! accepts would mean the listener outlived the server.
//!
//! **THE FAILURE THIS KEEPS VISIBLE.** Someone bumps `tonic`, or the `hyper`
//! under it. The new version resolves its graceful-shutdown future but keeps
//! the listener alive until in-flight connections close, or leaks it outright.
//! Every other test in this repository stays green — nothing else here stands a
//! real server through a drain — and in production a rotation exit or a rollout
//! starts the drain, the port keeps accepting, new connections land on a process
//! that is going away, and they are severed by the SIGKILL at the end of
//! `terminationGracePeriodSeconds`. Silent in CI; visible only as 5xx during
//! rollouts. `hyper` 0.14 to 1.0, `tonic` 0.10 to 0.11 and `axum` 0.6 to 0.7 all
//! touched exactly this.
//!
//! **ONE RIG PER TRANSPORT, NOT ONE PER SERVICE.** `iam` and `task` serve the
//! same tonic; this file stands for both, and it is here rather than in `task`
//! because the other surviving statement about the drain budget is here too —
//! `a_drain_budget_must_outlast_the_slowest_legitimate_call` compares
//! `DRAIN_BUDGET` against this repository's `DEFAULT_REDEEM_RESPONSE_FLOOR`.
//! `gateway/tests/drain.rs` is the axum half.
//!
//! **A GAP THIS RIG CANNOT CLOSE, stated rather than implied away.** `main.rs`
//! calls `serve_with_shutdown(addr, ..)` and lets tonic bind; a test needs port
//! 0 to run concurrently with anything, so it must bind first and call
//! `serve_with_incoming_shutdown` instead. A tonic release that broke only the
//! address-binding path's listener release would pass this file. Binding,
//! dropping and then handing over the address would close that gap by
//! introducing a race for the port, which is worse.
//!
//! Recovered from the `tests/drain.rs` deleted when this repository adopted
//! `yadgar-lifecycle`, reduced to the half the crate cannot hold. The other half
//! — that the budget's clock starts when shutdown is REQUESTED rather than when
//! `drain_within` is called — is transport-independent and is the crate's own.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;

use yadgar_iam::serve;
use yadgar_lifecycle::{drain_within, Drain};

/// Far shorter than the real `DRAIN_BUDGET`, so a case finishes quickly. A
/// server with nothing in flight drains at once, so the length is not what is
/// under test.
const BUDGET: Duration = Duration::from_millis(500);

async fn accepts(port: u16) -> bool {
    tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .is_ok()
}

/// A real tonic server, already spawned, with a oneshot as its shutdown future
/// — the shape `main` uses.
///
/// `Routes::default()` answers every method with `Unimplemented`. The LIFECYCLE
/// is what is under test, not any handler, and a router that needs no crypto
/// keys and no `iam-db` channel keeps the rig honest about that.
async fn spawned() -> (
    u16,
    tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
    tokio::sync::oneshot::Sender<()>,
) {
    let listener = TcpListener::bind::<SocketAddr>("127.0.0.1:0".parse().unwrap())
        .await
        .expect("a free loopback port");
    let port = listener.local_addr().unwrap().port();
    let (ask_to_stop, stop_requested) = tokio::sync::oneshot::channel();

    let mut builder = serve::builder(None).expect("a cleartext listener");
    let router = builder.add_routes(tonic::service::Routes::default());
    let serving = tokio::spawn(async move {
        router
            .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                let _ = stop_requested.await;
            })
            .await
    });
    (port, serving, ask_to_stop)
}

#[tokio::test]
async fn a_tonic_drain_releases_the_port_and_not_merely_the_future() {
    let (port, serving, ask_to_stop) = spawned().await;
    assert!(accepts(port).await, "the rig never came up");

    let outcome = drain_within(serving, ask_to_stop, std::future::ready(()), BUDGET).await;

    assert!(
        matches!(outcome, Drain::Finished(Ok(()))),
        "a server with nothing in flight drains at once, well inside {BUDGET:?}"
    );
    assert!(
        !accepts(port).await,
        "the drain returned but port {port} still accepts connections. tonic resolved its \
         graceful-shutdown future while its listener outlived the server, so a rollout would \
         keep landing new connections on a process that is going away until the SIGKILL"
    );
}
