//! THE EXIT CHAIN, held at the binary (ledger 748): the two ordinary ways a
//! running `iam` is asked to stop both reach exit code 0, and a third way a
//! server that can never start reaches 1 with its reason intact.
//!
//! **This file proves only that each real path reaches its real exit code —
//! never that an in-flight call survives to finish.** The library tests prove
//! the rest: `yadgar-lifecycle`'s own `tests/drain.rs` proves the budget and
//! that a call in flight when shutdown is requested is given until the budget
//! to finish; its `tests/shutdown.rs` proves a real SIGTERM reaches a real
//! drain; `tests/assembly.rs` proves the watch set holds the right files;
//! `src/key_identity/tests.rs` proves `until_stopped`/`until_stopped_with`
//! pick the right arm against a scripted twin. None of them can see `main.rs`
//! actually WIRE the real `shutdown()` future and the real `rotate::watch`
//! future into the `until_stopped_with` call that ends the real serve. Before
//! this file, deleting either wire compiled and passed every suite here. Only
//! running the binary can tell.
//!
//! **What each case kills, measured by mutating `src/main.rs`:**
//!
//! - Replace the `signals` argument with `std::future::pending()` (and never
//!   call `shutdown()`): no handler is ever installed, SIGTERM takes the
//!   kernel default, the status carries signal 15 and no code, and
//!   [`sigterm_drains_and_exits_zero`]'s `Some(0)` assert is red.
//! - Replace the `rotate::watch(watch_inputs, schedule)` argument with
//!   `std::future::pending()`: nothing polls the watcher, so
//!   [`a_rewritten_shared_document_drains_and_exits_zero`] never sees the
//!   CHANGED line and fails on its deadline.
//!
//! A failing drain is NOT one of these cases. `Drain::Overran` exits 0 by
//! design, so nothing about the drain's own TIMING moves the code the first
//! two cases assert. Nor is the key-identity arm: there is no `iam-db` in
//! this harness, so every round trip it makes fails to connect and
//! `until_stopped_with`'s third arm never resolves (ADR-0764) — it stays
//! pending for the life of every case below, exactly as it would against a
//! twin that has not finished migrating.
//!
//! **`Drain::Finished(Err(e))` IS one of this file's cases, and it is the
//! third.** `e` is a `tonic::transport::Error`, whose Display is the two
//! words `transport error` — `src/serve.rs`'s own `builder` doc makes the
//! identical point about the same type one call site over. A server that can
//! never accept — LISTEN already held by another socket is the ordinary way
//! — used to print exactly that dead end; [`a_bound_listen_port_is_printed_as_its_sentence`]
//! holds the chain walk that replaced it.
//!
//! See `tests/support/mod.rs` for why each run is in its own mount namespace,
//! and for why `YADGAR_KEYS_DIR` needs no mount of its own.

mod support;

use std::os::unix::process::ExitStatusExt;

use support::{cleartext_env, describe, fresh_keys_dir, Booted, FIXTURE, MARGIN, POLL, SPLAY_MAX};
use yadgar_lifecycle::DRAIN_BUDGET;

/// Case (i): kubelet's SIGTERM ends the process with 0.
///
/// The deadline is the drain's whole budget plus a margin, not less: an
/// `Overran` drain is a legal exit 0 that arrives one budget after the signal.
#[test]
fn sigterm_drains_and_exits_zero() {
    let keys_dir = fresh_keys_dir();
    let mut iam = Booted::start(&cleartext_env(&keys_dir));
    iam.wait_until_listening();

    iam.terminate();
    let status = iam.wait_for_exit("after SIGTERM", DRAIN_BUDGET + MARGIN);

    assert_eq!(
        status.code(),
        Some(0),
        "SIGTERM must drain and exit 0 ({}); signal 15 here means no handler was \
         installed",
        describe(Some(status))
    );
    assert_eq!(status.signal(), None);
    assert!(
        iam.seen()
            .iter()
            .any(|l| l.contains("draining in-flight requests") && l.contains("SIGTERM")),
        "the drain must name the signal that started it"
    );
}

/// Case (ii): a rewritten watched file ends the process with 0.
///
/// `shared.yaml` is the one watched file a cleartext deployment with no broker
/// credential and no enrolment CA has (`rotate::watch_set`'s fifth, never-absent
/// member). The rewrite keeps the schedule valid and changes the bytes, which
/// is all the watcher compares.
#[test]
fn a_rewritten_shared_document_drains_and_exits_zero() {
    let keys_dir = fresh_keys_dir();
    let mut iam = Booted::start(&cleartext_env(&keys_dir));
    iam.wait_until_listening();

    iam.rewrite_shared(&format!("{FIXTURE}# rotated by tests/exit_chain.rs\n"));
    // One poll to notice, the splay, then the drain's whole budget.
    let deadline = POLL + SPLAY_MAX + DRAIN_BUDGET + MARGIN;
    let started = std::time::Instant::now();

    let changed = iam.wait_for_line("the watcher's CHANGED line", deadline, |l| {
        l.contains("have CHANGED on disk")
    });
    assert!(
        changed.contains("shared.yaml"),
        "the CHANGED line must name the file that changed: {changed}"
    );
    // Neither TLS nor the broker credential nor the enrolment CA is configured,
    // so every one of the four optional materials is absent and both
    // fingerprints are reported, and reported as `none`.
    for field in [
        "\"serving_before\":\"none\"",
        "\"serving_after\":\"none\"",
        "\"client_before\":\"none\"",
        "\"client_after\":\"none\"",
    ] {
        assert!(
            changed.contains(field),
            "the CHANGED line must carry {field}: {changed}"
        );
    }

    let status = iam.wait_for_exit(
        "after the watched file changed",
        deadline.saturating_sub(started.elapsed()),
    );
    assert_eq!(
        status.code(),
        Some(0),
        "a rotation is not an error; it must drain and exit 0 ({})",
        describe(Some(status))
    );
}

/// Case (iii): a server that can never accept exits 1 with its REASON, not
/// tonic's dead-end Display.
///
/// Holding the port `LISTEN` names before the binary starts is the ordinary
/// way `serve_with_shutdown` never gets to accept at all — the same failure
/// an operator sees from a chart that collided two deployments on one port.
///
/// **`serve_and_drain`'s `"iam listening"` line is logged before the server
/// is spawned, so it says nothing about whether the bind below it succeeds —
/// `drain_within` only CHECKS the serving task once its own `stop` resolves.**
/// A boot held on an occupied port therefore sits until something ends `stop`;
/// SIGTERM is what a real rollout sends, and it is what this case sends too.
/// Whether SIGTERM arrives before or after the spawned task's bind fails,
/// tonic binds before it polls shutdown, so `drain_within` always reaps
/// `Finished(Err)` — `result?` fires before `ended_rx` is ever read, so
/// SIGTERM itself decides nothing about the exit code here.
#[test]
fn a_bound_listen_port_is_printed_as_its_sentence() {
    let keys_dir = fresh_keys_dir();
    let holder =
        std::net::TcpListener::bind("127.0.0.1:0").expect("the rig needs one free port to hold");
    let addr = holder
        .local_addr()
        .expect("a bound socket must report its address");

    let mut vars = cleartext_env(&keys_dir);
    vars.retain(|(k, _)| *k != "LISTEN");
    vars.push(("LISTEN", addr.to_string()));

    let mut iam = Booted::start(&vars);
    iam.wait_until_listening();
    iam.terminate();
    let status = iam.wait_for_exit("after the occupied port failed to bind", MARGIN);
    drop(holder);

    assert!(
        !status.success(),
        "a server that could never bind must exit non-zero: {status:?}"
    );
    let stderr = iam.seen().join("\n");
    let line = iam
        .seen()
        .iter()
        .rfind(|l| l.starts_with("Error: "))
        .unwrap_or_else(|| panic!("no `Error: ` line on stderr: {stderr}"));
    assert_ne!(
        line, "Error: transport error",
        "the operator got tonic's dead-end Display, not the chain below it: {line}"
    );
    assert!(
        line.contains(&addr.to_string()),
        "the sentence must name the address that could not be bound: {line}"
    );
    // The CAUSE, one level below tonic's `transport error`: only the chain
    // walk reaches it, so this is the assertion that holds `boot::refusal`.
    assert!(
        line.contains("already in use"),
        "the sentence must carry the bind failure's cause, not stop at `transport error`: {line}"
    );
}
