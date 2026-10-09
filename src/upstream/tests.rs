//! Unit tests for [`super`], in their own file.
//!
//! A submodule rather than a `#[cfg(test)]` block at the foot of `upstream.rs`,
//! the same seam `crypto` and `service` already take. These tests are the
//! larger half of what that file used to hold — 422 lines against 294 — and
//! the ceiling counts them against it.
//!
//! Still a UNIT test module: it reaches the private `ClientIdentity`, the
//! private `options`, and `from_lookup`, none of which an integration test can
//! see.

use super::*;

/// The values below are SENTINELS: nothing in `upstream.rs` could produce
/// either of them, so a test that sees one saw it travel from the lookup.
const SENTINEL_CA: &str = "/etc/yadgar/aardvark-9f3c/bundle.pem";
const SENTINEL_CLIENT_CERT: &str = "/etc/yadgar/aardvark-9f3c/iam-caller.pem";
const SENTINEL_CLIENT_KEY: &str = "/etc/yadgar/aardvark-9f3c/iam-caller-key.pem";
const SENTINEL_DOMAIN: &str = "iam-db.verified-as-this.invalid";

/// A host that resolves to nothing, so the only thing either dial can
/// report is WHICH dial it was.
const UNRESOLVABLE: &str = "iam-db-no-such-host-4b7e02.invalid";

fn lookup<'a>(pairs: &'a [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> + 'a {
    move |key| {
        pairs
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.to_string())
    }
}

/// NO UNCONFIGURED ANSWER ANY MORE (ADR-0845). The compiled-in default this
/// used to fall back to is deleted: absent is refused exactly like any other
/// value outside "1"/"0", naming the knob.
#[test]
fn absent_tls_enabled_is_refused() {
    let err = UpstreamTls::from_lookup(IAM_DB, IAM_DB_CHART_KEY, lookup(&[])).unwrap_err();
    // NOT INTERPOLATED into the assert message (CodeQL's cleartext-logging
    // query reads an enum variant's name — `ClientCertificateWithoutKey` and
    // `ClientKeyWithoutCertificate` are this error's sibling variants,
    // holding no secret of any kind, just a `&'static str` prefix — as a
    // signal that formatting ANY value of the type "logs sensitive data",
    // even though every field involved is a prefix or a chart key. The
    // boolean match below is the whole of the proof; a plain `assert!`
    // needs no diagnostic string to redden informatively, since the panic
    // already names the file and line.
    assert!(matches!(
        err,
        TlsConfigError::EnabledNotBoolean(IAM_DB, _, _)
    ));
    // ON THE MESSAGE, not only the variant: a refusal that dropped the
    // variable name or the chart key out of its sentence would still match
    // the `matches!` above, which is exactly the mutation this guards
    // against — the error's wording is what an operator reads, and
    // ADR-0845's own rule is that it names both.
    let printed = err.to_string();
    assert!(printed.contains("IAM_DB_TLS_ENABLED"));
    assert!(printed.contains("iamDb.tls.enabled"));
}

/// THE CHART KEY IS PER PREFIX, NOT DERIVED FROM IT (B-N3, ledger 925).
/// `IAM_DB`'s key is `iamDb.tls.enabled` — camelCase, with the `_` dropped —
/// so a refusal built by lowercasing the prefix would print `iam_db.tls
/// .enabled`, a key this chart does not declare. This is the mutant a second
/// upstream exposes: `NATS` lowercases correctly to `nats.tls.enabled`, so a
/// test that only ever reads `IAM_DB` cannot tell a derived key from a
/// threaded one apart. It also fixed a REAL bug: before `chart_key` was
/// threaded through, `NATS`'s refusal named `iamDb.tls.enabled` unconditionally
/// — the one message in this module hardcoded to the first upstream it ever
/// had.
#[test]
fn the_chart_key_in_the_refusal_is_the_callers_own_not_the_first_upstreams() {
    let err = UpstreamTls::from_lookup(NATS, NATS_CHART_KEY, lookup(&[])).unwrap_err();
    assert!(matches!(err, TlsConfigError::EnabledNotBoolean(NATS, _, _)));
    let printed = err.to_string();
    assert!(printed.contains("NATS_TLS_ENABLED"));
    assert!(printed.contains("nats.tls.enabled"));
    assert!(
        !printed.contains("iamDb"),
        "NATS's refusal must not name IAM_DB's chart key: {printed:?}"
    );
}

/// THE REVERTED STATE is now `"0"` WRITTEN EXPLICITLY, not absence. A bundle
/// left mounted while the flag is off is still legitimate — that is how the
/// cut-over gets reverted — so it must not become an error on its own.
#[test]
fn a_ca_bundle_alone_with_the_flag_explicitly_off_does_not_enable_tls() {
    let vars = [
        ("IAM_DB_TLS_ENABLED", "0"),
        ("IAM_DB_TLS_CA_FILE", SENTINEL_CA),
    ];
    assert_eq!(
        UpstreamTls::from_lookup(IAM_DB, IAM_DB_CHART_KEY, lookup(&vars)).unwrap(),
        None
    );
}

/// Exactly "0" is off; every OTHER value — including the ones a permissive
/// parse used to collapse into off — refuses rather than silently dialling
/// cleartext under a value nobody chose it to mean (ADR-0845).
#[test]
fn anything_but_zero_or_one_is_refused() {
    for value in ["false", "no", "true", "yes", "2", "", " "] {
        let vars = [
            ("IAM_DB_TLS_ENABLED", value),
            ("IAM_DB_TLS_CA_FILE", SENTINEL_CA),
        ];
        assert!(
            matches!(
                UpstreamTls::from_lookup(IAM_DB, IAM_DB_CHART_KEY, lookup(&vars)),
                Err(TlsConfigError::EnabledNotBoolean(IAM_DB, _, _))
            ),
            "{value:?} must be refused, not treated as off"
        );
    }
}

/// THE FAILURE THAT MUST NOT DEGRADE. Asking for TLS and naming no bundle
/// is a deployment mistake, and the answer to it is an error rather than a
/// cleartext channel or the platform trust store.
#[test]
fn asking_for_tls_without_a_ca_bundle_is_an_error() {
    for vars in [
        vec![("IAM_DB_TLS_ENABLED", "1")],
        vec![("IAM_DB_TLS_ENABLED", "1"), ("IAM_DB_TLS_CA_FILE", "")],
        vec![("IAM_DB_TLS_ENABLED", "1"), ("IAM_DB_TLS_CA_FILE", "   ")],
    ] {
        assert!(
            matches!(
                UpstreamTls::from_lookup(IAM_DB, IAM_DB_CHART_KEY, lookup(&vars)),
                Err(TlsConfigError::NoCaFile("IAM_DB"))
            ),
            "{vars:?} must be refused, not silently downgraded"
        );
    }
}

/// Both values reach the settings, proved with names the module could not
/// have chosen for itself.
#[test]
fn the_bundle_and_the_domain_both_arrive() {
    let vars = [
        ("IAM_DB_TLS_ENABLED", "1"),
        ("IAM_DB_TLS_CA_FILE", SENTINEL_CA),
        ("IAM_DB_TLS_DOMAIN", SENTINEL_DOMAIN),
    ];
    let tls = UpstreamTls::from_lookup(IAM_DB, IAM_DB_CHART_KEY, lookup(&vars))
        .unwrap()
        .expect("a flag and a bundle enable TLS");
    assert_eq!(tls.ca_file(), Path::new(SENTINEL_CA));
    assert_eq!(tls.domain(), Some(SENTINEL_DOMAIN));
}

/// The domain is OPTIONAL, and its absence means "verify against the host",
/// which is `yadgar_dial`'s own default rather than a value invented here.
#[test]
fn the_domain_is_optional() {
    let vars = [
        ("IAM_DB_TLS_ENABLED", "1"),
        ("IAM_DB_TLS_CA_FILE", SENTINEL_CA),
    ];
    let tls = UpstreamTls::from_lookup(IAM_DB, IAM_DB_CHART_KEY, lookup(&vars))
        .unwrap()
        .expect("a flag and a bundle enable TLS");
    assert_eq!(tls.domain(), None);
}

/// THE ARGUMENT IS NOT DECORATION. A `connect` that accepted `Some(tls)`
/// and called `yadgar_dial::connect` anyway would pass every test above —
/// they only inspect the configuration — and would ship a cleartext dial
/// wearing a TLS configuration.
///
/// `yadgar_dial::connect_tls` checks the CA bundle BEFORE it dials the
/// host, and `connect` does not check bundles at all. So a bundle that does
/// not exist, against a host that does not resolve, tells the two apart:
/// only the TLS path can answer `CaUnreadable`. Drop the `Some` arm and
/// this returns `Ok`.
///
/// **THAT LAST SENTENCE USED TO SAY `Dns`, and the pin move to `dial`
/// v0.2.0 is what changed it.** A cleartext dial at a name that does not
/// resolve is no longer an error at all (ADR-0532), so the cleartext arm
/// answers `Ok` rather than a different error. The discrimination survives
/// — an unusable bundle is still refused before a channel exists — and
/// `a_cleartext_dial_reads_no_bundle` below asserts the two answers against
/// each other rather than each against a constant.
#[tokio::test]
async fn a_tls_dial_goes_through_connect_tls_and_not_through_connect() {
    let vars = [
        ("IAM_DB_TLS_ENABLED", "1"),
        ("IAM_DB_TLS_CA_FILE", SENTINEL_CA),
    ];
    let tls = UpstreamTls::from_lookup(IAM_DB, IAM_DB_CHART_KEY, lookup(&vars))
        .unwrap()
        .unwrap();

    assert!(
        matches!(
            connect(UNRESOLVABLE, 50051, Some(&tls)).await,
            Err(BalanceError::CaUnreadable { .. })
        ),
        "a TLS dial must read the bundle, which only connect_tls does"
    );
}

/// The other direction, so the case above cannot start passing because
/// everything became TLS.
///
/// **AN ABSENT `iam-db` IS NO LONGER A FAILED DIAL, and this case is
/// where the pin move to `dial` v0.2.0 announced itself.** It asserted
/// `BalanceError::Dns` and went RED on the bump. ADR-0532 made the boot dial
/// lazy: a name with no Service behind it yet is seeded into the balancer
/// and dialled, so `connect` hands back a channel and the failure moves to
/// the request. `Dns` and `DnsTimedOut` remain `BalanceError` variants, and
/// as far as this repository can tell no public entry point of that crate
/// returns either one now: `resolve` is private, `connect_with` warns and
/// continues with an empty set, and the refresh loop reports through
/// `still_absent` and continues. Nothing here tests that claim about
/// another crate's internals, so it is written as a reading rather than a
/// property.
///
/// **THIS IS A DIFFERENTIAL PAIR, not two assertions against constants.**
/// Each `assert!` below IS against a constant — that is unavoidable and not
/// the point. What the case buys is that the two calls differ in ONE thing,
/// the `tls` argument: same host, same port, same function. So a `connect`
/// that ignored that argument could not pass both, which is the mutant
/// `is_ok()` on its own would let through.
#[tokio::test]
async fn a_cleartext_dial_reads_no_bundle() {
    let vars = [
        ("IAM_DB_TLS_ENABLED", "1"),
        ("IAM_DB_TLS_CA_FILE", SENTINEL_CA),
    ];
    let tls = UpstreamTls::from_lookup(IAM_DB, IAM_DB_CHART_KEY, lookup(&vars))
        .unwrap()
        .unwrap();

    let cleartext = connect(UNRESOLVABLE, 50051, None).await;
    let encrypted = connect(UNRESOLVABLE, 50051, Some(&tls)).await;

    assert!(
        cleartext.is_ok(),
        "a name that does not resolve must not fail the dial: {:?}",
        cleartext.err()
    );
    assert!(
        matches!(encrypted, Err(BalanceError::CaUnreadable { .. })),
        "the same host with a bundle must still read it: {encrypted:?}"
    );
}

/// The prefix is what selects the variables, so a value meant for another
/// upstream cannot configure this one. Cheap here, load-bearing in the
/// gateway, which reads two prefixes in one process.
#[test]
fn another_upstreams_variables_do_not_configure_this_one() {
    let vars = [
        ("IAM_TLS_ENABLED", "1"),
        ("IAM_TLS_CA_FILE", SENTINEL_CA),
        ("TLS_ENABLED", "1"),
        // `IAM_DB_TLS_ENABLED` stated explicitly, off — ADR-0845 leaves it no
        // default to fall into, so proving isolation needs a value rather
        // than absence.
        ("IAM_DB_TLS_ENABLED", "0"),
    ];
    assert_eq!(
        UpstreamTls::from_lookup(IAM_DB, IAM_DB_CHART_KEY, lookup(&vars)).unwrap(),
        None
    );
}

/// THE DEFAULT: no client certificate, so the dial presents no identity and
/// behaves exactly as it did before ADR-0516.
#[test]
fn no_client_certificate_is_the_default() {
    let vars = [
        ("IAM_DB_TLS_ENABLED", "1"),
        ("IAM_DB_TLS_CA_FILE", SENTINEL_CA),
    ];
    let tls = UpstreamTls::from_lookup(IAM_DB, IAM_DB_CHART_KEY, lookup(&vars))
        .unwrap()
        .expect("a flag and a bundle enable TLS");
    assert_eq!(tls.client_certificate_file(), None);
    assert_eq!(tls.client_key_file(), None);
}

/// BOTH PATHS ARRIVE, proved with names the module could not have chosen for
/// itself. This is what `UpstreamTls`'s `Material` implementation reads to
/// put them in the watch set, so a value that stopped travelling here would
/// silently empty half the set.
#[test]
fn the_client_certificate_and_its_key_both_arrive() {
    let vars = [
        ("IAM_DB_TLS_ENABLED", "1"),
        ("IAM_DB_TLS_CA_FILE", SENTINEL_CA),
        ("IAM_DB_TLS_CLIENT_CERT_FILE", SENTINEL_CLIENT_CERT),
        ("IAM_DB_TLS_CLIENT_KEY_FILE", SENTINEL_CLIENT_KEY),
    ];
    let tls = UpstreamTls::from_lookup(IAM_DB, IAM_DB_CHART_KEY, lookup(&vars))
        .unwrap()
        .expect("a flag and a bundle enable TLS");
    assert_eq!(
        tls.client_certificate_file(),
        Some(Path::new(SENTINEL_CLIENT_CERT))
    );
    assert_eq!(tls.client_key_file(), Some(Path::new(SENTINEL_CLIENT_KEY)));
}

/// HALF AN IDENTITY IS A DEPLOYMENT MISTAKE, refused at boot naming the
/// variable rather than at a handshake naming neither. A certificate cannot
/// be presented without its key, and a key on its own proves nothing.
#[test]
fn half_a_client_identity_is_refused() {
    let cert_only = [
        ("IAM_DB_TLS_ENABLED", "1"),
        ("IAM_DB_TLS_CA_FILE", SENTINEL_CA),
        ("IAM_DB_TLS_CLIENT_CERT_FILE", SENTINEL_CLIENT_CERT),
    ];
    assert!(matches!(
        UpstreamTls::from_lookup(IAM_DB, IAM_DB_CHART_KEY, lookup(&cert_only)),
        Err(TlsConfigError::ClientCertificateWithoutKey(IAM_DB))
    ));

    let key_only = [
        ("IAM_DB_TLS_ENABLED", "1"),
        ("IAM_DB_TLS_CA_FILE", SENTINEL_CA),
        ("IAM_DB_TLS_CLIENT_KEY_FILE", SENTINEL_CLIENT_KEY),
    ];
    assert!(matches!(
        UpstreamTls::from_lookup(IAM_DB, IAM_DB_CHART_KEY, lookup(&key_only)),
        Err(TlsConfigError::ClientKeyWithoutCertificate(IAM_DB))
    ));
}

/// AN EMPTY VALUE IS AN UNSET ONE, the same rule the CA bundle already gets.
/// A values override that nulls the Secret name renders an empty string, and
/// treating that as a configured path would fail the boot over a deployment
/// that simply asked for no identity.
#[test]
fn an_empty_client_path_is_the_same_as_an_unset_one() {
    let vars = [
        ("IAM_DB_TLS_ENABLED", "1"),
        ("IAM_DB_TLS_CA_FILE", SENTINEL_CA),
        ("IAM_DB_TLS_CLIENT_CERT_FILE", "  "),
        ("IAM_DB_TLS_CLIENT_KEY_FILE", ""),
    ];
    let tls = UpstreamTls::from_lookup(IAM_DB, IAM_DB_CHART_KEY, lookup(&vars))
        .unwrap()
        .expect("a flag and a bundle enable TLS");
    assert_eq!(tls.client_certificate_file(), None);
}

/// A CLIENT CERTIFICATE WITHOUT THE FLAG IS THE REVERTED STATE, not an
/// error. Mutual TLS runs inside the encrypted transport, so the one flag
/// turns both off, and leaving the paths in place is how the cut-over gets
/// pulled back.
#[test]
fn a_client_certificate_alone_does_not_enable_tls() {
    let vars = [
        ("IAM_DB_TLS_ENABLED", "0"),
        ("IAM_DB_TLS_CLIENT_CERT_FILE", SENTINEL_CLIENT_CERT),
        ("IAM_DB_TLS_CLIENT_KEY_FILE", SENTINEL_CLIENT_KEY),
    ];
    assert_eq!(
        UpstreamTls::from_lookup(IAM_DB, IAM_DB_CHART_KEY, lookup(&vars)).unwrap(),
        None
    );
}

/// THE PRESENTATION WIRING (audit B S-3, ADR-0845 sweep): the hop from
/// environment to `yadgar_dial::TlsOptions`, one layer past `UpstreamTls`'s
/// own fields. Everything above proves the struct holds the client
/// certificate; this proves [`UpstreamTls::options`] actually forwards it
/// into the identity `connect_tls` builds from, rather than stopping short.
///
/// `TlsOptions` publishes no getter for its identity, so this reads its
/// derived `Debug` string — `identity: None` or `identity: Some(..)` — at the
/// pinned `dial` tag. A field rename would still read as `None`/`Some`, which
/// is the property under test rather than the field's name.
#[test]
fn the_client_identity_reaches_tlsoptions_when_the_env_sets_it() {
    let base = [
        ("IAM_DB_TLS_ENABLED", "1"),
        ("IAM_DB_TLS_CA_FILE", SENTINEL_CA),
    ];

    let without = UpstreamTls::from_lookup(IAM_DB, IAM_DB_CHART_KEY, lookup(&base))
        .unwrap()
        .expect("a flag and a bundle enable TLS");
    assert!(
        format!("{:?}", without.options()).contains("identity: None"),
        "no client certificate configured must leave TlsOptions with no identity"
    );

    let with_client = [
        base[0],
        base[1],
        ("IAM_DB_TLS_CLIENT_CERT_FILE", SENTINEL_CLIENT_CERT),
        ("IAM_DB_TLS_CLIENT_KEY_FILE", SENTINEL_CLIENT_KEY),
    ];
    let with = UpstreamTls::from_lookup(IAM_DB, IAM_DB_CHART_KEY, lookup(&with_client))
        .unwrap()
        .expect("a flag and a bundle enable TLS");
    assert!(
        format!("{:?}", with.options()).contains("identity: Some"),
        "a client certificate and key configured must reach TlsOptions as an identity"
    );
}

/// The gauge `dial` publishes for an upstream that never resolved reaches
/// this binary's registry, under the name and the label an alert queries.
///
/// **A METRIC A LIBRARY EMITS IS NOT AUTOMATICALLY A SERIES THIS SERVICE
/// EXPORTS, and this case is what makes the difference visible.** On `dial`
/// v0.2.0 the key does not exist at all, so this went RED before the pin
/// moved. What it proves once green is the whole chain: the emission is on
/// the boot path this service actually calls, it goes through the `metrics`
/// facade this binary links rather than a second one, and
/// `yadgar_telemetry::metrics::install_prometheus` builds a
/// `PrometheusBuilder` with no allow-list, so a gauge in the registry is a
/// gauge on `/metrics`.
///
/// **THE NAME IS ASSERTED AS A STRING LITERAL, NOT AS
/// `yadgar_dial::UPSTREAM_NEVER_RESOLVED`.** Comparing that constant with
/// itself passes through a rename, and a rename is the one change to a
/// metric that fails nowhere: every consumer compiles, a dashboard blanks
/// and an alert stops. Spelling it out makes the next pin move that renames
/// it fail HERE instead.
///
/// **THERE IS NO `service` LABEL ON THIS SERIES.** `dial` is a library
/// dialling outward with no service identity of its own and documents that
/// it writes no second label, and `install_prometheus` adds no global one.
/// `upstream` is the only dimension; the pod and the job come from the
/// scrape. It differs from `yadgar_rotation_watched_files_unreadable` for
/// that reason, not by oversight.
#[test]
fn an_absent_iam_db_is_published_as_a_gauge() {
    let (emitted, _channel) = dial_under_a_recorder(UNRESOLVABLE);
    assert!(
        gauge_for(&emitted, UNRESOLVABLE, 1.0),
        "an iam-db that never resolved must be published as a gauge an \
         alert can read: {emitted:?}"
    );
}

/// The other direction, and it is not symmetry for its own sake.
///
/// **A GAUGE WRITTEN ONLY ON THE UNHEALTHY PATH DOES NOT EXIST ON A HEALTHY
/// POD**, and a series that does not exist cannot be compared against zero:
/// `> 0` matches nothing, so "healthy" reads the same as "this crate was
/// never linked" and the same as "the process died before its first tick".
/// The boot dial publishing BOTH ways is what the alert `> 0` depends on,
/// and it is a property of the pin rather than of this repository — so it is
/// asserted here, where the pin is.
#[test]
fn an_iam_db_that_resolves_publishes_the_same_gauge_at_zero() {
    let (emitted, _channel) = dial_under_a_recorder(RESOLVABLE);
    assert!(
        gauge_for(&emitted, RESOLVABLE, 0.0),
        "a resolvable iam-db must still publish the series, at zero: \
         {emitted:?}"
    );
}

/// One row of a [`metrics_util::debugging::Snapshotter`] snapshot: the key
/// with its kind, the unit and description a `describe_*` would have set,
/// and the value.
type Emitted = (
    metrics_util::CompositeKey,
    Option<metrics::Unit>,
    Option<metrics::SharedString>,
    metrics_util::debugging::DebugValue,
);

/// A name every host resolves without a network: `dial` only needs an
/// address to build an endpoint, and nothing here connects.
const RESOLVABLE: &str = "localhost";

/// Dial `host` with a LOCAL recorder and return everything it emitted.
///
/// Local rather than `metrics::set_global_recorder`: a global one is
/// process-wide and this binary runs its tests in parallel, so installing
/// here would race every other case that emits a metric.
///
/// The channel comes back with the snapshot and the caller HOLDS IT.
/// `dial`'s refresh loop writes this same gauge back to 0 on the way out,
/// and it leaves when the channel is dropped.
fn dial_under_a_recorder(host: &str) -> (Vec<Emitted>, tonic::transport::Channel) {
    let recorder = metrics_util::debugging::DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    let channel = metrics::with_local_recorder(&recorder, || {
        rt.block_on(async { connect(host, 50051, None).await })
    })
    .expect("a cleartext dial is lazy and hands back a channel");

    // ONE SNAPSHOT. `Snapshotter::snapshot` DRAINS the registry, so a second
    // call sees nothing and its assertion fails while the gauge is being
    // emitted perfectly well.
    let emitted = snapshotter.snapshot().into_vec();
    // LENGTH FIRST, AND IT IS NOT A FORMALITY. A `metrics-util` resolving
    // against another `metrics` major links a SECOND facade; then this
    // snapshot is empty, and every assertion built on it passes vacuously.
    assert!(
        !emitted.is_empty(),
        "the recorder saw no metric at all, which is what a second metrics \
         facade in the tree looks like"
    );
    (emitted, channel)
}

/// Is the gauge present for `upstream`, holding `want`?
fn gauge_for(emitted: &[Emitted], upstream: &str, want: f64) -> bool {
    emitted.iter().any(|(key, _, _, value)| {
        key.key().name() == "yadgar_dial_upstream_never_resolved"
            && key
                .key()
                .labels()
                .any(|l| l.key() == "upstream" && l.value() == upstream)
            && matches!(value, metrics_util::debugging::DebugValue::Gauge(g) if g.0 == want)
    })
}
