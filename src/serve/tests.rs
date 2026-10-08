//! Unit tests for [`super`], in their own file.
//!
//! A submodule rather than a `#[cfg(test)]` block at the foot of `serve.rs`,
//! the same seam `crypto` and `service` already take.
//!
//! **WHAT IS LEFT HERE IS THIS SERVICE'S WIRING (B-U5).** The `ServerTls` type
//! and its parser are `yadgar_lifecycle::serve_tls`'s, tested there. Every case
//! below goes through [`super::from_lookup`], so it asserts the prefix and the
//! chart key THIS service hands the crate. `tests/serve_tls.rs` proves the
//! handshakes.

use std::path::Path;

use super::*;

/// The values below are SENTINELS: nothing in `serve.rs` could produce
/// either of them, so a test that sees one saw it travel from the lookup.
const SENTINEL_CERT: &str = "/etc/yadgar/pangolin-7c21/server.pem";
const SENTINEL_KEY: &str = "/etc/yadgar/pangolin-7c21/server-key.pem";

fn lookup<'a>(pairs: &'a [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> + 'a {
    move |key| {
        pairs
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.to_string())
    }
}

/// A BUDGET SHORTER THAN THE WORK IS NOT A BUDGET, it is a request cut off.
///
/// Both sides are production constants that exist for their own reasons and
/// live in different modules — this is not two literals written together and
/// compared. `MEASURED_REDEEM_RESPONSE_FLOOR` is the MINIMUM time
/// `RedeemEnrolment` may answer in, so the slowest legitimate call is longer
/// still; an order of magnitude is the smallest margin that is
/// distinguishable from the floor itself.
#[test]
fn a_drain_budget_must_outlast_the_slowest_legitimate_call() {
    let floor = crate::service::MEASURED_REDEEM_RESPONSE_FLOOR;
    assert!(
        yadgar_lifecycle::DRAIN_BUDGET >= floor * 10,
        "a {:?} budget against a {floor:?} response-time floor cuts off calls that had \
         not finished, which is what the budget was meant to let happen",
        yadgar_lifecycle::DRAIN_BUDGET
    );
}

/// The chart key is `tls`, the block every listener key renders from. A
/// different value would make every refusal name a key the chart has not got.
#[test]
fn the_chart_key_is_the_values_block_the_listener_renders_from() {
    assert_eq!(CHART_KEY, "tls");
    assert_eq!(LISTEN, "LISTEN");
}

/// NO UNCONFIGURED ANSWER (ADR-0845). Absent refuses, naming the variable and
/// this service's chart key.
///
/// NOT INTERPOLATED into an assert message: CodeQL's cleartext-logging query
/// reads an error enum with Key- and Certificate-named variants as sensitive.
/// The `matches!` and the `contains` checks are the whole proof.
#[test]
fn absent_tls_enabled_is_refused() {
    let err = from_lookup(lookup(&[("LISTEN_TLS_CLIENT_AUTH", "off")])).unwrap_err();
    assert!(matches!(err, ServeTlsError::EnabledMissing { .. }));
    let printed = err.to_string();
    assert!(printed.contains("LISTEN_TLS_ENABLED"));
    assert!(printed.contains("`tls.enabled`"));
}

/// THE REVERTED STATE is `"0"` WRITTEN EXPLICITLY, with `off`. A certificate
/// left mounted while the flag is off is still legitimate — that is how the
/// cut-over gets reverted — so it must not become an error on its own.
#[test]
fn a_certificate_alone_with_the_flag_explicitly_off_does_not_enable_tls() {
    let vars = [
        ("LISTEN_TLS_ENABLED", "0"),
        ("LISTEN_TLS_CLIENT_AUTH", "off"),
        ("LISTEN_TLS_CERT_FILE", SENTINEL_CERT),
        ("LISTEN_TLS_KEY_FILE", SENTINEL_KEY),
    ];
    assert_eq!(from_lookup(lookup(&vars)).unwrap(), None);
}

/// Exactly "0" is off; every OTHER value — including the ones a permissive
/// parse used to collapse into off — refuses rather than silently serving
/// cleartext under a value nobody chose it to mean (ADR-0845).
#[test]
fn anything_but_zero_or_one_is_refused() {
    for value in ["false", "no", "true", "yes", "2"] {
        let vars = [
            ("LISTEN_TLS_ENABLED", value),
            ("LISTEN_TLS_CLIENT_AUTH", "off"),
            ("LISTEN_TLS_CERT_FILE", SENTINEL_CERT),
            ("LISTEN_TLS_KEY_FILE", SENTINEL_KEY),
        ];
        assert!(
            matches!(
                from_lookup(lookup(&vars)),
                Err(ServeTlsError::EnabledInvalid { .. })
            ),
            "a value outside 1/0 must be refused, not treated as off"
        );
    }
    for blank in ["", " "] {
        let vars = [
            ("LISTEN_TLS_ENABLED", blank),
            ("LISTEN_TLS_CLIENT_AUTH", "off"),
        ];
        assert!(
            matches!(
                from_lookup(lookup(&vars)),
                Err(ServeTlsError::EnabledMissing { .. })
            ),
            "an empty switch must be refused as absent"
        );
    }
}

/// THE FAILURE THAT MUST NOT DEGRADE. Asking for TLS and naming no
/// certificate — or no key — is a deployment mistake, and the answer is an
/// error naming the missing variable and `tls.certSecret`, never cleartext.
#[test]
fn asking_for_tls_without_a_certificate_or_a_key_is_an_error() {
    for (vars, missing) in [
        (
            vec![("LISTEN_TLS_CERT_FILE", "   ")],
            "LISTEN_TLS_CERT_FILE",
        ),
        (
            vec![("LISTEN_TLS_CERT_FILE", SENTINEL_CERT)],
            "LISTEN_TLS_KEY_FILE",
        ),
    ] {
        let mut vars = vars;
        vars.push(("LISTEN_TLS_ENABLED", "1"));
        vars.push(("LISTEN_TLS_CLIENT_AUTH", "off"));
        let err = from_lookup(lookup(&vars)).unwrap_err();
        assert!(matches!(err, ServeTlsError::NoServingFile { .. }));
        let printed = err.to_string();
        assert!(printed.contains(missing));
        assert!(printed.contains("`tls.certSecret`"));
    }
}

/// Both paths reach the settings, proved with names the module could not
/// have chosen for itself, and `off` verifies no caller.
#[test]
fn both_paths_arrive() {
    let vars = [
        ("LISTEN_TLS_ENABLED", "1"),
        ("LISTEN_TLS_CLIENT_AUTH", "off"),
        ("LISTEN_TLS_CERT_FILE", SENTINEL_CERT),
        ("LISTEN_TLS_KEY_FILE", SENTINEL_KEY),
    ];
    let tls = from_lookup(lookup(&vars))
        .unwrap()
        .expect("a flag, a mode, a certificate and a key enable TLS");
    assert_eq!(tls.cert_file(), Path::new(SENTINEL_CERT));
    assert_eq!(tls.key_file(), Path::new(SENTINEL_KEY));
    assert_eq!(tls.client_ca_file(), None);
}

/// The prefix is what selects the variables, so a value meant for something
/// else cannot configure the listener.
#[test]
fn variables_under_another_prefix_do_not_configure_the_listener() {
    let vars = [
        ("TLS_ENABLED", "1"),
        ("SERVER_TLS_ENABLED", "1"),
        ("IAM_DB_TLS_ENABLED", "1"),
        ("IAM_DB_TLS_CLIENT_AUTH", "required"),
        ("TLS_CERT_FILE", SENTINEL_CERT),
        // `LISTEN_TLS_*` itself, stated explicitly — ADR-0845 leaves neither
        // key a default to fall into, so proving isolation needs values
        // rather than absence.
        ("LISTEN_TLS_ENABLED", "0"),
        ("LISTEN_TLS_CLIENT_AUTH", "off"),
    ];
    assert_eq!(from_lookup(lookup(&vars)).unwrap(), None);
}

/// A CONFIGURATION error and a FILE error are different failures, and only
/// the first is decided here. `from_lookup` never touches the filesystem, so
/// a path that does not exist is still a complete configuration — the
/// refusal comes from `builder`, which is what `tests/serve_tls.rs` proves.
#[test]
fn from_lookup_does_not_read_the_files() {
    let vars = [
        ("LISTEN_TLS_ENABLED", "1"),
        ("LISTEN_TLS_CLIENT_AUTH", "required"),
        ("LISTEN_TLS_CLIENT_CA_FILE", SENTINEL_CERT),
        ("LISTEN_TLS_CERT_FILE", SENTINEL_CERT),
        ("LISTEN_TLS_KEY_FILE", SENTINEL_KEY),
    ];
    assert!(from_lookup(lookup(&vars)).is_ok());
}
