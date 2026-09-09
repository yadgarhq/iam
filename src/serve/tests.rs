//! Unit tests for [`super`], in their own file.
//!
//! A submodule rather than a `#[cfg(test)]` block at the foot of `serve.rs`,
//! the same seam `crypto` and `service` already take. The file-size ceiling
//! counts a test module's lines against the file that holds it, and splitting
//! `serve.rs`'s production half to make room for its tests would cut a module
//! that has no second concern in it.
//!
//! Still a UNIT test module: it reaches the private `tls_config` and
//! `ServerTls`'s own fields, which an integration test cannot see.

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
/// compared. `DEFAULT_REDEEM_RESPONSE_FLOOR` is the MINIMUM time
/// `RedeemEnrolment` may answer in, so the slowest legitimate call is longer
/// still; an order of magnitude is the smallest margin that is
/// distinguishable from the floor itself.
#[test]
fn a_drain_budget_must_outlast_the_slowest_legitimate_call() {
    let floor = crate::service::DEFAULT_REDEEM_RESPONSE_FLOOR;
    assert!(
        yadgar_lifecycle::DRAIN_BUDGET >= floor * 10,
        "a {:?} budget against a {floor:?} response-time floor cuts off calls that had \
         not finished, which is what the budget was meant to let happen",
        yadgar_lifecycle::DRAIN_BUDGET
    );
}

/// THE DEFAULT, and the property the whole change is built around: nothing
/// configured means the plaintext listener, unchanged.
#[test]
fn nothing_configured_means_no_tls() {
    assert_eq!(ServerTls::from_lookup(LISTEN, lookup(&[])).unwrap(), None);
}

/// Paths without the flag are the REVERTED state, not an error. The flag is
/// the lever; leaving the files named is how it gets pulled back.
#[test]
fn a_certificate_alone_does_not_enable_tls() {
    let vars = [
        ("LISTEN_TLS_CERT_FILE", SENTINEL_CERT),
        ("LISTEN_TLS_KEY_FILE", SENTINEL_KEY),
    ];
    assert_eq!(ServerTls::from_lookup(LISTEN, lookup(&vars)).unwrap(), None);
}

/// Anything but "1" is off. A permissive parse is how a setting meant to be
/// off ends up on — and here also how one meant to be revertible stops
/// being.
#[test]
fn only_exactly_one_enables_tls() {
    for value in ["0", "false", "no", "true", "yes", "", " "] {
        let vars = [
            ("LISTEN_TLS_ENABLED", value),
            ("LISTEN_TLS_CERT_FILE", SENTINEL_CERT),
            ("LISTEN_TLS_KEY_FILE", SENTINEL_KEY),
        ];
        assert_eq!(
            ServerTls::from_lookup(LISTEN, lookup(&vars)).unwrap(),
            None,
            "{value:?} must not enable TLS"
        );
    }
}

/// THE FAILURE THAT MUST NOT DEGRADE. Asking for TLS and naming no
/// certificate is a deployment mistake, and the answer to it is an error
/// rather than a plaintext listener.
#[test]
fn asking_for_tls_without_a_certificate_is_an_error() {
    for vars in [
        vec![("LISTEN_TLS_ENABLED", "1")],
        vec![("LISTEN_TLS_ENABLED", "1"), ("LISTEN_TLS_CERT_FILE", "")],
        vec![("LISTEN_TLS_ENABLED", "1"), ("LISTEN_TLS_CERT_FILE", "   ")],
    ] {
        assert!(
            matches!(
                ServerTls::from_lookup(LISTEN, lookup(&vars)),
                Err(ServerTlsError::NoCertFile("LISTEN"))
            ),
            "{vars:?} must be refused, not silently downgraded"
        );
    }
}

/// And the same for the key, separately — a certificate with no key serves
/// nothing, and half a configuration is not a reason to serve cleartext.
#[test]
fn asking_for_tls_without_a_key_is_an_error() {
    for vars in [
        vec![
            ("LISTEN_TLS_ENABLED", "1"),
            ("LISTEN_TLS_CERT_FILE", SENTINEL_CERT),
        ],
        vec![
            ("LISTEN_TLS_ENABLED", "1"),
            ("LISTEN_TLS_CERT_FILE", SENTINEL_CERT),
            ("LISTEN_TLS_KEY_FILE", "  "),
        ],
    ] {
        assert!(
            matches!(
                ServerTls::from_lookup(LISTEN, lookup(&vars)),
                Err(ServerTlsError::NoKeyFile("LISTEN"))
            ),
            "{vars:?} must be refused, not silently downgraded"
        );
    }
}

/// Both paths reach the settings, proved with names the module could not
/// have chosen for itself.
#[test]
fn both_paths_arrive() {
    let vars = [
        ("LISTEN_TLS_ENABLED", "1"),
        ("LISTEN_TLS_CERT_FILE", SENTINEL_CERT),
        ("LISTEN_TLS_KEY_FILE", SENTINEL_KEY),
    ];
    let tls = ServerTls::from_lookup(LISTEN, lookup(&vars))
        .unwrap()
        .expect("a flag, a certificate and a key enable TLS");
    assert_eq!(tls.cert_file(), Path::new(SENTINEL_CERT));
    assert_eq!(tls.key_file(), Path::new(SENTINEL_KEY));
}

/// The prefix is what selects the variables, so a value meant for something
/// else cannot configure the listener.
#[test]
fn variables_under_another_prefix_do_not_configure_the_listener() {
    let vars = [
        ("TLS_ENABLED", "1"),
        ("SERVER_TLS_ENABLED", "1"),
        ("IAM_DB_TLS_ENABLED", "1"),
        ("TLS_CERT_FILE", SENTINEL_CERT),
    ];
    assert_eq!(ServerTls::from_lookup(LISTEN, lookup(&vars)).unwrap(), None);
}

/// A CONFIGURATION error and a FILE error are different failures, and only
/// the first is decided here. `from_lookup` never touches the filesystem, so
/// a path that does not exist is still a complete configuration — the
/// refusal comes from `builder`, which is what `tests/serve_tls.rs` proves.
#[test]
fn from_lookup_does_not_read_the_files() {
    let vars = [
        ("LISTEN_TLS_ENABLED", "1"),
        ("LISTEN_TLS_CERT_FILE", SENTINEL_CERT),
        ("LISTEN_TLS_KEY_FILE", SENTINEL_KEY),
    ];
    assert!(ServerTls::from_lookup(LISTEN, lookup(&vars)).is_ok());
}
