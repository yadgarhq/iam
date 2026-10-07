//! Unit tests for [`super`], in their own file.
//!
//! A submodule rather than a `#[cfg(test)]` block at the foot of
//! `invalidate.rs`, the same seam `crypto`, `service`, `serve` and `upstream`
//! already take (ADR-0635/ADR-0577's 500-line ceiling, measured against this
//! file, is what made the split due rather than optional).

use super::*;

#[tokio::test]
async fn no_broker_is_a_working_publisher_that_publishes_nothing() {
    // The alternative — refusing to construct — would make a missing broker
    // an authentication outage, which is a worse failure than a late
    // revocation.
    let inv = Invalidator::connect(None, None).await;
    inv.credential_revoked("yadgar:user:x").await;
    inv.teams_changed("yadgar:user:x").await;
    assert!(!inv.is_publishing());
}

#[tokio::test]
async fn an_unreachable_broker_does_not_panic_or_block() {
    let inv = Invalidator::connect(Some("nats://127.0.0.1:1"), None).await;
    inv.credential_revoked("yadgar:user:y").await;
    assert!(!inv.is_publishing());
}

/// 965 CENSUS ROW M10. `ConnectOptions` publishes no getter for the
/// bound, so this reads its derived `Debug` string — the same technique
/// `upstream/tests.rs` uses for `TlsOptions::identity`, at the pinned
/// `async-nats` tag. A field rename would still show up as
/// `connection_timeout: 3s`, which is the property under test rather
/// than the field's name.
///
/// THROUGH [`connect_options`] ITSELF, the function [`Invalidator::connect`]
/// actually calls — not a second `ConnectOptions::new().connection_timeout(..)`
/// built here independently, which would pass whether or not `connect_options`
/// ever called `.connection_timeout` at all (a review caught this: deleting
/// the call from production left this test green). Both arms, because the
/// anonymous path is a separate branch inside `connect_options` and the
/// bound belongs to both.
#[test]
fn the_connect_options_carry_the_bound() {
    for credentials in [
        None,
        Some(Credentials {
            user: "iam".into(),
            password: "sentinel".into(),
            password_file: "/var/run/secrets/nats/password".into(),
        }),
    ] {
        let options = connect_options(&credentials);
        assert!(
            format!("{options:?}").contains("\"connection_timeout\": 3s"),
            "the bound built into the options sent to `connect` must be {CONNECT_TIMEOUT:?}"
        );
    }
}

#[test]
fn a_credential_never_prints_itself() {
    // The one place a password reaches a formatter. A derived `Debug` would
    // put it into every panic message and test failure that touched the
    // struct, which is how a secret ends up in a log nobody meant to write
    // it to.
    let c = Credentials {
        user: "iam".into(),
        password: "sentinel-of-the-nats-password".into(),
        password_file: "/var/run/secrets/nats/password".into(),
    };
    let printed = format!("{c:?}");
    assert!(
        !printed.contains("sentinel-of-the-nats-password"),
        "{printed}"
    );
    assert!(printed.contains("iam"), "{printed}");
}

#[test]
fn subjects_share_a_namespace_so_one_wildcard_can_catch_them() {
    assert!(subject::CREDENTIAL_REVOKED.starts_with("yadgar.iam."));
    assert!(subject::TEAMS_CHANGED.starts_with("yadgar.iam."));
}

#[test]
fn the_subjects_are_pinned_as_literals_because_three_parties_must_agree() {
    // AS LITERALS, never through `subject::*`. An assertion that reads the
    // constant renames both sides at once, so it cannot see a rename — the
    // namespace check above is exactly that shape, and both subjects can be
    // renamed under it with the whole suite still green.
    //
    // Three parties carry these strings and only one of them is this file.
    // `gateway/src/invalidate.rs` keeps its own copy, pinned there the same
    // way, and `deploy/infra/nats.yaml` names both in the broker's publish
    // and subscribe allow-lists. A rename no test can see leaves publisher,
    // subscriber and broker disagreeing while three suites stay green: the
    // broker refuses the publish, nothing subscribes to what is published,
    // and a revoked credential keeps working until the gateway's cache TTL
    // expires. That is a security bound, so the literal is the assertion.
    assert_eq!(subject::CREDENTIAL_REVOKED, "yadgar.iam.credential.revoked");
    assert_eq!(subject::TEAMS_CHANGED, "yadgar.iam.user.teams-changed");
}
