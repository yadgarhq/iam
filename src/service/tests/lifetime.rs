//! Credential lifetime (ADR-0972 (3), ledger 1628, train step I1d): the
//! deadline `Login` and `RedeemEnrolment` mint, the bound on
//! `CREDENTIAL_LIFETIME_SECONDS`, and the gateway cache clamp on
//! `ResolveCredential`.

use super::*;

/// A lifetime no test default shares, so a hard-coded 90 days cannot pass.
const LIFETIME: i64 = 3_600;

fn now_seconds() -> i64 {
    prost_types::Timestamp::from(SystemTime::now()).seconds
}

/// `at` is within two seconds of `now + LIFETIME`.
fn assert_near_lifetime(at: Option<prost_types::Timestamp>, what: &str) {
    let at = at.unwrap_or_else(|| panic!("{what}: an expiry is required"));
    let want = now_seconds() + LIFETIME;
    assert!(
        (at.seconds - want).abs() <= 2,
        "{what}: {} is not within 2 s of now + lifetime ({want})",
        at.seconds
    );
}

fn in_seconds(offset: i64) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: now_seconds() + offset,
        nanos: 0,
    }
}

async fn resolved_valid_for(expires_at: Option<prost_types::Timestamp>) -> i64 {
    let (iam, _rec, _inv) = iam_with(FakeDb {
        resolves_to: Some("yadgar:user:1".into()),
        resolves_expires_at: expires_at,
        ..Default::default()
    })
    .await;
    iam.resolve_credential_as(
        Some(GATEWAY_CALLER),
        Request::new(ResolveCredentialRequest::default()),
    )
    .await
    .expect("a resolution")
    .into_inner()
    .valid_for_seconds
}

// ---- The mints -------------------------------------------------------------

#[tokio::test]
async fn login_mints_a_credential_that_expires_after_the_configured_lifetime() {
    let password = fixture_password();
    let (iam, rec, _inv) = iam_with_lifetime(
        FakeDb {
            password: known_user(&password),
            ..Default::default()
        },
        LIFETIME,
    )
    .await;

    let got = iam
        .login_as(Some(GATEWAY_CALLER), login("ada", &password))
        .await
        .expect("a login")
        .into_inner();

    let stored = rec.lock().expect("recorded").create_credential[0].expires_at;
    assert_near_lifetime(stored, "the mint the store saw");
    assert_eq!(
        got.expires_at, stored,
        "the response carries the stored value"
    );
}

#[tokio::test]
async fn redemption_mints_a_credential_that_expires_after_the_configured_lifetime() {
    let password = fixture_password();
    let (iam, rec, _inv) = iam_with_lifetime(
        FakeDb {
            redeem: redeemed("ada"),
            password: known_user(&password),
            ..Default::default()
        },
        LIFETIME,
    )
    .await;

    let got = iam
        .redeem_enrolment_as(
            Some(GATEWAY_CALLER),
            redeem(&fixture_secret(), &password, "k1"),
        )
        .await
        .expect("a redemption")
        .into_inner();

    let stored = rec.lock().expect("recorded").create_credential[0].expires_at;
    assert_near_lifetime(stored, "the mint the store saw");
    assert_eq!(
        got.expires_at, stored,
        "the response carries the stored value"
    );
}

// ---- The bound -------------------------------------------------------------

#[test]
fn a_zero_credential_lifetime_is_refused() {
    // THERE IS NO "NEVER" VALUE (ADR-0972 (3)): 0 is not "no expiry" here.
    for raw in ["0", "-1"] {
        let refused = CredentialLifetime::parse(raw).expect_err(raw);
        assert!(refused.contains("CREDENTIAL_LIFETIME_SECONDS"), "{refused}");
        assert!(refused.contains("credential.lifetimeSeconds"), "{refused}");
    }
}

#[test]
fn a_lifetime_above_ten_years_is_refused() {
    // THE BOUND IS `IssueCredential`'s, from one function, so the two paths
    // cannot disagree: the maximum is accepted and one second more is not.
    CredentialLifetime::parse(&MAX_EXPIRES_IN_SECONDS.to_string())
        .expect("the IssueCredential maximum is a valid lifetime");
    let refused = CredentialLifetime::parse(&(MAX_EXPIRES_IN_SECONDS + 1).to_string())
        .expect_err("above the bound");
    assert!(refused.contains("CREDENTIAL_LIFETIME_SECONDS"), "{refused}");
}

#[test]
fn a_non_integer_lifetime_is_refused() {
    for raw in ["90d", "1.5", " 60"] {
        let refused = CredentialLifetime::parse(raw).expect_err(raw);
        assert!(refused.contains("CREDENTIAL_LIFETIME_SECONDS"), "{refused}");
    }
}

// ---- The cache clamp -------------------------------------------------------

#[tokio::test]
async fn valid_for_seconds_is_the_remaining_life_when_under_300() {
    let got = resolved_valid_for(Some(in_seconds(120))).await;
    assert!(
        (118..=120).contains(&got),
        "the cache must not outlive the credential: {got}"
    );
}

#[tokio::test]
async fn valid_for_seconds_is_300_for_a_long_lived_or_legacy_credential() {
    assert_eq!(resolved_valid_for(Some(in_seconds(86_400))).await, 300);
    assert_eq!(resolved_valid_for(None).await, 300, "a legacy NULL expiry");
}

#[tokio::test]
async fn valid_for_seconds_never_drops_below_1_for_a_live_credential() {
    // 0 is the REFUSAL signal to the gateway's cache. A credential under a
    // second from expiry, or one a skewed clock already reads as past, is
    // still a live answer from the store, so it gets the floor of 1.
    for offset in [0, -5] {
        assert_eq!(resolved_valid_for(Some(in_seconds(offset))).await, 1);
    }
}

#[tokio::test]
async fn a_negative_resolution_stays_uncacheable_whatever_the_expiry() {
    // GUARD: the clamp applies to a LIVE answer only.
    let (iam, _rec, _inv) = iam_with(FakeDb {
        resolves_expires_at: Some(in_seconds(120)),
        ..Default::default()
    })
    .await;
    let got = iam
        .resolve_credential_as(
            Some(GATEWAY_CALLER),
            Request::new(ResolveCredentialRequest::default()),
        )
        .await
        .expect("a negative answer")
        .into_inner();
    assert_eq!(got.valid_for_seconds, 0);
}
