//! The settings `main` hands to `Iam::new`: the response floors, the
//! credential lifetime and `IAM_ADMIN_FROM_TEAM`. Each is REQUIRED, with no
//! compiled-in default (ADR-0569), and each refusal names its chart key.

use std::time::Duration;

use super::env_required;
use crate::service::{
    parse_admin_from_team, CredentialLifetime, ResponseFloors, ADMIN_FROM_TEAM_CHART_KEY,
    ADMIN_FROM_TEAM_ENV, LIFETIME_CHART_KEY, LIFETIME_ENV,
};

/// The shortest times `Login` and `RedeemEnrolment` may answer in.
pub fn response_floors() -> Result<ResponseFloors, Box<dyn std::error::Error>> {
    // The shortest time `Login` may answer in, whatever it found. Argon2id takes
    // its cost from the PHC string it is verifying, so a stored hash provisioned
    // at parameters other than this build's makes the response time report which
    // usernames exist — see `crypto::Keys::verify_password`.
    //
    // PARSED, NOT SALVAGED, AND NOT INVENTED EITHER: the chart is the one source
    // of this number (ADR-0569), so an absent, empty or mistyped value fails the
    // boot naming the variable. There is no longer a compiled-in floor to fall
    // back to. Substituting one silently would leave an operator who believes
    // they raised the floor running the old one, and a security control nobody
    // can tell is misconfigured is the failure this floor's own warning exists
    // to prevent. `service::MEASURED_LOGIN_RESPONSE_FLOOR` survives as the
    // MEASUREMENT the chart's value was calibrated from — documentation, read by
    // no knob path.
    let login_response_floor = Duration::from_millis(
        env_required("LOGIN_RESPONSE_FLOOR_MS")?
            .parse()
            .map_err(|e| format!("LOGIN_RESPONSE_FLOOR_MS is not a number of milliseconds: {e}"))?,
    );

    // ITS OWN VALUE, because `RedeemEnrolment` legitimately does more work — two
    // Argon2id operations and a further round trip — and a floor sized for
    // `Login` would be exceeded by every successful redemption, turning the
    // warning that says "raise this" into one that fires on every call.
    let redeem_response_floor = Duration::from_millis(
        env_required("REDEEM_RESPONSE_FLOOR_MS")?
            .parse()
            .map_err(|e| {
                format!("REDEEM_RESPONSE_FLOOR_MS is not a number of milliseconds: {e}")
            })?,
    );
    tracing::info!(
        login_floor_ms = login_response_floor.as_millis() as u64,
        redeem_floor_ms = redeem_response_floor.as_millis() as u64,
        "Login and RedeemEnrolment answer no sooner than their response-time floors"
    );
    Ok(ResponseFloors {
        login: login_response_floor,
        redeem: redeem_response_floor,
    })
}

/// ADR-0972 (3): how long every `Login` and redemption credential lives.
///
/// REQUIRED, like the floors: no compiled-in default (ADR-0569), and no "never"
/// value. The chart renders it from `credential.lifetimeSeconds`.
pub fn credential_lifetime() -> Result<CredentialLifetime, Box<dyn std::error::Error>> {
    // Absent and empty get `env_required`'s own sentence, plus the chart key,
    // so every refusal of this knob names where to set it.
    let raw = env_required(LIFETIME_ENV)
        .map_err(|e| format!("{e} Set the chart's {LIFETIME_CHART_KEY}."))?;
    let lifetime = CredentialLifetime::parse(&raw)?;
    tracing::info!(
        lifetime_seconds = lifetime.seconds(),
        "Login and RedeemEnrolment credentials expire after CREDENTIAL_LIFETIME_SECONDS"
    );
    Ok(lifetime)
}

/// `IAM_ADMIN_FROM_TEAM` (ADR-0962, ADR-0963; plans/team-access.md §6): where
/// `is_admin` comes from, relayed to `iam-db` on every `ResolveCredential` and
/// `CreateEnrolment`, and the switch that retires `SetUserAdmin`.
///
/// REQUIRED, like the lifetime: no compiled-in default (ADR-0569). The chart
/// renders it from `adminFromTeam`, whose shipped value is `false`, so an
/// auto-pinned iam changes nothing until a deployment turns it on.
pub fn admin_from_team() -> Result<bool, Box<dyn std::error::Error>> {
    let raw = env_required(ADMIN_FROM_TEAM_ENV)
        .map_err(|e| format!("{e} Set the chart's {ADMIN_FROM_TEAM_CHART_KEY}."))?;
    let on = parse_admin_from_team(&raw)?;
    tracing::info!(
        admin_from_team = on,
        "IAM_ADMIN_FROM_TEAM: is_admin comes from the administrators team when true, \
         from the is_admin column when false"
    );
    Ok(on)
}
