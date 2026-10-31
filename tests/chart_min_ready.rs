//! The chart's `minReadySeconds` is this Deployment's only canary for the
//! key-identity check, and this is where that stops being a comment
//! (yaadgaar 500).
//!
//! The check ends the serve on `MISMATCH` or a failed adoption proof. Against
//! a reachable `iam-db` it decides within milliseconds of boot, before the
//! `tcpSocket` readiness probe makes the pod Ready (2-4 s,
//! `initialDelaySeconds: 2`), so the pod exits unready and the field adds
//! nothing. When the decision is delayed past readiness by the retry backoff —
//! 10-12 s was seen live while `iam-db` was still rolling — `minReadySeconds: 0`
//! with `maxUnavailable: 0` let the rollout count that pod available and
//! replace every old pod before the first new one exited. A pod must stay Ready
//! for `minReadySeconds` before it counts, so a value above the delayed
//! decision time holds the old pods back.
//!
//! Every number is pinned by a LITERAL (ADR-0599).

use std::path::PathBuf;

use serde_json::Value;

/// The longest DELAYED key-identity decision observed after boot, in seconds:
/// 2026-10-31 on kind-yadgar, iam 0.18.0 against a rolling `iam-db`.
const OBSERVED_DECISION_SECS: u64 = 12;

fn read(relative: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|why| panic!("{} must be readable: {why}", path.display()))
}

/// The TOP-LEVEL `minReadySeconds:` in `chart/values.yaml`. Anchored at the
/// start of the line, so the key named in a prose comment never matches; a
/// missing or duplicated key panics rather than defaulting.
fn values_default() -> u64 {
    let values = read("chart/values.yaml");
    let found: Vec<&str> = values
        .lines()
        .filter_map(|line| line.strip_prefix("minReadySeconds:"))
        .map(|rest| rest.split('#').next().unwrap_or_default().trim())
        .collect();
    assert_eq!(
        found.len(),
        1,
        "expected one top-level `minReadySeconds:`, got {found:?}"
    );
    found[0]
        .parse()
        .unwrap_or_else(|why| panic!("`{}` is not a whole number: {why}", found[0]))
}

#[test]
fn the_default_outlasts_the_key_identity_decision() {
    let default = values_default();
    assert_eq!(default, 30, "the shipped default moved");
    assert!(
        default > 2 * OBSERVED_DECISION_SECS,
        "minReadySeconds {default} leaves too little margin over the {OBSERVED_DECISION_SECS}s \
         key-identity decision: a pod that exits on MISMATCH could count available first"
    );
}

#[test]
fn the_deployment_renders_it_from_the_chart_key() {
    let deployment = read("chart/templates/deployment.yaml");
    let at = deployment
        .find("{{- with .Values.minReadySeconds }}")
        .expect("deployment.yaml must render minReadySeconds from `.Values.minReadySeconds`");
    let block: String = deployment[at..]
        .lines()
        .skip_while(|l| l.trim_start().starts_with('#') || l.contains("{{- with"))
        .take(1)
        .collect();
    assert_eq!(
        block.trim(),
        "minReadySeconds: {{ . }}",
        "the guarded block must render the field itself"
    );
    let spec = deployment
        .find("\nspec:\n")
        .expect("the Deployment has a spec");
    let template = deployment
        .find("\n  template:\n")
        .expect("the Deployment has a pod template");
    assert!(
        spec < at && at < template,
        "minReadySeconds is a Deployment spec field, not a pod spec field"
    );
}

#[test]
fn the_schema_admits_the_key() {
    let schema: Value = serde_json::from_str(&read("chart/values.schema.json"))
        .expect("chart/values.schema.json must be valid JSON");
    assert!(
        schema["properties"]["minReadySeconds"].is_object(),
        "the schema closes its root, so an undeclared `minReadySeconds` is refused at render"
    );
}
