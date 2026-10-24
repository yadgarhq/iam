//! The chart's `server.limits` are the listener's protocol limits, and this is
//! where the chart's numbers stop being comments (ADR-1006, yaadgaar #218).
//!
//! `chart/values.schema.json` states a `minimum` and a `maximum` per key, and
//! `yadgar_lifecycle::serve_tls::ServerLimits` states the same ranges as consts.
//! Nothing held them together: bump the pin to a library that widens or narrows a
//! range, and the chart would admit a value the binary refuses at boot. This test
//! reds on that bump, beside the numbers it compares.
//!
//! Every default and every bound is also pinned by a LITERAL (ADR-0599), so a
//! change to a const and the chart together is still a deliberate edit here.

use std::ops::RangeInclusive;
use std::path::PathBuf;

use serde_json::Value;
use yadgar_lifecycle::serve_tls::ServerLimits;

fn read(relative: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|why| panic!("{} must be readable: {why}", path.display()))
}

/// leaf, env variable, ADR-1006 default, the literal range, the library's const.
type Row = (
    &'static str,
    &'static str,
    u64,
    (u64, u64),
    RangeInclusive<u64>,
);

fn rows() -> Vec<Row> {
    vec![
        (
            "maxConcurrentStreams",
            "LISTEN_MAX_CONCURRENT_STREAMS",
            256,
            (1, 10_000),
            ServerLimits::MAX_CONCURRENT_STREAMS,
        ),
        (
            "keepaliveIntervalSeconds",
            "LISTEN_KEEPALIVE_INTERVAL_SECS",
            30,
            (1, 3_600),
            ServerLimits::KEEPALIVE_INTERVAL_SECS,
        ),
        (
            "keepaliveTimeoutSeconds",
            "LISTEN_KEEPALIVE_TIMEOUT_SECS",
            10,
            (1, 600),
            ServerLimits::KEEPALIVE_TIMEOUT_SECS,
        ),
        (
            "maxHeaderListBytes",
            "LISTEN_MAX_HEADER_LIST_BYTES",
            16_384,
            (1_024, 1_048_576),
            ServerLimits::MAX_HEADER_LIST_BYTES,
        ),
    ]
}

fn schema_block() -> Value {
    let schema: Value = serde_json::from_str(&read("chart/values.schema.json"))
        .expect("chart/values.schema.json must be valid JSON");
    let block = schema["properties"]["server"]["properties"]["limits"].clone();
    assert!(block.is_object(), "the schema has no `server.limits` block");
    block
}

#[test]
fn the_schema_requires_all_four_as_integers() {
    let block = schema_block();
    let required: Vec<&str> = block["required"]
        .as_array()
        .expect("`server.limits` must list `required` keys")
        .iter()
        .map(|k| k.as_str().unwrap())
        .collect();
    for (leaf, _, _, _, _) in rows() {
        assert!(
            required.contains(&leaf),
            "`{leaf}` must be `required`: the binary has no default"
        );
        assert_eq!(block["properties"][leaf]["type"], "integer", "{leaf}");
    }
    assert_eq!(block["properties"].as_object().unwrap().len(), 4);
    assert_eq!(block["additionalProperties"], false);
}

#[test]
fn the_schema_bounds_are_the_library_bounds() {
    let block = schema_block();
    for (leaf, _, _, (min, max), range) in rows() {
        let property = &block["properties"][leaf];
        let minimum = property["minimum"].as_u64().expect("`minimum` must be set");
        let maximum = property["maximum"].as_u64().expect("`maximum` must be set");
        assert_eq!(
            (minimum, maximum),
            (*range.start(), *range.end()),
            "{leaf}: the chart's bounds are not the range the pinned library refuses outside"
        );
        assert_eq!((minimum, maximum), (min, max), "{leaf}: the range moved");
    }
}

/// The value stated under `server:` / `limits:` in `chart/values.yaml`.
fn values_default(leaf: &str) -> u64 {
    let values = read("chart/values.yaml");
    let mut in_server = false;
    let mut found = Vec::new();
    for line in values.lines() {
        if !line.starts_with(' ') && !line.starts_with('#') && !line.is_empty() {
            in_server = line.starts_with("server:");
        }
        if in_server {
            if let Some(rest) = line.strip_prefix(&format!("    {leaf}:")) {
                found.push(
                    rest.split('#')
                        .next()
                        .unwrap_or_default()
                        .trim()
                        .to_string(),
                );
            }
        }
    }
    assert_eq!(
        found.len(),
        1,
        "expected one `server.limits.{leaf}`, got {found:?}"
    );
    found[0]
        .parse()
        .unwrap_or_else(|why| panic!("`{}` is not an integer: {why}", found[0]))
}

#[test]
fn the_defaults_are_the_ruled_ones_and_inside_the_library_ranges() {
    for (leaf, _, default, _, range) in rows() {
        let stated = values_default(leaf);
        assert_eq!(stated, default, "{leaf}: the ADR-1006 default moved");
        assert!(
            range.contains(&stated),
            "{leaf}: the chart default {stated} is outside the range the binary accepts"
        );
    }
    assert!(
        values_default("keepaliveTimeoutSeconds") < values_default("keepaliveIntervalSeconds"),
        "the keepalive timeout must stay below the interval, or the binary refuses to boot"
    );
}

#[test]
fn the_deployment_renders_each_variable_from_its_chart_key() {
    let deployment = read("chart/templates/deployment.yaml");
    for (leaf, variable, _, _, _) in rows() {
        let at = deployment
            .find(&format!("- name: {variable}\n"))
            .unwrap_or_else(|| panic!("deployment.yaml must render {variable}"));
        let next: String = deployment[at..]
            .lines()
            .take(2)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            next.contains(&format!(".Values.server.limits.{leaf}")),
            "{variable} is not rendered from `server.limits.{leaf}`: {next}"
        );
    }
}
