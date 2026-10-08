"""B-N3E: the EXPAND step for iam's NATS client TLS switch (ADR-0852,
ADR-0845, K-8 of the October ledger sweep). The twin of gateway#104.

WHAT AN EXPAND IS, AND WHY THIS ONE IS CHART-ONLY. Every iam release is
pinned into the parent chart with no PR CI, and this chart's schema closes
the `nats` block (`additionalProperties: false`, ledger 990). So the parent
cannot state `iam.nats.tls.enabled` until an iam release DECLARES it, and a
release that made the key required at once would turn every parent render
red the moment it was pinned. K-8 therefore moves the key in three steps:

  1. EXPAND (this file): the schema declares `nats.tls.enabled`; the
     template renders `NATS_TLS_ENABLED` only when `enabled` is present and
     validates it when present; the binary is unchanged. An absent key
     renders exactly what `origin/main` renders.
  2. FIXTURE (yadgarhq/chart, B-P2): the parent states `enabled: false`.
  3. CONTRACT (B-N3): the binary dials TLS and requires the variable; the
     schema makes `enabled` required; the CA mount lands.

`enabled: true` IS REFUSED IN THIS STEP. The binary does not read
`NATS_TLS_ENABLED` until B-N3, and platform's NATS serves no TLS until B-L1,
so a values file that says `true` would look encrypted while the hop stays
cleartext. B-N3 lifts the refusal.

THE SHAPE IS gateway#104's, RULED FOR BOTH REPOS: the schema declares
`nats.tls` as a closed `type: object` with `enabled: {type: boolean}` and no
`required`, so a null, a quoted string or a non-map `tls` is a SCHEMA refusal
(asserted as the stable wrapper plus the path, never helm's wording), and
`true` is refused by `templates/render-checks.yaml`'s own sentence (asserted
whole).

Run: python3 -m pytest scripts/tests/ -q
"""

from __future__ import annotations

from pathlib import Path

import yaml

from test_values_schema import CHART, SCHEMA_WRAPPER, helm, objects, render

NOT_BOOL = (
    "iam: nats.tls.enabled must be true or false when it is set; it renders "
    "NATS_TLS_ENABLED (ADR-0845, ADR-0797)"
)

REFUSE_TRUE = (
    "iam: nats.tls.enabled: true is refused by this chart version: it declares the key, "
    "but the binary reads NATS_TLS_ENABLED only from B-N3 and the broker serves no TLS "
    "until B-L1. Set it to false (ADR-0845, ADR-0852)"
)

# The two switches every render needs (ADR-0845), so only `nats.tls` is under
# test. Stated here rather than read from `chart/ci/values.yaml`, because that
# file states `nats.tls.enabled` too and the ABSENT case must not see it.
SWITCHES = {"tls": {"enabled": True}, "iamDb": {"tls": {"enabled": True}}}


def overlay(tmp_path: Path, nats_tls=..., **nats) -> Path:
    body = {"tls": dict(SWITCHES["tls"]), "iamDb": {"tls": dict(SWITCHES["iamDb"]["tls"])}}
    if nats_tls is not ...:
        nats["tls"] = nats_tls
    if nats:
        body["nats"] = nats
    path = tmp_path / "values.yaml"
    path.write_text(yaml.safe_dump(body))
    return path


def bare(path: Path):
    """Rendered WITHOUT `chart/ci/values.yaml`, over this overlay only."""
    return helm("template", "x", str(CHART), "-f", str(path))


def nats_env(stdout: str) -> dict[str, str]:
    (deployment,) = [o for o in objects(stdout) if o["kind"] == "Deployment"]
    (container,) = deployment["spec"]["template"]["spec"]["containers"]
    return {
        e["name"]: e.get("value")
        for e in container.get("env", [])
        if e["name"].startswith("NATS_TLS_")
    }


def refused(result, sentence: str) -> None:
    assert result.returncode != 0, result.stdout
    assert sentence in result.stderr, result.stderr


# ── 1. ABSENT: the render origin/main produces, with no NATS_TLS_* at all ───


def test_an_absent_nats_tls_enabled_renders_no_nats_tls_variable(tmp_path):
    result = bare(overlay(tmp_path))
    assert result.returncode == 0, result.stderr
    assert nats_env(result.stdout) == {}


def test_an_empty_nats_tls_map_renders_no_nats_tls_variable(tmp_path):
    """Presence is `enabled`, never the `tls` map: B-N3 adds the CA keys beside
    it, and a map holding only those must not state the switch."""
    result = bare(overlay(tmp_path, {}))
    assert result.returncode == 0, result.stderr
    assert nats_env(result.stdout) == {}


# ── 2. PRESENT AND FALSE: the literal "0" on the wire, and nothing else ─────


def test_false_renders_the_literal_zero_and_nothing_else(tmp_path):
    result = bare(overlay(tmp_path, {"enabled": False}))
    assert result.returncode == 0, result.stderr
    assert nats_env(result.stdout) == {"NATS_TLS_ENABLED": "0"}


def test_the_ci_values_state_false():
    """`chart/ci/values.yaml` is the fixture every offline gate renders with."""
    result = render(CHART)
    assert result.returncode == 0, result.stderr
    assert nats_env(result.stdout) == {"NATS_TLS_ENABLED": "0"}


# ── 3. PRESENT AND TRUE: refused until the contract ─────────────────────────


def test_true_is_refused_by_the_designed_sentence(tmp_path):
    refused(bare(overlay(tmp_path, {"enabled": True})), REFUSE_TRUE)


# ── 4. WRONG SHAPES: the schema's wrapper plus the path ─────────────────────


def schema_refused(result, path: str) -> None:
    assert result.returncode != 0, result.stdout
    combined = result.stdout + result.stderr
    assert SCHEMA_WRAPPER in combined, combined
    assert f"/{path.replace('.', '/')}" in combined or path in combined, combined


def test_a_quoted_enabled_is_a_schema_refusal(tmp_path):
    schema_refused(bare(overlay(tmp_path, {"enabled": "false"})), "nats.tls.enabled")


def test_a_null_enabled_is_a_schema_refusal(tmp_path):
    """`values.yaml` declares no `nats.tls`, so a null `enabled` survives
    coalescing and the schema's `type: boolean` refuses it before the
    template guard is reached."""
    schema_refused(bare(overlay(tmp_path, {"enabled": None})), "nats.tls.enabled")


def test_a_null_nats_tls_block_is_a_schema_refusal(tmp_path):
    schema_refused(bare(overlay(tmp_path, None)), "nats.tls")


def test_a_non_map_nats_tls_is_a_schema_refusal(tmp_path):
    """Without `type: object` a string `tls` would render nothing, silently."""
    schema_refused(bare(overlay(tmp_path, "on")), "nats.tls")


def test_an_unknown_key_under_nats_tls_is_a_schema_refusal(tmp_path):
    result = bare(overlay(tmp_path, {"enabled": False, "verify": True}))
    schema_refused(result, "nats.tls")
    assert "verify" in result.stdout + result.stderr


def test_a_null_enabled_past_the_schema_is_the_render_check_sentence(tmp_path):
    """`--skip-schema-validation` is how a render reaches the templates with a
    null `enabled` (hasKey true, not a bool). Without the render check, the
    `ternary` in `templates/deployment.yaml` fails with Go's type error, which
    names no key; the check must refuse first, with its own sentence."""
    path = overlay(tmp_path, {"enabled": None})
    refused(
        helm("template", "x", str(CHART), "-f", str(path), "--skip-schema-validation"),
        NOT_BOOL,
    )
