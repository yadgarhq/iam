"""B-N3: the CONTRACT step for iam's NATS client TLS switch (ADR-0852,
ADR-0845, ADR-0885). The twin of gateway#105.

WHAT THE CONTRACT DOES, AFTER THE EXPAND (B-N3E) AND THE PARENT FIXTURE
(yadgarhq/chart, B-P2) landed: `nats.tls.enabled` becomes REQUIRED with no
default — `chart/values.schema.json` marks it, and
`templates/render-checks.yaml` carries the K-1 guard every other
required-no-default switch in this chart already does. The expand's `true
is refused` line is LIFTED: this chart version renders `NATS_TLS_CA_FILE`
and, when a Secret is named, the client pair, whenever `nats.tls.enabled`
is `true`.

ADR-0885, THE PREMISE CORRECTION THIS UNIT SHIPPED WITH: the B-N3 plan card
assumed `iam` already shares one client-identity mount across every
upstream, the way `gateway` does. It does not — `iam`'s only client leaf
mount before this release was `iam-db-client-cert`, rendered only under
`iamDb.tls.enabled` + `iamDb.tls.clientCertSecret`. So the broker's client
identity gets its OWN chart key, `nats.tls.clientCertSecret`, with its OWN
mount at its OWN path, independent of every `iamDb.tls` key — tested below
as the INDEPENDENCE case.

Run: python3 -m pytest scripts/tests/ -q
"""

from __future__ import annotations

from pathlib import Path

import yaml

from test_values_schema import CHART, SCHEMA_WRAPPER, helm, objects, render

NOT_BOOL = "iam: nats.tls.enabled must be set to true or false; it renders NATS_TLS_ENABLED (ADR-0845, ADR-0797)"

# The two switches every render needs (ADR-0845), and the client-auth mode
# (ADR-0854, B-U5), so only `nats.tls` is under test. Stated here rather than
# read from `chart/ci/values.yaml`, because that file states `nats.tls.enabled`
# too and the ABSENT case must not see it.
SWITCHES = {"tls": {"enabled": True, "clientAuth": "off"}, "iamDb": {"tls": {"enabled": True}}}


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


def volume_names(stdout: str) -> set[str]:
    (deployment,) = [o for o in objects(stdout) if o["kind"] == "Deployment"]
    spec = deployment["spec"]["template"]["spec"]
    return {v["name"] for v in spec.get("volumes", [])}


def refused(result, sentence: str) -> None:
    assert result.returncode != 0, result.stdout
    assert sentence in result.stderr, result.stderr


# ── 1. ABSENT OR NON-BOOL: REFUSED, no chart default behind it ──────────────


def test_an_absent_nats_tls_block_is_a_schema_refusal(tmp_path):
    result = bare(overlay(tmp_path))
    assert result.returncode != 0, result.stdout
    assert SCHEMA_WRAPPER in result.stdout + result.stderr
    assert "enabled" in result.stdout + result.stderr


def test_an_empty_nats_tls_map_is_a_schema_refusal(tmp_path):
    """Presence is `enabled`, never the `tls` map — `{}` is a map with no
    `enabled` key, which the schema's `required: [enabled]` refuses."""
    result = bare(overlay(tmp_path, {}))
    schema_refused(result, "nats.tls")
    assert "enabled" in result.stdout + result.stderr


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


def test_a_quoted_enabled_is_a_schema_refusal(tmp_path):
    schema_refused(bare(overlay(tmp_path, {"enabled": "false"})), "nats.tls.enabled")


# ── 2. FALSE: the literal "0" on the wire, and nothing else ────────────────


def test_false_renders_the_literal_zero_and_nothing_else(tmp_path):
    result = bare(overlay(tmp_path, {"enabled": False}))
    assert result.returncode == 0, result.stderr
    assert nats_env(result.stdout) == {"NATS_TLS_ENABLED": "0"}
    assert "nats-ca" not in volume_names(result.stdout)
    assert "nats-client-cert" not in volume_names(result.stdout)


def test_the_ci_values_state_false():
    """`chart/ci/values.yaml` is the fixture every offline gate renders with —
    unchanged from the B-N3E expand, because platform's broker does not serve
    TLS until B-L1."""
    result = render(CHART)
    assert result.returncode == 0, result.stderr
    assert nats_env(result.stdout) == {"NATS_TLS_ENABLED": "0"}


# ── 3. TRUE: no longer refused — the CA renders, the client pair is opt-in ──


def test_true_with_no_client_secret_renders_the_ca_only(tmp_path):
    result = bare(
        overlay(
            tmp_path,
            {"enabled": True, "caSecret": "nats-tls", "caSecretKey": "ca.crt", "clientCertSecret": ""},
        )
    )
    assert result.returncode == 0, result.stderr
    assert nats_env(result.stdout) == {
        "NATS_TLS_ENABLED": "1",
        "NATS_TLS_CA_FILE": "/var/run/config/nats-ca/ca.pem",
    }
    volumes = volume_names(result.stdout)
    assert "nats-ca" in volumes
    assert "nats-client-cert" not in volumes


def test_true_with_a_client_secret_renders_the_whole_identity(tmp_path):
    result = bare(
        overlay(
            tmp_path,
            {
                "enabled": True,
                "caSecret": "nats-tls",
                "caSecretKey": "ca.crt",
                "clientCertSecret": "iam-client-tls",
                "clientCertSecretKey": "tls.crt",
                "clientKeySecretKey": "tls.key",
            },
        )
    )
    assert result.returncode == 0, result.stderr
    assert nats_env(result.stdout) == {
        "NATS_TLS_ENABLED": "1",
        "NATS_TLS_CA_FILE": "/var/run/config/nats-ca/ca.pem",
        "NATS_TLS_CLIENT_CERT_FILE": "/var/run/secrets/nats-client-tls/client.pem",
        "NATS_TLS_CLIENT_KEY_FILE": "/var/run/secrets/nats-client-tls/client-key.pem",
    }
    assert {"nats-ca", "nats-client-cert"} <= volume_names(result.stdout)


def test_the_ci_values_plus_true_render_the_default_client_identity():
    """Over `chart/ci/values.yaml`'s baseline, flipping just `enabled` reaches
    the real default `clientCertSecret` this chart's own `values.yaml` ships
    (`iam-client-tls`), not a sentinel this test invented."""
    result = render(CHART, "--set", "nats.tls.enabled=true")
    assert result.returncode == 0, result.stderr
    env = nats_env(result.stdout)
    assert env["NATS_TLS_CLIENT_CERT_FILE"] == "/var/run/secrets/nats-client-tls/client.pem"
    assert {"nats-ca", "nats-client-cert"} <= volume_names(result.stdout)


# ── 4. ADR-0885 INDEPENDENCE: the broker's identity does not read `iamDb.tls` ──


def test_the_brokers_identity_renders_whatever_iam_db_tls_states(tmp_path):
    """THE PREMISE CORRECTION ITSELF, PROVED: `nats.tls`'s client pair and CA
    render identically whether `iamDb.tls.enabled` is true or false, and the
    render reads NO `iamDb.tls` key to decide. Mutate this chart's own
    `and .Values.nats.tls.enabled .Values.nats.tls.clientCertSecret` guard to
    additionally require `.Values.iamDb.tls.enabled` and this case goes red."""
    outcomes = []
    for iam_db_enabled in (True, False):
        body = {
            "tls": dict(SWITCHES["tls"]),
            "iamDb": {"tls": {"enabled": iam_db_enabled}},
            "nats": {
                "tls": {
                    "enabled": True,
                    "caSecret": "nats-tls",
                    "caSecretKey": "ca.crt",
                    "clientCertSecret": "iam-client-tls",
                    "clientCertSecretKey": "tls.crt",
                    "clientKeySecretKey": "tls.key",
                }
            },
        }
        path = tmp_path / f"independence-{iam_db_enabled}.yaml"
        path.write_text(yaml.safe_dump(body))
        result = bare(path)
        assert result.returncode == 0, result.stderr
        outcomes.append(nats_env(result.stdout))
    assert outcomes[0] == outcomes[1], (
        "the broker's NATS_TLS_* variables must not depend on iamDb.tls.enabled: "
        f"{outcomes}"
    )
    assert outcomes[0]["NATS_TLS_CLIENT_CERT_FILE"] == "/var/run/secrets/nats-client-tls/client.pem"


def test_the_brokers_client_secret_is_a_separate_volume_from_iam_dbs(tmp_path):
    """Even when both name THE SAME Secret (the real default, `iam-client-tls`),
    the two render as DISTINCT volumes at DISTINCT mount paths — never one
    volume shared between two mounts, which would make the two hops' identity
    a single lever instead of two."""
    body = {
        "tls": dict(SWITCHES["tls"]),
        "iamDb": {
            "tls": {
                "enabled": True,
                "clientCertSecret": "iam-client-tls",
            }
        },
        "nats": {
            "tls": {
                "enabled": True,
                "caSecret": "nats-tls",
                "caSecretKey": "ca.crt",
                "clientCertSecret": "iam-client-tls",
                "clientCertSecretKey": "tls.crt",
                "clientKeySecretKey": "tls.key",
            }
        },
    }
    path = tmp_path / "shared-secret-name.yaml"
    path.write_text(yaml.safe_dump(body))
    result = bare(path)
    assert result.returncode == 0, result.stderr
    (deployment,) = [o for o in objects(result.stdout) if o["kind"] == "Deployment"]
    volumes = {
        v["name"]: v["secret"]["secretName"]
        for v in deployment["spec"]["template"]["spec"]["volumes"]
        if "secret" in v
    }
    assert volumes["iam-db-client-cert"] == "iam-client-tls"
    assert volumes["nats-client-cert"] == "iam-client-tls"
    container = deployment["spec"]["template"]["spec"]["containers"][0]
    mounts = {m["name"]: m["mountPath"] for m in container["volumeMounts"]}
    assert mounts["iam-db-client-cert"] == "/var/run/secrets/iam-client-tls"
    assert mounts["nats-client-cert"] == "/var/run/secrets/nats-client-tls"
    assert mounts["iam-db-client-cert"] != mounts["nats-client-cert"]


# ── 5. WRONG SHAPES: the schema's wrapper plus the path ─────────────────────


def schema_refused(result, path: str) -> None:
    assert result.returncode != 0, result.stdout
    combined = result.stdout + result.stderr
    assert SCHEMA_WRAPPER in combined, combined
    assert f"/{path.replace('.', '/')}" in combined or path in combined, combined


def test_a_null_nats_tls_block_is_refused(tmp_path):
    """REFUSED, but by the RENDER CHECK rather than the schema (measured —
    this is the one case in this file where the two differ on WHICH guard
    fires, and the reason is worth stating rather than asserting past).

    `nats: {tls: null}` in an OVERLAY does not survive merging as a null
    VALUE the way `{"tls": {"enabled": null}}` does in
    `test_a_null_enabled_...` elsewhere in this suite — Helm's values
    coalescing treats an explicit `null` as "delete this key", so the
    MERGED result has no `nats.tls` key at all, not a `tls` key holding
    `null`. `nats.tls` is optional at the PARENT `nats` object's own schema
    (no `required: ["tls"]` there), so an absent key — deleted or never
    stated — passes validation at that level; the nested
    `nats.tls.required: ["enabled"]` is only ever evaluated once `tls`
    exists as an object to check it against. The null case therefore
    reaches `templates/render-checks.yaml`'s own `kindIs "map"` guard, which
    treats a nil the same as any other non-map and fires `NOT_BOOL` by name.
    Compare `test_an_absent_nats_tls_block_is_a_schema_refusal` above: there
    the key is simply never MENTIONED in the overlay, so the chart's own
    `values.yaml` default (missing only `enabled`) survives the merge and
    IS present for the schema to find incomplete.
    """
    refused(bare(overlay(tmp_path, None)), NOT_BOOL)


def test_a_non_map_nats_tls_is_a_schema_refusal(tmp_path):
    """Without `type: object` a string `tls` would render nothing, silently."""
    schema_refused(bare(overlay(tmp_path, "on")), "nats.tls")


def test_an_unknown_key_under_nats_tls_is_a_schema_refusal(tmp_path):
    result = bare(overlay(tmp_path, {"enabled": False, "verify": True}))
    schema_refused(result, "nats.tls")
    assert "verify" in result.stdout + result.stderr
