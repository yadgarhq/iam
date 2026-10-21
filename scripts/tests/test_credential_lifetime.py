"""`credential.lifetimeSeconds` (ADR-0972 (3), ledger 1628, train step I1d).

The binary refuses to boot without `CREDENTIAL_LIFETIME_SECONDS`, so this chart
must render it, from a value it ships, and refuse at render every value the
binary would refuse at boot: absent, non-integer, zero or negative, and above
`IssueCredential`'s ten-year bound. Each refusal is a named sentence that names
the key, from `templates/render-checks.yaml`.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
CHART = REPO / "chart"
CI_VALUES = CHART / "ci" / "values.yaml"
KEY = "credential.lifetimeSeconds"


def helm(*arguments: str) -> subprocess.CompletedProcess[str]:
    binary = shutil.which("helm")
    # NOT A SKIP (ADR-0650): a pass reported without helm is a pass nobody earned.
    assert binary, "helm is not on PATH; install it rather than skipping"
    return subprocess.run([binary, *arguments], capture_output=True, text=True)


def render(*arguments: str) -> subprocess.CompletedProcess[str]:
    return helm("template", "x", str(CHART), "-f", str(CI_VALUES), *arguments)


def render_with(tmp_path: Path, credential) -> subprocess.CompletedProcess[str]:
    overlay = tmp_path / "credential.yaml"
    overlay.write_text(yaml.safe_dump({"credential": credential}))
    return render("-f", str(overlay))


def lifetime_env(stdout: str) -> str | None:
    for document in yaml.safe_load_all(stdout):
        if not isinstance(document, dict) or document.get("kind") != "Deployment":
            continue
        for container in document["spec"]["template"]["spec"]["containers"]:
            for env in container.get("env", []):
                if env["name"] == "CREDENTIAL_LIFETIME_SECONDS":
                    return env["value"]
    return None


def test_the_default_renders_ninety_days_into_the_env():
    done = render()
    assert done.returncode == 0, done.stderr
    assert lifetime_env(done.stdout) == "7776000"


def test_an_override_renders_as_a_whole_number_not_a_float():
    # YAML numbers reach helm as float64, and `quote` on a float64 renders
    # `7.776e+06`, which the binary refuses. So large values are pinned too.
    done = render("--set", f"{KEY}=315360000")
    assert done.returncode == 0, done.stderr
    assert lifetime_env(done.stdout) == "315360000"


def test_the_schema_admits_credential_lifetime_seconds():
    schema = json.loads((CHART / "values.schema.json").read_text())
    block = schema["properties"]["credential"]
    assert block["properties"] == {"lifetimeSeconds": {}}
    assert block["additionalProperties"] is False


def test_the_closed_block_refuses_a_misspelled_key(tmp_path):
    done = render_with(tmp_path, {"lifetimeSeconds": 60, "lifetimeSecs": 60})
    assert done.returncode != 0
    assert "lifetimeSecs" in done.stderr


def test_a_missing_lifetime_is_refused_naming_the_key(tmp_path):
    # A null DELETES the key in helm and restores no default, which is how an
    # override actually produces "missing". (`credential: {}` merges and keeps
    # the chart default, so it is not a missing value.)
    for body in [None, {"lifetimeSeconds": None}]:
        done = render_with(tmp_path, body)
        assert done.returncode != 0, f"{body!r} rendered"
        assert KEY in done.stderr, done.stderr
        assert "must be set" in done.stderr, done.stderr


def test_a_non_integer_lifetime_is_refused_naming_the_key(tmp_path):
    for value in ["90d", 1.5, "7776000", True]:
        done = render_with(tmp_path, {"lifetimeSeconds": value})
        assert done.returncode != 0, f"{value!r} rendered"
        assert KEY in done.stderr, done.stderr
        assert "whole number of seconds" in done.stderr, done.stderr


def test_a_zero_or_negative_lifetime_is_refused_naming_the_key(tmp_path):
    for value in [0, -1]:
        done = render_with(tmp_path, {"lifetimeSeconds": value})
        assert done.returncode != 0, f"{value!r} rendered"
        assert KEY in done.stderr, done.stderr
        assert "no \"never expires\" value" in done.stderr, done.stderr


def test_a_lifetime_above_ten_years_is_refused_naming_the_key(tmp_path):
    done = render_with(tmp_path, {"lifetimeSeconds": 315360001})
    assert done.returncode != 0
    assert KEY in done.stderr, done.stderr
    assert "ten years" in done.stderr, done.stderr


def test_helm_lint_strict_passes_at_the_defaults():
    done = helm("lint", "--strict", str(CHART), "-f", str(CI_VALUES))
    assert done.returncode == 0, done.stdout + done.stderr
