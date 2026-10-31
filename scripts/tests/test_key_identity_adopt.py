"""`keyIdentity.adopt` (ADR-1085, ADR-1089).

The binary refuses to boot without `KEY_IDENTITY_ADOPT` and reads it as exactly
"observe" or "adopt". A wrong value writes trust into iam-db or exits every
pod. The binary has no default, but the chart ships `observe` (Max, 2026-10-31;
`adminFromTeam`'s precedent), so a parent chart that omits the key still renders
and runs read-only. The chart must render the default, render each of the two
values, and refuse by name every value the binary would refuse at boot, a
deleted key included.
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
ENV = "KEY_IDENTITY_ADOPT"
KEY = "keyIdentity.adopt"


def helm(*arguments: str) -> subprocess.CompletedProcess[str]:
    binary = shutil.which("helm")
    # NOT A SKIP (ADR-0650): a pass reported without helm is a pass nobody earned.
    assert binary, "helm is not on PATH; install it rather than skipping"
    return subprocess.run([binary, *arguments], capture_output=True, text=True)


def render(*arguments: str) -> subprocess.CompletedProcess[str]:
    return helm("template", "x", str(CHART), "-f", str(CI_VALUES), *arguments)


def env_value(stdout: str) -> str | None:
    for document in yaml.safe_load_all(stdout):
        if not isinstance(document, dict) or document.get("kind") != "Deployment":
            continue
        for container in document["spec"]["template"]["spec"]["containers"]:
            for env in container.get("env", []):
                if env["name"] == ENV:
                    return env["value"]
    return None


def test_the_chart_ships_observe():
    shipped = yaml.safe_load((CHART / "values.yaml").read_text())
    assert shipped["keyIdentity"] == {"adopt": "observe"}


def test_the_schema_stays_closed():
    schema = json.loads((CHART / "values.schema.json").read_text())
    assert schema["properties"]["keyIdentity"]["additionalProperties"] is False


def test_no_override_renders_the_default_observe():
    done = render()
    assert done.returncode == 0, done.stderr
    assert env_value(done.stdout) == "observe"


def test_each_value_renders_into_the_env():
    for value in ["observe", "adopt"]:
        done = render("--set", f"{KEY}={value}")
        assert done.returncode == 0, done.stderr
        assert env_value(done.stdout) == value


def test_every_other_value_is_refused_naming_the_key_and_the_variable():
    for flag, raw in [
        ("--set-string", "Observe"),
        ("--set-string", "true"),
        ("--set-string", ""),
        ("--set", "true"),
        ("--set", "null"),
    ]:
        done = render(flag, f"{KEY}={raw}")
        assert done.returncode != 0, raw
        assert KEY in done.stderr and ENV in done.stderr, done.stderr


def test_a_non_map_block_is_refused_naming_the_key():
    done = render("--set", "keyIdentity=adopt")
    assert done.returncode != 0
    assert KEY in done.stderr, done.stderr
