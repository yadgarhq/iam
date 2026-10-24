"""`adminFromTeam` (team access stage 3, docs plans/team-access.md §6).

The binary refuses to boot without `IAM_ADMIN_FROM_TEAM` and reads it as
exactly "true" or "false". So this chart must render it from a value it ships
(`false`, so an auto-pinned iam changes nothing), render `true` when a
deployment turns it on, and refuse at render, by name, every value the binary
would refuse at boot.
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
ENV = "IAM_ADMIN_FROM_TEAM"


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


def test_the_shipped_value_is_false():
    shipped = yaml.safe_load((CHART / "values.yaml").read_text())
    assert shipped["adminFromTeam"] is False


def test_the_default_renders_false_into_the_env():
    done = render()
    assert done.returncode == 0, done.stderr
    assert env_value(done.stdout) == "false"


def test_true_renders_true_into_the_env():
    done = render("--set", "adminFromTeam=true")
    assert done.returncode == 0, done.stderr
    assert env_value(done.stdout) == "true"


def test_the_schema_admits_the_key():
    schema = json.loads((CHART / "values.schema.json").read_text())
    assert "adminFromTeam" in schema["properties"]


def test_a_string_is_refused_naming_the_key():
    for raw in ["false", "true", "yes"]:
        done = render("--set-string", f"adminFromTeam={raw}")
        assert done.returncode != 0, raw
        assert "adminFromTeam" in done.stderr, done.stderr
        assert ENV in done.stderr, done.stderr


def test_a_deleted_key_is_refused_naming_the_key():
    done = render("--set", "adminFromTeam=null")
    assert done.returncode != 0
    assert "adminFromTeam" in done.stderr, done.stderr
