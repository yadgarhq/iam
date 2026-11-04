"""THE NUMBER 0, A YAML NULL AND AN ABSENT KEY STILL RENDER NO FIELD (yaadgaar 639, AC4).

`terminationGracePeriodSeconds`, `preStopSleepSeconds` and `minReadySeconds` sit behind
`{{- with }}`, which skips nil and the number 0. chart/values.yaml:690-691: "`0` renders
nothing and returns the field to kubelet's 30s default." The string "0" is refused by name
(AC1-AC3); this file pins that the NUMBER 0 and null are NOT refused and render nothing.

Run: python3 -m pytest scripts/tests/test_zero_number_still_omits.py -q
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
CHART = REPO / "chart"
CI_VALUES = CHART / "ci" / "values.yaml"

KEYS = ("terminationGracePeriodSeconds", "preStopSleepSeconds", "minReadySeconds")


def helm(*arguments: str) -> subprocess.CompletedProcess[str]:
    binary = shutil.which("helm")
    # NOT A SKIP (ADR-0650): a pass reported without helm is a pass nobody earned.
    assert binary, "helm is not on PATH; install it rather than skipping"
    return subprocess.run([binary, *arguments], capture_output=True, text=True)


def deployment(body: dict, tmp_path: Path) -> dict:
    tmp_path.mkdir(parents=True, exist_ok=True)
    values = tmp_path / "values.yaml"
    values.write_text(yaml.safe_dump(body))
    result = helm("template", "x", str(CHART), "-f", str(CI_VALUES), "-f", str(values))
    assert result.returncode == 0, result.stderr
    deployments = [
        doc
        for doc in yaml.safe_load_all(result.stdout)
        if isinstance(doc, dict) and doc.get("kind") == "Deployment"
    ]
    assert len(deployments) == 1, [d["metadata"]["name"] for d in deployments]
    return deployments[0]


def pod_spec(dep: dict) -> dict:
    return dep["spec"]["template"]["spec"]


def lifecycles(dep: dict) -> list:
    return [c.get("lifecycle") for c in pod_spec(dep)["containers"]]


def test_default_render_has_all_three_fields(tmp_path: Path) -> None:
    # AC4 control: with no overlay the three fields DO render, so absence below means something.
    dep = deployment({}, tmp_path)
    assert pod_spec(dep)["terminationGracePeriodSeconds"] == 35
    assert dep["spec"]["minReadySeconds"] == 30
    assert lifecycles(dep) != [None] * len(lifecycles(dep))


@pytest.mark.parametrize("zero", [0, 0.0], ids=["int0", "float0"])
def test_number_zero_grace_renders_no_field(zero, tmp_path: Path) -> None:
    # AC4: terminationGracePeriodSeconds: 0 (number) -> exit 0, no key in pod spec.
    dep = deployment({"terminationGracePeriodSeconds": zero}, tmp_path)
    assert "terminationGracePeriodSeconds" not in pod_spec(dep)


@pytest.mark.parametrize("zero", [0, 0.0], ids=["int0", "float0"])
def test_number_zero_prestop_renders_no_lifecycle(zero, tmp_path: Path) -> None:
    # AC4: preStopSleepSeconds: 0 -> exit 0, the container has no key lifecycle.
    dep = deployment({"preStopSleepSeconds": zero}, tmp_path)
    containers = pod_spec(dep)["containers"]
    assert len(containers) == 1
    assert "lifecycle" not in containers[0]


@pytest.mark.parametrize("zero", [0, 0.0], ids=["int0", "float0"])
def test_number_zero_min_ready_renders_no_field(zero, tmp_path: Path) -> None:
    # AC4: minReadySeconds: 0 -> exit 0, the Deployment spec has no key minReadySeconds.
    dep = deployment({"minReadySeconds": zero}, tmp_path)
    assert "minReadySeconds" not in dep["spec"]


def test_all_three_number_zero_together(tmp_path: Path) -> None:
    # AC4 triangulation: the three keys at 0 at once, still nothing rendered for any of them.
    dep = deployment({key: 0 for key in KEYS}, tmp_path)
    assert "terminationGracePeriodSeconds" not in pod_spec(dep)
    assert "minReadySeconds" not in dep["spec"]
    assert all("lifecycle" not in c for c in pod_spec(dep)["containers"])


def test_null_renders_the_same_three_absences(tmp_path: Path) -> None:
    # AC4: each of the three keys set to null -> exit 0, the same three fields are absent.
    dep = deployment({key: None for key in KEYS}, tmp_path)
    assert "terminationGracePeriodSeconds" not in pod_spec(dep)
    assert "minReadySeconds" not in dep["spec"]
    assert all("lifecycle" not in c for c in pod_spec(dep)["containers"])


@pytest.mark.parametrize("key", KEYS)
def test_null_of_one_key_leaves_the_other_two_rendered(key: str, tmp_path: Path) -> None:
    # AC4 triangulation: null removes only its own field, so a blanket omit fails.
    dep = deployment({key: None}, tmp_path)
    present = {
        "terminationGracePeriodSeconds": "terminationGracePeriodSeconds" in pod_spec(dep),
        "minReadySeconds": "minReadySeconds" in dep["spec"],
        "preStopSleepSeconds": any("lifecycle" in c for c in pod_spec(dep)["containers"]),
    }
    assert present == {k: k != key for k in KEYS}
