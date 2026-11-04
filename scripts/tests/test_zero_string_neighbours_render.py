"""EVERY VALID VALUE OTHER THAN THE STRING "0" RENDERS THE SAME FIELD LINES AS BEFORE (AC5, yaadgaar 639).

The fix refuses the string "0" for `terminationGracePeriodSeconds`, `preStopSleepSeconds`
and `minReadySeconds` by name. It must not touch any other value: a string of digits
stays valid (`--set-string replicaCount=2` is accepted by design, ADR-0847,
`chart/templates/render-checks.yaml:352-353`). These cases guard the lines that render
today. They pass before and after the fix.

Expected values come from the plan's AC5 examples, not from reading the render.

Run: python3 -m pytest scripts/tests/test_zero_string_neighbours_render.py -q
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
CHART = REPO / "chart"
CI_VALUES = CHART / "ci" / "values.yaml"


class QuotingDumper(yaml.SafeDumper):
    """Every string is written QUOTED, so a string reaches helm as a string."""


QuotingDumper.add_representer(
    str, lambda dumper, data: dumper.represent_scalar("tag:yaml.org,2002:str", data, style='"')
)


def helm(*arguments: str) -> subprocess.CompletedProcess[str]:
    binary = shutil.which("helm")
    # NOT A SKIP (ADR-0650): a pass reported without helm is a pass nobody earned.
    assert binary, "helm is not on PATH; install it rather than skipping"
    return subprocess.run([binary, *arguments], capture_output=True, text=True)


def rendered(body: dict, tmp_path: Path) -> str:
    tmp_path.mkdir(parents=True, exist_ok=True)
    values = tmp_path / "values.yaml"
    values.write_text(yaml.dump(body, Dumper=QuotingDumper))
    result = helm("template", "x", str(CHART), "-f", str(CI_VALUES), "-f", str(values))
    assert result.returncode == 0, result.stderr
    return result.stdout


def has_line(text: str, line: str) -> bool:
    return re.search(rf"^\s*{re.escape(line)}\s*$", text, re.M) is not None


def deployment(stdout: str) -> dict:
    (found,) = [
        d for d in yaml.safe_load_all(stdout)
        if isinstance(d, dict) and d.get("kind") == "Deployment"
    ]
    return found


def pod_spec(stdout: str) -> dict:
    return deployment(stdout)["spec"]["template"]["spec"]


def prestop_seconds(stdout: str):
    (container,) = pod_spec(stdout)["containers"]
    return container["lifecycle"]["preStop"]["sleep"]["seconds"]


GRACE = "terminationGracePeriodSeconds"
PRESTOP = "preStopSleepSeconds"
MIN_READY = "minReadySeconds"
GRACE_VALUES = [1, 35, 999999, "1", "35"]
GRACE_EXPECTED = {1: 1, 35: 35, 999999: 999999, "1": 1, "35": 35}


def test_the_default_render_keeps_the_three_field_lines(tmp_path):
    # AC5: no overlay -> `terminationGracePeriodSeconds: 35`, `seconds: 5`, `minReadySeconds: 30`.
    text = rendered({}, tmp_path)
    assert has_line(text, "terminationGracePeriodSeconds: 35"), text
    assert has_line(text, "seconds: 5"), text
    assert has_line(text, "minReadySeconds: 30"), text


@pytest.mark.parametrize("value", GRACE_VALUES, ids=repr)
def test_a_grace_period_renders_as_a_plain_integer(value, tmp_path):
    # AC5: number 1, 35, 999999 and string "1", "35" -> integers 1, 35, 999999, 1, 35.
    text = rendered({GRACE: value}, tmp_path)
    expected = GRACE_EXPECTED[value]
    assert pod_spec(text)[GRACE] == expected
    assert type(pod_spec(text)[GRACE]) is int
    assert has_line(text, f"terminationGracePeriodSeconds: {expected}"), text


@pytest.mark.parametrize("value,expected", [(1, 1), (999999, 999999), ("35", 35)], ids=repr)
def test_a_prestop_sleep_renders_as_a_plain_integer(value, expected, tmp_path):
    # AC5: number 1, 999999 and string "35" -> `seconds: 1`, `seconds: 999999`, `seconds: 35`.
    text = rendered({PRESTOP: value}, tmp_path)
    assert prestop_seconds(text) == expected
    assert has_line(text, f"seconds: {expected}"), text


@pytest.mark.parametrize("value,expected", [(1, 1), ("35", 35)], ids=repr)
def test_a_min_ready_renders_as_a_plain_integer(value, expected, tmp_path):
    # AC5: number 1 and string "35" -> `minReadySeconds: 1`, `minReadySeconds: 35`.
    text = rendered({MIN_READY: value}, tmp_path)
    assert deployment(text)["spec"][MIN_READY] == expected
    assert has_line(text, f"minReadySeconds: {expected}"), text


@pytest.mark.parametrize("value,expected", [(7, 7), ("12", 12)], ids=repr)
def test_neighbouring_values_other_than_the_examples_also_render_unchanged(value, expected, tmp_path):
    # AC5 triangulation: values not named in the examples render as the same plain integer,
    # for all three keys at once, so a hardcoded return value fails.
    text = rendered({GRACE: value, PRESTOP: value, MIN_READY: value}, tmp_path)
    assert pod_spec(text)[GRACE] == expected
    assert prestop_seconds(text) == expected
    assert deployment(text)["spec"][MIN_READY] == expected
