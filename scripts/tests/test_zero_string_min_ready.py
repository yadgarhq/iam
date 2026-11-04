"""THE STRING "0" FOR minReadySeconds IS REFUSED AT RENDER, NAMING THE KEY (yaadgaar 639, AC3).

`{{- with .Values.minReadySeconds }}` skips nil and the NUMBER 0, but a Go template treats
every non-empty string as true, so the string "0" passes the guard and renders
`minReadySeconds: 0`. The chart refuses that string by name instead. The expected values
below come from the plan's examples, not from the current render.

Run: python3 -m pytest scripts/tests/test_zero_string_min_ready.py -q
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
CHART = REPO / "chart"
CI_VALUES = CHART / "ci" / "values.yaml"
KEY = "minReadySeconds"


class QuotingDumper(yaml.SafeDumper):
    """Every string is written QUOTED, so the chart receives a string and not a number."""


QuotingDumper.add_representer(
    str, lambda dumper, data: dumper.represent_scalar("tag:yaml.org,2002:str", data, style='"')
)


def helm(*arguments: str) -> subprocess.CompletedProcess[str]:
    binary = shutil.which("helm")
    # NOT A SKIP (ADR-0650): a pass reported without helm is a pass nobody earned.
    assert binary, "helm is not on PATH; install it rather than skipping"
    return subprocess.run([binary, *arguments], capture_output=True, text=True)


def render_with_file(body: dict, tmp_path: Path):
    values = tmp_path / "values.yaml"
    values.write_text(yaml.dump(body, Dumper=QuotingDumper))
    return helm("template", "x", str(CHART), "-f", str(CI_VALUES), "-f", str(values))


def test_set_string_zero_is_refused_naming_the_key():
    # AC3 main: --set-string minReadySeconds=0 -> exit != 0, output has key and "0"
    result = helm("template", "x", str(CHART), "-f", str(CI_VALUES), "--set-string", f"{KEY}=0")
    combined = result.stdout + result.stderr
    assert result.returncode != 0, result.stdout
    assert KEY in combined, combined
    assert '"0"' in combined, combined


def test_quoted_zero_in_a_values_file_is_refused_naming_the_key(tmp_path):
    # AC3 refusal: extra values file with minReadySeconds: "0" (quoted)
    result = render_with_file({KEY: "0"}, tmp_path)
    combined = result.stdout + result.stderr
    assert result.returncode != 0, result.stdout
    assert KEY in combined, combined
    assert '"0"' in combined, combined


def test_the_refusal_names_this_key_and_not_a_neighbour_that_is_valid(tmp_path):
    # AC3 triangulation of the main example: with a valid neighbour set beside the bad
    # key, the refusal still names minReadySeconds and does not name the valid one.
    result = helm(
        "template", "x", str(CHART), "-f", str(CI_VALUES),
        "--set-string", f"{KEY}=0", "--set-string", "terminationGracePeriodSeconds=35",
    )
    combined = result.stdout + result.stderr
    assert result.returncode != 0, result.stdout
    assert KEY in combined, combined
    assert '"0"' in combined, combined
    assert "terminationGracePeriodSeconds" not in combined, combined


def test_a_quoted_zero_is_refused_whatever_else_the_values_file_sets(tmp_path):
    # AC3 triangulation of the refusal example: a different values file shape (other
    # valid keys beside it) is still refused, naming the key.
    result = render_with_file({KEY: "0", "preStopSleepSeconds": "7"}, tmp_path)
    combined = result.stdout + result.stderr
    assert result.returncode != 0, result.stdout
    assert KEY in combined, combined
    assert '"0"' in combined, combined
