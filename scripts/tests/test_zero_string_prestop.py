"""THE STRING "0" FOR preStopSleepSeconds IS REFUSED AT RENDER, NAMING THE KEY (yaadgaar 639, AC2).

`{{- with .Values.preStopSleepSeconds }}` passes the string "0" (Go templates treat every
non-empty string as true), so the chart used to render `seconds: 0`. The render now refuses
that string by name. The number 0 is a different value and is covered elsewhere (AC4).

Run: python3 -m pytest scripts/tests/test_zero_string_prestop.py -q
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
CHART = REPO / "chart"
CI_VALUES = CHART / "ci" / "values.yaml"
KEY = "preStopSleepSeconds"


class QuotingDumper(yaml.SafeDumper):
    """Every string is written QUOTED, so a "0" reaches helm as a string and not a number."""


QuotingDumper.add_representer(
    str, lambda dumper, data: dumper.represent_scalar("tag:yaml.org,2002:str", data, style='"')
)


def helm(*arguments: str) -> subprocess.CompletedProcess[str]:
    binary = shutil.which("helm")
    # NOT A SKIP (ADR-0650): a pass reported without helm is a pass nobody earned.
    assert binary, "helm is not on PATH; install it rather than skipping"
    return subprocess.run([binary, *arguments], capture_output=True, text=True)


def render_with_file(body: dict, tmp_path: Path) -> subprocess.CompletedProcess[str]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    values = tmp_path / "values.yaml"
    values.write_text(yaml.dump(body, Dumper=QuotingDumper))
    return helm("template", "x", str(CHART), "-f", str(CI_VALUES), "-f", str(values))


def assert_refused_naming_key_and_zero(result: subprocess.CompletedProcess[str]) -> None:
    assert result.returncode != 0, result.stdout
    combined = result.stdout + result.stderr
    assert KEY in combined, combined
    assert '"0"' in combined, combined


def test_set_string_zero_is_refused_naming_the_key():
    # AC2: helm template x chart -f chart/ci/values.yaml --set-string preStopSleepSeconds=0
    result = helm("template", "x", str(CHART), "-f", str(CI_VALUES), "--set-string", f"{KEY}=0")
    assert_refused_naming_key_and_zero(result)


def test_quoted_zero_in_a_values_file_is_refused_naming_the_key(tmp_path):
    # AC2: extra values file preStopSleepSeconds: "0" (quoted)
    assert_refused_naming_key_and_zero(render_with_file({KEY: "0"}, tmp_path))


def test_set_string_zero_is_refused_whatever_the_neighbouring_knobs_hold(tmp_path):
    # AC2 triangulation: the refusal does not depend on the other two guarded knobs
    # holding their defaults; it still names this key and the value "0".
    body = {KEY: "0", "terminationGracePeriodSeconds": 40, "minReadySeconds": 7}
    assert_refused_naming_key_and_zero(render_with_file(body, tmp_path))
