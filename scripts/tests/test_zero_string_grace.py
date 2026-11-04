"""THE STRING "0" FOR terminationGracePeriodSeconds IS REFUSED AT RENDER, NAMING THE KEY (yaadgaar 639, AC1).

`with` passes every non-empty string, so "0" used to render `terminationGracePeriodSeconds: 0`,
an immediate SIGKILL with no drain. The render now refuses it. The NUMBER 0 is not covered here.

Run: python3 -m pytest scripts/tests/test_zero_string_grace.py -q
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
CHART = REPO / "chart"
CI_VALUES = CHART / "ci" / "values.yaml"
KEY = "terminationGracePeriodSeconds"


class QuotingDumper(yaml.SafeDumper):
    """Every string is written QUOTED, so a "0" reaches helm as a string and not the number 0."""


QuotingDumper.add_representer(
    str, lambda dumper, data: dumper.represent_scalar("tag:yaml.org,2002:str", data, style='"')
)


def helm(*arguments: str) -> subprocess.CompletedProcess[str]:
    binary = shutil.which("helm")
    # NOT A SKIP (ADR-0650): a pass reported without helm is a pass nobody earned.
    assert binary, "helm is not on PATH; install it rather than skipping"
    return subprocess.run([binary, *arguments], capture_output=True, text=True)


def render_file(value, tmp_path: Path) -> subprocess.CompletedProcess[str]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    values = tmp_path / "values.yaml"
    values.write_text(yaml.dump({KEY: value}, Dumper=QuotingDumper))
    return helm("template", "x", str(CHART), "-f", str(CI_VALUES), "-f", str(values))


def assert_refused_naming_key_and_zero(result: subprocess.CompletedProcess[str]) -> None:
    assert result.returncode != 0, result.stdout
    combined = result.stdout + result.stderr
    assert KEY in combined, combined
    assert '"0"' in combined, combined


def test_set_string_zero_is_refused_naming_the_key():
    # AC1: `--set-string terminationGracePeriodSeconds=0` exits non-zero, output has the key and "0".
    result = helm("template", "x", str(CHART), "-f", str(CI_VALUES), "--set-string", f"{KEY}=0")
    assert_refused_naming_key_and_zero(result)


def test_quoted_zero_in_a_values_file_is_refused_naming_the_key(tmp_path):
    # AC1: a values file with `terminationGracePeriodSeconds: "0"` (quoted) gets the same refusal.
    assert_refused_naming_key_and_zero(render_file("0", tmp_path))


def test_set_string_other_digit_string_still_renders():
    # AC1 triangulation: only "0" is refused; "7" must still render, so a blanket refusal fails.
    result = helm("template", "x", str(CHART), "-f", str(CI_VALUES), "--set-string", f"{KEY}=7")
    assert result.returncode == 0, result.stderr
    assert f"{KEY}: 7" in result.stdout


def test_quoted_other_digit_string_in_a_values_file_still_renders(tmp_path):
    # AC1 triangulation of the values-file example: "7" renders, "0" does not.
    result = render_file("7", tmp_path)
    assert result.returncode == 0, result.stderr
    assert f"{KEY}: 7" in result.stdout
