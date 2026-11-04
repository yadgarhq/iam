"""AC6: THE STRING "0" CARVE-OUT IS NARROW AND LOOSENS NOTHING (yaadgaar 639, ADR-0645).

Only the string "0" for terminationGracePeriodSeconds, preStopSleepSeconds and
minReadySeconds is refused by name. Every other knob keeps its behaviour for "0", and a
malformed zero string ("00", "0123", "") keeps the existing whole-number refusal.

Run: python3 -m pytest scripts/tests/test_zero_string_scope.py -q
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
CARVED_OUT = ["terminationGracePeriodSeconds", "preStopSleepSeconds", "minReadySeconds"]


class QuotingDumper(yaml.SafeDumper):
    """Every string is written QUOTED, so helm reads "00" as a string, not a number."""


QuotingDumper.add_representer(
    str, lambda dumper, data: dumper.represent_scalar("tag:yaml.org,2002:str", data, style='"')
)


def helm(*arguments: str) -> subprocess.CompletedProcess[str]:
    binary = shutil.which("helm")
    assert binary, "helm is not on PATH; install it rather than skipping"
    return subprocess.run([binary, *arguments], capture_output=True, text=True)


def template(*extra: str) -> subprocess.CompletedProcess[str]:
    return helm("template", "x", str(CHART), "-f", str(CI_VALUES), *extra)


def render_values(body: dict, tmp_path: Path) -> subprocess.CompletedProcess[str]:
    values = tmp_path / "values.yaml"
    values.write_text(yaml.dump(body, Dumper=QuotingDumper))
    return template("-f", str(values))


def combined(result: subprocess.CompletedProcess[str]) -> str:
    return result.stdout + result.stderr


def test_set_string_zero_replica_count_still_renders_zero_replicas():
    # AC6: --set-string replicaCount=0 -> exit 0, `replicas: 0\n`
    result = template("--set-string", "replicaCount=0")
    assert result.returncode == 0, result.stderr
    assert "replicas: 0\n" in result.stdout


def test_values_file_zero_string_replica_count_still_renders_zero_replicas(tmp_path):
    # AC6: the quoted string "0" in a values file, not a number
    result = render_values({"replicaCount": "0"}, tmp_path)
    assert result.returncode == 0, result.stderr
    assert "replicas: 0\n" in result.stdout


def test_other_digit_string_replica_count_still_renders_its_value():
    # AC6 (triangulation): replicaCount keeps every digit string, "3" -> `replicas: 3`
    result = template("--set-string", "replicaCount=3")
    assert result.returncode == 0, result.stderr
    assert "replicas: 3\n" in result.stdout


@pytest.mark.parametrize("key", ["login.responseFloorMs", "redeemEnrolment.responseFloorMs"])
def test_other_numeric_knob_still_accepts_the_zero_string(key):
    # AC6: "other knobs keep their behaviour for "0""
    result = template("--set-string", f"{key}=0")
    assert result.returncode == 0, combined(result)


def test_set_string_zero_port_is_refused_naming_the_key_and_the_minimum():
    # AC6: --set-string iamDb.port=0 -> exit != 0, names `iamDb.port` and `at least 1`
    result = template("--set-string", "iamDb.port=0")
    assert result.returncode != 0, result.stdout
    assert "iamDb.port" in combined(result)
    assert "at least 1" in combined(result)


def test_zero_number_port_is_refused_the_same_way():
    # AC6 (triangulation): the number 0 for the port hits the same minimum
    result = template("--set", "iamDb.port=0")
    assert result.returncode != 0, result.stdout
    assert "iamDb.port" in combined(result)
    assert "at least 1" in combined(result)


@pytest.mark.parametrize("key", CARVED_OUT)
@pytest.mark.parametrize("value", ["00", "0123", ""], ids=repr)
def test_malformed_zero_string_keeps_the_whole_number_refusal(key, value, tmp_path):
    # AC6: "00", "0123", "" -> exit != 0, names the key, `must be a whole number`
    result = render_values({key: value}, tmp_path)
    assert result.returncode != 0, result.stdout
    assert key in combined(result)
    assert "must be a whole number" in combined(result)


@pytest.mark.parametrize("key", CARVED_OUT)
@pytest.mark.parametrize("value", ["000", "007", "01"], ids=repr)
def test_other_leading_zero_strings_keep_the_whole_number_refusal(key, value, tmp_path):
    # AC6 (triangulation): any digit string with a leading zero is still not a whole number
    result = render_values({key: value}, tmp_path)
    assert result.returncode != 0, result.stdout
    assert key in combined(result)
    assert "must be a whole number" in combined(result)


@pytest.mark.parametrize("key", CARVED_OUT)
@pytest.mark.parametrize("value", [" 0", "0 ", "0.0", "-0", "+0", "0x0", "0e0"], ids=repr)
def test_every_other_string_that_could_mean_zero_is_refused_as_not_whole(key, value, tmp_path):
    # Fail closed: "0" is the ONLY string the whole-number regex admits whose int64 is 0,
    # so these spellings never reach the guard. Measured on helm 4.3.0 and 3.18.4.
    result = render_values({key: value}, tmp_path)
    assert result.returncode != 0, result.stdout
    assert key in combined(result)
    assert "must be a whole number" in combined(result)
