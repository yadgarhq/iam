"""THE ZERO-STRING REFUSAL READS THE VALUE, NOT ITS SPELLING (yaadgaar 641, from the iam#173 review).

The refusal for the three `with`-guarded knobs compares `int64 $value` with 0, not `$value`
with the text "0". Today the two forms agree: the whole-number regex admits no other string
whose `int64` is 0, so the change renders the same bytes. The exact-text form held only
because of the regex. Loosen the regex to `^[0-9]{1,18}$` and `--set-string
terminationGracePeriodSeconds=00` rendered `terminationGracePeriodSeconds: 0`, an immediate
SIGKILL. This test renders a copy of the chart with that loosened regex and requires the
refusal to hold.

Run: python3 -m pytest scripts/tests/test_zero_string_any_spelling.py -q
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
CHART = REPO / "chart"
STRICT = 'regexMatch "^(0|[1-9][0-9]{0,17})$" $value'
LOOSE = 'regexMatch "^[0-9]{1,18}$" $value'
ZERO_STRING_REFUSAL = "which a `with` guard treats as set"
KEYS = ["minReadySeconds", "terminationGracePeriodSeconds", "preStopSleepSeconds"]


def helm(*arguments: str) -> subprocess.CompletedProcess[str]:
    binary = shutil.which("helm")
    # NOT A SKIP (ADR-0650): a pass reported without helm is a pass nobody earned.
    assert binary, "helm is not on PATH; install it rather than skipping"
    return subprocess.run([binary, *arguments], capture_output=True, text=True)


@pytest.fixture
def loose_chart(tmp_path: Path) -> Path:
    """A copy of the chart whose whole-number regex also admits leading zeros."""
    chart = tmp_path / "chart"
    shutil.copytree(CHART, chart)
    checks = chart / "templates" / "render-checks.yaml"
    text = checks.read_text()
    # The regex is pinned here so that a change to it breaks this test loudly, not silently.
    assert text.count(STRICT) == 1, "the whole-number regex in render-checks.yaml changed"
    checks.write_text(text.replace(STRICT, LOOSE))
    return chart


@pytest.mark.parametrize("key", KEYS)
def test_a_zero_string_with_leading_zeros_is_refused_once_the_regex_admits_it(key, loose_chart):
    result = helm("template", "x", str(loose_chart), "-f", str(loose_chart / "ci" / "values.yaml"),
                  "--set-string", f"{key}=00")
    assert result.returncode != 0, result.stdout
    combined = result.stdout + result.stderr
    assert key in combined, combined
    # The zero-string message, not the whole-number one: the loosened regex admitted "00".
    assert ZERO_STRING_REFUSAL in combined, combined


@pytest.mark.parametrize("key", KEYS)
def test_a_nonzero_string_with_a_leading_zero_still_renders_once_the_regex_admits_it(key, loose_chart):
    """Triangulation: the refusal is for a zero, not for every string the loose regex admits."""
    result = helm("template", "x", str(loose_chart), "-f", str(loose_chart / "ci" / "values.yaml"),
                  "--set-string", f"{key}=07")
    assert result.returncode == 0, result.stderr
