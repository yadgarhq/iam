"""THE ESTATE'S HOSTNAME IS ONE VALUE, `global.hostname` (ADR-0808).

This chart carries one of the five keys that hold the public hostname,
`enrolment.gateway`, rendered into the Deployment as `ENROLMENT_GATEWAY` — the
URL every enrolment token carries (D73). It resolves in this order, in
`templates/_hostname.tpl`:

  1. `enrolment.gateway`, when it is set (an explicit per-chart value wins);
  2. `https://` + `global.hostname`, when `enrolment.gateway` is empty. No port:
     the edge listener answers on 443;
  3. `https://gateway.yadgar.internal:18443`, when neither is set — the value
     `values.yaml` shipped before this change, so a render with no hostname
     anywhere is the render it was.

THE THREE CASES ARE (a), (b) AND (c) BELOW, and each has a red case. Only (b) is
red on the chart before this change, because that chart never read `global`. (a)
and (c) were green there by construction, so their red cases are MUTATIONS: a copy
of the chart with `_hostname.tpl` rewritten to lose the property under test, which
the same check must then refuse.

Run: python3 -m pytest scripts/tests/ -q
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
CHART = REPO / "chart"
HELPER = "templates/_hostname.tpl"

BUILT_IN = "https://gateway.yadgar.internal:18443"
GLOBAL = "yadgar.example.com"
LOCAL = "https://enrol.local.example:8443"


def helm(*arguments: str) -> subprocess.CompletedProcess[str]:
    binary = shutil.which("helm")
    # NOT A SKIP (ADR-0650), the same wording as the sibling suites.
    assert binary, (
        "helm is not on PATH. This suite renders the chart — install helm rather "
        "than letting it report a pass it did not earn."
    )
    return subprocess.run([binary, *arguments], capture_output=True, text=True)


def template(chart: Path, *arguments: str) -> str:
    # `-f <chart>/ci/values.yaml` FIRST, ALWAYS, WHEN THE FILE EXISTS
    # (ADR-0845, C-SVb): `tls.enabled` and `iamDb.tls.enabled` carry no
    # default any more, so every bare render in this file needs the
    # baseline this chart's own `ci/values.yaml` states — read relative to
    # WHICHEVER `chart` directory is passed in, because `chart_with` below
    # renders a mutated COPY of the chart under a temp path. First, not
    # last, so a case-specific `--values`/`--set` in `*arguments` still
    # wins on any key the two happen to share.
    ci_values = chart / "ci" / "values.yaml"
    override = ("-f", str(ci_values)) if ci_values.is_file() else ()
    result = helm("template", "iam", str(chart), *override, *arguments)
    assert result.returncode == 0, result.stderr
    return result.stdout


def enrolment_gateway(chart: Path, *arguments: str) -> str:
    deployments = [
        document
        for document in yaml.safe_load_all(template(chart, *arguments))
        if isinstance(document, dict) and document.get("kind") == "Deployment"
    ]
    assert len(deployments) == 1, f"expected one Deployment, found {len(deployments)}"
    found = [
        variable["value"]
        for container in deployments[0]["spec"]["template"]["spec"]["containers"]
        for variable in container.get("env", [])
        if variable["name"] == "ENROLMENT_GATEWAY"
    ]
    assert len(found) == 1, f"expected one ENROLMENT_GATEWAY, found {len(found)}"
    return found[0]


def chart_with(destination: Path, old: str, new: str) -> Path:
    """A copy of the chart with one string in `_hostname.tpl` replaced. Red cases only.

    The edit is asserted to have landed: a replace whose pattern no longer matches
    leaves the chart unchanged, and the red case would then prove nothing.
    """
    copy = destination / "chart"
    shutil.copytree(CHART, copy)
    target = copy / HELPER
    before = target.read_text()
    assert old in before, f"the red case's edit matched nothing in {HELPER}"
    target.write_text(before.replace(old, new))
    return copy


def no_hostname_anywhere(chart: Path) -> str:
    return enrolment_gateway(chart)


def global_only(chart: Path) -> str:
    return enrolment_gateway(chart, "--set", f"global.hostname={GLOBAL}")


def global_and_local(chart: Path) -> str:
    return enrolment_gateway(
        chart,
        "--set", f"global.hostname={GLOBAL}",
        "--set", f"enrolment.gateway={LOCAL}",
    )


# ── (a) no global, no local: the render this chart always produced ─────────────


def test_a_no_hostname_anywhere_renders_the_built_in_default():
    assert no_hostname_anywhere(CHART) == BUILT_IN


def test_a_red_a_changed_built_in_default_is_caught(tmp_path):
    mutant = chart_with(
        tmp_path, f"\n{BUILT_IN}\n", "\nhttps://elsewhere.invalid\n"
    )
    assert no_hostname_anywhere(mutant) != BUILT_IN


def test_a_an_explicit_null_global_is_the_same_as_none(tmp_path):
    overlay = tmp_path / "overlay.yaml"
    overlay.write_text("global: null\n")
    assert enrolment_gateway(CHART, "-f", str(overlay)) == BUILT_IN


# ── (b) global set, local empty: the token carries https:// + the global ───────


def test_b_global_hostname_becomes_the_enrolment_url():
    assert global_only(CHART) == f"https://{GLOBAL}"


def test_b_global_hostname_leaves_no_trace_of_the_built_in_default():
    assert "gateway.yadgar.internal" not in template(
        CHART, "--set", f"global.hostname={GLOBAL}"
    )


def test_b_red_a_chart_that_ignores_global_is_caught(tmp_path):
    mutant = chart_with(
        tmp_path, '$hostname := get $global "hostname"', '$hostname := ""'
    )
    assert global_only(mutant) != f"https://{GLOBAL}"


# ── (c) local and global both set: the local key wins ──────────────────────────


def test_c_an_explicit_local_key_wins_over_global():
    assert global_and_local(CHART) == LOCAL


def test_c_red_a_chart_that_prefers_global_is_caught(tmp_path):
    mutant = chart_with(
        tmp_path,
        "{{- else if .local -}}",
        "{{- else if and .local (not $hostname) -}}",
    )
    assert global_and_local(mutant) != LOCAL


# ── (d) enrolment.enabled false: the off-switch beats every source ─────────────
#
# `enrolment.enabled: false` renders ENROLMENT_GATEWAY EMPTY. iam's
# `EnrolmentConfig::new` refuses an empty gateway, boot logs a WARN and keeps
# serving, and `IssueEnrolment` alone refuses with FAILED_PRECONDITION. Since an
# empty `enrolment.gateway` now means "derive", this key is the only way to turn
# IssueEnrolment off through the chart, so it must win over BOTH other sources.


def disabled(chart: Path, *arguments: str) -> str:
    return enrolment_gateway(chart, "--set", "enrolment.enabled=false", *arguments)


def test_d_enabled_false_renders_the_gateway_empty():
    assert disabled(CHART) == ""


def test_d_enabled_false_wins_over_global_hostname():
    assert disabled(CHART, "--set", f"global.hostname={GLOBAL}") == ""


def test_d_enabled_false_wins_over_an_explicit_gateway():
    assert (
        disabled(
            CHART,
            "--set", f"global.hostname={GLOBAL}",
            "--set", f"enrolment.gateway={LOCAL}",
        )
        == ""
    )


def test_d_enabled_true_is_the_default_render(tmp_path):
    assert template(CHART, "--set", "enrolment.enabled=true") == template(CHART)


def test_d_a_non_boolean_enabled_is_refused():
    result = helm(
        "template",
        "iam",
        str(CHART),
        "-f",
        str(CHART / "ci" / "values.yaml"),
        "--set-string",
        "enrolment.enabled=false",
    )
    assert result.returncode != 0
    assert "enrolment.enabled" in result.stderr


def test_d_red_a_chart_that_ignores_the_gate_is_caught(tmp_path):
    mutant = chart_with(tmp_path, "{{- if not $enabled -}}", "{{- if false -}}")
    assert disabled(mutant, "--set", f"global.hostname={GLOBAL}") != ""
