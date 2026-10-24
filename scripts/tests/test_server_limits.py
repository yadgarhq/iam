"""`server.limits` (ADR-1006, yaadgaar #218).

The binary refuses to boot without the four `LISTEN_*` limit variables, so this
chart must render all four from values it ships. The schema bounds each one to
the library's range. The one rule a schema cannot state, a keepalive timeout
below the keepalive interval, is a named refusal in `templates/render-checks.yaml`.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
CHART = REPO / "chart"
CI_VALUES = CHART / "ci" / "values.yaml"

ENV = {
    "LISTEN_MAX_CONCURRENT_STREAMS": ("maxConcurrentStreams", "256"),
    "LISTEN_KEEPALIVE_INTERVAL_SECS": ("keepaliveIntervalSeconds", "30"),
    "LISTEN_KEEPALIVE_TIMEOUT_SECS": ("keepaliveTimeoutSeconds", "10"),
    "LISTEN_MAX_HEADER_LIST_BYTES": ("maxHeaderListBytes", "16384"),
}


def helm(*arguments: str) -> subprocess.CompletedProcess[str]:
    binary = shutil.which("helm")
    # NOT A SKIP (ADR-0650): a pass reported without helm is a pass nobody earned.
    assert binary, "helm is not on PATH; install it rather than skipping"
    return subprocess.run([binary, *arguments], capture_output=True, text=True)


def render(*arguments: str) -> subprocess.CompletedProcess[str]:
    return helm("template", "x", str(CHART), "-f", str(CI_VALUES), *arguments)


def listener_env(stdout: str) -> dict[str, str]:
    for document in yaml.safe_load_all(stdout):
        if not isinstance(document, dict) or document.get("kind") != "Deployment":
            continue
        for container in document["spec"]["template"]["spec"]["containers"]:
            return {e["name"]: e.get("value") for e in container.get("env", [])}
    raise AssertionError("no Deployment rendered")


def test_the_defaults_render_all_four_variables_as_whole_numbers():
    done = render()
    assert done.returncode == 0, done.stderr
    env = listener_env(done.stdout)
    for variable, (_, default) in ENV.items():
        assert env.get(variable) == default, variable


def test_a_large_value_renders_as_a_whole_number_not_a_float():
    # YAML numbers reach helm as float64, and `quote` on a float64 renders
    # `1.048576e+06`, which the binary refuses.
    done = render("--set", "server.limits.maxHeaderListBytes=1048576")
    assert done.returncode == 0, done.stderr
    assert listener_env(done.stdout)["LISTEN_MAX_HEADER_LIST_BYTES"] == "1048576"


def test_a_timeout_at_the_interval_is_refused_naming_both_keys():
    done = render("--set", "server.limits.keepaliveTimeoutSeconds=30")
    assert done.returncode != 0
    assert "server.limits.keepaliveTimeoutSeconds" in done.stderr, done.stderr
    assert "server.limits.keepaliveIntervalSeconds" in done.stderr, done.stderr


def test_a_timeout_above_the_interval_is_refused():
    done = render(
        "--set",
        "server.limits.keepaliveTimeoutSeconds=40",
        "--set",
        "server.limits.keepaliveIntervalSeconds=30",
    )
    assert done.returncode != 0
    assert "not below" in done.stderr, done.stderr


def test_a_timeout_one_below_the_interval_renders():
    done = render("--set", "server.limits.keepaliveTimeoutSeconds=29")
    assert done.returncode == 0, done.stderr


def test_each_value_outside_its_library_range_is_refused_by_the_schema():
    for leaf, bad in [
        ("maxConcurrentStreams", 0),
        ("maxConcurrentStreams", 10001),
        ("keepaliveIntervalSeconds", 3601),
        ("keepaliveTimeoutSeconds", 601),
        ("maxHeaderListBytes", 1023),
        ("maxHeaderListBytes", 1048577),
    ]:
        done = render("--set", f"server.limits.{leaf}={bad}")
        assert done.returncode != 0, f"{leaf}={bad} rendered"
        assert leaf in done.stderr, done.stderr


def test_a_deleted_limit_is_refused_by_the_schema(tmp_path):
    # A null DELETES the key in helm and restores no default.
    for leaf, _ in ENV.values():
        overlay = tmp_path / f"{leaf}.yaml"
        overlay.write_text(yaml.safe_dump({"server": {"limits": {leaf: None}}}))
        done = render("-f", str(overlay))
        assert done.returncode != 0, f"{leaf} deleted but rendered"
        assert leaf in done.stderr, done.stderr


def test_a_misspelled_limit_is_refused_by_the_closed_block():
    done = render("--set", "server.limits.maxStreams=5")
    assert done.returncode != 0
    assert "maxStreams" in done.stderr, done.stderr


def test_a_values_file_number_renders_as_a_whole_number_not_a_float(tmp_path):
    # A values FILE delivers 1048576 as float64, and `quote` on a float64 renders
    # `1.048576e+06`, which the binary refuses. `--set` delivers int64 and hides it.
    overlay = tmp_path / "limits.yaml"
    overlay.write_text("server:\n  limits:\n    maxHeaderListBytes: 1048576\n")
    done = render("-f", str(overlay))
    assert done.returncode == 0, done.stderr
    assert listener_env(done.stdout)["LISTEN_MAX_HEADER_LIST_BYTES"] == "1048576"


def test_a_null_or_scalar_server_block_is_refused_naming_the_key(tmp_path):
    for body, needle in [
        ({"server": None}, "`server` is absent"),
        ({"server": "x"}, "`server` must be a map"),
        ({"server": {"limits": None}}, "limits"),  # the schema gets there first; its wording differs across helm versions
        ({"server": {"limits": "x"}}, "`server.limits` must be a map"),
        ({"server": {"limits": 5}}, "`server.limits` must be a map"),
    ]:
        overlay = tmp_path / "server.yaml"
        overlay.write_text(yaml.safe_dump(body))
        done = render("-f", str(overlay))
        assert done.returncode != 0, f"{body!r} rendered"
        assert needle in done.stderr, f"{body!r}: {done.stderr}"
