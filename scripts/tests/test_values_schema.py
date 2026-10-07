"""`chart/values.schema.json` CLOSES THIS CHART'S OWN KEY SET (ADR-0847, ADR-0850, ledger 990).

Before this file, `chart/values.yaml` had no schema at all: a typo anywhere in a
values file — `autoscalng`, `autoscaling.enabeld`, `networkPolicy.scrapeFrom.namespac`
— rendered successfully and silently did nothing, because helm merges an unknown
key into `.Values` and no template ever reads it back. Measured on `origin/main`
before this change: `helm template x chart -f <root-typo.yaml>` exits 0. That is
the defect this schema closes.

CLOSURE IS PER CHART. This file declares and closes only what THIS chart owns:
every block in `chart/values.yaml`, plus `global` (which helm injects into every
subchart; this chart reads only `global.hostname`, in `templates/_hostname.tpl`)
and the two EXTRAS templates read that
`values.yaml` does not state. It says nothing about any other chart's key set —
ADR-0850 is explicit that closure is local.

TYPES ARE NOT THIS FILE'S JOB (ADR-0847). Every leaf here is `{}`: no `type`, no
`enum`, no `default`, no `required`. `templates/render-checks.yaml` owns the shape
of `autoscaling` and `autoscaling.enabled` (ledger 1135, `kindIs "map"` /
`kindIs "bool"`, both `hasKey`-guarded first), and this suite's render-neutrality
cases below exist to prove the schema stays out of that check's way rather than
pre-empting it with a `type` line that would refuse the chart's own default
render the day a value's shape changed.

Run: python3 -m pytest scripts/tests/ -q
"""

from __future__ import annotations

import copy
import json
import shutil
import subprocess
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
CHART = REPO / "chart"
SCHEMA_PATH = CHART / "values.schema.json"

# Blocks `values.yaml` holds as real mappings but this schema leaves UNCONSTRAINED
# (declared as `{}`, no `properties`, no closure) — `global` because helm injects it
# into every subchart whether read or not, `resources` and `rollingUpdate` because
# their shape is the Kubernetes API's own and this chart only forwards them.
OPEN_PATHS = ("global", "resources", "rollingUpdate")

# Leaves the schema declares that `chart/values.yaml` does not state at all — read
# straight off the templates (`grep -rhoE '\.Values(\.[A-Za-z0-9_-]+)+' templates`):
# `image.digest` is rewritten at package time by ci-release (D65, `deployment.yaml`);
# `networkPolicy.scrapeFrom.namespace` is read by `networkpolicy.yaml`, and
# `values.yaml` ships the parent block empty (`scrapeFrom: {}`).
EXTRAS = ("image.digest", "networkPolicy.scrapeFrom.namespace")


def schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text())


def chart_values() -> dict:
    return yaml.safe_load((CHART / "values.yaml").read_text())


def helm(*arguments: str) -> subprocess.CompletedProcess[str]:
    binary = shutil.which("helm")
    # NOT A SKIP (ADR-0650): a pass reported without helm is a pass nobody earned.
    assert binary, (
        "helm is not on PATH. This suite renders the chart — install helm rather "
        "than letting it report a pass it did not earn."
    )
    return subprocess.run([binary, *arguments], capture_output=True, text=True)


def render(chart: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return helm("template", "x", str(chart), *arguments)


def objects(stdout: str) -> list[dict]:
    return [
        document
        for document in yaml.safe_load_all(stdout)
        if isinstance(document, dict) and document.get("apiVersion")
    ]


def values_file(path: Path, body) -> Path:
    path.write_text(body if isinstance(body, str) else yaml.safe_dump(body))
    return path


# ── STRUCTURAL, PURE (no helm) ───────────────────────────────────────────────


def declared_values_leaves(values: dict, open_paths=OPEN_PATHS, prefix: str = "") -> list[str]:
    """Every leaf path `values.yaml` states, stopping at an open path or an empty
    mapping rather than recursing into it. PURE.

    An open path (`OPEN_PATHS`) is a leaf for this purpose whatever it holds today
    — this schema makes no promise about what is under it. An empty mapping
    (`networkPolicy.scrapeFrom: {}`) is a leaf too: whether the schema later turns
    it into a closed block (because an EXTRA was declared under it) or leaves it
    `{}` is a question for `schema_leaves`/`EXTRAS`, not for this walk.
    """
    leaves: list[str] = []
    for key, value in values.items():
        path = f"{prefix}.{key}" if prefix else key
        if path in open_paths or not isinstance(value, dict) or not value:
            leaves.append(path)
        else:
            leaves.extend(declared_values_leaves(value, open_paths, path))
    return leaves


def schema_leaves(properties: dict, prefix: str = "") -> list[str]:
    """Every schema LEAF path — a node with no nested `properties` — dotted. PURE."""
    leaves: list[str] = []
    for key, subschema in (properties or {}).items():
        path = f"{prefix}.{key}" if prefix else key
        nested = (subschema or {}).get("properties")
        if isinstance(nested, dict) and nested:
            leaves.extend(schema_leaves(nested, path))
        else:
            leaves.append(path)
    return leaves


def every_object_with_properties(properties: dict, prefix: str = ""):
    """`(path, subschema)` for every node in the tree that declares `properties`."""
    for key, subschema in (properties or {}).items():
        path = f"{prefix}.{key}" if prefix else key
        nested = (subschema or {}).get("properties")
        if isinstance(nested, dict) and nested:
            yield path, subschema
            yield from every_object_with_properties(nested, path)


def node_at(doc: dict, path: str):
    """The schema node at a dotted path, walking `properties`, or `None`. PURE."""
    cursor = doc
    for step in path.split("."):
        properties = cursor.get("properties")
        if not isinstance(properties, dict) or step not in properties:
            return None
        cursor = properties[step]
    return cursor


def closed_at_every_level_failures(doc: dict) -> list[str]:
    """Every object with `properties` — root included — carries
    `additionalProperties: false`. No path is exempted: every open map this chart
    declares (`OPEN_PATHS`) is `{}`, with no `properties` at all, so this check
    never reaches one — `open_paths_stay_open_failures` is the gate on those.
    """
    failures = []
    if doc.get("additionalProperties") is not False:
        failures.append("root `additionalProperties` is not `false`")
    for path, subschema in every_object_with_properties(doc.get("properties", {})):
        if subschema.get("additionalProperties") is not False:
            failures.append(f"{path}: `additionalProperties` is not `false`")
    return failures


def global_declared_failures(doc: dict) -> list[str]:
    if node_at(doc, "global") is None:
        failures = ["`global` is not declared at the root"]
    else:
        failures = []
    return failures


def open_paths_stay_open_failures(doc: dict) -> list[str]:
    """Each of `OPEN_PATHS` is declared as a bare, unconstrained `{}` — no
    `properties`, no `additionalProperties`. A path CLOSED into a block still
    satisfies `closed_at_every_level_failures` (a closed empty block is still
    closed), so this is the only gate that would redden if `resources` or
    `rollingUpdate` or `global` were turned into a closed block instead of left
    open.
    """
    failures = []
    for path in OPEN_PATHS:
        node = node_at(doc, path)
        if node != {}:
            failures.append(f"{path} is declared as {node!r}, not the open map `{{}}`")
    return failures


def every_values_leaf_declared_failures(doc: dict, values: dict) -> list[str]:
    """Every leaf `values.yaml` states resolves to SOME node in the schema —
    closed block or bare leaf, it does not matter which. A leaf with no node at
    all is a key the chart ships that the schema would refuse outright.
    """
    failures = []
    for path in declared_values_leaves(values):
        if node_at(doc, path) is None:
            failures.append(f"{path} is in values.yaml and not declared in the schema")
    return failures


def every_extra_declared_failures(doc: dict) -> list[str]:
    failures = []
    for path in EXTRAS:
        if node_at(doc, path) is None:
            failures.append(f"{path} is an EXTRA and not declared in the schema")
    return failures


def every_schema_leaf_is_known_failures(doc: dict, values: dict) -> list[str]:
    """The reverse of `every_values_leaf_declared_failures`: every schema LEAF is
    either a `values.yaml` leaf, a declared EXTRA, or an open path — never a
    phantom key nobody asked for.
    """
    known = set(declared_values_leaves(values)) | set(EXTRAS) | set(OPEN_PATHS)
    failures = []
    for path in schema_leaves(doc.get("properties", {})):
        if path not in known:
            failures.append(
                f"{path} is a schema leaf that is in none of: values.yaml, EXTRAS, OPEN_PATHS"
            )
    return failures


def test_the_schema_is_closed_at_every_level():
    failures = closed_at_every_level_failures(schema())
    assert failures == [], "\n".join(failures)


def test_global_is_declared():
    failures = global_declared_failures(schema())
    assert failures == [], "\n".join(failures)


def test_the_open_paths_stay_open():
    failures = open_paths_stay_open_failures(schema())
    assert failures == [], "\n".join(failures)


def test_every_values_yaml_leaf_is_declared():
    failures = every_values_leaf_declared_failures(schema(), chart_values())
    assert failures == [], "\n".join(failures)


def test_every_extra_is_declared():
    failures = every_extra_declared_failures(schema())
    assert failures == [], "\n".join(failures)


def test_every_schema_leaf_is_known():
    failures = every_schema_leaf_is_known_failures(schema(), chart_values())
    assert failures == [], "\n".join(failures)


# ── MUTATION CHECKS: each of the four structural gates above must redden ────


def test_deleting_root_additionalProperties_reddens():
    mutated = copy.deepcopy(schema())
    del mutated["additionalProperties"]
    assert closed_at_every_level_failures(mutated) != []


def test_deleting_global_reddens():
    mutated = copy.deepcopy(schema())
    del mutated["properties"]["global"]
    assert global_declared_failures(mutated) != []
    assert open_paths_stay_open_failures(mutated) != []


def test_deleting_an_extra_reddens():
    mutated = copy.deepcopy(schema())
    del mutated["properties"]["image"]["properties"]["digest"]
    assert every_extra_declared_failures(mutated) != []


def test_closing_an_open_map_reddens():
    """`resources` turned into a closed, empty block — still closed by
    `closed_at_every_level_failures`'s own rule, which is exactly why that check
    alone cannot catch this mutation and `open_paths_stay_open_failures` has to.
    """
    mutated = copy.deepcopy(schema())
    mutated["properties"]["resources"] = {"properties": {}, "additionalProperties": False}
    assert closed_at_every_level_failures(mutated) == []
    assert open_paths_stay_open_failures(mutated) != []


# ── RENDER, THE RED-CASE TABLE (brief §5) ────────────────────────────────────
# Asserted on the KEY NAME and the PATH FRAGMENT, never on helm's wording: helm
# 3.18.4 prints `- <path>: Additional property X is not allowed`, helm 3.20.2 and
# 4.3.0 print `- at '/<path>': additional properties 'X' not allowed` — measured,
# both forms carry the key and the path, neither is this repository's to own.


def test_the_default_render_is_unchanged():
    """The render-neutrality floor every other case in this file is read against."""
    result = render(CHART)
    assert result.returncode == 0, result.stderr
    assert len(objects(result.stdout)) == 4


def test_root_typo_is_refused_by_name_at_the_root(tmp_path):
    overlay = values_file(tmp_path / "root-typo.yaml", {"autoscalng": {"enabled": True}})
    result = render(CHART, "-f", str(overlay))
    assert result.returncode != 0
    assert "autoscalng" in result.stderr
    assert "''" in result.stderr or "(root)" in result.stderr


def test_one_level_down_typo_is_refused_under_its_parent(tmp_path):
    overlay = values_file(tmp_path / "one-down.yaml", {"autoscaling": {"enabeld": True}})
    result = render(CHART, "-f", str(overlay))
    assert result.returncode != 0
    assert "enabeld" in result.stderr
    assert "autoscaling" in result.stderr


def test_two_levels_down_typo_is_refused_under_its_parent(tmp_path):
    overlay = values_file(
        tmp_path / "two-down.yaml",
        {"networkPolicy": {"scrapeFrom": {"namespac": "x"}}},
    )
    result = render(CHART, "-f", str(overlay))
    assert result.returncode != 0
    assert "namespac" in result.stderr
    assert "scrapeFrom" in result.stderr


def test_wrong_type_toggle_is_a_render_check_not_a_schema_line(tmp_path):
    """`autoscaling.enabled` is a declared, UNTYPED leaf (ADR-0847): the schema lets
    a string through, and `render-checks.yaml`'s ledger-1135 `kindIs "bool"` guard
    is what refuses it. A schema line here would mean the schema grew a `type` on
    a toggle, which §3.8 forbids.
    """
    overlay = values_file(tmp_path / "toggle-type.yaml", {"autoscaling": {"enabled": "false"}})
    result = render(CHART, "-f", str(overlay))
    assert result.returncode != 0
    assert "must be true or false" in result.stderr
    assert "additional propert" not in result.stderr.lower()


def test_block_scalar_is_a_render_check_not_a_schema_line(tmp_path):
    """A block has no `type` (§3.2): `autoscaling: "x"` passes the schema and
    reaches `render-checks.yaml`'s `kindIs "map"` guard instead.
    """
    overlay = values_file(tmp_path / "block-scalar.yaml", 'autoscaling: "x"\n')
    result = render(CHART, "-f", str(overlay))
    assert result.returncode != 0
    assert "must be a map" in result.stderr
    assert "additional propert" not in result.stderr.lower()


def test_deleted_block_is_a_render_check_not_a_schema_line(tmp_path):
    overlay = values_file(tmp_path / "deleted-key.yaml", "autoscaling:\n")
    result = render(CHART, "-f", str(overlay))
    assert result.returncode != 0
    assert "is absent from the values" in result.stderr
    assert "additional propert" not in result.stderr.lower()


def test_deleted_leaf_is_a_render_check_not_a_schema_line(tmp_path):
    overlay = values_file(tmp_path / "deleted-enabled.yaml", "autoscaling:\n  enabled:\n")
    result = render(CHART, "-f", str(overlay))
    assert result.returncode != 0
    assert "`autoscaling.enabled` is absent" in result.stderr
    assert "additional propert" not in result.stderr.lower()


def test_open_maps_accept_anything_and_change_nothing_else(tmp_path):
    for label, body in (
        ("resources", {"resources": {"foo": {"bar": 1}}}),
        ("global", {"global": {"whatever": 1}}),
        ("rollingUpdate", {"rollingUpdate": {"partition": 1}}),
    ):
        overlay = values_file(tmp_path / f"{label}.yaml", body)
        result = render(CHART, "-f", str(overlay))
        assert result.returncode == 0, f"{label}: {result.stderr}"
        assert len(objects(result.stdout)) == 4, label


def test_an_extra_is_accepted(tmp_path):
    overlay = values_file(
        tmp_path / "extra.yaml", {"image": {"digest": "sha256:" + "a" * 64}}
    )
    result = render(CHART, "-f", str(overlay))
    assert result.returncode == 0, result.stderr
    assert len(objects(result.stdout)) == 4


def test_an_untyped_leaf_accepts_a_set_string():
    result = render(CHART, "--set-string", "replicaCount=2")
    assert result.returncode == 0, result.stderr


def test_lint_strict_refuses_the_same_root_typo_by_name(tmp_path):
    overlay = values_file(tmp_path / "root-typo.yaml", {"autoscalng": {"enabled": True}})
    result = helm("lint", "--strict", str(CHART), "-f", str(overlay))
    assert result.returncode != 0
    output = result.stdout + result.stderr
    assert "[ERROR]" in output
    assert "autoscalng" in output


def test_the_suite_reads_the_chart_this_repository_ships():
    assert CHART == REPO / "chart", CHART
    assert SCHEMA_PATH.exists(), SCHEMA_PATH
    assert json.loads(SCHEMA_PATH.read_text())["title"] == "yadgar/iam"
