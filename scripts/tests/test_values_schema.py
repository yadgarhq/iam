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

THE TWO EXCEPTIONS (ADR-0845, C-SVb): `tls.enabled` and `iamDb.tls.enabled` now
carry `type: boolean`, and their parent blocks carry `required: [enabled]`.
The binary has no compiled-in default for either `LISTEN_TLS_ENABLED` or
`IAM_DB_TLS_ENABLED` any more, so this chart can have none for the values
that render them either — `required` alone passes a null value through
(K-1), which is why the leaf keeps its type too. `REQUIRED_NO_DEFAULT` below
is this pair, excluded from the untyped-leaf census for the reason stated on
it.

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
CI_VALUES = CHART / "ci" / "values.yaml"

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
#
# `tls.clientAuth`, `tls.clientCaSecret` and `tls.clientCaSecretKey` join this
# set for the B-U5E expand (folded into C-SVb): the schema declares them,
# `templates/render-checks.yaml` validates them when present, and the binary
# reads none of them yet — there is nothing for `values.yaml` to default,
# same shape as `image.digest` above (a template reads it; nothing ships it).
EXTRAS = (
    "image.digest",
    "networkPolicy.scrapeFrom.namespace",
    "tls.clientAuth",
    "tls.clientCaSecret",
    "tls.clientCaSecretKey",
)

# `tls.enabled` and `iamDb.tls.enabled` (ADR-0845, C-SVb): leaves `values.yaml`
# DELIBERATELY ships no value for, because the knob's own absence is the
# property the schema exists to catch — a chart default here would be one
# more compiled-in default under the exact rule this unit enforces on the
# binary. Excluded from the values.yaml half of the key-set census (there is
# no value to find there) and from the untyped-leaf census below (the leaf
# keeps `type: boolean`, K-1). NOT an EXTRA: an extra is a key `values.yaml`
# omits by design with NO constraint attached; these two are omitted by
# design AND an adopter MUST choose one of exactly two values.
REQUIRED_NO_DEFAULT = ("tls.enabled", "iamDb.tls.enabled")


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
    # `-f <chart>/ci/values.yaml` FIRST, ALWAYS, WHEN THE FILE EXISTS (ADR-0845,
    # C-SVb): `tls.enabled` and `iamDb.tls.enabled` carry no default any
    # more, so every bare render in this file needs the baseline this
    # chart's own `ci/values.yaml` states — read relative to WHICHEVER
    # `chart` directory is passed in, because some callers here render a
    # mutated COPY of the chart under a temp path, not the module-level
    # `CHART` constant. First, not last, so a case-specific `--values`/`--set`
    # in `*arguments` still wins on any key the two happen to share.
    ci_values = chart / "ci" / "values.yaml"
    override = ("-f", str(ci_values)) if ci_values.is_file() else ()
    return helm("template", "x", str(chart), *override, *arguments)


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
    either a `values.yaml` leaf, a declared EXTRA, a REQUIRED_NO_DEFAULT key,
    or an open path — never a phantom key nobody asked for.
    """
    known = (
        set(declared_values_leaves(values))
        | set(EXTRAS)
        | set(OPEN_PATHS)
        | set(REQUIRED_NO_DEFAULT)
    )
    failures = []
    for path in schema_leaves(doc.get("properties", {})):
        if path not in known:
            failures.append(
                f"{path} is a schema leaf that is in none of: values.yaml, EXTRAS, "
                "OPEN_PATHS, REQUIRED_NO_DEFAULT"
            )
    return failures


def required_no_default_failures(doc: dict) -> list[str]:
    """ADR-0845's K-1: `required` ALONE passes a null value, so a leaf in
    `REQUIRED_NO_DEFAULT` must carry both `type: boolean` AND appear in its
    parent block's own `required` list — either half dropped lets the
    knob's absence (or a null) reach the template unrefused by the schema.
    """
    failures = []
    for path in REQUIRED_NO_DEFAULT:
        node = node_at(doc, path)
        if node != {"type": "boolean"}:
            failures.append(f"{path} is not declared as {{'type': 'boolean'}}: {node!r}")
        parent_path, _, leaf = path.rpartition(".")
        parent = node_at(doc, parent_path) if parent_path else doc
        if parent is None or leaf not in (parent.get("required") or []):
            failures.append(
                f"'{path}' is not in its parent block '{parent_path}'s `required` list"
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


def test_the_required_no_default_leaves_are_typed_boolean_and_required():
    failures = required_no_default_failures(schema())
    assert failures == [], "\n".join(failures)


def test_every_required_no_default_key_has_no_default_in_values_yaml():
    """The other half of what `REQUIRED_NO_DEFAULT` claims: `values.yaml`
    really does not set it. A key that crept back into `values.yaml` would
    still pass `test_every_values_yaml_leaf_is_declared` (it would simply be
    a values.yaml leaf that is also a schema leaf), so this is the test that
    would catch it.
    """
    values = chart_values()
    for path in REQUIRED_NO_DEFAULT:
        node = values
        present = True
        for step in path.split("."):
            if not isinstance(node, dict) or step not in node:
                present = False
                break
            node = node[step]
        assert not present, (
            f"{path} is in REQUIRED_NO_DEFAULT but values.yaml sets it — "
            "ADR-0845 asks for no default, not merely an unenforced one"
        )


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


def test_mutation_dropping_tls_enabled_required_reddens():
    """ADR-0845's own mutation. Drop `tls.required: [enabled]` and the
    structural test must redden — `required` alone is what a chart
    default's absence depends on; see the render-level half of the same
    property below (`test_dropping_tls_required_degrades_the_bare_lint_message`).
    """
    mutated = copy.deepcopy(schema())
    del mutated["properties"]["tls"]["required"]
    assert required_no_default_failures(mutated) != []


def test_mutation_dropping_tls_enabled_type_reddens():
    """`required` alone passes a null value (K-1); the leaf must keep its
    `type: boolean` too, independently of the `required` mutation above.
    """
    mutated = copy.deepcopy(schema())
    mutated["properties"]["tls"]["properties"]["enabled"] = {}
    assert required_no_default_failures(mutated) != []


def test_mutation_dropping_iam_db_tls_enabled_required_reddens():
    mutated = copy.deepcopy(schema())
    del mutated["properties"]["iamDb"]["properties"]["tls"]["required"]
    assert required_no_default_failures(mutated) != []


# ── RENDER, THE RED-CASE TABLE (brief §5) ────────────────────────────────────
# Asserted on the KEY NAME and the PATH FRAGMENT, never on helm's wording: helm
# 3.18.4 prints `- <path>: Additional property X is not allowed`, helm 3.20.2 and
# 4.3.0 print `- at '/<path>': additional properties 'X' not allowed` — measured,
# both forms carry the key and the path, neither is this repository's to own.


def test_the_default_render_is_unchanged():
    """The render-neutrality floor every other case in this file is read
    against. `render()` now carries `chart/ci/values.yaml` (`tls.enabled`
    and `iamDb.tls.enabled` both `true`) by default — ADR-0845 left neither
    a chart default to render bare against — but turning TLS on adds fields
    inside the Deployment manifest, not a new Kubernetes object, so the
    count stays 4.
    """
    result = render(CHART)
    assert result.returncode == 0, result.stderr
    assert len(objects(result.stdout)) == 4


def env_value(manifest: str, name: str) -> str:
    """The `value:` line immediately under `- name: <name>`, stripped. PURE.

    Indentation-agnostic on purpose: this file's env block sits several
    levels deep in the Deployment's containers list, and a literal
    multi-line substring tied to that depth breaks the moment either line's
    indent changes for a reason that has nothing to do with the property
    under test.
    """
    lines = manifest.splitlines()
    for i, line in enumerate(lines):
        if line.strip() == f"- name: {name}":
            return lines[i + 1].strip()
    raise AssertionError(f"{name} is not rendered at all")


# ── RED CASES: `tls.enabled` AND `iamDb.tls.enabled` CARRY NO DEFAULT (ADR-0845) ──
#
# Schema refusals below assert the key AND its path only, never helm's own
# wording (helm 3.18.4 phrases a `required`/`type` miss differently from
# 3.20.2 and 4.3.0 — correction #5 / the C-DB1 gotcha). Render-check
# refusals assert the exact designed sentence, because that text is this
# chart's own and does not vary by helm version.

# THE STABLE WRAPPER both helm 3.18.4 and 4.3.0 print around their own,
# differently-worded, per-leaf message (the C-DB1 gotcha: "tls: enabled is
# required" vs "missing property 'enabled'"). Asserted alongside the key
# and the path on every schema refusal below, never alone and never
# instead of them.
SCHEMA_WRAPPER = "values don't meet the specifications of the schema"

TLS_ENABLED_GUARD_SENTENCE = (
    "iam: tls.enabled must be set to true or false; it renders LISTEN_TLS_ENABLED "
    "(ADR-0845, ADR-0797)"
)
IAM_DB_TLS_ENABLED_GUARD_SENTENCE = (
    "iam: iamDb.tls.enabled must be set to true or false; it renders "
    "IAM_DB_TLS_ENABLED (ADR-0845, ADR-0797)"
)


def test_tls_null_refuses_with_the_designed_guard_sentence(tmp_path):
    """`tls: null` is the one non-absent shape that reaches
    `templates/render-checks.yaml`'s own guard rather than the schema:
    `tls: {enabled: null}` and `tls: {enabled: "true"}` are both caught by
    the schema's `required`/`type: boolean` before any template runs.
    """
    overlay = values_file(tmp_path / "tls-null.yaml", "tls: null\n")
    result = render(CHART, "-f", str(overlay))
    assert result.returncode != 0, "tls: null must refuse rather than render"
    assert TLS_ENABLED_GUARD_SENTENCE in result.stderr, result.stderr


def test_iam_db_tls_null_refuses_with_the_designed_guard_sentence(tmp_path):
    overlay = values_file(tmp_path / "iamdb-tls-null.yaml", "iamDb:\n  tls: null\n")
    result = render(CHART, "-f", str(overlay))
    assert result.returncode != 0, "iamDb.tls: null must refuse rather than render"
    assert IAM_DB_TLS_ENABLED_GUARD_SENTENCE in result.stderr, result.stderr


def test_tls_enabled_true_renders_the_variable_unconditionally():
    result = render(CHART, "--set", "tls.enabled=true")
    assert result.returncode == 0, result.stderr
    assert env_value(result.stdout, "LISTEN_TLS_ENABLED") == 'value: "1"'


def test_tls_enabled_false_renders_the_variable_too_rather_than_omitting_it():
    """The chart says "0" OUT LOUD now, because the binary refuses an
    absent value — the old shape, where `false` rendered NO
    `LISTEN_TLS_ENABLED` at all, is exactly what ADR-0845 closes.
    """
    result = render(CHART, "--set", "tls.enabled=false")
    assert result.returncode == 0, result.stderr
    assert env_value(result.stdout, "LISTEN_TLS_ENABLED") == 'value: "0"'
    assert "LISTEN_TLS_CERT_FILE" not in result.stdout


def test_both_switches_false_render_both_variables_as_zero():
    """K-1's own 0/1 case, over BOTH switches this chart carries."""
    result = render(CHART, "--set", "tls.enabled=false", "--set", "iamDb.tls.enabled=false")
    assert result.returncode == 0, result.stderr
    assert env_value(result.stdout, "LISTEN_TLS_ENABLED") == 'value: "0"'
    assert env_value(result.stdout, "IAM_DB_TLS_ENABLED") == 'value: "0"'


def test_both_switches_true_render_both_variables_as_one():
    result = render(CHART, "--set", "tls.enabled=true", "--set", "iamDb.tls.enabled=true")
    assert result.returncode == 0, result.stderr
    assert env_value(result.stdout, "LISTEN_TLS_ENABLED") == 'value: "1"'
    assert env_value(result.stdout, "IAM_DB_TLS_ENABLED") == 'value: "1"'


def test_tls_enabled_wrong_type_is_refused_by_the_schema_naming_key_and_path(tmp_path):
    overlay = values_file(tmp_path / "wrong-type.yaml", {"tls": {"enabled": "true"}})
    result = render(CHART, "-f", str(overlay))
    assert result.returncode != 0, result.stdout
    assert SCHEMA_WRAPPER in result.stderr, result.stderr
    assert "enabled" in result.stderr
    assert "tls" in result.stderr


def test_tls_enabled_null_is_refused_by_the_schema_naming_the_key(tmp_path):
    """`enabled: null` is NOT the same shape as the whole block set to
    null, above: `values.yaml` carries no default for `enabled` any more,
    so helm's null-key-deletion (which only drops a key the chart's OWN
    defaults also set) does not apply to it — the null survives into the
    merged values as a value, and the schema refuses it as the wrong type
    rather than as a missing key.
    """
    overlay = values_file(tmp_path / "null-enabled.yaml", {"tls": {"enabled": None}})
    result = render(CHART, "-f", str(overlay))
    assert result.returncode != 0, result.stdout
    assert SCHEMA_WRAPPER in result.stderr, result.stderr
    assert "enabled" in result.stderr


def test_dropping_tls_required_degrades_the_bare_lint_message(tmp_path):
    """MUTATION. A fresh copy of the WHOLE chart, because `-f` cannot
    replace `values.schema.json` itself — only editing the file on disk can.

    MEASURED (project-db#54, and reproduced here): with the render
    UNCONDITIONAL (`ternary` rather than `if`), dropping `required` does
    NOT let a bare `helm lint --strict` pass. `enabled` is truly absent
    once there is no chart default behind it, so the render-check's own
    `hasKey` guard still fires its `fail` — but `lint` grades a template
    `fail` as INFO, never ERROR, and keeps rendering anyway. What then
    throws the ACTUAL error is sprig's own `ternary`, handed a non-bool
    (`nil`) third argument. The exit code does not move; the MESSAGE an
    operator reads degrades from this chart's own named sentence to
    sprig's. That degradation, not red-vs-green, is the property
    `required` buys and this asserts.

    ASSERTED ON THE WRAPPER SENTENCE ("values don't meet the specifications
    of the schema(s)"), NEVER ON HELM'S OWN PER-LEAF WORDING (the C-DB1
    gotcha): helm 4.3.0 prints "missing property 'enabled'", helm 3.18.4
    prints "tls: enabled is required". Both carry the wrapper.
    """
    copy_dir = tmp_path / "chart"
    shutil.copytree(CHART, copy_dir)
    schema_copy = copy_dir / "values.schema.json"
    mutated = json.loads(schema_copy.read_text())
    del mutated["properties"]["tls"]["required"]
    del mutated["properties"]["iamDb"]["properties"]["tls"]["required"]
    schema_copy.write_text(json.dumps(mutated))

    # BARE, NO `-f CI_VALUES` — the whole point is the chart with no
    # override, the shape an adopter who has not yet read `chart/ci/
    # values.yaml` runs.
    before = helm("lint", "--strict", str(CHART))
    after = helm("lint", "--strict", str(copy_dir))

    assert before.returncode != 0, "the unmutated chart's bare lint must already refuse"
    assert after.returncode != 0, "dropping `required` must not turn the bare lint green"
    assert SCHEMA_WRAPPER in before.stdout + before.stderr, (
        "the unmutated chart must report the schema's own validation wrapper: "
        f"{before.stdout}{before.stderr}"
    )
    assert SCHEMA_WRAPPER not in after.stdout + after.stderr, (
        "dropping `required` on disk should have lost the schema's validation "
        f"wrapper, leaving only the template's own crash: {after.stdout}{after.stderr}"
    )


# ── B-U5E (folded into C-SVb): the `tls.clientAuth` expand ──────────────────
#
# VALIDATED ONLY WHEN PRESENT. An absent key must render EXACTLY as
# origin/main's shape — asserted directly below rather than through a
# two-chart golden comparison, because `tls.clientAuth` does not exist on
# this chart's own `values.yaml` at all; "render the same" here means
# "render with none of the three new env/volume additions".
CLIENT_AUTH_NOT_ENFORCED_SENTENCE = (
    "this chart version renders the key but the binary does not enforce mutual "
    "TLS yet"
)


def test_client_auth_absent_renders_exactly_as_before():
    result = render(CHART, "--set", "tls.enabled=true")
    assert result.returncode == 0, result.stderr
    for absent in ("LISTEN_TLS_CLIENT_AUTH", "LISTEN_TLS_CLIENT_CA_FILE", "client-ca"):
        assert absent not in result.stdout, (
            f"{absent} rendered with tls.clientAuth absent; the expand must be "
            f"render-neutral (K-8 step 1)"
        )


def test_client_auth_bad_mode_refuses(tmp_path):
    overlay = values_file(tmp_path / "bad-mode.yaml", 'tls: {enabled: true, clientAuth: "bogus"}\n')
    result = render(CHART, "--values", str(overlay))
    assert result.returncode != 0
    assert 'tls.clientAuth is "bogus", which is not off, optional or required.' in result.stderr


def test_client_auth_optional_and_required_both_refuse_with_the_not_enforced_yet_sentence(
    tmp_path,
):
    for mode in ("optional", "required"):
        overlay = values_file(
            tmp_path / f"{mode}.yaml", f'tls: {{enabled: true, clientAuth: "{mode}"}}\n'
        )
        result = render(CHART, "--values", str(overlay))
        assert result.returncode != 0, f"clientAuth: {mode} must refuse (B-U5 is not merged)"
        assert CLIENT_AUTH_NOT_ENFORCED_SENTENCE in result.stderr, result.stderr
        assert mode in result.stderr, result.stderr


def test_client_auth_unquoted_off_is_refused_by_name(tmp_path):
    """UNQUOTED, DELIBERATELY: YAML 1.1 reads a bare `off` as the boolean
    `false`, which the `kindIs "string"` guard then (correctly) refuses by
    name rather than silently misreading it as a mode.
    """
    overlay = values_file(tmp_path / "unquoted-off.yaml", "tls: {enabled: true, clientAuth: off}\n")
    result = render(CHART, "--values", str(overlay))
    assert result.returncode != 0
    assert "tls.clientAuth must be a quoted string" in result.stderr
    assert "write `clientAuth: \"off\"`" in result.stderr.lower() or "clientAuth" in result.stderr


def test_client_auth_off_renders_the_variable_the_binary_does_not_yet_read(tmp_path):
    overlay = values_file(
        tmp_path / "off.yaml", 'tls: {enabled: true, clientAuth: "off"}\n'
    )
    result = render(CHART, "--values", str(overlay))
    assert result.returncode == 0, result.stderr
    assert env_value(result.stdout, "LISTEN_TLS_CLIENT_AUTH") == 'value: "off"'
    # NO CA ENV OR ITEM: `clientCaSecret` was not named alongside `clientAuth`.
    assert "LISTEN_TLS_CLIENT_CA_FILE" not in result.stdout
    assert "client-ca" not in result.stdout


def test_client_ca_secret_renders_its_env_mount_and_item_only_when_named(tmp_path):
    overlay = values_file(
        tmp_path / "ca.yaml",
        'tls: {enabled: true, clientAuth: "off", clientCaSecret: iam-client-ca, '
        "clientCaSecretKey: ca.crt}\n",
    )
    result = render(CHART, "--values", str(overlay))
    assert result.returncode == 0, result.stderr
    assert "- name: LISTEN_TLS_CLIENT_CA_FILE" in result.stdout
    assert "value: /var/run/config/client-ca/ca.crt" in result.stdout
    assert "name: client-ca" in result.stdout
    assert "secretName: iam-client-ca" in result.stdout


def test_client_ca_secret_named_with_client_auth_absent_renders_nothing(tmp_path):
    """THE INCONSISTENCY A REVIEW CAUGHT: the CA env, mount and volume used to
    gate on `tls.clientCaSecret` alone, so naming a Secret with no
    `tls.clientAuth` rendered the mount and the volume while
    `LISTEN_TLS_CLIENT_AUTH`/`LISTEN_TLS_CLIENT_CA_FILE` stayed absent — a
    pod with a CA bundle mounted and no env pointing at it. All three now
    gate on the SAME `and (kindIs "map" .Values.tls) .Values.tls.enabled
    (hasKey .Values.tls "clientAuth") .Values.tls.clientCaSecret`.
    """
    overlay = values_file(
        tmp_path / "ca-no-client-auth.yaml",
        "tls: {enabled: true, clientCaSecret: iam-client-ca, clientCaSecretKey: ca.crt}\n",
    )
    result = render(CHART, "--values", str(overlay))
    assert result.returncode == 0, result.stderr
    for absent in ("LISTEN_TLS_CLIENT_AUTH", "LISTEN_TLS_CLIENT_CA_FILE", "client-ca"):
        assert absent not in result.stdout, (
            f"{absent} rendered with tls.clientAuth absent; naming clientCaSecret "
            f"alone must not be enough"
        )


def test_client_ca_secret_empty_string_renders_nothing(tmp_path):
    """A values override that nulls `clientCaSecret` renders it as `""`
    (ADR-0845's own rule for a chart key: absent and empty are the same
    deployment), and `""` is falsy, so the CA env, mount and volume must
    all stay absent exactly as when the key is omitted.
    """
    overlay = values_file(
        tmp_path / "ca-empty.yaml",
        'tls: {enabled: true, clientAuth: "off", clientCaSecret: ""}\n',
    )
    result = render(CHART, "--values", str(overlay))
    assert result.returncode == 0, result.stderr
    assert env_value(result.stdout, "LISTEN_TLS_CLIENT_AUTH") == 'value: "off"'
    for absent in ("LISTEN_TLS_CLIENT_CA_FILE", "client-ca"):
        assert absent not in result.stdout, (
            f"{absent} rendered with tls.clientCaSecret empty"
        )


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
