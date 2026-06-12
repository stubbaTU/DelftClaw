"""Substrate-2 CLI: dojo-benign / dojo-control as real live paths.

Plan 2026-06-10 (OpenRouter backend), Step 2: both subcommands take a
REQUIRED ``--model`` spec (``openrouter:<model-id>``, passed verbatim to
``build_llm``), validate arms early through ``interceptors_for``, fetch the
suite via ``get_suite(benchmark_version, suite)``, and dispatch to the
Substrate-2 runners -- printing the written jsonl path and returning 0.

Fail-fast convention preserved: ``build_llm``'s ValueError/RuntimeError and
the arm registry's KeyError become ``SystemExit(f"{command}: {exc}")`` with
nothing written. The old backend-not-chosen ``NotImplementedError`` gate is
GONE (plan Step 1 replaces it); the tests that pinned it are updated here per
the plan's Tests section.

Offline discipline: the wiring tests monkeypatch the two seams the plan names
-- ``build_llm`` (-> scripted fake element) and ``get_suite`` (-> the shared
stub suite) -- so no network is reachable and no provider client exists. The
missing-key test exercises the REAL ``build_llm``, which the plan guarantees
raises BEFORE any client is constructed.
"""

from __future__ import annotations

import json

import pytest

from redteam_ablation.cli import build_parser, main
from redteam_ablation.metrics.alr import BENIGN_TRIAL_KEYS
from redteam_ablation.substrates.agentdojo_native.runner import BEHAVIOUR_TRIAL_KEYS

from tests.agentdojo_stub import FakeLLM, StubEnv, make_stub_suite

MODEL_SPEC = "openrouter:test/model"

# A claude-resolvable spec + the stock alias it maps to (attack wiring,
# 2026-06-11). dojo-control needs a spec whose FAMILY resolves so the attack's
# load-target pipeline name carries a stock model key; MODEL_SPEC above does
# not resolve and is kept for the family-agnostic dojo-benign / fail-fast tests.
CLAUDE_MODEL_SPEC = "openrouter:anthropic/claude-sonnet-4-6"
CLAUDE_ALIAS = "claude-3-7-sonnet-20250219"


# ---------------------------------------------------------------------------
# Wiring helper: the two monkeypatch seams the plan's Tests section names.
# ---------------------------------------------------------------------------


def _wire(monkeypatch):
    """Patch ``build_llm`` -> scripted fake element and ``get_suite`` -> the
    shared stub suite. Returns the recorded calls for verbatim-arg checks.

    ``build_llm`` is patched at its source module: the CLI lazy-imports it at
    call time, so the patched attribute is what ``_cmd_dojo`` binds. The
    runner keeps its own module-level reference to the REAL ``build_llm``,
    which then just passes the fake element through (the existing seam).

    ``get_suite`` is patched on BOTH plausible lazy-import sources
    (``agentdojo.task_suite`` re-export and ``...task_suite.load_suites``,
    API_NOTES section 4) so the test does not care which one the CLI uses.
    """
    import agentdojo.task_suite as task_suite_pkg
    import agentdojo.task_suite.load_suites as load_suites
    import redteam_ablation.substrates.agentdojo_native.model as model

    calls: dict[str, list] = {"build_llm": [], "get_suite": []}

    def fake_build_llm(spec=None, **kwargs):
        calls["build_llm"].append(spec)
        return FakeLLM([])

    suite = make_stub_suite()
    # The live CLI path passes no environment_factory (real suites load their
    # yaml when environment=None); the stub suite has no data files on disk,
    # so satisfy that path offline on this throwaway instance.
    suite.load_and_inject_default_environment = lambda injections: StubEnv()

    def fake_get_suite(benchmark_version, suite_name):
        calls["get_suite"].append((benchmark_version, suite_name))
        return suite

    monkeypatch.setattr(model, "build_llm", fake_build_llm)
    monkeypatch.setattr(task_suite_pkg, "get_suite", fake_get_suite)
    monkeypatch.setattr(load_suites, "get_suite", fake_get_suite)
    return calls


def _patch_attack_loader(monkeypatch, attack_name="important_instructions"):
    """Patch the agentdojo loader the runner lazily resolves
    (``agentdojo.attacks.attack_registry.load_attack``) with a recording fake
    that returns an OFFLINE attack object -- never the real BaseAttack, whose
    __init__ reads the stub suite's missing injection_vectors.yaml.

    The runner lazy-imports ``load_attack`` at call time, so patching the
    attribute on its source module is what the runner binds (mirrors how
    ``_wire`` patches ``get_suite`` at its source). Returns the recorded loader
    calls (one dict per call, including the target pipeline's ``.name``).
    """
    import agentdojo.attacks.attack_registry as attack_registry

    calls = []

    class _FakeAttack:
        name = attack_name

        def attack(self, user_task, injection_task):
            return {"injection_payload": "EVIL"}

    def fake_load_attack(name, task_suite, target_pipeline):
        calls.append(
            {
                "attack_name": name,
                "suite": task_suite,
                "target_name": getattr(target_pipeline, "name", None),
            }
        )
        return _FakeAttack()

    monkeypatch.setattr(attack_registry, "load_attack", fake_load_attack)
    return calls


# ---------------------------------------------------------------------------
# Argument surface
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("command", ["dojo-benign", "dojo-control"])
def test_subcommand_parses_grid_args(command):
    """Grid args parse as before, now including the required --model spec
    (plan Step 2: 'Add --model (required=True) to both dojo subparsers')."""
    parser = build_parser()
    args = parser.parse_args(
        [
            command,
            "--run-id",
            "r1",
            "--n",
            "3",
            "--arms",
            "V0,P1-strict",
            "--model",
            MODEL_SPEC,
        ]
    )
    assert args.run_id == "r1"
    assert args.n == 3
    assert args.arms == "V0,P1-strict"
    assert args.model == MODEL_SPEC


@pytest.mark.parametrize("command", ["dojo-benign", "dojo-control"])
def test_model_flag_is_required(command):
    """No --model -> argparse refuses (SystemExit code 2), before anything
    else runs (plan Tests: 'dojo subcommand without --model -> SystemExit')."""
    with pytest.raises(SystemExit) as excinfo:
        main([command, "--run-id", "r1"])
    assert excinfo.value.code == 2


@pytest.mark.parametrize("command", ["dojo-benign", "dojo-control"])
def test_grid_defaults(command):
    """The documented defaults are pinned: v1 benchmark, workspace suite,
    n=10, all 7 arms, run-id 'dojo' (plan: 'CLI default stays v1,
    overridable'; test-review patch)."""
    from redteam_ablation.interceptors.registry import VARIANT_ORDER

    args = build_parser().parse_args([command, "--model", MODEL_SPEC])
    assert args.benchmark_version == "v1"
    assert args.suite == "workspace"
    assert args.n == 10
    assert args.arms == ",".join(VARIANT_ORDER)
    assert args.run_id == "dojo"


# ---------------------------------------------------------------------------
# Fail-fast paths (no network; nothing written)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("command", ["dojo-benign", "dojo-control"])
def test_missing_openrouter_key_fails_fast(command, tmp_path, monkeypatch):
    """The REAL build_llm with no OPENROUTER_API_KEY -> RuntimeError, which
    the CLI converts to SystemExit(f'{command}: {exc}'); no run dir created.
    Offline-safe: the plan pins that the error is raised BEFORE any client
    is constructed."""
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    with pytest.raises(SystemExit) as excinfo:
        main(
            [
                command,
                "--model",
                MODEL_SPEC,
                "--run-id",
                "keyless",
                "--out",
                str(tmp_path),
            ]
        )
    message = str(excinfo.value)
    assert message.startswith(f"{command}: ")
    assert "OPENROUTER_API_KEY" in message
    assert list(tmp_path.iterdir()) == []  # nothing written at all


@pytest.mark.parametrize("command", ["dojo-benign", "dojo-control"])
@pytest.mark.parametrize("bad_spec", ["anthropic:x", "openrouter:"])
def test_bad_model_spec_fails_fast(command, bad_spec, tmp_path, monkeypatch):
    """build_llm's ValueError half of the CLI catch (unknown prefix / empty
    id) -> SystemExit with the command prefix; nothing written (test-review
    MAJOR: the ValueError branch was implemented but unexercised through
    main()). The key is SET so the spec is the only possible failure."""
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test-123")
    with pytest.raises(SystemExit) as excinfo:
        main(
            [
                command,
                "--model",
                bad_spec,
                "--run-id",
                "badspec",
                "--out",
                str(tmp_path),
            ]
        )
    message = str(excinfo.value)
    assert message.startswith(f"{command}: ")
    assert "openrouter:" in message
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("command", ["dojo-benign", "dojo-control"])
@pytest.mark.parametrize("bad_n", ["0", "-3"])
def test_non_positive_n_fails_fast(command, bad_n, tmp_path, monkeypatch):
    """--n < 1 refuses up front (review patch A5: an empty grid would
    otherwise 'succeed' vacuously, writing an empty jsonl with exit 0).
    First rung of the ladder: no key, no seams needed."""
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    with pytest.raises(SystemExit) as excinfo:
        main(
            [
                command,
                "--model",
                MODEL_SPEC,
                "--n",
                bad_n,
                "--run-id",
                "badn",
                "--out",
                str(tmp_path),
            ]
        )
    message = str(excinfo.value)
    assert message.startswith(f"{command}: ")
    assert "--n must be >= 1" in message
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("command", ["dojo-benign", "dojo-control"])
def test_unknown_arm_fails_fast(command, tmp_path, monkeypatch):
    """Arms are validated EARLY through interceptors_for: a typo'd arm ->
    SystemExit carrying the registry's message, nothing written (plan Step 2,
    item 2). The recorded seam calls pin the ladder ORDER: build_llm already
    ran (rung 2), get_suite never did (rung 4) -- test-review MAJOR."""
    calls = _wire(monkeypatch)  # build_llm patched -> no key needed, no client
    with pytest.raises(SystemExit) as excinfo:
        main(
            [
                command,
                "--model",
                MODEL_SPEC,
                "--arms",
                "V0,bogus",
                "--run-id",
                "badarm",
                "--out",
                str(tmp_path),
            ]
        )
    message = str(excinfo.value)
    assert message.startswith(f"{command}: ")
    assert "unknown arm" in message
    assert "bogus" in message
    assert calls["build_llm"] == [MODEL_SPEC]  # arms validate AFTER build_llm
    assert calls["get_suite"] == []  # ...and BEFORE suite loading
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("command", ["dojo-benign", "dojo-control"])
def test_duplicate_arms_fail_fast(command, tmp_path, monkeypatch):
    """Duplicate arms refuse before anything runs (review patch A6: a
    repeated arm would double-run and double-count its rows in a metered
    grid). The ' V0 ' spelling also proves entries are stripped first --
    without the strip these would not collide."""
    calls = _wire(monkeypatch)
    with pytest.raises(SystemExit) as excinfo:
        main(
            [
                command,
                "--model",
                MODEL_SPEC,
                "--arms",
                "V0, V0",
                "--run-id",
                "duparm",
                "--out",
                str(tmp_path),
            ]
        )
    message = str(excinfo.value)
    assert message.startswith(f"{command}: ")
    assert "duplicate arms" in message
    assert calls["get_suite"] == []
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("command", ["dojo-benign", "dojo-control"])
def test_unknown_suite_and_version_fail_legibly(command, tmp_path, monkeypatch):
    """Suite/version typos are legible SystemExits, not raw KeyError
    tracebacks (review patch A1) -- and the two cases are disambiguated:
    load_suites keeps a defaultdict, so an unknown VERSION would otherwise
    masquerade as a missing suite. Uses the REAL get_suite registry (offline:
    failure happens before any data file is touched); only build_llm is
    seamed."""
    import redteam_ablation.substrates.agentdojo_native.model as model

    monkeypatch.setattr(model, "build_llm", lambda spec=None, **kw: FakeLLM([]))

    # Suite typo under a real version: names the suite and lists what exists.
    with pytest.raises(SystemExit) as excinfo:
        main(
            [
                command,
                "--model",
                MODEL_SPEC,
                "--suite",
                "wrkspace",
                "--run-id",
                "badsuite",
                "--out",
                str(tmp_path),
            ]
        )
    message = str(excinfo.value)
    assert message.startswith(f"{command}: ")
    assert "unknown suite 'wrkspace'" in message
    assert "workspace" in message  # the available list names the real suites

    # Version typo: blamed on the VERSION, not the (real) suite name.
    with pytest.raises(SystemExit) as excinfo:
        main(
            [
                command,
                "--model",
                MODEL_SPEC,
                "--benchmark-version",
                "v9",
                "--run-id",
                "badver",
                "--out",
                str(tmp_path),
            ]
        )
    message = str(excinfo.value)
    assert message.startswith(f"{command}: ")
    assert "unknown benchmark-version 'v9'" in message
    assert list(tmp_path.iterdir()) == []


# ---------------------------------------------------------------------------
# Full live wiring (seams patched per the plan's Tests section)
# ---------------------------------------------------------------------------


def test_dojo_benign_live_wiring(tmp_path, monkeypatch, capsys):
    """dojo-benign drives run_benign end-to-end: benign.jsonl written under
    <out>/<run-id>/ with EXACTLY the pinned benign keys, grid shape
    arms x user-tasks x n, spec passed verbatim to build_llm, suite fetched
    via get_suite(benchmark_version, suite), path printed, exit code 0."""
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)  # seams, not env
    calls = _wire(monkeypatch)

    rc = main(
        [
            "dojo-benign",
            "--model",
            MODEL_SPEC,
            "--run-id",
            "wired",
            "--n",
            "2",
            "--arms",
            "V0",
            "--suite",
            "stub-notes",
            "--benchmark-version",
            "v1",
            "--out",
            str(tmp_path),
        ]
    )

    assert rc == 0
    assert calls["build_llm"] == [MODEL_SPEC]
    assert calls["get_suite"] == [("v1", "stub-notes")]

    out_path = tmp_path / "wired" / "benign.jsonl"
    assert out_path.exists()
    records = [
        json.loads(line)
        for line in out_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    # 1 arm x 2 stub user tasks x 2 trials -- the full CROSS-PRODUCT, not
    # just matching sets (test-review MINOR: a degenerate grid satisfies the
    # set-based checks).
    assert len(records) == 4
    for rec in records:
        assert tuple(rec.keys()) == BENIGN_TRIAL_KEYS
    assert sorted((r["task_id"], r["trial_index"]) for r in records) == [
        ("user_task_0", 0),
        ("user_task_0", 1),
        ("user_task_1", 0),
        ("user_task_1", 1),
    ]
    assert all(r["variant"] == "V0" for r in records)
    assert all(r["suite"] == "stub-notes" for r in records)

    # Provenance: the model spec is pinned in meta.json (review patch A4).
    meta = json.loads((tmp_path / "wired" / "meta.json").read_text(encoding="utf-8"))
    assert meta["model_spec"] == MODEL_SPEC

    assert str(out_path) in capsys.readouterr().out


def test_dojo_control_live_wiring(tmp_path, monkeypatch, capsys):
    """dojo-control drives run_behaviour_control with the WIRED attack:
    behaviour.jsonl written with EXACTLY the pinned behaviour keys, the loaded
    attack's identity + the resolved model alias recorded in meta, the loader
    called once against a load-target pipeline named for the alias, an
    informational line (NO warning) printed, exit code 0.

    Conscious rewrite of the A7 known-gap test (attack wiring, 2026-06-11): the
    two WARNING assertions are GONE; the loader seam is patched where the runner
    resolves it (agentdojo.attacks.attack_registry.load_attack)."""
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)  # seams, not env
    calls = _wire(monkeypatch)
    loader_calls = _patch_attack_loader(monkeypatch)

    rc = main(
        [
            "dojo-control",
            "--model",
            CLAUDE_MODEL_SPEC,
            "--run-id",
            "wired",
            "--n",
            "2",
            "--arms",
            "V0",
            "--suite",
            "stub-notes",
            "--benchmark-version",
            "v1",
            "--out",
            str(tmp_path),
        ]
    )

    assert rc == 0
    assert calls["build_llm"] == [CLAUDE_MODEL_SPEC]
    assert calls["get_suite"] == [("v1", "stub-notes")]

    out_path = tmp_path / "wired" / "behaviour.jsonl"
    assert out_path.exists()
    records = [
        json.loads(line)
        for line in out_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    # 1 arm x 1 stub injection task x 2 trials.
    assert len(records) == 2
    for rec in records:
        assert tuple(rec.keys()) == BEHAVIOUR_TRIAL_KEYS
        assert rec["attack_id"] == "injection_task_0"
        assert rec["attack_class"] == "Behaviour"
        # The pre-registered default pairing: lowest-numbered user task.
        assert rec["paired_user_task"] == "user_task_0"
        assert rec["suite"] == "stub-notes"
    assert {r["trial_index"] for r in records} == {0, 1}

    # Provenance: spec pinned, plus the loaded attack name and resolved alias.
    meta = json.loads((tmp_path / "wired" / "meta.json").read_text(encoding="utf-8"))
    assert meta["model_spec"] == CLAUDE_MODEL_SPEC
    assert meta["attack"] == "important_instructions"
    assert meta["model_alias"] == CLAUDE_ALIAS

    # The loader fired once, against a load-target pipeline named for the alias.
    assert len(loader_calls) == 1
    assert loader_calls[0]["attack_name"] == "important_instructions"
    assert loader_calls[0]["target_name"] == f"redteam-ablation/V0/{CLAUDE_ALIAS}"

    out = capsys.readouterr().out
    assert str(out_path) in out
    # A7 closed: the warning is GONE; an informational line names the attack.
    # Kept loose on wording so a phrasing tweak survives.
    assert "WARNING" not in out
    assert "important_instructions" in out


def test_dojo_control_unknown_attack_fails_fast(tmp_path, monkeypatch):
    """An unknown --attack name fails fast against the populated ATTACKS
    registry (ladder rung 6): SystemExit names the bad attack, nothing is
    written (attack wiring, 2026-06-11)."""
    calls = _wire(monkeypatch)
    with pytest.raises(SystemExit) as excinfo:
        main(
            [
                "dojo-control",
                "--model",
                CLAUDE_MODEL_SPEC,
                "--attack",
                "bogus",
                "--arms",
                "V0",
                "--run-id",
                "badattack",
                "--out",
                str(tmp_path),
            ]
        )
    message = str(excinfo.value)
    assert message.startswith("dojo-control: ")
    assert "bogus" in message
    # Rung 6 fires AFTER suite lookup (rung 4) and alias resolution (rung 5).
    assert calls["get_suite"] == [("v1", "workspace")]
    assert list(tmp_path.iterdir()) == []


def test_dojo_control_unknown_model_family_fails_fast(tmp_path, monkeypatch):
    """A model spec whose family resolves to no stock key fails fast at the
    alias rung (ladder rung 5) -- AFTER the suite was resolved (rung 4),
    mirroring the existing rung-ordering pins. SystemExit names the spec;
    nothing is written (attack wiring, 2026-06-11)."""
    calls = _wire(monkeypatch)
    with pytest.raises(SystemExit) as excinfo:
        main(
            [
                "dojo-control",
                "--model",
                "openrouter:foo/bar-9",
                "--arms",
                "V0",
                "--n",
                "1",
                "--run-id",
                "badfamily",
                "--out",
                str(tmp_path),
            ]
        )
    message = str(excinfo.value)
    assert message.startswith("dojo-control: ")
    assert "openrouter:foo/bar-9" in message
    # rung 5 (alias) fires AFTER suite lookup (rung 4): the earlier rungs all
    # ran first (both directions pinned, mirroring test_unknown_arm_fails_fast).
    assert calls["build_llm"] == ["openrouter:foo/bar-9"]
    assert calls["get_suite"] == [("v1", "workspace")]
    assert list(tmp_path.iterdir()) == []


def test_dojo_benign_rejects_attack_arg():
    """--attack is a dojo-control-only argument: dojo-benign rejects it with an
    argparse error (SystemExit code 2), so the benign grid can never be handed
    an attack it would silently ignore (attack wiring, 2026-06-11)."""
    with pytest.raises(SystemExit) as excinfo:
        main(["dojo-benign", "--model", MODEL_SPEC, "--attack", "x"])
    assert excinfo.value.code == 2
