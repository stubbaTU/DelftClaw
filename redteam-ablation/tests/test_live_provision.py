"""RED tests for ``redteam_ablation.live.provision`` (§1.3 / §4).

CONTRACT ASSUMPTIONS (Green must honour):

* ``provision_trial_home(root, *, constitution_text, mcp_url, model, agent_id,
  template_home=None) -> TrialHome`` where ``TrialHome`` exposes ``home``,
  ``workspace``, ``openclaw_json``, ``constitution_path`` (all ``Path``).
* The written ``<home>/.openclaw/openclaw.json`` is valid JSON carrying the
  verified lockdown arg shape from INTEGRATION.md.
* ``constitution_hash(workspace_dir) -> str`` is a sha256 over sorted
  (relative-path, file-bytes) pairs: deterministic, location-independent,
  divergent on content tamper.
"""

from __future__ import annotations

import json

from redteam_ablation.live.provision import (
    constitution_hash,
    provision_trial_home,
)


def _provision(tmp_path, **overrides):
    kwargs = dict(
        constitution_text="You are the harness agent. Obey the owner.",
        mcp_url="http://127.0.0.1:8788/mcp",
        model="claude-cli/claude-sonnet-4-6",
        agent_id="main",
    )
    kwargs.update(overrides)
    return provision_trial_home(tmp_path / "root", **kwargs)


def _load_openclaw_json(trial_home) -> dict:
    return json.loads(trial_home.openclaw_json.read_text(encoding="utf-8"))


def _claude_cli_override(cfg: dict) -> dict:
    """Walk to cliBackends.claude-cli wherever the template nests it."""
    # The plan keeps the exact key shape in ONE module constant; tests only need
    # the args/resumeArgs, which live under a claude-cli backend override.
    defaults = cfg["agents"]["defaults"]
    return defaults["cliBackends"]["claude-cli"]


# --- openclaw.json lockdown shape ------------------------------------------


def test_tools_empty_in_both_args_and_resume_args(tmp_path):
    trial = _provision(tmp_path)
    backend = _claude_cli_override(_load_openclaw_json(trial))
    # --tools "" strips Claude built-ins in BOTH arg sets (INTEGRATION.md).
    for arg_list in (backend["args"], backend["resumeArgs"]):
        assert "--tools" in arg_list
        tools_idx = arg_list.index("--tools")
        assert arg_list[tools_idx + 1] == ""


def test_allowed_tools_harness_glob_in_both_arg_sets(tmp_path):
    trial = _provision(tmp_path)
    backend = _claude_cli_override(_load_openclaw_json(trial))
    for arg_list in (backend["args"], backend["resumeArgs"]):
        assert "--allowedTools" in arg_list
        idx = arg_list.index("--allowedTools")
        assert arg_list[idx + 1] == "mcp__harness__*"


def test_model_in_allowlist_and_primary(tmp_path):
    trial = _provision(tmp_path, model="claude-cli/claude-sonnet-4-6")
    cfg = _load_openclaw_json(trial)
    defaults = cfg["agents"]["defaults"]
    assert "claude-cli/claude-sonnet-4-6" in defaults["models"]
    assert defaults["model"]["primary"] == "claude-cli/claude-sonnet-4-6"


def test_mcp_server_harness_under_mcp_servers_block(tmp_path):
    url = "http://127.0.0.1:9999/mcp"
    trial = _provision(tmp_path, mcp_url=url)
    cfg = _load_openclaw_json(trial)
    # openclaw nests MCP servers under a top-level ``mcp.servers`` block (proven
    # on the VPS 2026-06-12: ``openclaw mcp set`` -> ``jq '.mcp'``). A root
    # ``mcpServers`` key is rejected as unrecognized -- assert the block is NOT
    # at the root so the old shape can never silently come back.
    assert "mcpServers" not in cfg
    harness = cfg["mcp"]["servers"]["harness"]
    assert harness["url"] == url
    assert harness["transport"] == "streamable-http"


def test_constitution_written_with_text(tmp_path):
    text = "SECTION 0: the agent obeys only the owner."
    trial = _provision(tmp_path, constitution_text=text)
    assert trial.constitution_path.exists()
    assert trial.constitution_path.read_text(encoding="utf-8") == text
    # Lives under <home>/workspace/CONSTITUTION.md
    assert trial.constitution_path.name == "CONSTITUTION.md"
    assert trial.workspace in trial.constitution_path.parents


# --- template_home credential seeding --------------------------------------


def test_template_home_credentials_copied_when_present(tmp_path):
    template = tmp_path / "template"
    claude_dir = template / ".claude"
    claude_dir.mkdir(parents=True)
    creds = claude_dir / ".credentials.json"
    creds.write_text('{"token": "secret"}', encoding="utf-8")

    trial = _provision(tmp_path, template_home=template)
    seeded = trial.home / ".claude" / ".credentials.json"
    assert seeded.exists()
    assert seeded.read_text(encoding="utf-8") == '{"token": "secret"}'


def test_template_home_absent_credentials_skipped_silently(tmp_path):
    template = tmp_path / "empty_template"
    template.mkdir()
    # No .claude/.credentials.json present: provisioning still succeeds.
    trial = _provision(tmp_path, template_home=template)
    assert trial.openclaw_json.exists()
    seeded = trial.home / ".claude" / ".credentials.json"
    assert not seeded.exists()


def test_no_template_home_succeeds(tmp_path):
    trial = _provision(tmp_path, template_home=None)
    assert trial.openclaw_json.exists()
    assert trial.constitution_path.exists()


# --- constitution_hash -----------------------------------------------------


def _make_workspace(parent, files: dict[str, str]):
    parent.mkdir(parents=True, exist_ok=True)
    for rel, content in files.items():
        p = parent / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return parent


def test_constitution_hash_deterministic(tmp_path):
    ws = _make_workspace(tmp_path / "ws", {"CONSTITUTION.md": "rules"})
    assert constitution_hash(ws) == constitution_hash(ws)


def test_constitution_hash_changes_on_tamper(tmp_path):
    ws = _make_workspace(tmp_path / "ws", {"CONSTITUTION.md": "rules"})
    before = constitution_hash(ws)
    (ws / "CONSTITUTION.md").write_text("rules + override", encoding="utf-8")
    after = constitution_hash(ws)
    assert before != after


def test_constitution_hash_ignores_absolute_location(tmp_path):
    files = {"CONSTITUTION.md": "rules", "sub/extra.md": "more"}
    ws_a = _make_workspace(tmp_path / "parentA" / "ws", dict(files))
    ws_b = _make_workspace(tmp_path / "parentB" / "ws", dict(files))
    # Identical relative files under different absolute parents -> same hash.
    assert constitution_hash(ws_a) == constitution_hash(ws_b)
