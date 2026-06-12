"""Per-trial throwaway-HOME provisioner (plan 2026-06-11 §1.3 + §0).

A fresh ``$HOME`` per trial isolates workspace/constitution state (P3) and
openclaw session state (§0.3); the provisioned ``openclaw.json`` enforces the
verified lockdown (§0.2) so the harness MCP server is the agent's sole tool
surface. Stdlib only -- this module must be importable WITHOUT fastmcp.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import dataclass
from pathlib import Path

# --- The ONE place the openclaw.json shape lives ---------------------------
#
# These arg arrays are the VERIFIED lockdown override from INTEGRATION.md
# ("Lockdown" section), confirmed on the VPS 2026-06-07. ``--tools ""`` strips
# all Claude built-ins (in BOTH args and resumeArgs -- resumed sessions revert
# to unrestricted defaults otherwise), and ``--allowedTools mcp__harness__*``
# whitelists only the harness MCP tools. ISOLATED here (single template
# constant) so a rename after the VPS smoke is a one-line change.
_CLAUDE_CLI_ARGS: list = [
    "-p",
    "--output-format",
    "stream-json",
    "--include-partial-messages",
    "--verbose",
    "--setting-sources",
    "user",
    "--allowedTools",
    "mcp__harness__*",
    "--tools",
    "",
]
_CLAUDE_CLI_RESUME_ARGS: list = _CLAUDE_CLI_ARGS + ["--resume", "{sessionId}"]


@dataclass
class TrialHome:
    """The provisioned trial HOME and the paths the runtime / tests walk."""

    home: Path
    workspace: Path
    openclaw_json: Path
    constitution_path: Path


def _build_openclaw_json(
    *, mcp_url: str, model: str, agent_id: str, workspace: Path
) -> dict:
    """Build the openclaw.json mapping (the lockdown + model allowlist + MCP).

    ``agents.defaults`` carries the model allowlist + primary (§0.6 -- openclaw
    rejects ``--model`` values not in ``models``), the verified
    ``cliBackends.claude-cli`` override (§0.2), the trial workspace, and an
    ``mcpServers.harness`` entry pointing at ``mcp_url``.
    """
    return {
        "agents": {
            "defaults": {
                # openclaw's schema wants ``models`` as a RECORD keyed by model
                # id (value = per-model config object), NOT an array -- proven on
                # the VPS 2026-06-07 (agents.defaults.models["<id>"]={}). An array
                # is rejected: "agents.defaults.models: expected record, received
                # array".
                "models": {model: {}},
                "model": {"primary": model},
                "workspace": str(workspace),
                "cliBackends": {
                    "claude-cli": {
                        "command": "claude",
                        "args": list(_CLAUDE_CLI_ARGS),
                        "resumeArgs": list(_CLAUDE_CLI_RESUME_ARGS),
                    }
                },
            }
        },
        # openclaw stores MCP servers under a top-level ``mcp.servers`` block
        # (NOT a root ``mcpServers`` key -- that is rejected as an unrecognized
        # key). Shape proven on the VPS 2026-06-12 via ``openclaw mcp set`` ->
        # ``jq '.mcp'``: ``{"servers": {"<name>": {"url", "transport"}}}`` with
        # ``transport == "streamable-http"`` for an HTTP server. The server name
        # ``harness`` matches ``FastMCP("harness")`` and the ``mcp__harness__*``
        # lockdown allowlist.
        "mcp": {
            "servers": {
                "harness": {
                    "url": mcp_url,
                    "transport": "streamable-http",
                }
            }
        },
    }


def _seed_credentials(template_home: Path, home: Path) -> None:
    """Seed Claude auth from ``template_home`` (§0.7); silent when absent.

    Claude auth lives in the real ``$HOME`` (``~/.claude/.credentials.json``); a
    throwaway HOME must seed it or auth fails. Copies
    ``<template>/.claude/.credentials.json`` and ``<template>/.claude.json``
    when they exist; succeeds silently when they don't.
    """
    src_creds = template_home / ".claude" / ".credentials.json"
    if src_creds.exists():
        dst_dir = home / ".claude"
        dst_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src_creds, dst_dir / ".credentials.json")

    src_claude_json = template_home / ".claude.json"
    if src_claude_json.exists():
        shutil.copy2(src_claude_json, home / ".claude.json")


def provision_trial_home(
    root: str | Path,
    *,
    constitution_text: str,
    mcp_url: str,
    model: str,
    agent_id: str,
    template_home: str | Path | None = None,
) -> TrialHome:
    """Provision a fresh trial HOME under ``root`` and return its :class:`TrialHome`.

    Writes ``<home>/workspace/CONSTITUTION.md`` (caller supplies the text -- the
    runtime passes tampered text for a ``tampers_constitution`` attack) and
    ``<home>/.openclaw/openclaw.json`` (lockdown + model allowlist + MCP entry).
    Seeds Claude credentials from ``template_home`` when given.
    """
    home = Path(root)
    workspace = home / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)

    constitution_path = workspace / "CONSTITUTION.md"
    constitution_path.write_text(constitution_text, encoding="utf-8")

    openclaw_dir = home / ".openclaw"
    openclaw_dir.mkdir(parents=True, exist_ok=True)
    openclaw_json = openclaw_dir / "openclaw.json"
    cfg = _build_openclaw_json(
        mcp_url=mcp_url, model=model, agent_id=agent_id, workspace=workspace
    )
    openclaw_json.write_text(
        json.dumps(cfg, indent=2), encoding="utf-8"
    )

    if template_home is not None:
        _seed_credentials(Path(template_home), home)

    return TrialHome(
        home=home,
        workspace=workspace,
        openclaw_json=openclaw_json,
        constitution_path=constitution_path,
    )


def constitution_hash(workspace_dir: str | Path) -> str:
    """Hash the constitution workspace deterministically (plan §1.3, §2 step 1).

    sha256 over sorted ``(relative-path, file-bytes)`` pairs: deterministic,
    LOCATION-independent (the relative path, not the absolute, feeds the hash --
    two identical workspaces under different parents hash the same), and
    tamper-divergent (any byte change in any file moves the hash). The published
    baseline is this function over an honestly-provisioned workspace.
    """
    workspace_dir = Path(workspace_dir)
    digest = hashlib.sha256()
    files = sorted(
        p for p in workspace_dir.rglob("*") if p.is_file()
    )
    for file_path in files:
        rel = file_path.relative_to(workspace_dir).as_posix()
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        digest.update(file_path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()
