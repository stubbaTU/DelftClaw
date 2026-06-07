"""Reusable OpenClaw workspace provisioning for VPS scenarios and experiments."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence


EXPERIMENT_TOOLS = (
    "lineage_experiment_prepare_case",
    "lineage_experiment_request_join",
    "lineage_experiment_peer_status",
)

DENIED_BUILTIN_TOOLS = (
    "exec",
    "process",
    "read",
    "write",
    "edit",
    "apply_patch",
    "browser",
    "message",
    "gateway",
)


@dataclass(frozen=True)
class OpenClawWorkspaceSpec:
    home: Path
    agent_id: str
    mcp_name: str
    mcp_url: str
    provider: str = "openrouter"
    model_id: str = "openrouter/owl-alpha"
    base_url: str = "https://openrouter.ai/api/v1"
    api: str = "openai-completions"
    api_key_env: str = "OPENROUTER_API_KEY"
    timeout_s: int = 210
    temperature: float = 0.0
    seed: int = 1337
    max_tokens: int = 1024
    tool_allow: tuple[str, ...] = EXPERIMENT_TOOLS
    tool_deny: tuple[str, ...] = DENIED_BUILTIN_TOOLS

    @property
    def model_ref(self) -> str:
        return f"{self.provider}/{self.model_id}"

    @property
    def workspace(self) -> Path:
        return self.home / "openclaw" / "workspace"

    @property
    def agent_dir(self) -> Path:
        return self.home / "openclaw" / "agent"


def openclaw_environment(home: Path, api_key_env: str) -> dict[str, str]:
    env = os.environ.copy()
    env["HOME"] = str(home)
    env["OPENCLAW_DISABLE_TELEMETRY"] = "1"
    env["OPENCLAW_API_KEY_ENV"] = api_key_env
    env.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")
    return env


def run_openclaw_cli(
    args: Sequence[str],
    *,
    env: dict[str, str] | None = None,
    command_prefix: Sequence[str] = (),
    timeout_s: int = 60,
    capture: bool = False,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Run OpenClaw with a bounded timeout and script-friendly text output."""

    return subprocess.run(
        [*command_prefix, "openclaw", *args],
        env=env,
        check=check,
        capture_output=capture,
        text=True,
        timeout=timeout_s,
    )


def set_openclaw_config(
    path: str,
    value: object,
    *,
    env: dict[str, str] | None = None,
    command_prefix: Sequence[str] = (),
) -> None:
    run_openclaw_cli(
        ["config", "set", path, json.dumps(value), "--json"],
        env=env,
        command_prefix=command_prefix,
        timeout_s=30,
    )


def _agent_ids(stdout: str) -> list[str]:
    try:
        blob = json.loads(stdout or "[]")
    except json.JSONDecodeError:
        return []
    rows = blob.get("agents", []) if isinstance(blob, dict) else blob
    if not isinstance(rows, list):
        return []
    return [
        str(row.get("id") or row.get("name"))
        for row in rows
        if isinstance(row, dict) and (row.get("id") or row.get("name"))
    ]


def provision_openclaw_workspace(spec: OpenClawWorkspaceSpec) -> None:
    """Create one isolated OpenClaw agent configured for an experiment trial."""

    if spec.agent_id == "main":
        raise ValueError("experiment OpenClaw agent id must not be the reserved id 'main'")
    spec.workspace.mkdir(parents=True, exist_ok=True)
    spec.agent_dir.mkdir(parents=True, exist_ok=True)
    env = openclaw_environment(spec.home, spec.api_key_env)

    provider_config = {
        "baseUrl": spec.base_url.rstrip("/") + "/",
        "api": spec.api,
        "apiKey": spec.api_key_env,
        "models": [{
            "id": spec.model_id,
            "name": spec.model_id,
            "reasoning": False,
            "input": ["text"],
            "cost": {
                "input": 0,
                "output": 0,
                "cacheRead": 0,
                "cacheWrite": 0,
            },
            "contextWindow": 1_000_000,
            "maxTokens": spec.max_tokens,
        }],
    }
    set_openclaw_config("agents.defaults.timeoutSeconds", spec.timeout_s, env=env)
    set_openclaw_config("models.mode", "merge", env=env)
    set_openclaw_config(f"models.providers.{spec.provider}", provider_config, env=env)
    set_openclaw_config(
        "agents.defaults.models",
        {
            spec.model_ref: {
                "params": {
                    "temperature": spec.temperature,
                    "seed": spec.seed,
                    "maxTokens": spec.max_tokens,
                }
            }
        },
        env=env,
    )
    set_openclaw_config(
        "agents.defaults.model",
        {"primary": spec.model_ref, "fallbacks": []},
        env=env,
    )
    set_openclaw_config("tools.allow", list(spec.tool_allow), env=env)
    set_openclaw_config("tools.deny", list(spec.tool_deny), env=env)

    mcp_value = json.dumps({
        "url": spec.mcp_url,
        "transport": "streamable-http",
    })
    run_openclaw_cli(
        ["mcp", "set", spec.mcp_name, mcp_value],
        env=env,
        timeout_s=30,
    )
    listed = run_openclaw_cli(
        ["agents", "list", "--json"],
        env=env,
        timeout_s=30,
        capture=True,
        check=False,
    )
    if spec.agent_id not in _agent_ids(listed.stdout):
        run_openclaw_cli(
            [
                "agents",
                "add",
                spec.agent_id,
                "--non-interactive",
                "--workspace",
                str(spec.workspace),
                "--agent-dir",
                str(spec.agent_dir),
                "--model",
                spec.model_ref,
            ],
            env=env,
            timeout_s=60,
        )


def reset_openclaw_sessions(home: Path, agent_id: str) -> None:
    sessions = home / ".openclaw" / "agents" / agent_id / "sessions"
    if sessions.exists():
        shutil.rmtree(sessions)


def invoke_openclaw_agent(
    spec: OpenClawWorkspaceSpec,
    prompt: str,
) -> subprocess.CompletedProcess[str]:
    reset_openclaw_sessions(spec.home, spec.agent_id)
    return run_openclaw_cli(
        [
            "agent",
            "--local",
            "--agent",
            spec.agent_id,
            "--model",
            spec.model_ref,
            "--message",
            prompt,
            "--json",
            "--timeout",
            str(spec.timeout_s),
            "--thinking",
            "off",
        ],
        env=openclaw_environment(spec.home, spec.api_key_env),
        timeout_s=spec.timeout_s + 30,
        capture=True,
        check=False,
    )


def openclaw_preflight() -> dict[str, Any]:
    """Return secret-safe OpenClaw compatibility and host metadata."""

    if shutil.which("openclaw") is None:
        raise RuntimeError("openclaw executable is not on PATH")

    def capture(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        return run_openclaw_cli(
            command,
            timeout_s=30,
            capture=True,
            check=False,
        )

    version = capture(["--version"])
    agent_help = capture(["agent", "--help"])
    agents_help = capture(["agents", "add", "--help"])
    required_agent_flags = ("--local", "--agent", "--message", "--json", "--timeout")
    required_add_flags = ("--workspace", "--agent-dir", "--model", "--non-interactive")
    missing = [
        flag for flag in required_agent_flags if flag not in (agent_help.stdout + agent_help.stderr)
    ]
    missing.extend(
        flag for flag in required_add_flags if flag not in (agents_help.stdout + agents_help.stderr)
    )
    if version.returncode != 0 or missing:
        raise RuntimeError(
            "incompatible OpenClaw CLI"
            + (f"; missing flags: {', '.join(missing)}" if missing else "")
        )
    return {
        "openclaw_version": (version.stdout or version.stderr).strip().splitlines()[0],
        "openclaw_path": shutil.which("openclaw"),
        "required_flags_present": True,
    }
