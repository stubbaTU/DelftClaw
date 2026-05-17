"""Bring a multi-agent scenario up on the VPS.

Run as root (the script `sudo`s where needed). What it does, in order:

  1. Parse ``deploy/scenarios/<name>/scenario.yaml``.
  2. For each agent:
       a. Create ``/var/lib/delftclaw/<scenario>/<agent>/{,bitcoinlib,torrents}``.
       b. Generate a deterministic seed file if one isn't there yet.
       c. Materialise the agent's mission.md (and the scenario tree)
          under ``/etc/delftclaw/scenarios/<scenario>-<agent>/``.
       d. Write the per-instance env file under
          ``/etc/delftclaw/instances/<scenario>-<agent>.env``.
  3. ``systemctl enable --now delftclaw-mcp@<instance>.service`` per agent.
  4. Wait until each MCP server's port is open.
  5. Probe each MCP server via ``deploy.probe_mcp`` (real handshake) to
     fetch ``wallet_address`` and the IPv8 pubkey.
  6. Cross-introduce peers — for every ``a peers: [b]``, call ``a``'s
     ``peer_add`` tool with ``b``'s host/port/pubkey.
  7. ``systemctl start delftclaw-watchdog@<instance>.service`` per agent.

``--dry-run`` skips all systemd / sudo / state-dir work; it only parses
the manifest and prints the plan. Useful from your laptop.

``--teardown`` stops everything for the scenario and removes the state
+ instance env files (but keeps the seed files, so identities survive).

Usage:
    python -m deploy.scenario_boot seek_cc
    python -m deploy.scenario_boot seek_cc --dry-run
    python -m deploy.scenario_boot seek_cc --teardown
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Iterable

from fastmcp import Client

from deploy.scenario import AgentSpec, Scenario, parse_scenario, REPO_ROOT


SCENARIOS_REPO_DIR = REPO_ROOT / "deploy" / "scenarios"
ETC_INSTANCES = Path("/etc/delftclaw/instances")
ETC_SCENARIOS = Path("/etc/delftclaw/scenarios")
STATE_ROOT = Path("/var/lib/delftclaw")
SERVICE_USER = "delftclaw"
HOST_ENV_FILE = REPO_ROOT / "configs" / "host.env"


def _load_host_env(path: Path = HOST_ENV_FILE) -> dict[str, str]:
    """Parse ``configs/host.env`` as KEY=VALUE pairs. Missing file → empty dict.

    Lines starting with ``#`` and blank lines are ignored; ``KEY=`` with
    no value is also ignored (treated as "unset, fall through to default").
    Quoting and shell-style escapes are NOT honoured — this file is a
    simple env table, not a shell script. The dotenv-light implementation
    keeps the dependency surface flat (no python-dotenv requirement).
    """
    if not path.is_file():
        return {}
    out: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if not key or not value:
            continue
        out[key] = value
    return out


DEFAULT_QWEN_BASE_URL = "http://100.73.168.12:11434/v1"
DEFAULT_QWEN_MODEL = "qwen3.6:27b"
DEFAULT_OLLAMA_API_KEY = "ollama"
DEFAULT_OPENCLAW_PROVIDER = "ollama"


def _resolve_qwen(host_env_file: Path = HOST_ENV_FILE) -> tuple[str, str, str]:
    """Resolve QWEN_BASE_URL + QWEN_MODEL.

    Order: process env var → configs/host.env (if present) →
    hard-coded default. Exposed as a function so tests can stub the
    file path without re-executing the whole module body.
    """
    host_env = _load_host_env(host_env_file)
    base = os.environ.get(
        "QWEN_BASE_URL",
        host_env.get("QWEN_BASE_URL", DEFAULT_QWEN_BASE_URL),
    )
    model = os.environ.get(
        "QWEN_MODEL",
        host_env.get("QWEN_MODEL", DEFAULT_QWEN_MODEL),
    )
    api_key = os.environ.get(
        "OLLAMA_API_KEY",
        host_env.get("OLLAMA_API_KEY", DEFAULT_OLLAMA_API_KEY),
    )
    return base, model, api_key


def _resolve_openclaw_provider(host_env_file: Path = HOST_ENV_FILE) -> dict[str, str]:
    """Resolve the reasoning-LLM provider OpenClaw should use.

    The MCP/overlay compiler path still reads QWEN_*; OpenClaw's reasoning
    process can point somewhere else, e.g. Gemini's OpenAI-compatible API.
    """
    host_env = _load_host_env(host_env_file)
    provider = os.environ.get(
        "OPENCLAW_PROVIDER",
        host_env.get("OPENCLAW_PROVIDER", DEFAULT_OPENCLAW_PROVIDER),
    ).strip().lower()
    base_url = os.environ.get(
        "OPENCLAW_BASE_URL",
        host_env.get("OPENCLAW_BASE_URL", host_env.get("QWEN_BASE_URL", DEFAULT_QWEN_BASE_URL)),
    ).strip()
    model = os.environ.get(
        "OPENCLAW_MODEL",
        host_env.get("OPENCLAW_MODEL", host_env.get("QWEN_MODEL", DEFAULT_QWEN_MODEL)),
    ).strip()
    api = os.environ.get("OPENCLAW_API", host_env.get("OPENCLAW_API", "")).strip().lower()
    if not api:
        api = "ollama" if provider == "ollama" else "openai-completions"
    api_key_env = os.environ.get(
        "OPENCLAW_API_KEY_ENV",
        host_env.get("OPENCLAW_API_KEY_ENV", "OLLAMA_API_KEY" if provider == "ollama" else "GEMINI_API_KEY"),
    ).strip()
    api_key_value = os.environ.get(api_key_env, host_env.get(api_key_env, "")).strip()
    api_keys_raw = os.environ.get(
        "OPENCLAW_API_KEYS",
        host_env.get("OPENCLAW_API_KEYS", host_env.get("GEMINI_API_KEYS", "")),
    )
    api_keys = [part.strip() for part in api_keys_raw.split(",") if part.strip()]
    if not api_keys and api_key_value:
        api_keys = [api_key_value]
    watchdog_driver = os.environ.get(
        "WATCHDOG_DRIVER",
        host_env.get("WATCHDOG_DRIVER", "direct" if provider == "gemini" else "openclaw"),
    ).strip().lower()
    return {
        "provider": provider,
        "api": api,
        "base_url": base_url,
        "model": model,
        "api_key_env": api_key_env,
        "api_key_value": api_key_value,
        "api_keys": "\n".join(api_keys),
        "watchdog_driver": watchdog_driver,
    }


# Module-level constants used by `_instance_env_contents` and the
# OpenClaw provider patch. Tests that need to vary these stub
# ``HOST_ENV_FILE`` then re-call ``_resolve_qwen`` directly.
QWEN_BASE_URL, QWEN_MODEL, OLLAMA_API_KEY = _resolve_qwen()
OPENCLAW_LLM = _resolve_openclaw_provider()


def _ollama_base_from(qwen_base_url: str) -> str:
    """Strip the trailing ``/v1`` from an OpenAI-compat URL to get Ollama's native base."""
    return qwen_base_url.rstrip("/").removesuffix("/v1")


def _normalise_openclaw_base_url(provider: str, base_url: str) -> str:
    if provider == "ollama":
        return _ollama_base_from(base_url)
    return base_url.rstrip("/") + "/"


def _openclaw_api_key_for_agent(scenario: Scenario, agent: AgentSpec) -> str:
    keys = [part for part in OPENCLAW_LLM.get("api_keys", "").splitlines() if part]
    if not keys:
        return OPENCLAW_LLM.get("api_key_value", "")
    names = list(scenario.agents)
    try:
        idx = names.index(agent.name)
    except ValueError:
        idx = 0
    return keys[idx % len(keys)]


def c_info(msg: str) -> None: print(f"\033[1;36m[boot]\033[0m {msg}", flush=True)
def c_ok(msg: str) -> None:   print(f"\033[1;32m[ ok ]\033[0m {msg}", flush=True)
def c_dry(msg: str) -> None:  print(f"\033[1;33m[dry ]\033[0m {msg}", flush=True)
def c_warn(msg: str) -> None: print(f"\033[1;33m[warn]\033[0m {msg}", flush=True)
def c_fail(msg: str) -> None: print(f"\033[1;31m[FAIL]\033[0m {msg}", file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------
# Filesystem helpers
# ---------------------------------------------------------------------------

def _state_dir(scenario_name: str, agent_name: str) -> Path:
    return STATE_ROOT / scenario_name / agent_name


def _prepare_shared_state(scenario: Scenario) -> None:
    """Create scenario-level writable state that is shared across agents."""
    if scenario.name not in {"paper_security", "paper_integrated_security"}:
        return
    security_root = STATE_ROOT / scenario.name / "security"
    _sudo(["install", "-d", "-o", SERVICE_USER, "-g", SERVICE_USER, "-m", "0750", str(security_root)])
    c_ok(f"{scenario.name}: shared security evidence dir ready ({security_root})")


def _instance_env_path(scenario: Scenario, agent: AgentSpec) -> Path:
    return ETC_INSTANCES / f"{scenario.instance_id(agent.name)}.env"


def _scenario_dir_on_vps(scenario: Scenario, agent: AgentSpec) -> Path:
    return ETC_SCENARIOS / scenario.instance_id(agent.name)


def _manifest_file_path(scenario: Scenario, agent: AgentSpec) -> Path:
    """Where scenario_boot writes the synthesised manifest the watchdog reads."""
    return _scenario_dir_on_vps(scenario, agent) / "network_manifest.md"


def _seed_content_file_path(scenario: Scenario, agent: AgentSpec) -> Path:
    return _scenario_dir_on_vps(scenario, agent) / "seed_content.json"


def _instance_env_contents(scenario: Scenario, agent: AgentSpec) -> str:
    state = _state_dir(scenario.name, agent.name)
    seed_file = state / "seed.txt"
    security_root = STATE_ROOT / scenario.name / "security"
    openclaw_api_key_value = _openclaw_api_key_for_agent(scenario, agent)
    overlay = agent.publish_overlays[0] if agent.publish_overlays else (
        REPO_ROOT / "protocol" / "examples" / "content_community.md"
    )
    # Phase 6: cross-wire pull-loop URLs so every member-agent in the
    # scenario pulls from every other member-agent. ``redteam_port=0``
    # on a peer disables both serving and being pulled from.
    peer_redteam_urls = [
        f"http://127.0.0.1:{other.redteam_port}"
        for other in scenario.agents.values()
        if other.name != agent.name and other.redteam_port != 0
    ]
    lines = [
        "# generated by deploy.scenario_boot — do not hand-edit",
        f"PYTHONPATH={REPO_ROOT}",
        f"HOME={state}",
        f"SEED_FILE={seed_file}",
        "NETWORK=TESTNET",
        # ``mock`` keeps the synthetic wallet + DonationVerifier path so
        # the demo runs without a funded testnet wallet. Override by
        # setting ``btc_network`` per-agent in scenario.yaml once the
        # live-chain admission path is wired back in.
        "BTC_NETWORK=mock",
        f"INITIAL_BALANCE_SATS={agent.initial_balance_sats}",
        f"IPV8_HOST=0.0.0.0",
        f"IPV8_PORT={agent.ipv8_port}",
        f"MCP_HOST=0.0.0.0",
        f"MCP_PORT={agent.mcp_port}",
        # Phase 6: redteam FastAPI port + cross-wired peer URLs.
        # ``REDTEAM_PORT=0`` disables both the local FastAPI server and
        # the pull loop; ``PEER_LOG_URLS`` is space-separated.
        f"REDTEAM_HOST=0.0.0.0",
        f"REDTEAM_PORT={agent.redteam_port}",
        f"PEER_LOG_URLS={' '.join(peer_redteam_urls)}",
        # Per-instance community-log + peer-log paths so multiple agents
        # on the same VPS don't trample each other's files.
        f"COMMUNITY_LOG_PATH={state / 'community.log'}",
        f"PEER_LOG_DIR={state / 'peer_logs'}",
        f"PUBLISH_OVERLAY={overlay}",
        f"SEED_CONTENT_FILE={_seed_content_file_path(scenario, agent)}",
        # The watchdog reads this file at boot and calls load_manifest on its
        # snapshot agent. Without it, state.network would be null in every
        # snapshot — Phase 4b's MCP-driven injection only reaches the *MCP*
        # process's agent, not the watchdog's separate snapshot collector.
        f"MANIFEST_FILE={_manifest_file_path(scenario, agent)}",
        f"QWEN_BASE_URL={QWEN_BASE_URL}",
        f"QWEN_MODEL={QWEN_MODEL}",
        f"OPENCLAW_PROVIDER={OPENCLAW_LLM['provider']}",
        f"OPENCLAW_API={OPENCLAW_LLM['api']}",
        f"OPENCLAW_BASE_URL={OPENCLAW_LLM['base_url']}",
        f"OPENCLAW_MODEL={OPENCLAW_LLM['model']}",
        f"OPENCLAW_API_KEY_ENV={OPENCLAW_LLM['api_key_env']}",
        f"WATCHDOG_DRIVER={'direct' if scenario.name in {'paper_security', 'paper_integrated_security'} else OPENCLAW_LLM['watchdog_driver']}",
        *(
            [
                f"DIRECT_TOOL_ALLOWLIST={'paper_security' if scenario.name == 'paper_security' else 'paper_integrated_security'}",
                f"SECURITY_DEMO_ROOT={security_root}",
                f"SECURITY_EVIDENCE_PATH={security_root / 'security_evidence.json'}",
                "INTEGRATED_ATTACKER_ID=agent_2",
            ]
            if scenario.name in {"paper_security", "paper_integrated_security"} else []
        ),
        # Ollama doesn't authenticate, but OpenClaw demands a value for any
        # provider's apiKey. The string ``OLLAMA_API_KEY`` in the openclaw.json
        # config resolves to this env var; any non-empty string works.
        f"OLLAMA_API_KEY={OLLAMA_API_KEY}",
        *(
            [f"{OPENCLAW_LLM['api_key_env']}={openclaw_api_key_value}"]
            if openclaw_api_key_value else []
        ),
        f"LOG_DIR={scenario.log_dir}",
    ]
    return "\n".join(lines) + "\n"


def _redact_env_for_log(body: str) -> str:
    secret_keys = {
        "GEMINI_API_KEY",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        OPENCLAW_LLM.get("api_key_env", ""),
    }
    redacted: list[str] = []
    for line in body.splitlines():
        key, sep, value = line.partition("=")
        if sep and key in secret_keys and value:
            redacted.append(f"{key}=<redacted>")
        else:
            redacted.append(line)
    return "\n".join(redacted) + ("\n" if body.endswith("\n") else "")


# ---------------------------------------------------------------------------
# Subprocess wrappers
# ---------------------------------------------------------------------------

def _run(cmd: list[str], *, check: bool = True, capture: bool = False) -> subprocess.CompletedProcess:
    """Wrapper around subprocess.run that prints what it's about to do."""
    c_info("$ " + " ".join(cmd))
    return subprocess.run(cmd, check=check, capture_output=capture, text=True)


def _sudo(cmd: list[str], *, check: bool = True, capture: bool = False) -> subprocess.CompletedProcess:
    """Run as root if we're not already root. Forwards ``check``/``capture`` to ``_run``."""
    if os.geteuid() == 0:
        return _run(cmd, check=check, capture=capture)
    return _run(["sudo", *cmd], check=check, capture=capture)


def _seed_for_agent(scenario: Scenario, agent: AgentSpec) -> None:
    """Generate the seed file if missing. Uses the wallet CLI's auto-gen path."""
    seed_file = _state_dir(scenario.name, agent.name) / "seed.txt"
    if seed_file.exists() and seed_file.stat().st_size > 0:
        c_ok(f"{agent.name}: seed file already exists ({seed_file})")
        return
    c_info(f"{agent.name}: generating seed at {seed_file}")
    state = _state_dir(scenario.name, agent.name)
    _sudo(["install", "-d", "-o", SERVICE_USER, "-g", SERVICE_USER, "-m", "0750", str(state)])
    _sudo([
        "sudo", "-u", SERVICE_USER, "env",
        f"PYTHONPATH={REPO_ROOT}",
        f"HOME={state}",
        f"{REPO_ROOT}/venv/bin/python", "-m", "identity.wallet",
        "--seed-file", str(seed_file), "address",
    ])


def _write_env_file(scenario: Scenario, agent: AgentSpec) -> None:
    env_path = _instance_env_path(scenario, agent)
    body = _instance_env_contents(scenario, agent)
    # Write through sudo tee so /etc/delftclaw is writable only by root.
    _sudo(["install", "-d", "-o", "root", "-g", SERVICE_USER, "-m", "0750",
           str(ETC_INSTANCES)])
    proc = subprocess.run(
        ["sudo", "tee", str(env_path)],
        input=body, capture_output=True, text=True, check=True,
    )
    _sudo(["chmod", "0640", str(env_path)])
    _sudo(["chown", f"root:{SERVICE_USER}", str(env_path)])
    c_ok(f"{agent.name}: wrote {env_path}")


def _stage_scenario_dir(scenario: Scenario, agent: AgentSpec) -> None:
    """Copy the whole scenario source tree into ``/etc/delftclaw/scenarios/<instance>/``.

    The manifest references files relative to ``scenario.yaml`` (e.g.
    ``alice/mission.md``). The watchdog re-parses the manifest at boot,
    which means the *full* directory layout must be present — not just
    this agent's mission — so the parser can validate every peer's
    paths exist. Each instance gets its own copy so per-agent state can
    diverge later without affecting siblings.
    """
    dst = _scenario_dir_on_vps(scenario, agent)
    src_dir = scenario.manifest_path.parent
    # Clean any prior partial stage so re-runs are deterministic; `cp -aT`
    # only touches the contents of dst, not its perms.
    _sudo(["rm", "-rf", str(dst)], check=False)
    _sudo(["install", "-d", "-o", "root", "-g", SERVICE_USER, "-m", "0750", str(dst)])
    _sudo(["cp", "-aT", str(src_dir), str(dst)])
    _sudo(["chown", "-R", f"root:{SERVICE_USER}", str(dst)])
    _write_seed_content_file(scenario, agent)
    # Files readable by the delftclaw group; dirs traversable.
    _sudo(["chmod", "-R", "g+rX,o-rwx", str(dst)])
    c_ok(f"{agent.name}: staged scenario tree under {dst}")


def _write_seed_content_file(scenario: Scenario, agent: AgentSpec) -> None:
    target = _seed_content_file_path(scenario, agent)
    content_dir = _state_dir(scenario.name, agent.name) / "seed_content"
    rows = []
    if agent.seed_content:
        _sudo(["install", "-d", "-o", SERVICE_USER, "-g", SERVICE_USER, "-m", "0750", str(content_dir)])
    for item in agent.seed_content:
        safe_name = "".join(c if c.isalnum() or c in "._-" else "_" for c in item.name)
        content_path = content_dir / safe_name
        payload = (
            "DelftClaw paper demo seed content\n"
            f"name={item.name}\n"
            f"magnet={item.magnet}\n"
        )
        subprocess.run(
            ["sudo", "tee", str(content_path)],
            input=payload,
            capture_output=True,
            text=True,
            check=True,
        )
        _sudo(["chmod", "0640", str(content_path)])
        _sudo(["chown", f"{SERVICE_USER}:{SERVICE_USER}", str(content_path)])
        rows.append({
            "magnet": item.magnet,
            "name": item.name,
            "size": item.size,
            "mime": item.mime,
            "tags": list(item.tags),
            "path": str(content_path),
        })
    subprocess.run(
        ["sudo", "tee", str(target)],
        input=json.dumps(rows, indent=2, sort_keys=True) + "\n",
        capture_output=True,
        text=True,
        check=True,
    )
    _sudo(["chmod", "0640", str(target)])
    _sudo(["chown", f"root:{SERVICE_USER}", str(target)])


def _enable_unit(unit: str) -> None:
    # ``restart`` not ``enable --now`` so re-running ``make scenario`` after
    # a code rsync always picks up fresh Python — ``enable --now`` is a
    # no-op for already-running units and leaves the previous process in
    # place with the stale code loaded. ``daemon-reload`` re-parses the
    # unit file (env path may have changed); ``reset-failed`` clears any
    # prior crash flag so restart isn't rate-limited; ``enable`` is still
    # needed once for the WantedBy hookup; ``restart`` then guarantees a
    # fresh process.
    _sudo(["systemctl", "daemon-reload"])
    _sudo(["systemctl", "reset-failed", unit], check=False)
    _sudo(["systemctl", "enable", unit])
    _sudo(["systemctl", "restart", unit])


def _stop_unit(unit: str) -> None:
    _sudo(["systemctl", "stop", unit], check=False)
    _sudo(["systemctl", "disable", unit], check=False)


def _openclaw_run(
    sudo_env: list[str],
    args: list[str],
    *,
    timeout_s: int = 60,
    capture: bool = False,
    check: bool = True,
) -> subprocess.CompletedProcess:
    """Run an OpenClaw CLI command with a hard timeout.

    A hung OpenClaw process used to make scenario boot or teardown appear
    successful while leaving stopped sudo children behind. Fail fast here so
    the operator sees an actionable error before watchdog turn 1.
    """
    return subprocess.run(
        [*sudo_env, "openclaw", *args],
        check=check,
        capture_output=capture,
        text=True,
        timeout=timeout_s,
    )


def _openclaw_config_set(sudo_env: list[str], path: str, value: object) -> None:
    """Set one OpenClaw config path using the stable JSON value interface."""
    _openclaw_run(
        sudo_env,
        ["config", "set", path, json.dumps(value), "--json"],
        timeout_s=30,
    )


# ---------------------------------------------------------------------------
# MCP introspection
# ---------------------------------------------------------------------------

async def _await_mcp_up(url: str, timeout_s: float = 60.0) -> None:
    """Wait until the MCP server at ``url`` answers ``tools/list``.

    Logs the last error every 10s while waiting so a hung MCP unit is
    diagnosable from the orchestrator side (the unit itself may be
    silent if it's hung inside agent.start() before the [mcp] log).
    """
    start = time.monotonic()
    last_err: Exception | None = None
    last_report = 0.0
    while time.monotonic() - start < timeout_s:
        try:
            async with Client(url) as c:
                await c.list_tools()
                return
        except Exception as exc:
            last_err = exc
        elapsed = time.monotonic() - start
        if elapsed - last_report >= 10.0:
            c_warn(f"still waiting for {url} after {elapsed:.0f}s; last error: "
                   f"{type(last_err).__name__}: {last_err}")
            last_report = elapsed
        await asyncio.sleep(1.0)
    raise TimeoutError(f"MCP at {url} did not come up within {timeout_s}s: {last_err}")


async def _call_mcp(url: str, tool: str, args: dict) -> dict | str:
    async with Client(url) as c:
        result = await c.call_tool(tool, args)
    if getattr(result, "content", None):
        text = getattr(result.content[0], "text", "")
        try:
            return json.loads(text)
        except (json.JSONDecodeError, TypeError):
            return text
    return getattr(result, "structured_content", {}) or {}


async def _agent_self_info(url: str) -> dict:
    """Fetch ``wallet_address``. The IPv8 pubkey we can't get over MCP yet
    (no tool exposes it), so we derive it locally from the seed file the
    boot script generated.
    """
    addr = await _call_mcp(url, "wallet_address", {})
    return {"wallet_address": addr if isinstance(addr, str) else str(addr)}


def _provision_openclaw_workspace(scenario: Scenario, agent: AgentSpec) -> None:
    """Register an isolated OpenClaw agent + MCP server in its per-HOME config.

    Each delftclaw agent boots its watchdog with ``HOME=/var/lib/delftclaw/
    <scenario>/<agent>``. OpenClaw resolves its config at ``$HOME/.openclaw/``,
    so writing per-agent state under that HOME naturally isolates them.

    Three sub-steps:
      1. ``openclaw mcp set <instance> '{"url": "http://127.0.0.1:<port>/mcp",
         "transport": "streamable-http"}'`` — wire the agent's MCP server into
         its config so ``openclaw agent`` knows where to look.
      2. ``openclaw agents add <instance> --non-interactive --workspace …
         --agent-dir …`` — register the agent name the watchdog will pass to
         ``--agent <instance>``.
      3. Verify with ``openclaw agents list --json``.

    Each command runs as the ``delftclaw`` user with HOME pointing at this
    agent's state dir, so the config writes land in the right place.
    """
    instance = scenario.instance_id(agent.name)
    state = _state_dir(scenario.name, agent.name)
    workspace = state / "openclaw" / "workspace"
    agent_dir = state / "openclaw" / "agent"
    mcp_url = f"http://127.0.0.1:{agent.mcp_port}/mcp"

    _sudo(["install", "-d", "-o", SERVICE_USER, "-g", SERVICE_USER,
           "-m", "0750", str(workspace)])
    _sudo(["install", "-d", "-o", SERVICE_USER, "-g", SERVICE_USER,
           "-m", "0750", str(agent_dir)])

    sudo_env = [
        "sudo", "-u", SERVICE_USER, "env",
        f"HOME={state}",
        "PATH=/usr/local/bin:/usr/bin:/bin",
        "OLLAMA_API_KEY=ollama",
        "OPENCLAW_DISABLE_TELEMETRY=1",
    ]
    openclaw_api_key_value = _openclaw_api_key_for_agent(scenario, agent)
    if openclaw_api_key_value:
        sudo_env.append(f"{OPENCLAW_LLM['api_key_env']}={openclaw_api_key_value}")

    # (1) Update the agent's openclaw.json so the reasoning provider is
    # registered before any model lookup happens. Without this,
    # ``openclaw agent --local --model <provider>/<model>`` can't resolve.
    #
    # ``agents.defaults.timeoutSeconds`` is the *inner* LLM call timeout (the
    # subprocess-level timeout we pass via --timeout is unrelated). Keep it
    # below the watchdog's subprocess budget (interval_s + 30) so provider
    # failures surface inside OpenClaw instead of being truncated by the
    # watchdog. Gemini free-tier calls can be slow under load, so cap this
    # high enough for first-turn cold starts.
    provider_id = OPENCLAW_LLM["provider"]
    provider_api = OPENCLAW_LLM["api"]
    provider_model = OPENCLAW_LLM["model"]
    provider_config = {
        "baseUrl": _normalise_openclaw_base_url(provider_id, OPENCLAW_LLM["base_url"]),
        "api": provider_api,
        # OpenClaw resolves this string against the process environment.
        # For Ollama we set OLLAMA_API_KEY=ollama; for Gemini set
        # GEMINI_API_KEY in configs/host.env or the shell before boot.
        "apiKey": OPENCLAW_LLM["api_key_env"],
        "models": [
            {
                "id": provider_model,
                "name": provider_model,
                "reasoning": False,
                "input": ["text"],
                "cost": {"input": 0, "output": 0,
                         "cacheRead": 0, "cacheWrite": 0},
                "contextWindow": 32768,
                "maxTokens": 4096,
            },
        ],
    }
    # Assign the provider object directly so re-runs replace the model list
    # instead of keeping stale models from earlier scenario boots. Use
    # ``config set`` rather than ``config patch --stdin`` because older
    # OpenClaw CLIs reject the newer ``--stdin`` flag.
    c_info(f"{agent.name}: openclaw config set ({provider_id} provider)")
    inner_timeout_s = max(60, min(210, scenario.watchdog.interval_s - 15))
    _openclaw_config_set(sudo_env, "agents.defaults.timeoutSeconds", inner_timeout_s)
    _openclaw_config_set(sudo_env, "models.mode", "merge")
    _openclaw_config_set(sudo_env, f"models.providers.{provider_id}", provider_config)

    # (2) Register the MCP server in this HOME's openclaw.json.
    mcp_value = json.dumps({"url": mcp_url, "transport": "streamable-http"})
    c_info(f"{agent.name}: openclaw mcp set {instance} -> {mcp_url}")
    _openclaw_run(
        sudo_env,
        ["mcp", "set", instance, mcp_value],
        timeout_s=30,
    )

    # (3) Register the agent. ``openclaw agents add`` errors if already
    # present, so we list-and-skip when re-running.
    proc = _openclaw_run(
        sudo_env,
        ["agents", "list", "--json"],
        timeout_s=30,
        capture=True,
        check=False,
    )
    existing: list[str] = []
    if proc.returncode == 0:
        try:
            blob = json.loads(proc.stdout or "[]")
            if isinstance(blob, list):
                existing = [a.get("name") for a in blob if isinstance(a, dict)]
            elif isinstance(blob, dict) and "agents" in blob:
                existing = [a.get("name") for a in blob["agents"] if isinstance(a, dict)]
        except json.JSONDecodeError:
            pass

    if instance in existing:
        c_info(f"{agent.name}: openclaw agent {instance!r} already registered")
    else:
        c_info(f"{agent.name}: openclaw agents add {instance}")
        _openclaw_run(
            sudo_env,
            ["agents", "add", instance,
             "--non-interactive",
             "--workspace", str(workspace),
             "--agent-dir", str(agent_dir),
             "--model", f"{provider_id}/{provider_model}"],
            timeout_s=60,
        )

    c_ok(f"{agent.name}: OpenClaw workspace provisioned ({state}/.openclaw/)")


# ---------------------------------------------------------------------------
# Network manifest synthesis
# ---------------------------------------------------------------------------

def _pick_genesis(scenario: Scenario) -> str | None:
    """Pick the agent referenced as a peer by the most other agents.

    For a scenario like ``seek_cc`` where bob.peers = [alice] and alice has
    no peers entry, alice wins. For scenarios where nobody references a
    peer (single-agent demos), this returns the first agent in YAML order.
    """
    refs: dict[str, int] = {name: 0 for name in scenario.agents}
    for agent in scenario.agents.values():
        for peer in agent.peers:
            refs[peer] = refs.get(peer, 0) + 1
    if not refs:
        return None
    name, count = max(refs.items(), key=lambda kv: kv[1])
    if count == 0:
        # No-one referenced; pick the first declared agent for determinism.
        return next(iter(scenario.agents))
    return name


def _default_overlay_hashes(scenario: Scenario, genesis_name: str) -> list[str]:
    """Sha1[:20] (hex) of every overlay the genesis agent publishes at boot."""
    from protocol.compiler import community_id_from_md
    hashes: list[str] = []
    for p in scenario.agents[genesis_name].publish_overlays:
        text = Path(p).read_text(encoding="utf-8")
        hashes.append(community_id_from_md(text).hex())
    return hashes


def _build_manifest_md(
    *,
    scenario: Scenario,
    genesis_name: str,
    genesis_coords: dict,
    default_overlay_hashes: list[str],
    min_sats: int = 10_000,
    min_confirmations: int = 0,
    bootstrap_cap_sats: int = 100_000,
    max_agents_per_seedbox: int = 3,
    seedbox_cost_sats: int = 20_000,
) -> str:
    """Render a network manifest .md from the genesis agent's runtime coords."""
    if default_overlay_hashes:
        overlays_section = "\n".join(
            f"- sha1: {h}  (default overlay)" for h in default_overlay_hashes
        )
    else:
        overlays_section = "(none — joiners discover overlays via OVERLAY_OFFER)"
    return (
        "# Identity\n"
        f"- name: {scenario.name}\n"
        "- version: 1.0.0\n"
        f"- description: Auto-generated manifest for scenario {scenario.name}.\n"
        "\n"
        "# Admission\n"
        f"- gatekeeper_address: {genesis_coords['wallet_address']}\n"
        f"- min_sats: {min_sats}\n"
        f"- min_confirmations: {min_confirmations}\n"
        f"- bootstrap_cap_sats: {bootstrap_cap_sats}\n"
        f"- max_agents_per_seedbox: {max_agents_per_seedbox}\n"
        f"- seedbox_cost_sats: {seedbox_cost_sats}\n"
        "\n"
        "# Genesis Peers\n"
        "| host | port | pubkey_hex |\n"
        "|------|------|------------|\n"
        f"| {genesis_coords['host']} | {genesis_coords['port']} | {genesis_coords['pubkey_hex']} |\n"
        "\n"
        "# Default Overlays\n"
        f"{overlays_section}\n"
    )


def _pubkey_for_agent(scenario: Scenario, agent: AgentSpec) -> str:
    """Read the agent's seed file (as the delftclaw user) and derive its IPv8 pubkey hex."""
    seed_file = _state_dir(scenario.name, agent.name) / "seed.txt"
    cmd = [
        "sudo", "-u", SERVICE_USER, "env",
        f"PYTHONPATH={REPO_ROOT}",
        f"{REPO_ROOT}/venv/bin/python", "-c",
        (
            "from identity.seed import KeyfileSeedSource;"
            "from identity.agent_identity import AgentIdentity;"
            f"seed = KeyfileSeedSource('{seed_file}').load();"
            "ident = AgentIdentity.from_seed(seed, network='TESTNET');"
            "print(ident.ipv8.pubkey.hex())"
        ),
    ]
    proc = subprocess.run(cmd, check=True, capture_output=True, text=True)
    return proc.stdout.strip()


# ---------------------------------------------------------------------------
# Top-level orchestration
# ---------------------------------------------------------------------------

async def _bring_up(scenario: Scenario, dry_run: bool) -> int:
    # Phase 1: filesystem + env + scenario staging.
    if not dry_run:
        _prepare_shared_state(scenario)
    for agent in scenario.agents.values():
        if dry_run:
            c_dry(f"{agent.name}: would seed + write env at {_instance_env_path(scenario, agent)}")
            c_dry(f"  env body:\n{_redact_env_for_log(_instance_env_contents(scenario, agent))}")
            continue
        _seed_for_agent(scenario, agent)
        _stage_scenario_dir(scenario, agent)
        _write_env_file(scenario, agent)

    if dry_run:
        c_dry(f"would systemctl enable --now delftclaw-mcp@<instance> for {list(scenario.agents)}")
        for agent in scenario.agents.values():
            instance = scenario.instance_id(agent.name)
            c_dry(f"  would openclaw mcp set {instance} (HOME=/var/lib/delftclaw/{scenario.name}/{agent.name})")
            c_dry(f"  would openclaw agents add {instance} --non-interactive --model {OPENCLAW_LLM['provider']}/{OPENCLAW_LLM['model']}")
        c_dry("would call MCP peer_add for cross-introductions:")
        for agent in scenario.agents.values():
            for peer_name in agent.peers:
                c_dry(f"  {agent.name}.peer_add({peer_name})")
        c_dry(f"would systemctl start delftclaw-watchdog@<instance> for {list(scenario.agents)}")
        return 0

    # Phase 2: start MCP services + wait for them to come up.
    for agent in scenario.agents.values():
        _enable_unit(f"delftclaw-mcp@{scenario.instance_id(agent.name)}.service")

    for agent in scenario.agents.values():
        url = f"http://127.0.0.1:{agent.mcp_port}/mcp"
        c_info(f"{agent.name}: waiting for MCP at {url}")
        await _await_mcp_up(url)
        c_ok(f"{agent.name}: MCP up at {url}")

    # Phase 2b: provision the per-agent OpenClaw workspace + MCP config so
    # the watchdog's ``openclaw agent --agent <instance>`` calls resolve.
    for agent in scenario.agents.values():
        _provision_openclaw_workspace(scenario, agent)

    # Phase 3: collect (pubkey, host, port) per agent.
    coords: dict[str, dict] = {}
    for agent in scenario.agents.values():
        info = await _agent_self_info(f"http://127.0.0.1:{agent.mcp_port}/mcp")
        coords[agent.name] = {
            "host": "127.0.0.1",          # same-VPS demo; for cross-VPS, override
            "port": agent.ipv8_port,
            "pubkey_hex": _pubkey_for_agent(scenario, agent),
            **info,
        }
        c_ok(f"{agent.name}: wallet={info['wallet_address']}  pubkey={coords[agent.name]['pubkey_hex'][:24]}...")

    # Phase 4: cross-introduce peers.
    for agent in scenario.agents.values():
        for peer_name in agent.peers:
            target = coords[peer_name]
            url = f"http://127.0.0.1:{agent.mcp_port}/mcp"
            c_info(f"{agent.name}.peer_add({peer_name})")
            try:
                result = await _call_mcp(url, "peer_add", {
                    "host": target["host"],
                    "port": target["port"],
                    "pubkey_hex": target["pubkey_hex"],
                })
            except Exception as exc:
                c_fail(f"peer_add {agent.name}->{peer_name} failed: {exc}")
                return 1
            c_ok(f"{agent.name} now knows {peer_name}: {result}")

    # Phase 4b: build a network manifest from the genesis agent's runtime
    # coords and inject it into every agent. Without this, state.network is
    # null in the snapshot and the LLMs have no admission target — the most
    # common cause of "scenario is up but nothing happens."
    #
    # We do both: (a) push the manifest via MCP into each agent's MCP-process
    # runtime, and (b) write the manifest to disk under the staged scenario
    # dir so the watchdog (a SEPARATE in-process snapshot agent on
    # ``ipv8_port + 1000``) can load it at boot via the MANIFEST_FILE env var.
    # Skipping (b) leaves state.network null in every snapshot.
    genesis_name = _pick_genesis(scenario)
    if genesis_name is None:
        c_warn("manifest: no agents declared; skipping injection")
    else:
        default_hashes = _default_overlay_hashes(scenario, genesis_name)
        manifest_md = _build_manifest_md(
            scenario=scenario,
            genesis_name=genesis_name,
            genesis_coords=coords[genesis_name],
            default_overlay_hashes=default_hashes,
        )
        c_info(f"manifest: genesis={genesis_name}, "
               f"gatekeeper={coords[genesis_name]['wallet_address']}, "
               f"overlays={len(default_hashes)}")
        for agent in scenario.agents.values():
            # (b) Write to disk first so a watchdog restart re-finds it
            # without re-running scenario_boot. The staged scenario dir is
            # owned by root:delftclaw 0750 (cp -aT preserves that).
            manifest_path = _manifest_file_path(scenario, agent)
            proc = subprocess.run(
                ["sudo", "tee", str(manifest_path)],
                input=manifest_md, capture_output=True, text=True, check=True,
            )
            _sudo(["chmod", "0640", str(manifest_path)])
            _sudo(["chown", f"root:{SERVICE_USER}", str(manifest_path)])
            c_ok(f"{agent.name}: manifest written to {manifest_path}")

            # (a) Inject into the MCP-process agent so OpenClaw-driven tool
            # calls (network_join, agent_inject_manifest, etc.) see it
            # immediately without waiting for the watchdog's first tick.
            url = f"http://127.0.0.1:{agent.mcp_port}/mcp"
            c_info(f"{agent.name}.agent_inject_manifest(...)")
            try:
                result = await _call_mcp(url, "agent_inject_manifest", {
                    "md_text": manifest_md,
                })
            except Exception as exc:
                c_fail(f"agent_inject_manifest {agent.name} failed: {exc}")
                return 1
            if isinstance(result, dict) and "error" in result:
                c_fail(f"agent_inject_manifest {agent.name}: {result['error']}")
                return 1
            c_ok(f"{agent.name}: manifest cached in MCP agent: {result}")

    # Phase 5: start watchdogs.
    for agent in scenario.agents.values():
        _enable_unit(f"delftclaw-watchdog@{scenario.instance_id(agent.name)}.service")

    c_ok(f"scenario '{scenario.name}' is up. Watch with: make watch NAME={scenario.name}")
    return 0


def _teardown(scenario: Scenario, dry_run: bool) -> int:
    for agent in scenario.agents.values():
        instance = scenario.instance_id(agent.name)
        state = _state_dir(scenario.name, agent.name)
        if dry_run:
            c_dry(f"would stop delftclaw-watchdog@{instance} and delftclaw-mcp@{instance}")
            c_dry(f"would openclaw agents delete {instance} (HOME={state})")
            continue
        _stop_unit(f"delftclaw-watchdog@{instance}.service")
        _stop_unit(f"delftclaw-mcp@{instance}.service")
        # Unregister the per-agent OpenClaw workspace; don't fail teardown if
        # it was never created (re-runs after partial boots).
        _openclaw_run(
            [
                "sudo", "-u", SERVICE_USER, "env",
                f"HOME={state}",
                "PATH=/usr/local/bin:/usr/bin:/bin",
                "OPENCLAW_DISABLE_TELEMETRY=1",
            ],
            ["agents", "delete", instance, "--force"],
            timeout_s=30,
            check=False,
        )
        env_path = _instance_env_path(scenario, agent)
        if env_path.exists():
            _sudo(["rm", "-f", str(env_path)])
    c_ok(f"scenario '{scenario.name}' torn down")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="python -m deploy.scenario_boot")
    parser.add_argument("scenario", help="scenario name (directory under deploy/scenarios/)")
    parser.add_argument("--dry-run", action="store_true",
                        help="parse + print plan; do not touch the system")
    parser.add_argument("--teardown", action="store_true",
                        help="stop the scenario instead of starting it")
    args = parser.parse_args()

    manifest = SCENARIOS_REPO_DIR / args.scenario / "scenario.yaml"
    scenario = parse_scenario(manifest)

    if args.teardown:
        return _teardown(scenario, dry_run=args.dry_run)
    return asyncio.run(_bring_up(scenario, dry_run=args.dry_run))


if __name__ == "__main__":
    raise SystemExit(main())
