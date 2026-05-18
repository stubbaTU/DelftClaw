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


DEFAULT_LLM_BASE_URL = "http://100.73.168.12:11434/v1"
DEFAULT_LLM_MODEL = "qwen3.6:27b"
DEFAULT_LLM_API_KEY = "ollama"


def _resolve_bitcoin_rpc(host_env_file: Path = HOST_ENV_FILE) -> tuple[str, str, str]:
    """Resolve (rpc_url, rpc_user, rpc_password) for regtest RPC.

    Order: process env var → configs/host.env (if present) → defaults.
    Defaults match deploy/setup_bitcoin_regtest.sh.
    """
    host_env = _load_host_env(host_env_file)
    rpc_url = os.environ.get(
        "BITCOIN_RPC_URL",
        host_env.get("BITCOIN_RPC_URL", "http://127.0.0.1:18443"),
    )
    rpc_user = os.environ.get(
        "BITCOIN_RPC_USER",
        host_env.get("BITCOIN_RPC_USER", host_env.get("BITCOIN_RPC_USERNAME", "")),
    )
    rpc_password = os.environ.get(
        "BITCOIN_RPC_PASSWORD",
        host_env.get("BITCOIN_RPC_PASSWORD", host_env.get("BITCOIN_RPC_PASS", "")),
    )
    return rpc_url, rpc_user, rpc_password


def _resolve_llm(host_env_file: Path = HOST_ENV_FILE) -> tuple[str, str, str]:
    """Resolve LLM_BASE_URL + LLM_MODEL + LLM_API_KEY.

    Order: process env var → configs/host.env (if present) →
    hard-coded default. Exposed as a function so tests can stub the
    file path without re-executing the whole module body.
    """
    host_env = _load_host_env(host_env_file)
    base = os.environ.get(
        "LLM_BASE_URL",
        host_env.get("LLM_BASE_URL", DEFAULT_LLM_BASE_URL),
    )
    model = os.environ.get(
        "LLM_MODEL",
        host_env.get("LLM_MODEL", DEFAULT_LLM_MODEL),
    )
    api_key = os.environ.get(
        "LLM_API_KEY",
        host_env.get("LLM_API_KEY", DEFAULT_LLM_API_KEY),
    )
    return base, model, api_key


# Module-level constants used by `_instance_env_contents` and the
# OpenClaw provider patch. Tests that need to vary these stub
# ``HOST_ENV_FILE`` then re-call ``_resolve_llm`` directly.
LLM_BASE_URL, LLM_MODEL, LLM_API_KEY = _resolve_llm()


def _native_base_from(base_url: str) -> str:
    """Strip the trailing ``/v1`` from an OpenAI-compat URL to get Ollama's native base."""
    return base_url.rstrip("/").removesuffix("/v1")


def _direct_patch_openclaw_json(path: Path, provider_key: str, provider_cfg: dict) -> None:
    """Set ``models.providers`` in openclaw.json to a single provider.

    Bypasses ``openclaw config patch`` to sidestep its size-drop safety
    check (which fires when wiping a stale multi-provider map). Uses
    ``sudo tee`` to write since the file is owned by ``delftclaw``.
    """
    if not path.is_file():
        raise RuntimeError(f"expected openclaw.json at {path} but file is missing")
    raw_text = subprocess.run(
        ["sudo", "cat", str(path)],
        capture_output=True, text=True, check=True,
    ).stdout
    try:
        cfg = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"openclaw.json at {path} is not valid JSON: {exc}") from exc

    models = cfg.setdefault("models", {})
    models["mode"] = "merge"
    models["providers"] = {provider_key: provider_cfg}

    body = json.dumps(cfg, indent=2)
    subprocess.run(
        ["sudo", "tee", str(path)],
        input=body, capture_output=True, text=True, check=True,
    )
    subprocess.run(
        ["sudo", "chown", f"{SERVICE_USER}:{SERVICE_USER}", str(path)],
        check=True,
    )


def _provider_for(base_url: str) -> tuple[str, str, str]:
    """Resolve (provider_key, api_type, base_url) from a configured URL.

    OpenClaw validates ``api`` against a fixed list — ``"ollama"`` for
    Ollama's native protocol (POST /api/chat), ``"openai-completions"``
    for OpenAI-compatible endpoints (POST /v1/chat/completions). The
    OpenAI-compat path covers Anthropic (via its OpenAI-compat endpoint
    fronted by llm_proxy.py), OpenAI itself, vLLM, Groq, etc. We pick
    based on whether the configured URL keeps the ``/v1`` suffix.

    Returns ``(provider_key, api_type, base_url)``. The ``provider_key``
    must match the ``--model <key>/<name>`` prefix used at agent
    registration time. We deliberately AVOID common provider names
    (``openai``, ``anthropic``, ``google``) because OpenClaw appears to
    treat those as reserved and silently overrides our baseUrl/api
    with its built-in defaults. ``compat`` is a generic placeholder
    that doesn't collide.
    """
    trimmed = base_url.rstrip("/")
    if trimmed.endswith("/v1"):
        return ("compat", "openai-completions", trimmed)
    return ("ollama", "ollama", _native_base_from(base_url))


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


def _instance_env_path(scenario: Scenario, agent: AgentSpec) -> Path:
    return ETC_INSTANCES / f"{scenario.instance_id(agent.name)}.env"


def _scenario_dir_on_vps(scenario: Scenario, agent: AgentSpec) -> Path:
    return ETC_SCENARIOS / scenario.instance_id(agent.name)


def _manifest_file_path(scenario: Scenario, agent: AgentSpec) -> Path:
    """Where scenario_boot writes the synthesised manifest the watchdog reads."""
    return _scenario_dir_on_vps(scenario, agent) / "network_manifest.md"


def _instance_env_contents(scenario: Scenario, agent: AgentSpec) -> str:
    state = _state_dir(scenario.name, agent.name)
    seed_file = state / "seed.txt"
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
    # Stagger the first turn across agents so they don't all hit the LLM
    # provider at the same instant. Each agent gets a different slot in
    # the interval_s window — agent i waits (i / N) * interval_s seconds
    # before its first tick. After that the sleep loop keeps them offset.
    agent_index = list(scenario.agents).index(agent.name)
    num_agents = len(scenario.agents)
    initial_delay_s = (agent_index * scenario.watchdog.interval_s) / num_agents
    # Bitcoin / regtest RPC config.
    bitcoin_rpc_url, bitcoin_rpc_user, bitcoin_rpc_password = _resolve_bitcoin_rpc()
    if agent.bitcoin_rpc_url:
        bitcoin_rpc_url = agent.bitcoin_rpc_url
    bitcoin_rpc_wallet = agent.bitcoin_rpc_wallet or agent.name

    lines = [
        "# generated by deploy.scenario_boot — do not hand-edit",
        f"PYTHONPATH={REPO_ROOT}",
        f"HOME={state}",
        f"SEED_FILE={seed_file}",
        "NETWORK=TESTNET",
        # BTC network mode for admission verifier + higher-level policy.
        # For real Regtest transactions, scenarios set agent.btc_network=regtest.
        f"BTC_NETWORK={agent.btc_network}",
        f"INITIAL_BALANCE_SATS={agent.initial_balance_sats}",
        # Regtest RPC wiring (consumed by agent/cli.py). These do not affect
        # the synthetic wallet tools; they only enable the btc_* RPC tools.
        f"BITCOIN_RPC_URL={bitcoin_rpc_url}",
        f"BITCOIN_RPC_WALLET={bitcoin_rpc_wallet}",
        f"BITCOIN_RPC_USER={bitcoin_rpc_user}",
        f"BITCOIN_RPC_PASSWORD={bitcoin_rpc_password}",
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
        # The watchdog reads this file at boot and calls load_manifest on its
        # snapshot agent. Without it, state.network would be null in every
        # snapshot — Phase 4b's MCP-driven injection only reaches the *MCP*
        # process's agent, not the watchdog's separate snapshot collector.
        f"MANIFEST_FILE={_manifest_file_path(scenario, agent)}",
        f"LLM_BASE_URL={LLM_BASE_URL}",
        f"LLM_MODEL={LLM_MODEL}",
        # Mirror of the literal ``apiKey`` written into openclaw.json. Kept
        # here too so any code path that reads the env var (rather than the
        # openclaw config) sees the same value.
        f"LLM_API_KEY={LLM_API_KEY}",
        # Compatibility aliases: the checked-in systemd unit uses QWEN_*.
        # Keep both until the unit file is updated everywhere.
        f"QWEN_BASE_URL={LLM_BASE_URL}",
        f"QWEN_MODEL={LLM_MODEL}",
        # The watchdog passes ``--model {OPENCLAW_PROVIDER_KEY}/{LLM_MODEL}``
        # to ``openclaw agent``. The key must match what we wrote into the
        # agent's openclaw.json providers map (``compat`` for OpenAI-compat
        # endpoints, ``ollama`` for native Ollama).
        f"OPENCLAW_PROVIDER_KEY={_provider_for(LLM_BASE_URL)[0]}",
        f"LOG_DIR={scenario.log_dir}",
        f"WATCHDOG_INITIAL_DELAY_S={initial_delay_s:.2f}",
    ]
    return "\n".join(lines) + "\n"


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
    # Files readable by the delftclaw group; dirs traversable.
    _sudo(["chmod", "-R", "g+rX,o-rwx", str(dst)])
    c_ok(f"{agent.name}: staged scenario tree under {dst}")


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
    """Stop+disable a systemd unit and verify the main PID actually died.

    ``systemctl stop`` returns success the moment systemd has sent SIGTERM,
    not when the worker process has actually exited. If the worker hangs
    inside teardown (IPv8 shutdown can stall, uvicorn doesn't honour
    ``should_exit`` mid-keepalive, the asyncio loop is wedged in an await
    that never wakes), the next ``make demo`` boots a NEW worker that
    fights the zombie for the same TCP/UDP ports and fails to bind. The
    pattern looks like: ``ss -ltnp`` shows the redteam port held but
    ``systemctl status`` reports the unit as inactive — load-bearing
    foot-gun caught live in the seek_cc 20:46 session.

    Defence:
      1. ``systemctl stop`` — polite SIGTERM.
      2. Poll ``systemctl is-active`` for 5s — wait for systemd to
         report the unit as inactive.
      3. If still active, escalate to ``systemctl kill -s SIGKILL``.
      4. ``systemctl disable`` regardless so the unit doesn't auto-start.
    """
    _sudo(["systemctl", "stop", unit], check=False)
    # Step 2: short poll for `is-active` to flip to inactive/failed.
    for _ in range(10):
        proc = subprocess.run(
            ["systemctl", "is-active", unit],
            capture_output=True, text=True, check=False,
        )
        state = (proc.stdout or "").strip()
        if state in ("inactive", "failed", "deactivating"):
            break
        time.sleep(0.5)
    else:
        # Step 3: escalate.
        c_warn(f"{unit}: still active after 5s — escalating to SIGKILL")
        _sudo(["systemctl", "kill", "-s", "SIGKILL", unit], check=False)
        time.sleep(0.5)
    _sudo(["systemctl", "disable", unit], check=False)


def _scenario_python_patterns(scenario: Scenario) -> list[str]:
    """pgrep patterns that match any python process this scenario could own."""
    return [
        # MCP-process agents — match the systemd ExecStart cmdline.
        f"python -m agent .*{scenario.name}-",
        # Watchdog processes — match the systemd ExecStart cmdline.
        f"python -m deploy.watchdog .*{scenario.name}-",
    ]


def _purge_orphans(scenario: Scenario) -> None:
    """Kill any leftover delftclaw worker process that systemd lost track of.

    Sweeps every TCP port the scenario manifest declares (mcp / redteam)
    plus every UDP port (ipv8), plus pgrep-by-cmdline as a belt-and-
    braces fallback. Runs BEFORE ``_enable_unit`` so a half-dead
    previous run can't hold the ports we're about to ask the new
    services to bind.

    Idempotent. Cheap (<1s) when the host is clean.
    """
    # Collect every port this scenario will try to bind. We don't know
    # what the previous run actually held, but binding the new run's
    # ports is the only thing we need to clear.
    tcp_ports: list[int] = []
    udp_ports: list[int] = []
    for agent in scenario.agents.values():
        tcp_ports.append(agent.mcp_port)
        if agent.redteam_port:
            tcp_ports.append(agent.redteam_port)
        udp_ports.append(agent.ipv8_port)

    # ``fuser -k`` sends SIGKILL to any process holding a given port.
    # ``-n tcp`` / ``-n udp`` picks the address family. We invoke
    # silently and ignore exit codes — a port being unbound is the
    # success case and fuser returns 1 there.
    for port in tcp_ports:
        _sudo(["fuser", "-k", "-s", f"{port}/tcp"], check=False)
    for port in udp_ports:
        _sudo(["fuser", "-k", "-s", f"{port}/udp"], check=False)

    # Belt + braces: pkill anything that looks like a scenario worker
    # whose ports we somehow missed (e.g. a worker that already crashed
    # mid-bind and is in zombie state with no port).
    for pattern in _scenario_python_patterns(scenario):
        _sudo(["pkill", "-9", "-f", pattern], check=False)

    # Brief settle so the kernel actually releases the sockets before
    # the next systemctl start tries to bind. SO_REUSEADDR mitigates
    # the TIME_WAIT race but not all UDP setups honour it.
    time.sleep(0.5)
    c_ok(f"{scenario.name}: purged orphan workers + freed scenario ports")


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

    sudo_env = ["sudo", "-u", SERVICE_USER, "env", f"HOME={state}"]

    # (1) Patch the agent's openclaw.json so the configured provider is
    # registered before any model lookup happens. Without this,
    # ``openclaw agent --local --model <provider>/<model>`` can't resolve
    # the model.
    #
    # ``agents.defaults.timeoutSeconds`` is the *inner* LLM call timeout (the
    # subprocess-level timeout we pass via --timeout is unrelated). qwen3.6:27b
    # cold-starts ~30s on the GPU host; the OpenClaw default of 30s would
    # always fire on turn 1. Set this generously below the watchdog tick
    # ``interval_s`` so timeouts surface as turn errors rather than truncated
    # responses mid-call.
    provider_key, api_type, provider_base = _provider_for(LLM_BASE_URL)
    new_provider = {
        "baseUrl": provider_base,
        "api": api_type,
        # OpenClaw refuses to register a provider without an apiKey;
        # we write a literal value rather than relying on env-var
        # interpolation (which this field doesn't support).
        "apiKey": LLM_API_KEY,
        "models": [
            {
                "id": LLM_MODEL,
                "name": LLM_MODEL,
                "reasoning": False,
                "input": ["text"],
                "cost": {"input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0},
                "contextWindow": 32768,
                "maxTokens": 4096,
            },
        ],
    }

    openclaw_json = state / ".openclaw" / "openclaw.json"

    # First, ensure openclaw.json exists by running a trivial patch
    # (the ``agents.defaults`` field doesn't shrink the file so it
    # doesn't trip openclaw's size-drop safety check). This also
    # sets the inner-LLM timeout to 150s, well below the watchdog
    # interval, so cold-starts don't surface as truncated responses.
    subprocess.run(
        [*sudo_env, "openclaw", "config", "patch", "--stdin"],
        input=json.dumps({"agents": {"defaults": {"timeoutSeconds": 150}}}),
        text=True, check=True,
    )

    # Now overwrite the providers map directly. ``openclaw config patch``
    # has a "size-drop" safety check that rejects writes shrinking the
    # file by more than a threshold, which fires when wiping stale
    # providers from prior boots. Sidestep it by editing openclaw.json
    # in place — that's the only file openclaw reads at startup.
    c_info(f"{agent.name}: openclaw config patch ({provider_key} / api={api_type})")
    _direct_patch_openclaw_json(openclaw_json, provider_key, new_provider)

    # (2) Register the MCP server in this HOME's openclaw.json.
    mcp_value = json.dumps({"url": mcp_url, "transport": "streamable-http"})
    c_info(f"{agent.name}: openclaw mcp set {instance} -> {mcp_url}")
    subprocess.run(
        [*sudo_env, "openclaw", "mcp", "set", instance, mcp_value],
        check=True,
    )

    # (3) Register the agent. ``openclaw agents add`` errors if already
    # present, so we list-and-skip when re-running.
    proc = subprocess.run(
        [*sudo_env, "openclaw", "agents", "list", "--json"],
        check=False, capture_output=True, text=True,
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
        subprocess.run(
            [*sudo_env, "openclaw", "agents", "add", instance,
             "--non-interactive",
             "--workspace", str(workspace),
             "--agent-dir", str(agent_dir),
             "--model", f"{provider_key}/{LLM_MODEL}"],
            check=True,
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
    for agent in scenario.agents.values():
        if dry_run:
            c_dry(f"{agent.name}: would seed + write env at {_instance_env_path(scenario, agent)}")
            c_dry(f"  env body:\n{_instance_env_contents(scenario, agent)}")
            continue
        _seed_for_agent(scenario, agent)
        _stage_scenario_dir(scenario, agent)
        _write_env_file(scenario, agent)

    if dry_run:
        c_dry(f"would systemctl enable --now delftclaw-mcp@<instance> for {list(scenario.agents)}")
        for agent in scenario.agents.values():
            instance = scenario.instance_id(agent.name)
            c_dry(f"  would openclaw mcp set {instance} (HOME=/var/lib/delftclaw/{scenario.name}/{agent.name})")
            _pk, _api, _ = _provider_for(LLM_BASE_URL)
            c_dry(f"  would openclaw agents add {instance} --non-interactive --model {_pk}/{LLM_MODEL}")
        c_dry("would call MCP peer_add for cross-introductions:")
        for agent in scenario.agents.values():
            for peer_name in agent.peers:
                c_dry(f"  {agent.name}.peer_add({peer_name})")
        c_dry(f"would systemctl start delftclaw-watchdog@<instance> for {list(scenario.agents)}")
        return 0

    # Phase 1.5: purge any worker process or port-holder the previous
    # run left behind. Without this, a zombie ``delftclaw-mcp@`` worker
    # whose systemctl stop never fully landed will keep holding the
    # ports the new services are about to ask the kernel for, and only
    # one of the four agents (whichever port happens to be free) will
    # actually come up — caught live in the seek_cc 20:46 session
    # where ``ss -ltnp`` showed exactly one redteam port bound out of
    # four. Idempotent + cheap on a clean host.
    _purge_orphans(scenario)

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
        subprocess.run(
            ["sudo", "-u", SERVICE_USER, "env", f"HOME={state}",
             "openclaw", "agents", "delete", instance, "--force"],
            check=False,
        )
        env_path = _instance_env_path(scenario, agent)
        if env_path.exists():
            _sudo(["rm", "-f", str(env_path)])
    # Final sweep — kill any worker that the per-instance stop missed.
    # ``_stop_unit`` already SIGKILLs the unit's main PID on hang, but
    # a child process orphaned by an asyncio.create_task that the
    # parent never awaited can survive and keep holding ports.
    _purge_orphans(scenario)
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
