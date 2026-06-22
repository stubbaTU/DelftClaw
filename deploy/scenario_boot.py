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
  5. Probe each MCP server with a real ``fastmcp`` client handshake to
     fetch ``wallet_address`` and the IPv8 pubkey.
  6. Cross-introduce peers — for every ``a peers: [b]``, call ``a``'s
     ``peer_add`` tool with ``b``'s host/port/pubkey.
  7. ``systemctl start delftclaw-watchdog@<instance>.service`` per agent.

``--dry-run`` skips all systemd / sudo / state-dir work; it only parses
the manifest and prints the plan. Useful from your laptop.

``--teardown`` stops everything for the scenario, removes the instance env
files, and wipes each agent's regenerable runtime artifacts — the
``torrents/`` dir (downloaded files + the cross-process download / offer
ledgers) and the ``overlay_archive/`` dir (per-demo spec archive). This is
what makes a re-run start CLEAN: otherwise a stale completed-download or a
stale authored-overlay satisfies a stop predicate at turn 0 and the agents
skip the demo. Seed files and the signed community/peer logs are kept, so
agent identities and the accountability history survive.

Usage:
    python -m deploy.scenario_boot payment
    python -m deploy.scenario_boot payment --dry-run
    python -m deploy.scenario_boot payment --teardown
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

from fastmcp import Client

from deploy.scenario import AgentSpec, Scenario, parse_scenario, REPO_ROOT


SCENARIOS_REPO_DIR = REPO_ROOT / "deploy" / "scenarios"
ETC_INSTANCES = Path("/etc/delftclaw/instances")
ETC_SCENARIOS = Path("/etc/delftclaw/scenarios")
STATE_ROOT = Path("/var/lib/delftclaw")
SERVICE_USER = "delftclaw"
HOST_ENV_FILE = REPO_ROOT / "configs" / ".env"


def _load_host_env(path: Path = HOST_ENV_FILE) -> dict[str, str]:
    """Parse ``configs/.env`` as KEY=VALUE pairs. Missing file → empty dict.

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


def _require_env(name: str, host_env: dict[str, str]) -> str:
    """Return ``name`` from the process env, else ``.env`` — and fail loud
    if it is set nowhere. There are no hard-coded fallbacks: a missing value is
    a configuration error the operator must fix in ``configs/.env``, not
    something we paper over with a placeholder endpoint."""
    value = os.environ.get(name, host_env.get(name, "")).strip()
    if not value:
        c_fail(f"{name} is not set — add it to {HOST_ENV_FILE}")
        raise SystemExit(2)
    return value


def _resolve_llm(host_env_file: Path = HOST_ENV_FILE) -> tuple[str, str, str]:
    """Resolve the compiler/agent LLM endpoint: LLM_BASE_URL / LLM_MODEL /
    LLM_API_KEY (process env > .env, else error). This is the single source
    of the overlay-compiler endpoint; the systemd MCP unit and the watchdog
    both read these LLM_* names directly. Resolved at boot time, never at import
    (so the module stays importable without .env)."""
    host_env = _load_host_env(host_env_file)
    return (
        _require_env("LLM_BASE_URL", host_env),
        _require_env("LLM_MODEL", host_env),
        _require_env("LLM_API_KEY", host_env),
    )


# The single env var that holds the upstream API key, everywhere. OpenClaw's
# config references this name and resolves it against the process env.
LLM_API_KEY_ENV = "LLM_API_KEY"


def _resolve_openclaw_provider(host_env_file: Path = HOST_ENV_FILE) -> dict[str, str]:
    """Resolve the OpenClaw reasoning-provider config.

    The provider id is ``LLM_API_PROVIDER`` (required). The reasoning endpoint
    defaults to the same LLM_* as the compiler, but a host can override it via
    ``OPENCLAW_BASE_URL`` / ``OPENCLAW_MODEL`` (e.g. a different tier). The API
    shape is always OpenAI-compatible, and the apiKey always comes from
    ``LLM_API_KEY``.
    """
    host_env = _load_host_env(host_env_file)
    base, model, _api_key = _resolve_llm(host_env_file)
    provider = _require_env("LLM_API_PROVIDER", host_env).lower()
    base_url = os.environ.get("OPENCLAW_BASE_URL", host_env.get("OPENCLAW_BASE_URL", base)).strip()
    oc_model = os.environ.get("OPENCLAW_MODEL", host_env.get("OPENCLAW_MODEL", model)).strip()
    return {
        "provider": provider,
        "api": "openai-completions",
        "base_url": base_url,
        "model": oc_model,
    }


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
    # Scenario-root dir owned by the service user. Hosts version_history.{jsonl,md}
    # (the fleet-merged thesis artifact), which every agent's OverlayArchive
    # writes via VERSION_HISTORY_DIR=STATE_ROOT/<scenario>. Without explicit
    # ownership the parent inherits root:root from `install -d` ancestors and
    # the delftclaw service silently fails to append (PermissionError ->
    # logged warning in protocol/version_history.py).
    scenario_root = STATE_ROOT / scenario.name
    _sudo(["install", "-d", "-o", SERVICE_USER, "-g", SERVICE_USER, "-m", "0755",
           str(scenario_root)])
    c_ok(f"{scenario.name}: scenario root ready ({scenario_root})")


def _instance_env_path(scenario: Scenario, agent: AgentSpec) -> Path:
    return ETC_INSTANCES / f"{scenario.instance_id(agent.name)}.env"


def _scenario_dir_on_vps(scenario: Scenario, agent: AgentSpec) -> Path:
    return ETC_SCENARIOS / scenario.instance_id(agent.name)


def _manifest_file_path(scenario: Scenario, agent: AgentSpec) -> Path:
    """Where scenario_boot writes the synthesised manifest the watchdog reads."""
    return _scenario_dir_on_vps(scenario, agent) / "network_manifest.md"


def _seed_content_file_path(scenario: Scenario, agent: AgentSpec) -> Path:
    return _scenario_dir_on_vps(scenario, agent) / "seed_content.json"


def _overlay_author_mode(scenario: Scenario, agent: AgentSpec) -> str:
    """Authoring role for the multi-version evolution chain (see env comment).

    Declared per-agent in scenario.yaml as ``overlay_author_role`` —
    ``genesis`` authors v1.0.0, ``successor`` adopts it + designs v1.1.0,
    ``""`` = no special role. file_share's fetcher_1/fetcher_2 and the
    payment demo's bob/charlie set these; every other agent is "".
    """
    return agent.overlay_author_role


def _instance_env_contents(scenario: Scenario, agent: AgentSpec) -> str:
    state = _state_dir(scenario.name, agent.name)
    seed_file = state / "seed.txt"
    llm_base_url, llm_model, llm_api_key = _resolve_llm()
    # PUBLISH_OVERLAY semantics:
    #   - agent declares ``publish_overlays`` in scenario.yaml -> publish ALL of
    #     them. The MCP unit bakes ``--publish-overlay ${PUBLISH_OVERLAY}``;
    #     systemd word-splits the expanded value, and the CLI's
    #     ``--publish-overlay`` is ``action="append"``, so emitting the paths
    #     joined by `` --publish-overlay `` makes every overlay a separate flag.
    #     (A genesis seeder that hosts more than one overlay — e.g. the
    #     file_transfer scenario's content_community + file_transfer — must load
    #     all of them locally: it cannot wire-fetch from itself.)
    #   - agent declares none -> emit the ``none`` sentinel so it publishes
    #     nothing. Under ``wire_distribute_overlays: true`` the agent instead
    #     relies on ``OpenClawAgent.ensure_default_overlays_loaded`` to fetch
    #     each descriptor from a genesis peer over the bootstrap community
    #     (OVERLAY_REQUEST -> OVERLAY_DELIVERY); otherwise it simply runs no
    #     application overlay (e.g. the admission demo).
    if agent.publish_overlays:
        publish_value = " --publish-overlay ".join(str(p) for p in agent.publish_overlays)
    else:
        publish_value = "none"
    # Phase 6: cross-wire pull-loop URLs so every member-agent in the
    # scenario pulls from every other member-agent. ``signed_log_port=0``
    # on a peer disables both serving and being pulled from.
    peer_signed_log_urls = [
        f"http://127.0.0.1:{other.signed_log_port}"
        for other in scenario.agents.values()
        if other.name != agent.name and other.signed_log_port != 0
    ]
    lines = [
        "# generated by deploy.scenario_boot — do not hand-edit",
        f"PYTHONPATH={REPO_ROOT}",
        f"HOME={state}",
        f"SEED_FILE={seed_file}",
        f"SCENARIO_NAME={scenario.name}",
        f"AGENT_NAME={agent.name}",
        "NETWORK=TESTNET",
        "BTC_NETWORK=mock",
        f"INITIAL_BALANCE_SATS={agent.initial_balance_sats}",
        f"IPV8_HOST=0.0.0.0",
        f"IPV8_PORT={agent.ipv8_port}",
        f"MCP_HOST=0.0.0.0",
        f"MCP_PORT={agent.mcp_port}",
        f"SIGNED_LOG_HOST=0.0.0.0",
        f"SIGNED_LOG_PORT={agent.signed_log_port}",
        f"PEER_LOG_URLS={' '.join(peer_signed_log_urls)}",
        f"COMMUNITY_LOG_PATH={state / 'community.log'}",
        f"PEER_LOG_DIR={state / 'peer_logs'}",
        f"OVERLAY_ARCHIVE_DIR={state / 'overlay_archive'}",
        f"VERSION_HISTORY_DIR={STATE_ROOT / scenario.name}",
        f"EVOLUTION_BASE_OVERLAY_NAME={scenario.evolution_base_overlay}",
        f"OVERLAY_AUTHOR_MODE={_overlay_author_mode(scenario, agent)}",
        f"PUBLISH_OVERLAY={publish_value}",
        f"SEED_CONTENT_FILE={_seed_content_file_path(scenario, agent)}",
        f"FILE_SHARE_MODE={'1' if scenario.file_share_mode else '0'}",
        f"PAYMENT_MODE={'1' if scenario.payment_mode else '0'}",
        *(
            [f"MCP_TOOL_ALLOWLIST={','.join(agent.mcp_tool_allowlist)}"]
            if agent.mcp_tool_allowlist is not None
            else []
        ),
        f"MANIFEST_FILE={_manifest_file_path(scenario, agent)}",
        f"LLM_BASE_URL={llm_base_url}",
        f"LLM_MODEL={llm_model}",
        f"LLM_API_KEY={llm_api_key}",
        f"LOG_DIR={scenario.log_dir}",
    ]
    return "\n".join(lines) + "\n"


def _redact_env_for_log(body: str) -> str:
    secret_keys = {
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        LLM_API_KEY_ENV,
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
    subprocess.run(
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

    if agent.library_csv is not None:
        rows = _stage_library_csv(agent.library_csv, content_dir)
    else:
        rows = _stage_inline_seed_content(agent.seed_content, content_dir)

    subprocess.run(
        ["sudo", "tee", str(target)],
        input=json.dumps(rows, indent=2, sort_keys=True) + "\n",
        capture_output=True,
        text=True,
        check=True,
    )
    _sudo(["chmod", "0640", str(target)])
    _sudo(["chown", f"root:{SERVICE_USER}", str(target)])


def _stage_inline_seed_content(
    seed_content: tuple, content_dir: Path
) -> list[dict]:
    rows: list[dict] = []
    if seed_content:
        _sudo([
            "install", "-d",
            "-o", SERVICE_USER, "-g", SERVICE_USER, "-m", "0750",
            str(content_dir),
        ])
    for item in seed_content:
        safe_name = "".join(c if c.isalnum() or c in "._-" else "_" for c in item.name)
        content_path = content_dir / safe_name
        payload = (
            "DelftClaw community demo seed content\n"
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
    return rows


def _parse_library_csv(csv_path: Path) -> list[dict]:
    """Pure: read ``csv_path``, validate, return one dict per row.

    Each dict has keys ``magnet`` ``name`` ``size`` ``mime`` ``tags``
    ``source_path``. ``source_path`` is the resolved absolute Path to the
    file referenced by the row (co-located with the CSV). Raises
    ``ValueError`` on missing columns and ``FileNotFoundError`` when a
    row references a file that does not exist. No filesystem mutation.
    """
    import csv

    library_dir = csv_path.parent
    rows: list[dict] = []
    with csv_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        required = {"magnet", "name", "size", "mime", "tags"}
        missing = required - set(reader.fieldnames or ())
        if missing:
            raise ValueError(
                f"library_csv {csv_path} missing columns: {sorted(missing)}"
            )
        for entry in reader:
            name = entry["name"].strip()
            source = library_dir / name
            if not source.is_file():
                raise FileNotFoundError(
                    f"library_csv {csv_path} references missing file {source}"
                )
            tags = [t for t in entry["tags"].split(";") if t]
            rows.append({
                "magnet": entry["magnet"].strip(),
                "name": name,
                "size": int(entry["size"]),
                "mime": entry["mime"].strip(),
                "tags": tags,
                "source_path": source.resolve(),
            })
    return rows


def _stage_library_csv(csv_path: Path, content_dir: Path) -> list[dict]:
    """Copy each library file referenced in ``csv_path`` into ``content_dir`` and emit seed_content rows.

    The CSV is expected at the repo-tracked library directory; each row's
    ``name`` column names a file co-located with the CSV. Real bytes get
    copied into the seedbox content directory so the stub BitTorrent
    service can serve them later via ``StubBitTorrentService.prime``.
    """
    parsed = _parse_library_csv(csv_path)

    _sudo([
        "install", "-d",
        "-o", SERVICE_USER, "-g", SERVICE_USER, "-m", "0750",
        str(content_dir),
    ])

    rows: list[dict] = []
    for entry in parsed:
        safe_name = "".join(c if c.isalnum() or c in "._-" else "_" for c in entry["name"])
        content_path = content_dir / safe_name
        payload = entry["source_path"].read_bytes()
        subprocess.run(
            ["sudo", "tee", str(content_path)],
            input=payload,
            capture_output=True,
            check=True,
        )
        _sudo(["chmod", "0640", str(content_path)])
        _sudo(["chown", f"{SERVICE_USER}:{SERVICE_USER}", str(content_path)])
        rows.append({
            "magnet": entry["magnet"],
            "name": entry["name"],
            "size": entry["size"],
            "mime": entry["mime"],
            "tags": entry["tags"],
            "path": str(content_path),
        })
    return rows


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

    openclaw = _resolve_openclaw_provider()
    _base, _model, llm_api_key = _resolve_llm()
    sudo_env = [
        "sudo", "-u", SERVICE_USER, "env",
        f"HOME={state}",
        "PATH=/usr/local/bin:/usr/bin:/bin",
        "OPENCLAW_DISABLE_TELEMETRY=1",
        # OpenClaw resolves its config apiKey (the literal "LLM_API_KEY") against
        # the process env, so the config-set commands below need the key present.
        f"{LLM_API_KEY_ENV}={llm_api_key}",
    ]

    # (1) Update the agent's openclaw.json so the reasoning provider is
    # registered before any model lookup happens. Without this,
    # ``openclaw agent --local --model <provider>/<model>`` can't resolve.
    #
    # ``agents.defaults.timeoutSeconds`` is the *inner* LLM call timeout (the
    # subprocess-level timeout we pass via --timeout is unrelated). Keep it
    # below the watchdog's subprocess budget (interval_s + 30) so provider
    # failures surface inside OpenClaw instead of being truncated by the
    # watchdog, with headroom for first-turn cold starts.
    provider_id = openclaw["provider"]
    provider_model = openclaw["model"]
    provider_config = {
        "baseUrl": openclaw["base_url"].rstrip("/") + "/",
        "api": openclaw["api"],
        # OpenClaw resolves this string against the process environment;
        # LLM_API_KEY carries the key.
        "apiKey": LLM_API_KEY_ENV,
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

    For a scenario like ``admission`` where bob.peers = [alice] and alice has
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
        openclaw = _resolve_openclaw_provider()
        c_dry(f"would systemctl enable --now delftclaw-mcp@<instance> for {list(scenario.agents)}")
        for agent in scenario.agents.values():
            instance = scenario.instance_id(agent.name)
            c_dry(f"  would openclaw mcp set {instance} (HOME=/var/lib/delftclaw/{scenario.name}/{agent.name})")
            c_dry(f"  would openclaw agents add {instance} --non-interactive --model {openclaw['provider']}/{openclaw['model']}")
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

    # Phase 4a: also register each peer's WATCHDOG IPv8 port. The watchdog
    # process runs its own IPv8 instance on ``ipv8_port + 1000`` and
    # shares ``seed.txt`` with the MCP process, so identity is identical —
    # what differs is the UDP source port packets originate from. Without
    # this loop the seeder's MCP IPv8 would receive an OVERLAY_REQUEST
    # from the fetcher's watchdog but have no peer record to address the
    # OVERLAY_DELIVERY response back to. Only fires for scenarios that
    # turn on wire distribution; legacy scenarios skip it.
    if scenario.wire_distribute_overlays:
        for agent in scenario.agents.values():
            for peer_name in agent.peers:
                peer_spec = scenario.agents[peer_name]
                # The watchdog cross-reg was added so a joiner's watchdog IPv8
                # (on ipv8_port+1000) can wire-fetch the boot default overlay
                # from the GENESIS peer at startup. For peer pairs where
                # neither side publishes overlays (e.g. the two fetchers in
                # the v4 mesh) it serves no purpose AND creates a routing
                # hazard: ez_send to the peer's mid can pick the watchdog
                # port, and a watchdog snapshot agent does NOT hold runtime-
                # AUTHORED overlays (e.g. download_announce v1.0.0), so its
                # IPv8 silently drops the OVERLAY_REQUEST and the caller
                # times out. Skip when neither side publishes.
                if not (agent.publish_overlays or peer_spec.publish_overlays):
                    continue
                target = coords[peer_name]
                watchdog_port = peer_spec.ipv8_port + 1000
                url = f"http://127.0.0.1:{agent.mcp_port}/mcp"
                c_info(
                    f"{agent.name}.peer_add({peer_name} watchdog @ {watchdog_port})"
                )
                try:
                    result = await _call_mcp(url, "peer_add", {
                        "host": target["host"],
                        "port": watchdog_port,
                        "pubkey_hex": target["pubkey_hex"],
                    })
                except Exception as exc:
                    c_fail(
                        f"watchdog peer_add {agent.name}->{peer_name} failed: {exc}"
                    )
                    return 1
                c_ok(
                    f"{agent.name} now knows {peer_name}'s watchdog: {result}"
                )

    # Phase 4b: build a network manifest from the genesis agent's runtime
    # coords and inject it into every agent. Without this, state.network is
    # null in the snapshot and the LLMs have no admission target — the most
    # common cause of "scenario is up but nothing happens."
    #
    # This central synthesis + injection is a TEST-HARNESS CONVENIENCE: it
    # fakes N independent owners on one VPS so a demo bootstraps reproducibly.
    # It is NOT part of the decentralised channel. In a real deployment the
    # manifest is authored once by the network's founder and reaches a joiner
    # out-of-band (a peer hands it over, a file, a link) — content-addressing
    # by ``network_id`` makes that integrity-safe without any orchestrator.
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
            subprocess.run(
                ["sudo", "tee", str(manifest_path)],
                input=manifest_md, capture_output=True, text=True, check=True,
            )
            _sudo(["chmod", "0640", str(manifest_path)])
            _sudo(["chown", f"root:{SERVICE_USER}", str(manifest_path)])
            c_ok(f"{agent.name}: manifest written to {manifest_path}")

            # (a) Inject into the MCP-process agent so OpenClaw-driven tool
            # calls (agent_inject_manifest, community_donate_and_join, etc.)
            # see it immediately without waiting for the watchdog's first tick.
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
            c_dry(f"would wipe {state}/torrents and {state}/overlay_archive")
            continue
        _stop_unit(f"delftclaw-watchdog@{instance}.service")
        _stop_unit(f"delftclaw-mcp@{instance}.service")
        # Wipe per-run runtime artifacts so a re-run starts clean. Stale
        # entries here otherwise satisfy stop predicates at turn 0 (a prior
        # completed download -> torrent_progress_gte_1; a prior authored
        # overlay -> download_done_and_overlay_authored), making agents skip
        # the demo. Regenerated at boot. Signed logs (community.log /
        # peer_logs) are deliberately NOT touched — the community/security
        # scenarios rely on that accountability history surviving.
        for runtime_sub in ("torrents", "overlay_archive"):
            _sudo(["rm", "-rf", str(state / runtime_sub)], check=False)
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
    # Wipe the scenario-wide fleet artifacts so a re-run starts truly clean:
    # version_history.{jsonl,md} live next to the per-agent dirs (one dir up),
    # and a stale ledger here would otherwise show a misleading two-version
    # chain in trace before the fresh run has caught up.
    if not dry_run:
        scenario_root = STATE_ROOT / scenario.name
        for fname in ("version_history.jsonl", "version_history.md"):
            _sudo(["rm", "-f", str(scenario_root / fname)], check=False)
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
