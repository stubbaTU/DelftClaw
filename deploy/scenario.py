"""Strict ``scenario.yaml`` parser + validator.

A scenario is a directory under ``deploy/scenarios/<name>/`` containing:

  scenario.yaml         (this file describes the agents + watchdog policy)
  <agent>/mission.md    (the single zero-shot intent doc, per agent)

The parser is intentionally strict — every error fails fast at boot, not
mid-run on the VPS. Validation rules:

  1. Required keys present at every level.
  2. Every ``stop_predicate`` resolves via ``stop_predicates.resolve``.
  3. Every ``peers: [...]`` entry references another agent in the manifest.
  4. Every ``publish_overlays:`` path exists relative to the repo root.
  5. IPv8 + MCP ports unique inside this scenario; ranges checked.
  6. ``mission_file`` exists as a sibling of scenario.yaml AND parses
     cleanly via ``deploy.mission.parse_mission``.
  7. Legacy ``persona_file`` / ``goal_file`` keys (pre-v5.1) raise a
     clear migration error rather than being silently ignored.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from deploy import stop_predicates
from deploy.mission import MissionParseError, parse_mission
from protocol.manifest import LineagePolicy


REPO_ROOT = Path(__file__).resolve().parent.parent


class ScenarioError(Exception):
    """Raised when a scenario manifest fails validation."""


# ---------------------------------------------------------------------------
# Typed model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class WatchdogPolicy:
    interval_s: int
    max_iterations_per_turn: int
    max_total_turns: int
    max_wall_clock_s: int

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "WatchdogPolicy":
        required = ("interval_s", "max_iterations_per_turn",
                    "max_total_turns", "max_wall_clock_s")
        missing = [k for k in required if k not in d]
        if missing:
            raise ScenarioError(f"watchdog: missing keys {missing}")
        return cls(
            interval_s=int(d["interval_s"]),
            max_iterations_per_turn=int(d["max_iterations_per_turn"]),
            max_total_turns=int(d["max_total_turns"]),
            max_wall_clock_s=int(d["max_wall_clock_s"]),
        )


@dataclass(frozen=True)
class SeedContent:
    magnet: str
    name: str
    size: int
    mime: str
    tags: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "SeedContent":
        for k in ("magnet", "name", "size", "mime"):
            if k not in d:
                raise ScenarioError(f"seed_content entry missing key {k!r}")
        return cls(
            magnet=str(d["magnet"]),
            name=str(d["name"]),
            size=int(d["size"]),
            mime=str(d["mime"]),
            tags=tuple(str(t) for t in d.get("tags", [])),
        )


@dataclass(frozen=True)
class AgentSpec:
    name: str
    ipv8_port: int
    mcp_port: int
    publish_overlays: tuple[Path, ...]
    mission_file: Path
    stop_predicate: str
    peers: tuple[str, ...] = ()
    seed_content: tuple[SeedContent, ...] = ()
    # Per-agent synthetic wallet balance the LLM sees via wallet_balance.
    # Default 0 keeps legacy "always-zero" mock behaviour; set >0 for
    # agents that need to make donations (e.g. seek_cc's bob).
    initial_balance_sats: int = 0
    # Phase 6: per-agent FastAPI port for the redteam community-log
    # server. 0 disables (legacy single-agent / no-replication mode).
    # When set, scenario_boot cross-wires every other agent's pull
    # loop to fetch from http://127.0.0.1:<redteam_port>.
    redteam_port: int = 0

    # Optional: Bitcoin network mode for this agent's runtime.
    # Historically this was always forced to "mock" by scenario_boot.
    # Scenarios that need real Regtest transactions set this to "regtest".
    btc_network: str = "mock"

    # Optional Regtest RPC config (consumed by agent/cli.py via env vars).
    # When unset, agents default to BITCOIN_RPC_URL=http://127.0.0.1:18443
    # and BITCOIN_RPC_WALLET=<agent name>.
    bitcoin_rpc_url: str = ""
    bitcoin_rpc_wallet: str = ""

    # Optional deploy-time founder admission. When set on the selected
    # genesis agent, scenario_boot writes a donation_intent before the
    # watchdogs start so the founder is already an admitted member in the
    # first autonomous turn.
    bootstrap_community_sats: int = 0


@dataclass(frozen=True)
class Scenario:
    name: str
    description: str
    watchdog: WatchdogPolicy
    agents: dict[str, AgentSpec]
    log_dir: Path
    manifest_path: Path = field(default_factory=Path)
    lineage: LineagePolicy = field(default_factory=LineagePolicy)

    def instance_id(self, agent_name: str) -> str:
        """Systemd instance id: ``<scenario>-<agent>``."""
        return f"{self.name}-{agent_name}"


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def parse_scenario(manifest_path: str | Path) -> Scenario:
    """Read + validate a scenario.yaml. Raises ``ScenarioError`` on any problem."""
    path = Path(manifest_path).resolve()
    if not path.is_file():
        raise ScenarioError(f"manifest not found: {path}")

    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ScenarioError(f"manifest top level must be a mapping; got {type(raw).__name__}")

    for key in ("name", "watchdog", "agents"):
        if key not in raw:
            raise ScenarioError(f"manifest missing top-level key {key!r}")

    scenario_dir = path.parent

    name = str(raw["name"])
    if not name.replace("_", "").replace("-", "").isalnum():
        raise ScenarioError(f"scenario name must be alnum/underscore/hyphen; got {name!r}")

    watchdog = WatchdogPolicy.from_dict(raw["watchdog"])
    agents_raw = raw["agents"]
    if not isinstance(agents_raw, dict) or not agents_raw:
        raise ScenarioError("'agents' must be a non-empty mapping")

    agents: dict[str, AgentSpec] = {}
    seen_ipv8_ports: dict[int, str] = {}
    seen_mcp_ports: dict[int, str] = {}
    seen_redteam_ports: dict[int, str] = {}

    for agent_name, agent_raw in agents_raw.items():
        if not isinstance(agent_raw, dict):
            raise ScenarioError(f"agent {agent_name!r}: entry must be a mapping")
        agent = _parse_agent(agent_name, agent_raw, scenario_dir)

        # Port-collision checks within this scenario.
        if agent.ipv8_port in seen_ipv8_ports:
            raise ScenarioError(
                f"ipv8_port {agent.ipv8_port} clashes between agents "
                f"{seen_ipv8_ports[agent.ipv8_port]!r} and {agent.name!r}"
            )
        if agent.mcp_port in seen_mcp_ports:
            raise ScenarioError(
                f"mcp_port {agent.mcp_port} clashes between agents "
                f"{seen_mcp_ports[agent.mcp_port]!r} and {agent.name!r}"
            )
        if agent.ipv8_port == agent.mcp_port:
            raise ScenarioError(
                f"agent {agent.name!r}: ipv8_port and mcp_port must differ"
            )
        if agent.redteam_port != 0:
            if agent.redteam_port in seen_redteam_ports:
                raise ScenarioError(
                    f"redteam_port {agent.redteam_port} clashes between agents "
                    f"{seen_redteam_ports[agent.redteam_port]!r} and {agent.name!r}"
                )
            if agent.redteam_port in (agent.ipv8_port, agent.mcp_port):
                raise ScenarioError(
                    f"agent {agent.name!r}: redteam_port must differ from "
                    f"ipv8_port and mcp_port"
                )
            seen_redteam_ports[agent.redteam_port] = agent.name
        seen_ipv8_ports[agent.ipv8_port] = agent.name
        seen_mcp_ports[agent.mcp_port] = agent.name

        agents[agent_name] = agent

    # Cross-agent peer references must resolve.
    for agent in agents.values():
        for peer_name in agent.peers:
            if peer_name not in agents:
                raise ScenarioError(
                    f"agent {agent.name!r} peers reference unknown agent {peer_name!r}"
                )
            if peer_name == agent.name:
                raise ScenarioError(
                    f"agent {agent.name!r} cannot peer with itself"
                )

    log_dir = Path(
        (raw.get("observability") or {}).get("log_dir")
        or f"/var/log/delftclaw/scenarios/{name}"
    )
    lineage = _parse_lineage_policy(raw.get("lineage"))

    return Scenario(
        name=name,
        description=str(raw.get("description", "")),
        watchdog=watchdog,
        agents=agents,
        log_dir=log_dir,
        lineage=lineage,
        manifest_path=path,
    )


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _parse_lineage_policy(raw: Any) -> LineagePolicy:
    if raw is None:
        return LineagePolicy()
    if not isinstance(raw, dict):
        raise ScenarioError(f"lineage: must be a mapping; got {type(raw).__name__}")

    return LineagePolicy(
        enabled=_bool(raw.get("enabled", False), "lineage.enabled"),
        required=_bool(raw.get("required", False), "lineage.required"),
        trusted_roots=_trusted_roots(raw.get("trusted_roots", [])),
        btc_network=str(raw.get("btc_network", "mock") or "mock").strip() or "mock",
        min_anchor_confirmations=_uint(
            raw.get("min_anchor_confirmations", 0),
            "lineage.min_anchor_confirmations",
            max_value=65535,
        ),
        birth_package_path=str(raw.get("birth_package_path", "") or "").strip(),
        cache_path=str(raw.get("cache_path", "") or "").strip(),
        cache_dir=str(raw.get("cache_dir", "") or "").strip(),
        revocation_feed=(
            str(raw.get("revocation_feed", "lineage/revocations.jsonl") or "").strip()
            or "lineage/revocations.jsonl"
        ),
        accepted_capabilities=_string_tuple(
            raw.get("accepted_capabilities", []), "lineage.accepted_capabilities"
        ),
    )


def _bool(value: Any, context: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized == "true":
            return True
        if normalized == "false":
            return False
    raise ScenarioError(f"{context}: must be a boolean (got {value!r})")


def _uint(value: Any, context: str, *, max_value: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ScenarioError(f"{context}: must be an int (got {value!r})") from exc
    if parsed < 0:
        raise ScenarioError(f"{context}: must be >= 0 (got {parsed})")
    if parsed > max_value:
        raise ScenarioError(f"{context}: must be <= {max_value} (got {parsed})")
    return parsed


def _string_tuple(value: Any, context: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ScenarioError(f"{context}: must be a list")
    out: list[str] = []
    for entry in value:
        if not isinstance(entry, str):
            raise ScenarioError(f"{context}: entries must be strings")
        out.append(entry)
    return tuple(out)


def _trusted_roots(value: Any) -> tuple[dict[str, str], ...]:
    if not isinstance(value, list):
        raise ScenarioError("lineage.trusted_roots: must be a list")
    roots: list[dict[str, str]] = []
    for entry in value:
        if not isinstance(entry, dict):
            raise ScenarioError("lineage.trusted_roots: entries must be mappings")
        root: dict[str, str] = {}
        for k, v in entry.items():
            if not isinstance(k, str) or not isinstance(v, str):
                raise ScenarioError(
                    "lineage.trusted_roots: entries must contain string keys and values"
                )
            root[k] = v
        roots.append(root)
    return tuple(roots)


def _parse_agent(name: str, d: dict[str, Any], scenario_dir: Path) -> AgentSpec:
    # Pre-v5.1 keys are a fatal migration error — don't silently ignore them
    # or the operator will not notice the recipe is no longer being shown.
    for legacy in ("persona_file", "goal_file"):
        if legacy in d:
            raise ScenarioError(
                f"agent {name!r}: {legacy!r} is removed in v5.1. Replace "
                f"persona_file + goal_file with a single mission_file pointing "
                f"at a mission.md (see deploy/mission_schema.md)."
            )

    for key in ("ipv8_port", "mcp_port", "mission_file", "stop_predicate"):
        if key not in d:
            raise ScenarioError(f"agent {name!r}: missing key {key!r}")

    ipv8_port = _port(d["ipv8_port"], f"agent {name}.ipv8_port")
    mcp_port = _port(d["mcp_port"], f"agent {name}.mcp_port")

    overlays_raw = d.get("publish_overlays") or []
    if not isinstance(overlays_raw, list):
        raise ScenarioError(f"agent {name!r}: publish_overlays must be a list")
    overlays: list[Path] = []
    for entry in overlays_raw:
        p = (REPO_ROOT / str(entry)).resolve()
        if not p.is_file():
            raise ScenarioError(
                f"agent {name!r}: publish_overlay {entry!r} does not exist "
                f"(resolved to {p})"
            )
        overlays.append(p)

    mission_file = _resolve_relative(scenario_dir, d["mission_file"], "mission_file", name)
    # Parse the mission now — schema violations fail at boot, not mid-run.
    try:
        parse_mission(mission_file.read_text(encoding="utf-8"))
    except MissionParseError as exc:
        raise ScenarioError(f"agent {name!r}: mission_file {mission_file}: {exc}") from exc

    # Validate stop predicate at parse time so the watchdog never explodes mid-run.
    stop_spec = str(d["stop_predicate"])
    try:
        stop_predicates.resolve(stop_spec)
    except stop_predicates.UnknownPredicate as exc:
        raise ScenarioError(f"agent {name!r}: stop_predicate {stop_spec!r}: {exc}") from exc

    peers_raw = d.get("peers") or []
    if not isinstance(peers_raw, list):
        raise ScenarioError(f"agent {name!r}: peers must be a list")
    peers = tuple(str(p) for p in peers_raw)

    seed_raw = d.get("seed_content") or []
    if not isinstance(seed_raw, list):
        raise ScenarioError(f"agent {name!r}: seed_content must be a list")
    seed_content = tuple(SeedContent.from_dict(s) for s in seed_raw)

    initial_balance_sats = d.get("initial_balance_sats", 0)
    try:
        initial_balance_sats = int(initial_balance_sats)
    except (TypeError, ValueError) as exc:
        raise ScenarioError(
            f"agent {name!r}: initial_balance_sats must be an int (got {initial_balance_sats!r})"
        ) from exc
    if initial_balance_sats < 0:
        raise ScenarioError(
            f"agent {name!r}: initial_balance_sats must be >= 0 (got {initial_balance_sats})"
        )

    redteam_port_raw = d.get("redteam_port", 0)
    if redteam_port_raw == 0:
        redteam_port = 0
    else:
        redteam_port = _port(redteam_port_raw, f"agent {name}.redteam_port")

    btc_network = str(d.get("btc_network", d.get("btc-network", "mock")) or "mock").strip()
    # Keep validation deliberately loose — the runtime decides what it supports.
    if not btc_network:
        btc_network = "mock"

    bitcoin_rpc_url = str(d.get("bitcoin_rpc_url", d.get("bitcoin-rpc-url", "")) or "").strip()
    bitcoin_rpc_wallet = str(d.get("bitcoin_rpc_wallet", d.get("bitcoin-rpc-wallet", "")) or "").strip()

    bootstrap_community_sats = d.get(
        "bootstrap_community_sats",
        d.get("bootstrap-community-sats", 0),
    )
    try:
        bootstrap_community_sats = int(bootstrap_community_sats)
    except (TypeError, ValueError) as exc:
        raise ScenarioError(
            f"agent {name!r}: bootstrap_community_sats must be an int "
            f"(got {bootstrap_community_sats!r})"
        ) from exc
    if bootstrap_community_sats < 0:
        raise ScenarioError(
            f"agent {name!r}: bootstrap_community_sats must be >= 0 "
            f"(got {bootstrap_community_sats})"
        )

    return AgentSpec(
        name=name,
        ipv8_port=ipv8_port,
        mcp_port=mcp_port,
        publish_overlays=tuple(overlays),
        mission_file=mission_file,
        stop_predicate=stop_spec,
        peers=peers,
        seed_content=seed_content,
        initial_balance_sats=initial_balance_sats,
        redteam_port=redteam_port,
        btc_network=btc_network,
        bitcoin_rpc_url=bitcoin_rpc_url,
        bitcoin_rpc_wallet=bitcoin_rpc_wallet,
        bootstrap_community_sats=bootstrap_community_sats,
    )


def _port(value: Any, context: str) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ScenarioError(f"{context}: not an int ({value!r})") from exc
    if not 1024 <= port <= 65535:
        raise ScenarioError(f"{context}: port must be in [1024, 65535]; got {port}")
    return port


def _resolve_relative(base: Path, value: Any, what: str, agent_name: str) -> Path:
    p = (base / str(value)).resolve()
    if not p.is_file():
        raise ScenarioError(
            f"agent {agent_name!r}: {what} {value!r} does not exist (resolved to {p})"
        )
    return p
