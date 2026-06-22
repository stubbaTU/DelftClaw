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
    library_csv: Path | None = None
    mcp_tool_allowlist: tuple[str, ...] | None = None
    initial_balance_sats: int = 0
    signed_log_port: int = 0
    # Role in the two-author overlay-evolution chain: "genesis" authors
    # v1.0.0, "successor" adopts it + designs v1.1.0, "" = no special role.
    overlay_author_role: str = ""


@dataclass(frozen=True)
class Scenario:
    name: str
    watchdog: WatchdogPolicy
    agents: dict[str, AgentSpec]
    log_dir: Path
    manifest_path: Path = field(default_factory=Path)
    file_share_mode: bool = False
    wire_distribute_overlays: bool = False
    # Name of the overlay agents author + evolve at runtime (e.g.
    # "download_announce", "payment_receipt"). "" disables the chain.
    evolution_base_overlay: str = ""
    # Flips the watchdog's next_objective into the payment ladder
    # (request -> receive -> author) after admission.
    payment_mode: bool = False

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
    seen_signed_log_ports: dict[int, str] = {}

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
        if agent.signed_log_port != 0:
            if agent.signed_log_port in seen_signed_log_ports:
                raise ScenarioError(
                    f"signed_log_port {agent.signed_log_port} clashes between agents "
                    f"{seen_signed_log_ports[agent.signed_log_port]!r} and {agent.name!r}"
                )
            if agent.signed_log_port in (agent.ipv8_port, agent.mcp_port):
                raise ScenarioError(
                    f"agent {agent.name!r}: signed_log_port must differ from "
                    f"ipv8_port and mcp_port"
                )
            seen_signed_log_ports[agent.signed_log_port] = agent.name
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

    file_share_mode_raw = raw.get("file_share_mode", False)
    if not isinstance(file_share_mode_raw, bool):
        raise ScenarioError(
            f"file_share_mode must be a boolean; got {type(file_share_mode_raw).__name__}"
        )

    wire_distribute_raw = raw.get("wire_distribute_overlays", False)
    if not isinstance(wire_distribute_raw, bool):
        raise ScenarioError(
            f"wire_distribute_overlays must be a boolean; "
            f"got {type(wire_distribute_raw).__name__}"
        )

    payment_mode_raw = raw.get("payment_mode", False)
    if not isinstance(payment_mode_raw, bool):
        raise ScenarioError(
            f"payment_mode must be a boolean; got {type(payment_mode_raw).__name__}"
        )

    evolution_base_overlay = str(raw.get("evolution_base_overlay", "") or "")

    # The two-author chain needs exactly one genesis + at most one successor.
    roles = [a.overlay_author_role for a in agents.values() if a.overlay_author_role]
    if evolution_base_overlay and roles.count("genesis") > 1:
        raise ScenarioError(
            "at most one agent may have overlay_author_role: genesis"
        )
    if roles and not evolution_base_overlay:
        raise ScenarioError(
            "overlay_author_role is set on an agent but evolution_base_overlay "
            "is empty — set the scenario-level evolution_base_overlay"
        )

    return Scenario(
        name=name,
        watchdog=watchdog,
        agents=agents,
        log_dir=log_dir,
        manifest_path=path,
        file_share_mode=file_share_mode_raw,
        wire_distribute_overlays=wire_distribute_raw,
        evolution_base_overlay=evolution_base_overlay,
        payment_mode=payment_mode_raw,
    )


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

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
    # We also keep the parsed Mission so its optional ``# Tools`` allowlist
    # can propagate into AgentSpec.mcp_tool_allowlist below.
    try:
        mission = parse_mission(mission_file.read_text(encoding="utf-8"))
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

    library_csv_raw = d.get("library_csv")
    library_csv: Path | None = None
    if library_csv_raw is not None:
        library_csv = Path(str(library_csv_raw))
        if not library_csv.is_absolute():
            library_csv = (REPO_ROOT / library_csv).resolve()
        if not library_csv.is_file():
            raise ScenarioError(
                f"agent {name!r}: library_csv {library_csv} is not a file"
            )

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

    signed_log_port_raw = d.get("signed_log_port", 0)
    if signed_log_port_raw == 0:
        signed_log_port = 0
    else:
        signed_log_port = _port(signed_log_port_raw, f"agent {name}.signed_log_port")

    overlay_author_role = str(d.get("overlay_author_role", "") or "")
    if overlay_author_role not in ("", "genesis", "successor"):
        raise ScenarioError(
            f"agent {name!r}: overlay_author_role must be one of "
            f"'', 'genesis', 'successor'; got {overlay_author_role!r}"
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
        signed_log_port=signed_log_port,
        library_csv=library_csv,
        mcp_tool_allowlist=mission.tools,
        overlay_author_role=overlay_author_role,
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
