"""Per-agent server configuration loaded from YAML.

Each MCP server process boots from a single YAML file:

    integration/configs/alice.yaml
    integration/configs/bob.yaml

The file pins:
* identity (seed file path, network label),
* IPv8 bind address + port,
* MCP HTTP bind address + port,
* the path to the shared ``peers.yaml``,
* zero or more pre-issued VCs to load into the agent's ``TrustStore``,
* an optional issuer keypair if this agent should also issue VCs,
* an optional faucet credit for development.

This module exposes the dataclasses and a ``load(path)`` helper. It does NOT
boot any IPv8 / AgentChannel — that happens in ``boot.py`` once the config
is in hand.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class AgentConfig:
    name: str
    seed_path: Path
    network: str = "TESTNET"


@dataclass(frozen=True)
class IPv8BindConfig:
    bind_ip: str = "127.0.0.1"
    bind_port: int = 9091


@dataclass(frozen=True)
class MCPBindConfig:
    bind_ip: str = "127.0.0.1"
    bind_port: int = 8081


@dataclass(frozen=True)
class VCEntry:
    vc_id: str
    file: Path


@dataclass(frozen=True)
class FaucetConfig:
    amount: int = 0  # 0 disables


@dataclass(frozen=True)
class LoggingConfig:
    log_file: Path | None = None
    no_stdout: bool = False


@dataclass(frozen=True)
class ServerConfig:
    agent: AgentConfig
    ipv8: IPv8BindConfig
    mcp: MCPBindConfig
    peers_file: Path
    vc_store: tuple[VCEntry, ...] = field(default_factory=tuple)
    issuer_keypair_path: Path | None = None
    faucet: FaucetConfig = field(default_factory=FaucetConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)

    @property
    def mcp_url(self) -> str:
        """The streamable-HTTP URL OpenClaw should be configured with."""
        return f"http://{self.mcp.bind_ip}:{self.mcp.bind_port}/mcp"


def load(path: str | Path) -> ServerConfig:
    """Parse a per-agent YAML config; raise ValueError on missing/invalid keys."""
    p = Path(path).expanduser()
    text = p.read_text(encoding="utf-8")
    data: dict[str, Any] = yaml.safe_load(text) or {}

    agent_block = _require(data, "agent", dict, source=p)
    agent = AgentConfig(
        name=str(_require(agent_block, "name", str, source=p, key_path="agent.name")),
        seed_path=_path(agent_block.get("seed_path", "~/.openclaw/seed.txt")),
        network=str(agent_block.get("network", "TESTNET")),
    )

    ipv8_block = data.get("ipv8") or {}
    ipv8 = IPv8BindConfig(
        bind_ip=str(ipv8_block.get("bind_ip", "127.0.0.1")),
        bind_port=int(ipv8_block.get("bind_port", 9091)),
    )

    mcp_block = data.get("mcp") or {}
    mcp = MCPBindConfig(
        bind_ip=str(mcp_block.get("bind_ip", "127.0.0.1")),
        bind_port=int(mcp_block.get("bind_port", 8081)),
    )

    peers_file = _path(_require(data, "peers_file", str, source=p))

    vc_entries: list[VCEntry] = []
    for raw in data.get("vc_store") or []:
        if not isinstance(raw, dict):
            raise ValueError(f"{p}: each vc_store entry must be a mapping, got {raw!r}")
        try:
            vc_entries.append(
                VCEntry(
                    vc_id=str(raw["vc_id"]),
                    file=_path(raw["file"]),
                )
            )
        except KeyError as exc:
            raise ValueError(f"{p}: vc_store entry missing key {exc}") from exc

    issuer_path = data.get("issuer_keypair_path")
    issuer_keypair_path = _path(issuer_path) if issuer_path else None

    faucet_block = data.get("faucet") or {}
    faucet = FaucetConfig(amount=int(faucet_block.get("amount", 0)))

    logging_block = data.get("logging") or {}
    log_file_raw = logging_block.get("log_file")
    logging_config = LoggingConfig(
        log_file=_path(log_file_raw) if log_file_raw else None,
        no_stdout=bool(logging_block.get("no_stdout", False)),
    )

    return ServerConfig(
        agent=agent,
        ipv8=ipv8,
        mcp=mcp,
        peers_file=peers_file,
        vc_store=tuple(vc_entries),
        issuer_keypair_path=issuer_keypair_path,
        faucet=faucet,
        logging=logging_config,
    )


# --- helpers -----------------------------------------------------------------


def _require(d: dict[str, Any], key: str, kind: type, *, source: Path, key_path: str | None = None) -> Any:
    if key not in d:
        loc = key_path or key
        raise ValueError(f"{source}: missing required key '{loc}'")
    val = d[key]
    if not isinstance(val, kind):
        loc = key_path or key
        raise ValueError(
            f"{source}: key '{loc}' expected {kind.__name__}, got {type(val).__name__}"
        )
    return val


def _path(p: str | Path) -> Path:
    return Path(str(p)).expanduser()


__all__ = [
    "AgentConfig",
    "IPv8BindConfig",
    "MCPBindConfig",
    "VCEntry",
    "FaucetConfig",
    "LoggingConfig",
    "ServerConfig",
    "load",
]
