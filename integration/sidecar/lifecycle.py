"""Sidecar entrypoint: load config, build deps, run forever."""

from __future__ import annotations

from pathlib import Path


def run(config_path: Path) -> None:
    """Entry point invoked by ``python -m sidecar``."""
    # Load config, build AgentIdentity from a SeedSource, build AgentChannel, start Sidecar,
    # install SIGTERM/SIGINT handlers that call sidecar.stop().
    ...
