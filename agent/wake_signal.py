"""Cross-agent wake bridge: a per-agent ``.wake_signal`` file whose mtime lets
one agent's tool poke another's watchdog to wake early, instead of waiting a
full poll interval. Best-effort, and a no-op when ``SCENARIO_NAME`` /
``AGENT_NAME`` are unset (tests). The ledger is the source of truth; this is
only a latency optimization."""

from __future__ import annotations

import logging
import os
from pathlib import Path


SIGNAL_FILENAME = ".wake_signal"
STATE_ROOT = Path("/var/lib/delftclaw")

_log = logging.getLogger(__name__)


def signal_peers(reason: str) -> int:
    """Touch ``.wake_signal`` in every peer's state dir and this agent's own;
    return the count poked (0/no-op when the scenario env is unset). Self is
    included so a tool advancing this agent's own next_objective wakes it too;
    the watchdog's ``MIN_FLOOR_S`` still bounds same-agent re-fires. ``reason``
    is a short tag logged at INFO for the deployment journal."""
    scenario_name = os.environ.get("SCENARIO_NAME", "").strip()
    agent_name = os.environ.get("AGENT_NAME", "").strip()
    if not scenario_name or not agent_name:
        return 0

    scenario_root = STATE_ROOT / scenario_name
    try:
        target_dirs = [
            entry for entry in scenario_root.iterdir() if entry.is_dir()
        ]
    except OSError as exc:
        _log.info("wake_signal: dir enumeration failed: %s", exc)
        return 0

    poked = 0
    for target_dir in target_dirs:
        signal_path = target_dir / SIGNAL_FILENAME
        try:
            signal_path.touch(exist_ok=True)  # atomic mtime bump on POSIX
            poked += 1
        except OSError as exc:
            # peer dir may be mid-teardown; never break the tool path over this
            _log.info("wake_signal: touch failed at %s: %s", signal_path, exc)

    if poked:
        _log.info("wake_signal: poked %d dir(s) reason=%s", poked, reason)
    return poked


def read_signal_mtime(state_dir: Path | str) -> float:
    """Mtime of ``<state_dir>/.wake_signal``, or ``0.0`` if absent (the watchdog
    compares this across its sleep; a greater value means a peer touched it)."""
    signal_path = Path(state_dir) / SIGNAL_FILENAME
    try:
        return signal_path.stat().st_mtime
    except OSError:
        return 0.0


def self_state_dir() -> Path | None:
    """This agent's state dir (``STATE_ROOT/<scenario>/<agent>``), or ``None``
    if the scenario env is unset."""
    scenario_name = os.environ.get("SCENARIO_NAME", "").strip()
    agent_name = os.environ.get("AGENT_NAME", "").strip()
    if not scenario_name or not agent_name:
        return None
    return STATE_ROOT / scenario_name / agent_name
