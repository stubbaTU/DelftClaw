"""``agent.wake_signal`` — cross-agent latency optimization.

Pins the contract MCP tools and the watchdog rely on:

  * Env-gated: when ``SCENARIO_NAME`` / ``AGENT_NAME`` are unset (unit-test
    default), ``signal_peers`` is a no-op. This is what keeps every existing
    test silent — the four tool-site calls inserted in ``agent/tools.py``,
    ``agent/mcp_server.py``, ``agent/overlay_authoring_tool.py``, and
    ``agent/content_fetch.py`` must not write anywhere when the suite runs.
  * When set: touches ``.wake_signal`` in EVERY agent's state dir (peers AND
    self), under ``STATE_ROOT/<scenario>/``. Same-agent inclusion matters for
    fetch→author transitions where the actor IS the agent that needs to
    advance.
  * Robust to a missing/teardown'd peer dir; counts what it managed to poke.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent import wake_signal


@pytest.fixture
def state_root(tmp_path, monkeypatch):
    """Point STATE_ROOT at a tmpdir and stage three sibling agents."""
    monkeypatch.setattr(wake_signal, "STATE_ROOT", tmp_path)
    scenario_root = tmp_path / "demo"
    for name in ("alice", "bob", "carol"):
        (scenario_root / name).mkdir(parents=True)
    return tmp_path


def test_signal_peers_noop_when_env_unset(state_root, monkeypatch):
    """Unit-test default: env not set -> 0 dirs touched, no .wake_signal
    written. Guards every existing test from accidental filesystem chatter."""
    monkeypatch.delenv("SCENARIO_NAME", raising=False)
    monkeypatch.delenv("AGENT_NAME", raising=False)
    assert wake_signal.signal_peers("test") == 0
    # No file was created anywhere.
    written = list(state_root.rglob(wake_signal.SIGNAL_FILENAME))
    assert written == []


def test_signal_peers_touches_all_agents_including_self(state_root, monkeypatch):
    """Deployed shape: when env is set, every agent's dir (peers + self) gets
    a .wake_signal. Self inclusion matters for fetch->author same-agent
    transitions; the watchdog's MIN_FLOOR_S still gates re-fires."""
    monkeypatch.setenv("SCENARIO_NAME", "demo")
    monkeypatch.setenv("AGENT_NAME", "alice")
    poked = wake_signal.signal_peers("overlay_published:abcd")
    assert poked == 3
    for name in ("alice", "bob", "carol"):
        assert (state_root / "demo" / name / wake_signal.SIGNAL_FILENAME).is_file()


def test_signal_peers_survives_missing_scenario_root(tmp_path, monkeypatch):
    """The deployed scenario_root dir was wiped (concurrent ``make stop``) —
    signal_peers must not raise. Returns 0 and logs INFO."""
    monkeypatch.setattr(wake_signal, "STATE_ROOT", tmp_path)
    monkeypatch.setenv("SCENARIO_NAME", "ghost")
    monkeypatch.setenv("AGENT_NAME", "alice")
    assert wake_signal.signal_peers("x") == 0


def test_read_signal_mtime_returns_zero_when_absent(tmp_path):
    """``0.0`` is the sentinel that means 'no signal yet'. POSIX real mtimes
    are never zero so this can never false-positive a real touch."""
    assert wake_signal.read_signal_mtime(tmp_path) == 0.0


def test_read_signal_mtime_increases_after_touch(tmp_path):
    """A touch updates mtime; the watchdog detects 'newer than baseline'."""
    import time
    (tmp_path / wake_signal.SIGNAL_FILENAME).touch()
    t1 = wake_signal.read_signal_mtime(tmp_path)
    assert t1 > 0.0
    # Sleep just enough that mtime can change on this filesystem.
    time.sleep(0.05)
    (tmp_path / wake_signal.SIGNAL_FILENAME).touch()
    t2 = wake_signal.read_signal_mtime(tmp_path)
    assert t2 >= t1   # strictly > on most filesystems; equality tolerated


def test_self_state_dir_returns_none_when_env_unset(monkeypatch):
    monkeypatch.delenv("SCENARIO_NAME", raising=False)
    monkeypatch.delenv("AGENT_NAME", raising=False)
    assert wake_signal.self_state_dir() is None


def test_self_state_dir_composes_from_env(state_root, monkeypatch):
    monkeypatch.setenv("SCENARIO_NAME", "demo")
    monkeypatch.setenv("AGENT_NAME", "alice")
    expected = state_root / "demo" / "alice"
    assert wake_signal.self_state_dir() == expected
