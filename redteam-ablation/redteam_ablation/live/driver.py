"""Per-trial OpenClaw launch seam (plan 2026-06-11 §1.4 + §0.4).

``openclaw agent`` drives the real Sonnet turn in ONE shot; we do not run the
LLM loop. This module builds that command, runs it through an injectable seam
(tests fake the subprocess), reads the only useful field from its opaque
``--json`` stdout (``meta.agentMeta.sessionId``, §0.4), and builds the per-trial
env that points ``$HOME`` at the throwaway trial home. Stdlib only.
"""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:  # pragma: no cover -- typing only (avoids an import cycle)
    from redteam_ablation.runtime.openclaw import OpenClawConfig


@dataclass
class LaunchResult:
    """The subprocess outcome the runtime inspects (§1.4)."""

    returncode: int
    stdout: str
    stderr: str = ""


def build_agent_command(
    config: "OpenClawConfig", session_id: str, message: str
) -> list[str]:
    """Build the ``openclaw agent`` command for one trial (§1.4).

    A fresh ``--session-id`` per call starts a NEW claude session (§0.3 -- never
    rely on resume). ``--json`` is opaque but carries the session id we tail.
    """
    return [
        config.openclaw_bin,
        "agent",
        "--agent",
        config.agent_id,
        "--local",
        "--model",
        config.model,
        "--session-id",
        session_id,
        "--message",
        message,
        "--json",
        "--timeout",
        str(config.timeout_s),
    ]


def parse_openclaw_json(stdout: str) -> str:
    """Extract ``meta.agentMeta.sessionId`` from ``openclaw agent --json`` stdout.

    Per §0.4 this is the ONLY field we read -- ``payloads`` is empty under the
    stream-json backend. Raise legibly if it is absent.
    """
    try:
        data = json.loads(stdout)
        return data["meta"]["agentMeta"]["sessionId"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ValueError(
            "openclaw agent --json stdout missing "
            f"meta.agentMeta.sessionId (got: {stdout!r})"
        ) from exc


def build_trial_env(home: str | Path) -> dict[str, str]:
    """Copy ``os.environ`` and point HOME (+ USERPROFILE) at the trial ``home``.

    A throwaway HOME isolates workspace/constitution + openclaw session state
    (§0.3). ``USERPROFILE`` is set alongside ``HOME`` for Windows test parity so
    the same home resolves on either platform.
    """
    env = dict(os.environ)
    home_str = str(home)
    env["HOME"] = home_str
    env["USERPROFILE"] = home_str
    return env


def launch_openclaw(
    cmd: list[str],
    env: dict[str, str],
    timeout: float,
    runner: Callable[..., Any] = subprocess.run,
) -> LaunchResult:
    """Run ``cmd`` through ``runner`` (default ``subprocess.run``); thin + injectable.

    Returns a :class:`LaunchResult`. The ``runner`` seam is what tests replace
    to play the agent offline without touching a real ``openclaw`` binary.
    """
    completed = runner(
        cmd,
        env=env,
        timeout=timeout,
        capture_output=True,
        text=True,
    )
    return LaunchResult(
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )
