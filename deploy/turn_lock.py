"""Cross-agent serialization lock for LLM turns.

A scenario runs N watchdog processes side by side, one per agent. By
default each one drives its own openclaw turn loop, so all N can be
calling the LLM provider at the same instant. That pattern hammers the
provider's concurrent-request and per-minute token caps even when each
individual turn is tiny.

This module gives every watchdog a system-wide mutex via ``fcntl.flock``
on a single lock file. While one agent holds the lock, the others block
inside ``acquire``. The result: turns serialise — alice finishes her
openclaw call, releases, then bob takes the lock, and so on.

Why a file lock and not a Python ``asyncio.Lock``: the watchdogs live in
*separate processes* (one systemd unit each). Python locks scope to a
single process. ``fcntl.flock`` is the OS-level primitive that crosses
process boundaries on Linux.

Usage::

    from deploy.turn_lock import acquire_llm_turn_lock

    async with acquire_llm_turn_lock(instance="seek_cc-alice", log=_log):
        ok, stdout, stderr = await asyncio.to_thread(_invoke_openclaw_agent, ...)

The lock is held for the duration of the ``async with`` block. The
``acquire_llm_turn_lock`` coroutine releases the FD (and any other
agent waiting on flock wakes up) when it exits — both on normal exit
and on exception.
"""

from __future__ import annotations

import asyncio
import contextlib
import fcntl
import logging
import os
import time
from pathlib import Path

DEFAULT_LOCK_PATH = Path("/tmp/delftclaw-llm-turn.lock")


@contextlib.asynccontextmanager
async def acquire_llm_turn_lock(
    *,
    instance: str,
    log: logging.Logger,
    lock_path: Path = DEFAULT_LOCK_PATH,
):
    """Acquire the cross-process LLM-turn lock for the duration of the block.

    ``fcntl.flock`` is a blocking syscall — we run it on a worker thread
    via ``asyncio.to_thread`` so the watchdog's event loop stays
    responsive (e.g. systemd's TERM signal still wakes us). The lock
    file lives at ``lock_path`` and is created with mode 0600 if it
    doesn't already exist; subsequent acquirers reuse the same inode.

    The held duration is logged at INFO so a slow turn doesn't silently
    starve the other agents.
    """
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    log.info("[%s] waiting for llm turn lock %s", instance, lock_path)
    wait_started = time.monotonic()

    def _grab() -> None:
        fcntl.flock(fd, fcntl.LOCK_EX)

    try:
        await asyncio.to_thread(_grab)
    except BaseException:
        os.close(fd)
        raise

    wait_s = time.monotonic() - wait_started
    log.info("[%s] acquired llm turn lock after %.1fs", instance, wait_s)
    held_started = time.monotonic()
    try:
        yield
    finally:
        held_s = time.monotonic() - held_started
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
        log.info("[%s] released llm turn lock after %.1fs", instance, held_s)
