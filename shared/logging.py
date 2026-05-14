"""Project-wide structlog configuration.

Logs are emitted as JSON, one event per line. By default they go to stdout.

Two environment variables control routing:

* ``OPENCLAW_LOG_FILE`` — path to a JSON-Lines log file. The file is created
  fresh on each run (mode "w"). If unset, no file is written.
* ``OPENCLAW_LOG_NO_STDOUT`` — set to any non-empty value to suppress stdout
  output. Useful when piping the file through ``jq`` afterwards.

Programmatic equivalents (kwargs on :func:`configure_logging`): ``log_file``,
``stdout``. Env vars take effect only on the first call; subsequent calls are
no-ops.

Why we don't touch the root logger
----------------------------------
Frameworks like uvicorn (used by FastMCP for streamable-HTTP) reconfigure
the root logger when they start. If we attached our handlers there, the
file output would silently disappear after framework startup. Instead we
attach handlers to each *named* project logger as it's first requested
through :func:`get_logger`, and turn off propagation so uvicorn's root
manipulation can't reach our records. The handler list is shared so all
project loggers write to the same file/stdout pair.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

import structlog

_configured = False
_handlers: list[logging.Handler] = []
_attached_loggers: set[str] = set()

# Project loggers that need our handlers attached even if their modules
# haven't been imported yet at configure_logging() time. Pre-attaching
# protects them against frameworks (uvicorn, FastMCP) that reconfigure
# logging after startup. New project loggers should be added here.
#
# Currently empty: redteam.primitives.{signed,peer}_log are the only
# `shared.logging.get_logger` consumers and they pull their loggers
# lazily under their own module-derived names. The historical v4.0
# names (trustroom_community, stake_oracle, agent_channel, ...) were
# removed when those modules were withdrawn on 2026-05-08.
_PROJECT_LOGGER_NAMES: tuple[str, ...] = ()


class _JsonOnlyFilter(logging.Filter):
    """Drop any record whose rendered message is not a JSON object.

    A defence-in-depth measure: even if a non-project module ever logged
    through one of our handlers, the file would stay parseable JSONL.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        return msg.startswith("{") and msg.endswith("}")


class _FlushingFileHandler(logging.FileHandler):
    """``FileHandler`` that calls ``flush()`` on every record.

    The default ``FileHandler`` only flushes on close, so log lines written
    by long-running async servers (FastMCP / uvicorn) sit in the buffer
    until the process exits. Tail / inspection during a live demo gets
    nothing. Flushing per-record is fine at our event volumes.
    """

    def emit(self, record: logging.LogRecord) -> None:
        super().emit(record)
        self.flush()


def configure_logging(
    *,
    log_file: str | Path | None = None,
    stdout: bool = True,
) -> None:
    global _configured, _handlers
    if _configured:
        return

    # Env vars override explicit args so users can redirect output without
    # editing demo scripts. Empty string means "use the explicit arg".
    env_path = os.environ.get("OPENCLAW_LOG_FILE")
    if env_path:
        log_file = env_path
    if os.environ.get("OPENCLAW_LOG_NO_STDOUT"):
        stdout = False

    handlers: list[logging.Handler] = []
    if stdout:
        handlers.append(logging.StreamHandler(sys.stdout))
    if log_file is not None:
        path = Path(log_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(_FlushingFileHandler(path, mode="w", encoding="utf-8"))

    if not handlers:
        # Don't end up with a silent logger; at least keep stdout.
        handlers.append(logging.StreamHandler(sys.stdout))

    formatter = logging.Formatter("%(message)s")
    json_filter = _JsonOnlyFilter()
    for h in handlers:
        h.setFormatter(formatter)
        h.addFilter(json_filter)

    _handlers = handlers

    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
    )
    _configured = True

    # Pre-attach handlers to every known project logger now, so that even
    # if uvicorn / FastMCP later reconfigure stdlib logging, our handlers
    # stay bound to the project loggers.
    for name in _PROJECT_LOGGER_NAMES:
        _attach_handlers(name)


def _attach_handlers(name: str) -> None:
    """Attach our shared handlers to ``logging.getLogger(name)``; idempotent.

    Sets ``propagate=False`` so any future root-logger reconfiguration (e.g.
    by uvicorn) can't divert our records to a different sink.
    """
    if name in _attached_loggers:
        return
    stdlib_logger = logging.getLogger(name)
    for h in _handlers:
        if h not in stdlib_logger.handlers:
            stdlib_logger.addHandler(h)
    stdlib_logger.setLevel(logging.DEBUG)
    stdlib_logger.propagate = False
    _attached_loggers.add(name)


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    configure_logging()
    _attach_handlers(name)
    return structlog.get_logger(name)


__all__ = ["configure_logging", "get_logger"]
