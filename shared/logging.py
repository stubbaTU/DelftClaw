"""Project-wide structlog configuration.

JSON output is required for the SQ3 attempt log; this module is the single
place that wires the processor chain so every importer sees the same shape.
"""

from __future__ import annotations

import structlog

_configured = False


def configure_logging() -> None:
    global _configured
    if _configured:
        return
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ],
    )
    _configured = True


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    configure_logging()
    return structlog.get_logger(name)
