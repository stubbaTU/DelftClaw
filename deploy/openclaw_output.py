"""Helpers for interpreting ``openclaw agent --json`` output.

OpenClaw currently emits a top-level JSON object with a ``payloads`` list
whose entries may contain assistant ``text``. Keep the parser deliberately
small: callers only need extracted text and whether the model returned the
literal sentinel ``ERROR`` while still exiting zero.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class OpenClawJsonSummary:
    """Small, stable summary of an OpenClaw JSON stdout blob."""

    texts: tuple[str, ...]
    parse_error: str | None = None

    @property
    def assistant_text(self) -> str:
        return "\n".join(text for text in self.texts if text)

    @property
    def semantic_error(self) -> str | None:
        if any(text.strip() == "ERROR" for text in self.texts):
            return "openclaw_semantic_error:literal_ERROR"
        return None


def parse_openclaw_json_stdout(stdout: str) -> OpenClawJsonSummary:
    """Extract assistant payload text from ``openclaw agent --json`` stdout.

    Empty stdout and JSON without text payloads are valid summaries with no
    semantic error; autonomous wait turns may intentionally produce no text.
    Malformed JSON is reported to diagnostics but is not by itself classified
    as the literal ``ERROR`` sentinel.
    """
    raw = stdout.strip()
    if not raw:
        return OpenClawJsonSummary(texts=())
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        return OpenClawJsonSummary(texts=(), parse_error=f"json_decode_error:{exc.msg}")

    texts: list[str] = []
    payloads = data.get("payloads") if isinstance(data, dict) else None
    if isinstance(payloads, list):
        for payload in payloads:
            if not isinstance(payload, dict):
                continue
            text = payload.get("text")
            if isinstance(text, str):
                texts.append(text)
    return OpenClawJsonSummary(texts=tuple(texts))
