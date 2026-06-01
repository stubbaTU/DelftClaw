from __future__ import annotations

import json
import re
from typing import Any

from security.preventative_layer.permissions.models import ValidationResult


DEFAULT_SECRET_PATTERNS = [
    "VUKZERO_IDENTITY_KEY_CANARY_",
    "VUKZERO_WALLET_CANARY_",
    "VUKZERO_LOG_SECRET_CANARY_",
    "DELFTCLAW_TEST_PRIVATE_KEY_CANARY_",
]


class EgressGuard:
    def __init__(self, secret_patterns: list[str] | None = None) -> None:
        self.secret_patterns = secret_patterns or list(DEFAULT_SECRET_PATTERNS)

    def check_text(self, text: str) -> ValidationResult:
        for pattern in self.secret_patterns:
            if pattern in text:
                return ValidationResult(False, f"egress contains protected canary pattern {pattern}")
        if re.search(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", text):
            return ValidationResult(False, "egress contains private-key shaped material")
        return ValidationResult(True, "egress accepted")

    def check_payload(self, payload: Any) -> ValidationResult:
        try:
            text = self._stringify(payload)
        except Exception:
            return ValidationResult(False, "egress payload could not be inspected")
        return self.check_text(text)

    def _stringify(self, payload: Any) -> str:
        if isinstance(payload, str):
            return payload
        return json.dumps(payload, default=str, sort_keys=True)
