"""Diagnostic CLI for validating remote Qwen model connectivity over Tailscale."""

from __future__ import annotations

import argparse
import json
import sys

from security.integration.model_config import load_model_runtime_config
from security.integration.qwen_client import QwenModelClient


def main() -> int:
    """Resolve model config and run basic endpoint diagnostics."""
    parser = argparse.ArgumentParser(description="Check Qwen model endpoint configuration and health.")
    parser.add_argument("--config", help="Optional explicit path to openclaw.json")
    parser.add_argument("--prompt", default="Return only the word OK.", help="Optional smoke prompt")
    args = parser.parse_args()

    try:
        cfg = load_model_runtime_config(args.config)
    except ValueError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2))
        return 1

    client = QwenModelClient(cfg)
    status = {
        "ok": True,
        "base_url": cfg.base_url,
        "model": cfg.model,
        "health": client.health(),
    }

    try:
        status["models"] = client.list_models()
    except Exception as exc:  # noqa: BLE001
        status["models_error"] = str(exc)

    try:
        status["smoke_reply"] = client.quick_prompt(args.prompt)
    except Exception as exc:  # noqa: BLE001
        status["smoke_error"] = str(exc)

    print(json.dumps(status, indent=2, sort_keys=True))
    return 0 if status.get("health") else 2


if __name__ == "__main__":
    sys.exit(main())

