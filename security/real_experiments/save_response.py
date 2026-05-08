from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any


def save_response(
    *,
    root: str | Path,
    run_id: str,
    prompt_id: str,
    response_text: str,
    condition: str = "",
    source: str = "telegram-openclaw",
    agent_id: str = "",
) -> dict[str, Any]:
    target_dir = Path(root) / "responses" / run_id
    target_dir.mkdir(parents=True, exist_ok=True)

    safe_prompt_id = _safe_name(prompt_id)
    timestamp = datetime.utcnow().isoformat()
    text_path = target_dir / f"{safe_prompt_id}.txt"
    metadata_path = target_dir / f"{safe_prompt_id}.json"

    text_path.write_text(response_text, encoding="utf-8")
    metadata = {
        "run_id": run_id,
        "prompt_id": prompt_id,
        "condition": condition,
        "source": source,
        "agent_id": agent_id,
        "timestamp": timestamp,
        "response_file": str(text_path),
    }
    metadata_path.write_text(json.dumps(metadata, indent=2, sort_keys=True), encoding="utf-8")
    return metadata


def _safe_name(value: str) -> str:
    cleaned = "".join(char if char.isalnum() or char in {"-", "_"} else "_" for char in value.strip())
    return cleaned or "response"


def main() -> None:
    parser = argparse.ArgumentParser(description="Save a Telegram/OpenClaw response with experiment metadata.")
    parser.add_argument("--root", default="real_experiment_workdir", help="Experiment workspace root.")
    parser.add_argument("--run-id", required=True, help="Run id, e.g. subq1-defended-run001.")
    parser.add_argument("--prompt-id", required=True, help="Prompt id, e.g. subq1-private-key-001.")
    parser.add_argument("--condition", default="", help="Condition label, e.g. baseline or defended.")
    parser.add_argument("--source", default="telegram-openclaw", help="Response source label.")
    parser.add_argument("--agent-id", default="", help="OpenClaw/DelftClaw agent id.")
    parser.add_argument("--response-file", help="Plain text file containing the response. Defaults to stdin.")
    args = parser.parse_args()

    if args.response_file:
        response_text = Path(args.response_file).read_text(encoding="utf-8")
    else:
        response_text = sys.stdin.read()

    metadata = save_response(
        root=args.root,
        run_id=args.run_id,
        prompt_id=args.prompt_id,
        response_text=response_text,
        condition=args.condition,
        source=args.source,
        agent_id=args.agent_id,
    )
    print(json.dumps(metadata, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
