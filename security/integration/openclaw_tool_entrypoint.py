from __future__ import annotations

import argparse
import json
from typing import Any

from security.integration.openclaw_tools import (
    EXPERIMENT_ONLY_TOOL_REGISTRY,
    TOOL_REGISTRY,
    tool_manifest,
)


def call_tool(tool_name: str, args: dict[str, Any], include_experiment_only: bool = False) -> dict[str, Any]:
    registry = dict(TOOL_REGISTRY)
    if include_experiment_only:
        registry.update(EXPERIMENT_ONLY_TOOL_REGISTRY)

    if tool_name not in registry:
        return {
            "ok": False,
            "error": f"unknown DelftClaw tool: {tool_name}",
            "available_tools": sorted(registry),
        }

    try:
        return registry[tool_name](**args)
    except TypeError as exc:
        return {
            "ok": False,
            "error": f"invalid arguments for {tool_name}: {exc}",
            "tool": tool_name,
        }


def main() -> None:
    parser = argparse.ArgumentParser(description="Call a DelftClaw OpenClaw tool from a command-line adapter.")
    parser.add_argument("--manifest", action="store_true", help="Print the DelftClaw tool manifest.")
    parser.add_argument("--tool", help="Tool name to call, e.g. delftclaw_send_message.")
    parser.add_argument("--args-json", default="{}", help="JSON object passed as keyword arguments to the tool.")
    parser.add_argument(
        "--include-experiment-only",
        action="store_true",
        help="Allow experiment-only tools such as delftclaw_run_blocking_probe.",
    )
    args = parser.parse_args()

    if args.manifest:
        print(json.dumps(tool_manifest(include_experiment_only=args.include_experiment_only), indent=2, sort_keys=True))
        return

    if not args.tool:
        raise SystemExit("--tool is required unless --manifest is used")

    try:
        tool_args = json.loads(args.args_json)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"--args-json must be valid JSON: {exc}") from exc

    if not isinstance(tool_args, dict):
        raise SystemExit("--args-json must decode to a JSON object")

    result = call_tool(args.tool, tool_args, include_experiment_only=args.include_experiment_only)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
