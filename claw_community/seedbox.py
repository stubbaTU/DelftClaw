from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from claw_community.seedbox_providers import DEFAULT_ROOT, provider_for


def main() -> None:
    parser = argparse.ArgumentParser(prog="delftclaw seedbox", description="Plan or launch DelftClaw seedboxes safely.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    for command in ("plan", "launch"):
        sub = subparsers.add_parser(command)
        sub.add_argument("--provider", choices=("mock", "local", "sporestack"), default="mock")
        sub.add_argument("--hostname", default="delftclaw-seedbox-demo")
        sub.add_argument("--content-dir", default="seedbox_artifacts/content")
        sub.add_argument("--capacity-gb", type=int, default=100)
        sub.add_argument("--root", default=str(DEFAULT_ROOT), help="Directory for generated metadata/logs.")

    args = parser.parse_args()
    provider = provider_for(args.provider, root=Path(args.root))
    content_dir = Path(args.content_dir)

    if args.command == "plan":
        result = provider.plan(
            hostname=args.hostname,
            content_dir=content_dir,
            capacity_gb=args.capacity_gb,
        )
    else:
        result = provider.launch(
            hostname=args.hostname,
            content_dir=content_dir,
            capacity_gb=args.capacity_gb,
        )

    print(json.dumps(asdict(result), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
