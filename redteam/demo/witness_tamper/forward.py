"""Forward a signed v2 entry to a target server's ``/entries`` endpoint."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import httpx


def forward_entry(entry: dict, target_url: str) -> httpx.Response:
    return httpx.post(f"{target_url}/entries", json=entry, timeout=10.0)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="redteam.demo.witness_tamper.forward"
    )
    parser.add_argument("--target", required=True)
    parser.add_argument("--entry-file", required=True, type=Path)
    args = parser.parse_args()

    entry = json.loads(args.entry_file.read_text(encoding="utf-8"))
    resp = forward_entry(entry, args.target)
    print(f"status={resp.status_code}")
    print(resp.text)


if __name__ == "__main__":  # pragma: no cover
    main()
