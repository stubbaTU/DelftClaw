"""Run the barebones OpenClaw agent on a real IPv8 runtime.

This is the actual proof-of-concept agent: it creates a persistent OpenClaw identity,
starts IPv8, wires the `ClawPoCCommunity`, and announces the identity hash.

Run:
    python examples\openclaw_poc.py
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Make sure both the project root and libsodium are available before importing IPv8.
sys.path.insert(0, str(ROOT))
if os.name == "nt":
	os.add_dll_directory(str(ROOT))

from communication.claw.openclaw_agent import OpenClawAgent


async def main() -> None:
	agent = OpenClawAgent(network="MAINNET", port=9000)
	try:
		await agent.start()
		print(f"OpenClaw agent running with identity hash: {agent.identity_hash}")
		await asyncio.sleep(2)
	finally:
		await agent.stop()


if __name__ == "__main__":
	asyncio.run(main())





