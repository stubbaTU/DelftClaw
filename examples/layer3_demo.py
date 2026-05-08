"""End-to-end Layer 3 HTTP dev-mode demo: Alice → Bob signed-entry round trip.

Drives the manual curl flow as a single Python script so the cross-agent
sync story is easy to demo. Assumes two ``redteam.integration.server``
instances are already running on localhost — see the header comment in
``run()`` for the exact commands.

What it does:
    1. Probes both servers via ``GET /identity``; bails if either is down.
    2. Has Alice write three signed self entries via ``POST /log``.
    3. Pulls Alice's chain via ``GET /entries``.
    4. Pushes each entry into Bob's peer cache via ``POST /entries``.
    5. Re-POSTs the last entry to demonstrate idempotency
       (``stored=False, duplicate=True``).
    6. Reads Bob's per-source ``<alice_id>.jsonl`` to confirm persistence.

Run:
    .venv\\Scripts\\python.exe examples\\layer3_demo.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import httpx

ALICE_URL = "http://127.0.0.1:8800"
BOB_URL = "http://127.0.0.1:8801"
BOB_PEER_LOG_DIR = Path("bob_peers")

ENTRIES_TO_POST = [
    {"action": "hello_bob", "details": {"msg": "first contact"}},
    {"action": "share_seedbox", "details": {"host": "seed.example", "port": 51413}},
    {"action": "broadcast_seedbox_donation", "details": {"amount_sat": 10_000}},
]


def _probe(url: str) -> dict:
    """Return ``GET /identity`` body, or print + exit on failure."""
    try:
        resp = httpx.get(f"{url}/identity", timeout=2.0)
        resp.raise_for_status()
        return resp.json()
    except (httpx.HTTPError, httpx.ConnectError) as exc:
        print(f"[FAIL] {url} not reachable: {exc}")
        print("       Start it first — see the header comment in this file.")
        sys.exit(1)


def _post(url: str, path: str, body: dict) -> httpx.Response:
    return httpx.post(f"{url}{path}", json=body, timeout=5.0)


def _section(title: str) -> None:
    print(f"\n--- {title} ---")


def run() -> None:
    print("Layer 3 HTTP dev-mode demo")
    print("Expects two servers running:")
    print(f"  Alice: {ALICE_URL}  (--log alice.log --key-path alice.pem ...)")
    print(f"  Bob:   {BOB_URL}  (--log bob.log --key-path bob.pem "
          f"--peer-log-dir {BOB_PEER_LOG_DIR} ...)")

    _section("1. Probe identities")
    alice = _probe(ALICE_URL)
    bob = _probe(BOB_URL)
    print(f"Alice id: {alice['identity_hash'][:16]}...")
    print(f"Bob   id: {bob['identity_hash'][:16]}...")
    if alice["identity_hash"] == bob["identity_hash"]:
        print("[FAIL] Both servers report the same identity. Check --key-path.")
        sys.exit(1)

    _section("2. Alice writes 3 self entries")
    for body in ENTRIES_TO_POST:
        resp = _post(ALICE_URL, "/log", body)
        resp.raise_for_status()
        print(f"  {body['action']:<30} -> entry_hash {resp.json()['entry_hash'][:16]}...")

    _section("3. Pull Alice's chain")
    resp = httpx.get(f"{ALICE_URL}/entries", params={"limit": 100}, timeout=5.0)
    resp.raise_for_status()
    payload = resp.json()
    entries = payload["entries"]
    print(f"  fetched {len(entries)} entries; head_hash={payload['head_hash'][:16]}...")

    _section("4. Push each entry to Bob's peer cache")
    for entry in entries:
        resp = _post(BOB_URL, "/entries", entry)
        if resp.status_code != 200:
            print(f"  [FAIL] {entry['entry_hash'][:16]}... -> {resp.status_code} {resp.text}")
            sys.exit(1)
        body = resp.json()
        print(f"  {entry['action']:<30} -> stored={body['stored']} duplicate={body['duplicate']}")

    _section("5. Re-POST last entry (idempotency)")
    resp = _post(BOB_URL, "/entries", entries[-1])
    body = resp.json()
    if body["stored"] or not body["duplicate"]:
        print(f"  [FAIL] expected duplicate=True, stored=False; got {body}")
        sys.exit(1)
    print(f"  duplicate detected as expected: stored={body['stored']} duplicate={body['duplicate']}")

    _section("6. Read Bob's peer log on disk")
    peer_file = BOB_PEER_LOG_DIR / f"{alice['identity_hash']}.jsonl"
    if not peer_file.exists():
        print(f"  [FAIL] expected file {peer_file} not found")
        print(f"         did you start Bob with --peer-log-dir {BOB_PEER_LOG_DIR}?")
        sys.exit(1)
    lines = peer_file.read_text(encoding="utf-8").splitlines()
    print(f"  {peer_file} has {len(lines)} cached entries from Alice")
    if len(lines) != len(entries):
        print(f"  [FAIL] line count {len(lines)} != entry count {len(entries)}")
        sys.exit(1)
    cached_hashes = [json.loads(line)["entry_hash"] for line in lines]
    chain_hashes = [e["entry_hash"] for e in entries]
    if cached_hashes != chain_hashes:
        print("  [FAIL] cached entry_hashes do not match Alice's chain")
        sys.exit(1)

    print("\nDone. Layer 3 round trip verified end-to-end.")


if __name__ == "__main__":
    run()
