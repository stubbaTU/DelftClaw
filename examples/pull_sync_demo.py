"""3-server convergence demo: pull-based Layer 3 sync.

Spins up three Layer 3 servers (alice 8800, bob 8801, charlie 8802),
each configured to pull from the other two. Alice writes a few signed
self entries via her ``/log`` endpoint. Within ``--pull-interval``
seconds, bob's and charlie's per-source PeerLog files for alice fill
up automatically — no explicit forwarding, no PUSH.

This is the demoable shape of pull sync: configure peers once, and
chains converge. The same algorithm slot will accept an IPv8 transport
later; the wire layer is the only thing that changes.

Run:

    .venv\\Scripts\\python.exe examples\\pull_sync_demo.py

Cleanup is automatic on exit (Ctrl+C or normal completion). On Windows
the subprocesses are killed via ``Popen.terminate()`` — uvicorn's
graceful-shutdown lifespan won't fire, but the demo creates fresh
keys/logs/peer-dirs each run so leftover state is harmless.

Distinct from ``examples/layer3_demo.py``:

* layer3_demo.py exercises the *push* path — a script POSTs entries
  from alice's chain into bob's PeerLog over HTTP.
* pull_sync_demo.py exercises the *pull* path — bob and charlie
  discover alice's entries themselves via their own pull loops.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
import sys
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
PYTHON = sys.executable
PULL_INTERVAL = 1.0  # snappier than the 5s default so the demo finishes fast
ARTIFACTS = Path(__file__).resolve().parent / "pull_sync_artifacts"


def _section(title: str) -> None:
    print(f"\n--- {title} ---")


def _spawn_server(
    *,
    port: int,
    key_path: Path,
    log_path: Path,
    peer_log_dir: Path,
    peers: list[str],
) -> subprocess.Popen:
    """Spawn one ``redteam.integration.server`` subprocess."""
    cmd = [
        PYTHON,
        "-m",
        "redteam.integration.server",
        "--host", "127.0.0.1",
        "--port", str(port),
        "--network", "DEV",
        "--key-path", str(key_path),
        "--log", str(log_path),
        "--peer-log-dir", str(peer_log_dir),
        "--pull-interval", str(PULL_INTERVAL),
        "--pull-batch", "100",
    ]
    if peers:
        cmd += ["--peers", ",".join(peers)]
    return subprocess.Popen(
        cmd,
        cwd=str(ROOT),
        stdout=subprocess.DEVNULL,
    )


async def _wait_for_ready(url: str, timeout: float = 10.0) -> dict:
    """Poll ``GET /identity`` until it answers, or raise on timeout."""
    deadline = asyncio.get_event_loop().time() + timeout
    last_err: Exception | None = None
    async with httpx.AsyncClient(timeout=1.0) as client:
        while asyncio.get_event_loop().time() < deadline:
            try:
                resp = await client.get(f"{url}/identity")
                resp.raise_for_status()
                return resp.json()
            except (httpx.HTTPError, httpx.ConnectError) as exc:
                last_err = exc
                await asyncio.sleep(0.2)
    raise TimeoutError(f"server at {url} did not become ready: {last_err}")


async def _post_entry(url: str, action: str, details: dict) -> dict:
    async with httpx.AsyncClient(timeout=5.0) as client:
        resp = await client.post(
            f"{url}/log",
            json={"action": action, "details": details},
        )
        resp.raise_for_status()
        return resp.json()


def _count_alice_entries_in(peer_log_dir: Path, alice_id: str) -> int:
    """Return how many of Alice's entries are cached at ``peer_log_dir``."""
    f = peer_log_dir / f"{alice_id}.jsonl"
    if not f.exists():
        return 0
    return sum(1 for line in f.read_text(encoding="utf-8").splitlines() if line.strip())


async def run() -> int:
    # Persistent artifacts directory next to the demo script so the
    # produced peer-log files survive past process exit and can be
    # inspected manually after the demo. Wiped at the start of each
    # run so we always demonstrate from a clean state.
    if ARTIFACTS.exists():
        shutil.rmtree(ARTIFACTS, ignore_errors=True)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    workdir = ARTIFACTS
    print(f"artifacts: {workdir}")

    alice_url = "http://127.0.0.1:8800"
    bob_url = "http://127.0.0.1:8801"
    charlie_url = "http://127.0.0.1:8802"

    nodes = [
        ("alice",   8800, [bob_url, charlie_url]),
        ("bob",     8801, [alice_url, charlie_url]),
        ("charlie", 8802, [alice_url, bob_url]),
    ]

    procs: list[subprocess.Popen] = []
    try:
        _section("1. Launch 3 servers (each peered with the other two)")
        for name, port, peers in nodes:
            key_path = workdir / f"{name}.pem"
            log_path = workdir / f"{name}.log"
            peer_dir = workdir / f"{name}_peers"
            peer_dir.mkdir(parents=True, exist_ok=True)
            procs.append(_spawn_server(
                port=port,
                key_path=key_path,
                log_path=log_path,
                peer_log_dir=peer_dir,
                peers=peers,
            ))
            print(f"  spawned {name} on :{port} (pid {procs[-1].pid})")

        _section("2. Wait for all three to advertise /identity")
        idents = {}
        for (name, port, _), _proc in zip(nodes, procs):
            url = f"http://127.0.0.1:{port}"
            ident = await _wait_for_ready(url)
            idents[name] = ident
            print(f"  {name}: id={ident['identity_hash'][:16]}...")

        _section("3. Alice writes 3 self entries via her own /log")
        bodies = [
            ("share_seedbox", {"host": "seed.example", "port": 51413}),
            ("broadcast_seedbox_donation", {"amount_sat": 10_000}),
            ("hello_network", {"msg": "alice up"}),
        ]
        for action, details in bodies:
            entry = await _post_entry(alice_url, action, details)
            print(f"  {action:<30} -> entry_hash {entry['entry_hash'][:16]}...")

        _section("4. Wait for bob + charlie to converge on alice's chain")
        alice_id = idents["alice"]["identity_hash"]
        bob_peer_dir = workdir / "bob_peers"
        charlie_peer_dir = workdir / "charlie_peers"

        deadline = asyncio.get_event_loop().time() + 15.0
        while asyncio.get_event_loop().time() < deadline:
            bob_n = _count_alice_entries_in(bob_peer_dir, alice_id)
            charlie_n = _count_alice_entries_in(charlie_peer_dir, alice_id)
            print(f"  bob has {bob_n}/3, charlie has {charlie_n}/3", end="\r")
            if bob_n >= 3 and charlie_n >= 3:
                print()  # newline after the carriage-return line
                break
            await asyncio.sleep(0.25)
        else:
            print()
            print("  [FAIL] convergence did not complete within 15s")
            return 1

        _section("5. Verify the entries on disk match alice's chain")
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{alice_url}/entries", params={"limit": 100})
            resp.raise_for_status()
            alice_entries = resp.json()["entries"]
        alice_hashes = {e["entry_hash"] for e in alice_entries}

        bob_peer_file = bob_peer_dir / f"{alice_id}.jsonl"
        charlie_peer_file = charlie_peer_dir / f"{alice_id}.jsonl"

        for name, peer_file in (("bob", bob_peer_file), ("charlie", charlie_peer_file)):
            cached = [
                json.loads(line)
                for line in peer_file.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            cached_hashes = {e["entry_hash"] for e in cached}
            ok = cached_hashes == alice_hashes
            print(f"  {name}: cached={len(cached)} entries, hashes_match={ok}")
            if not ok:
                return 1

        _section("6. Inspect one real entry as bob saw it")
        first_entry = json.loads(
            bob_peer_file.read_text(encoding="utf-8").splitlines()[0]
        )
        # Print key fields only — full entry is verbose. Truncate hashes
        # so the output fits on a slide / terminal.
        compact = {
            "kind": first_entry.get("kind"),
            "action": first_entry.get("action"),
            "reporter_id": first_entry.get("reporter_id", "")[:16] + "...",
            "reporter_pubkey": first_entry.get("reporter_pubkey", "")[:16] + "...",
            "previous_hash": first_entry.get("previous_hash", "")[:16] + "...",
            "entry_hash": first_entry.get("entry_hash", "")[:16] + "...",
            "signature": first_entry.get("signature", "")[:16] + "...",
        }
        for k, v in compact.items():
            print(f"  {k:<16} {v}")
        print(f"  (full entry: {bob_peer_file})")

        _section("7. Independent verification via redteam.primitives.verify")
        # Use the standalone CLI verifier to chain-walk + sig-check +
        # binding-check bob's cached copy of alice's chain. It does
        # not import from signed_log -- this is genuine third-party
        # cryptographic verification of the artifacts on disk.
        verify_result = subprocess.run(
            [
                PYTHON,
                "-m",
                "redteam.primitives.verify",
                "--log", str(bob_peer_file),
                "--network", "DEV",
            ],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
        )
        # Print stdout/stderr indented so it's clearly the verifier's output.
        for line in (verify_result.stdout or "").splitlines():
            print(f"  | {line}")
        for line in (verify_result.stderr or "").splitlines():
            print(f"  | (stderr) {line}")
        print(f"  exit code: {verify_result.returncode}")
        if verify_result.returncode != 0:
            print("  [FAIL] verifier rejected bob's cached chain")
            return 1

        print(
            "\nDone. Convergence verified - pull-only, no explicit forwarding."
        )
        print(f"Artifacts left at: {workdir}")
        return 0

    finally:
        _section("teardown")
        for proc in procs:
            try:
                proc.terminate()
            except Exception:
                pass
        for proc in procs:
            try:
                proc.wait(timeout=3.0)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2.0)
        # Artifacts directory is intentionally NOT removed here -- it's
        # the whole point. Wiped at the START of the next run instead.


if __name__ == "__main__":
    sys.exit(asyncio.run(run()))
