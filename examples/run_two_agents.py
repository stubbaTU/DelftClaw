"""Run two real ``python -m agent`` processes that talk to each other.

Demonstrates the v5.1 genesis/consumer split via ``--genesis`` /
``--manifest``:

  1. We generate a network manifest from Alice's actual identity
     (her IPv8 pubkey + wallet address). The manifest names her as
     the only genesis peer + admission gatekeeper and lists
     ``content_community.md`` as a default overlay.

  2. Alice boots with ``--genesis <manifest>`` and
     ``--publish-overlay content_community.md`` so she advertises the
     manifest AND serves the search overlay's descriptor.

  3. Bob boots with ``--manifest <manifest>`` — his ``load_manifest``
     call pre-introduces Alice from the genesis peer list, no
     ``--peer`` flag needed.

  4. Bob's scripted tool loop runs ``overlay_fetch_and_load`` +
     ``overlay_invoke`` on the content community. The full
     ``network_join`` (including the donation broadcast) is exercised
     by ``tests/test_network_join.py`` against a mocked verifier;
     this demo skips that step because Bob's wallet is unfunded.

  5. Bob's ``run`` exits when the loop produces final text; we tear
     Alice down. The whole thing exits in <10s.

To run with a real LLM endpoint, drop ``--compiler-stub`` and
``--llm-stub-script`` on Bob and add ``--llm-base-url``/``--llm-model``
on both.

Usage:

    python -m examples.run_two_agents
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

ALICE_MNEMONIC = (
    "army van defense carry jealous true garbage claim echo media make crunch"
)
BOB_MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
)

ALICE_PORT = 18290
BOB_PORT = 18291

CONTENT_MD = REPO_ROOT / "protocol" / "examples" / "content_community.md"


def _run(*args: str, **kw) -> subprocess.CompletedProcess:
    """``python -m agent ...`` synchronously (for ``info`` / one-shot ``run``)."""
    return subprocess.run(
        [sys.executable, "-m", "agent", *args],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=15,
        **kw,
    )


def _info(mnemonic: str, port: int) -> dict:
    """Boot the agent in info mode + parse the JSON tail of stdout."""
    proc = _run(
        "--mnemonic", mnemonic,
        "--port", str(port),
        "info",
    )
    if proc.returncode != 0:
        sys.stderr.write(f"info failed:\n{proc.stderr}\n")
        proc.check_returncode()
    # Skip the leading ``[agent] ...`` status lines, parse the JSON tail.
    lines = proc.stdout.splitlines()
    json_start = next(i for i, ln in enumerate(lines) if ln.startswith("{"))
    return json.loads("\n".join(lines[json_start:]))


def _build_bob_script(alice_mid_hex: str, content_md_hash_hex: str) -> Path:
    """Scripted chat-completion responses Bob's tool loop will play through.

    Three tool calls, then a final-text reply:
      1. peers_list                     (the LLM looks at who we know)
      2. overlay_fetch_and_load         (fetch + compile + register the
                                         content community from Alice)
      3. overlay_invoke SEARCH_REQUEST  (query="creative")
      4. assistant text                 (loop ends)
    """
    script = [
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [{
                "id": "c1", "type": "function",
                "function": {"name": "peers_list", "arguments": "{}"},
            }],
        },
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [{
                "id": "c2", "type": "function",
                "function": {
                    "name": "overlay_fetch_and_load",
                    "arguments": json.dumps({
                        "peer_mid": alice_mid_hex,
                        "md_hash_hex": content_md_hash_hex,
                    }),
                },
            }],
        },
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [{
                "id": "c3", "type": "function",
                "function": {
                    "name": "overlay_invoke",
                    "arguments": json.dumps({
                        "community_id_hex": content_md_hash_hex,
                        "message_name": "SEARCH_REQUEST",
                        "peer_mid": alice_mid_hex,
                        "fields": {"query": "creative"},
                    }),
                },
            }],
        },
        {
            "role": "assistant",
            "content": "Asked Alice; the SEARCH_REQUEST was sent on the content community.",
        },
    ]
    f = tempfile.NamedTemporaryFile(prefix="bob_script_", suffix=".json",
                                    delete=False, mode="w", encoding="utf-8")
    json.dump(script, f)
    f.close()
    return Path(f.name)


def _build_manifest(*, alice_address: str, alice_pubkey_hex: str,
                    alice_port: int, content_hash_hex: str) -> str:
    return (
        "# Identity\n"
        "- name: delftclaw_demo\n"
        "- version: 1.0.0\n"
        "- description: Two-agent demo network for run_two_agents.\n"
        "\n"
        "# Admission\n"
        f"- gatekeeper_address: {alice_address}\n"
        "- min_sats: 10000\n"
        "- min_confirmations: 0\n"
        "\n"
        "# Genesis Peers\n"
        "| host | port | pubkey_hex |\n"
        "|------|------|------------|\n"
        f"| 127.0.0.1 | {alice_port} | {alice_pubkey_hex} |\n"
        "\n"
        "# Default Overlays\n"
        f"- sha1: {content_hash_hex}  (content_community v1)\n"
    )


def main() -> int:
    # 1. Discover Alice's IPv8 pubkey + wallet address deterministically.
    info = _info(ALICE_MNEMONIC, ALICE_PORT)
    alice_pubkey_hex = info["ipv8_pubkey_hex"]
    alice_wallet = info["wallet_address"]
    print(f"[demo] Alice pubkey_hex = {alice_pubkey_hex[:24]}...")
    print(f"[demo] Alice wallet     = {alice_wallet}")

    # 2. Compute mid_hex (Peer.mid = sha1(serialized pubkey)[:20]) and
    #    content_community hash so Bob's scripted tool calls can refer
    #    to them by id.
    import hashlib
    alice_mid_hex = hashlib.sha1(bytes.fromhex(alice_pubkey_hex)).digest()[:20].hex()
    content_md_text = CONTENT_MD.read_text(encoding="utf-8")
    from protocol.compiler import community_id_from_md
    content_md_hash_hex = community_id_from_md(content_md_text).hex()
    print(f"[demo] content_community md_hash = {content_md_hash_hex}")

    # 3. Generate the network manifest from Alice's actual identity and
    #    write it to a temp file both processes will read.
    manifest_text = _build_manifest(
        alice_address=alice_wallet,
        alice_pubkey_hex=alice_pubkey_hex,
        alice_port=ALICE_PORT,
        content_hash_hex=content_md_hash_hex,
    )
    mf = tempfile.NamedTemporaryFile(
        prefix="delftclaw_demo_manifest_", suffix=".md",
        delete=False, mode="w", encoding="utf-8",
    )
    mf.write(manifest_text)
    mf.close()
    manifest_path = Path(mf.name)
    print(f"[demo] manifest written to {manifest_path}")

    # 4. Start Alice with --genesis (publishes the manifest + serves the
    #    content overlay descriptor).
    print("[demo] starting Alice (genesis, long-running)...")
    alice = subprocess.Popen(
        [sys.executable, "-m", "agent",
         "--mnemonic", ALICE_MNEMONIC,
         "--port", str(ALICE_PORT),
         "--genesis", str(manifest_path),
         "--publish-overlay", str(CONTENT_MD),
         "--compiler-stub",
         "serve"],
        cwd=str(REPO_ROOT),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        # Wait for Alice's "ready" line on stdout.
        for _ in range(50):
            if alice.poll() is not None:
                out, err = alice.communicate(timeout=1)
                sys.stderr.write(f"Alice exited prematurely:\n{err}\n{out}\n")
                return 1
            line = alice.stdout.readline()
            if "[serve] ready" in line:
                break
            time.sleep(0.1)
        print("[demo] Alice is up.")

        # 5. Run Bob with --manifest (load_manifest pre-introduces Alice
        #    from the genesis peer list — no --peer flag needed). His
        #    scripted tool loop skips the donation step (covered by
        #    tests/test_network_join.py against a mocked verifier).
        bob_script = _build_bob_script(alice_mid_hex, content_md_hash_hex)
        print(f"[demo] starting Bob (consumer)...")
        bob = _run(
            "--mnemonic", BOB_MNEMONIC,
            "--port", str(BOB_PORT),
            "--manifest", str(manifest_path),
            "--compiler-stub",
            "--publish-overlay", str(CONTENT_MD),
            "--llm-stub-script", str(bob_script),
            "run", "--query", "what files are on our claw network?",
        )
        bob_script.unlink(missing_ok=True)

        if bob.returncode != 0:
            sys.stderr.write(f"Bob failed:\n{bob.stderr}\n")
            return bob.returncode

        print("[demo] Bob output:")
        print(bob.stdout)
        return 0
    finally:
        manifest_path.unlink(missing_ok=True)
        if alice.poll() is None:
            alice.terminate()
            try:
                alice.wait(timeout=5)
            except subprocess.TimeoutExpired:
                alice.kill()


if __name__ == "__main__":
    raise SystemExit(main())
