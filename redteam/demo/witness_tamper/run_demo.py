"""Witness-tamper-and-forward demo orchestrator.

End-to-end:
  A donates → B witnesses (amount=5) → B tampers (amount=5000) →
  B forwards to C → C cryptographically rejects → audit fires →
  ReputationEngine expels B.

With ``--live``, A and B are full OpenClawAgent instances and the witness
entry on B's log is produced by real MCP-tool calls.
"""

from __future__ import annotations

import argparse
import socket
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx
import uvicorn

from redteam.demo.witness_tamper.forward import forward_entry
from redteam.demo.witness_tamper.setup import bootstrap, live_bootstrap
from redteam.demo.witness_tamper.tamper import tamper_witness_entry
from redteam.integration.server import build_app
from security.subq2_accountability.reputation import ReputationEngine


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _wait_for_head(base_url: str, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            resp = httpx.get(f"{base_url}/head", timeout=1.0)
            if resp.status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(0.05)
    raise RuntimeError(f"server at {base_url} never became ready")


def run_demo(live: bool = False) -> int:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    prefix = f"witness_tamper_demo_{'live_' if live else ''}{stamp}_"
    tmp_root = Path(tempfile.mkdtemp(prefix=prefix))
    print(f"[artifacts] {tmp_root}")

    if live:
        boot = live_bootstrap(tmp_root)
        amount_key = "amount_sats"
        original_amount = boot.witness_entry["details"][amount_key]
        print(
            "[setup] A and B are live OpenClawAgent instances; A called "
            "community_donate_and_join, B called community_witness_event. "
            f"B's real community log has the witness entry (amount_sats={original_amount})."
        )
    else:
        boot = bootstrap(tmp_root)
        amount_key = "amount"
        original_amount = boot.witness_entry["details"][amount_key]
        print(
            "[setup] A, B, C identities created; B's log has the witness entry "
            f"recording A's donation (amount={original_amount})."
        )

    tampered = tamper_witness_entry(
        boot.witness_entry, boot.b_identity, amount_key=amount_key
    )
    print(
        f"[tamper] B tampered the witness entry: {amount_key} "
        f"{original_amount} -> 5000, re-signed wrapper with B's key."
    )

    port = _free_port()
    app = build_app(
        identity=boot.c_identity,
        log_path=boot.c_log_path,
        peer_log_dir=tmp_root / "c_peers",
        enable_integrity_audit=True,
    )
    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=port,
        log_level="warning",
        access_log=False,
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{port}"
    _wait_for_head(base_url)
    print(
        f"[server] C's auditor server listening on {base_url} "
        f"(enable_integrity_audit=True)."
    )

    try:
        response = forward_entry(tampered, base_url)
        assert response.status_code == 400, (
            f"expected 400, got {response.status_code}: {response.text}"
        )
        detail = response.json().get("detail")
        print(
            f"[forward] C rejected the tampered entry: HTTP "
            f"{response.status_code}. Errors: {detail}."
        )

        time.sleep(0.2)

        engine = ReputationEngine(
            log_path=str(boot.c_log_path), ban_threshold=10
        )
        engine.scan_log()
        b_id = boot.b_identity.identity_hash
        assert engine.is_banned(b_id), (
            f"expected B ({b_id}) to be banned; score={engine.get_score(b_id)}"
        )
        print(
            f"[reputation] B is BANNED. Score: {engine.get_score(b_id)}. "
            f"Threshold: 10."
        )
        print(
            "[done] Witness-tamper-and-forward demo complete: "
            "B's malicious entry was cryptographically caught and B was expelled."
        )
    finally:
        server.should_exit = True
        thread.join(timeout=5.0)

    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--live",
        action="store_true",
        help="Use live OpenClawAgent instances + real MCP tool calls "
             "to produce B's witness entry (vs synthetic bootstrap).",
    )
    args = parser.parse_args()
    raise SystemExit(run_demo(live=args.live))


if __name__ == "__main__":  # pragma: no cover
    main()
