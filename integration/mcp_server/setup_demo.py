"""Prepare a fresh two-agent demo workspace from scratch.

End state after running this:

* ``~/.openclaw-alice/seed.txt`` — Alice's BIP-39-truncated 32-byte seed.
* ``~/.openclaw-bob/seed.txt`` — Bob's seed.
* ``~/.openclaw-issuer/issuer.key`` — 32-byte raw Ed25519 issuer key.
* ``~/.openclaw-bob/credentials/dev-vc.json`` — VC for Bob's app pubkey,
  signed by the fresh issuer.
* ``integration/configs/peers.yaml`` — peer directory with both agents'
  real ``pubkey_bin_hex`` (74-byte LibNaCLPK form).
* ``integration/configs/alice.yaml`` — host config (no VC store needed —
  she's only the issuer/host in the demo).
* ``integration/configs/bob.yaml`` — joiner config with the dev-vc loaded.

Idempotent: re-running re-uses existing seeds; only the issuer keypair,
peers.yaml, and the VC are re-derived (so peers.yaml stays in sync with
whatever pubkeys come out of the seeds).

Run::

    python -m integration.mcp_server.setup_demo
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import yaml

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from identity.agent_identity import AgentIdentity
from identity.seed import KeyfileSeedSource
from integration.mcp_server.vc_loader import dump_credential_to_json
from trust.formats.toy import ToyEd25519Format


REPO_ROOT = Path(__file__).resolve().parents[2]


def _agent_pubkeys(seed_path: Path, network: str) -> dict[str, str]:
    seed = KeyfileSeedSource(seed_path).load()
    ident = AgentIdentity.from_seed(seed, network=network)
    return {
        "agent_id": str(ident.agent_id),
        "pubkey_bin_hex": ident.ipv8.pubkey.hex(),
        "app_pubkey_hex": ident.app.pubkey.hex(),
        "wallet_pubkey_hex": ident.wallet.pubkey.hex(),
    }


def _ensure_issuer_key(path: Path) -> bytes:
    """Mint a fresh issuer key if missing; otherwise reuse. Return raw 32 bytes."""
    if path.exists():
        priv = path.read_bytes()
        if len(priv) == 32:
            return priv
        print(f"warning: {path} is the wrong length; regenerating", file=sys.stderr)

    sk = Ed25519PrivateKey.generate()
    priv = sk.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(priv)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return priv


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m integration.mcp_server.setup_demo",
        description="Prepare a clean two-agent demo workspace.",
    )
    parser.add_argument(
        "--alice-seed", type=Path,
        default=Path("~/.openclaw-alice/seed.txt").expanduser(),
    )
    parser.add_argument(
        "--bob-seed", type=Path,
        default=Path("~/.openclaw-bob/seed.txt").expanduser(),
    )
    parser.add_argument(
        "--issuer-key", type=Path,
        default=Path("~/.openclaw-issuer/issuer.key").expanduser(),
    )
    parser.add_argument(
        "--bob-vc-out", type=Path,
        default=Path("~/.openclaw-bob/credentials/dev-vc.json").expanduser(),
    )
    parser.add_argument(
        "--peers-out", type=Path,
        default=REPO_ROOT / "integration" / "configs" / "peers.yaml",
    )
    parser.add_argument(
        "--alice-port", type=int, default=9091,
        help="Alice's IPv8 UDP port for the peers.yaml entry.",
    )
    parser.add_argument(
        "--bob-port", type=int, default=9092,
        help="Bob's IPv8 UDP port for the peers.yaml entry.",
    )
    parser.add_argument("--network", default="TESTNET")
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    print("== deriving Alice's identity ==", file=sys.stderr)
    alice = _agent_pubkeys(args.alice_seed, args.network)
    print(f"  agent_id={alice['agent_id']}", file=sys.stderr)
    print(f"  app_pubkey_hex={alice['app_pubkey_hex']}", file=sys.stderr)

    print("== deriving Bob's identity ==", file=sys.stderr)
    bob = _agent_pubkeys(args.bob_seed, args.network)
    print(f"  agent_id={bob['agent_id']}", file=sys.stderr)
    print(f"  app_pubkey_hex={bob['app_pubkey_hex']}", file=sys.stderr)

    print("== writing peers.yaml ==", file=sys.stderr)
    peers_doc = {
        "peers": {
            "alice": {
                "agent_id": alice["agent_id"],
                "pubkey_bin_hex": alice["pubkey_bin_hex"],
                "ip": "127.0.0.1",
                "ipv8_port": args.alice_port,
            },
            "bob": {
                "agent_id": bob["agent_id"],
                "pubkey_bin_hex": bob["pubkey_bin_hex"],
                "ip": "127.0.0.1",
                "ipv8_port": args.bob_port,
            },
        }
    }
    args.peers_out.parent.mkdir(parents=True, exist_ok=True)
    args.peers_out.write_text(yaml.safe_dump(peers_doc, sort_keys=False), encoding="utf-8")
    print(f"  → {args.peers_out}", file=sys.stderr)

    print("== ensuring issuer keypair ==", file=sys.stderr)
    issuer_priv = _ensure_issuer_key(args.issuer_key)
    issuer_pub = (
        Ed25519PrivateKey.from_private_bytes(issuer_priv)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )
    print(f"  issuer_pubkey_hex={issuer_pub.hex()}", file=sys.stderr)

    print("== issuing dev-vc for Bob ==", file=sys.stderr)
    fmt = ToyEd25519Format()
    bob_subject = bytes.fromhex(bob["app_pubkey_hex"])
    credential = fmt.issue(
        issuer_pubkey=issuer_pub,
        subject_pubkey=bob_subject,
        claims={"role": "agent", "name": "bob"},
        signing_key=issuer_priv,
    )
    dump_credential_to_json(credential, args.bob_vc_out)
    print(f"  → {args.bob_vc_out}", file=sys.stderr)

    # Print the issuer pubkey to stdout so demo drivers can capture it.
    print(issuer_pub.hex())
    return 0


if __name__ == "__main__":
    sys.exit(main())
