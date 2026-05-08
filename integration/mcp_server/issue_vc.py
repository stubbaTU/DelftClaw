"""Offline VC issuer + agent introspection CLI.

Two subcommands:

* ``derive-pubkeys`` — given a seed file, print every pubkey an agent will
  use. Run for each agent before populating ``peers.yaml`` so the directory
  contains correct ``pubkey_bin_hex`` and ``agent_id`` values.

* ``issue`` — issue a toy Ed25519 Verifiable Credential. Either reuse an
  existing 32-byte raw issuer key file, or generate a new one with
  ``--new-issuer-out``. Writes the credential as JSON readable by
  :func:`vc_loader.load_credential_from_json`.

Examples
--------
::

    # 1. Derive Alice's and Bob's pubkeys (seed files auto-create on first
    #    boot; run once per agent to populate peers.yaml).
    python -m integration.mcp_server.issue_vc derive-pubkeys \\
        ~/.openclaw-alice/seed.txt
    python -m integration.mcp_server.issue_vc derive-pubkeys \\
        ~/.openclaw-bob/seed.txt

    # 2. Mint a fresh issuer keypair, issue a VC binding Bob's app pubkey to
    #    role=agent, and save the credential JSON for Bob's vc_store.
    python -m integration.mcp_server.issue_vc issue \\
        --subject-app-pubkey-hex <bob's app_pubkey_hex from step 1> \\
        --claims '{"role": "agent"}' \\
        --new-issuer-out ~/.openclaw-issuer/issuer.key \\
        --output ~/.openclaw-bob/credentials/dev-vc.json

    # 3. Reuse the same issuer to issue another VC for Alice:
    python -m integration.mcp_server.issue_vc issue \\
        --subject-app-pubkey-hex <alice's app_pubkey_hex> \\
        --claims '{"role": "issuer"}' \\
        --issuer-key ~/.openclaw-issuer/issuer.key \\
        --output ~/.openclaw-alice/credentials/dev-vc.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from identity.agent_identity import AgentIdentity
from identity.seed import KeyfileSeedSource
from integration.mcp_server.vc_loader import dump_credential_to_json
from trust.formats.toy import ToyEd25519Format


def _cmd_derive_pubkeys(args: argparse.Namespace) -> int:
    seed = KeyfileSeedSource(args.seed_file).load()
    ident = AgentIdentity.from_seed(seed, network=args.network)

    info = {
        "seed_file": str(Path(args.seed_file).expanduser()),
        "network": ident.network,
        "agent_id": str(ident.agent_id),
        "ipv8_pubkey_bin_hex": ident.ipv8.pubkey.hex(),
        "ipv8_raw_verify_key_hex": ident.ipv8.raw_pubkey.hex(),
        "app_pubkey_hex": ident.app.pubkey.hex(),
        "wallet_pubkey_hex": ident.wallet.pubkey.hex(),
    }

    if args.format == "json":
        print(json.dumps(info, indent=2))
    else:
        # Human-readable, plus a peers.yaml snippet ready to paste.
        for key, value in info.items():
            print(f"{key}: {value}")
        print()
        print("# peers.yaml entry:")
        alias = args.alias or "TODO_alias"
        print(f"  {alias}:")
        print(f"    agent_id: {info['agent_id']}")
        print(f"    pubkey_bin_hex: {info['ipv8_pubkey_bin_hex']}")
        print(f"    ip: 127.0.0.1")
        print(f"    ipv8_port: TODO_port")
    return 0


def _cmd_issue(args: argparse.Namespace) -> int:
    # Resolve issuer private key.
    if args.new_issuer_out and args.issuer_key:
        print("error: --new-issuer-out and --issuer-key are mutually exclusive", file=sys.stderr)
        return 2
    if args.new_issuer_out:
        sk = Ed25519PrivateKey.generate()
        priv = sk.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        out_path = Path(args.new_issuer_out).expanduser()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(priv)
        # Restrict to the user (best-effort; ignored on filesystems that
        # don't honour mode bits).
        try:
            os.chmod(out_path, 0o600)
        except OSError:
            pass
        print(f"issuer_keypair_path: {out_path}", file=sys.stderr)
        issuer_priv = priv
    elif args.issuer_key:
        issuer_priv = Path(args.issuer_key).expanduser().read_bytes()
        if len(issuer_priv) != 32:
            print(
                f"error: --issuer-key must be exactly 32 raw Ed25519 bytes, "
                f"got {len(issuer_priv)}",
                file=sys.stderr,
            )
            return 2
    else:
        print(
            "error: provide --new-issuer-out (mint) or --issuer-key (reuse)",
            file=sys.stderr,
        )
        return 2

    issuer_pub = (
        Ed25519PrivateKey.from_private_bytes(issuer_priv)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )

    subject_pubkey = bytes.fromhex(args.subject_app_pubkey_hex)
    if len(subject_pubkey) != 32:
        print(
            f"error: --subject-app-pubkey-hex must decode to 32 bytes, "
            f"got {len(subject_pubkey)}",
            file=sys.stderr,
        )
        return 2

    claims = json.loads(args.claims)
    if not isinstance(claims, dict):
        print("error: --claims must be a JSON object", file=sys.stderr)
        return 2

    fmt = ToyEd25519Format()
    credential = fmt.issue(
        issuer_pubkey=issuer_pub,
        subject_pubkey=subject_pubkey,
        claims=claims,
        signing_key=issuer_priv,
    )
    out = Path(args.output).expanduser()
    dump_credential_to_json(credential, out)

    print(f"issued: {out}", file=sys.stderr)
    print(f"issuer_pubkey_hex: {issuer_pub.hex()}")
    print(f"subject_pubkey_hex: {subject_pubkey.hex()}")
    print(f"format_id: {credential.format_id}")
    print(f"claims: {json.dumps(claims, sort_keys=True)}")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m integration.mcp_server.issue_vc",
        description="Offline VC issuer + agent pubkey introspection.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_derive = sub.add_parser(
        "derive-pubkeys",
        help="Derive an agent's IPv8 / app / wallet pubkeys from a seed file.",
    )
    p_derive.add_argument("seed_file", type=str, help="Path to the seed file (KeyfileSeedSource).")
    p_derive.add_argument("--network", default="TESTNET")
    p_derive.add_argument(
        "--format", choices=("text", "json"), default="text",
        help="Output format. 'text' includes a paste-able peers.yaml snippet.",
    )
    p_derive.add_argument(
        "--alias", default=None,
        help="Optional alias for the peers.yaml snippet (defaults to TODO_alias).",
    )
    p_derive.set_defaults(func=_cmd_derive_pubkeys)

    p_issue = sub.add_parser("issue", help="Issue a toy VC.")
    p_issue.add_argument("--subject-app-pubkey-hex", required=True,
                         help="32-byte hex of the credential subject's AppSigningKey pubkey.")
    p_issue.add_argument("--claims", required=True,
                         help='JSON object of claims, e.g. \'{"role": "agent"}\'.')
    p_issue.add_argument("--output", required=True,
                         help="Path to write the credential JSON.")
    grp = p_issue.add_mutually_exclusive_group(required=True)
    grp.add_argument("--new-issuer-out",
                     help="Generate a fresh issuer keypair and save the 32-byte private key here.")
    grp.add_argument("--issuer-key",
                     help="Reuse an existing 32-byte raw issuer private-key file.")
    p_issue.set_defaults(func=_cmd_issue)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
