"""JSON ↔ :class:`shared.credentials.Credential` round-trip.

Credentials are issued offline (see :mod:`integration.mcp_server.issue_vc`)
and saved to disk as JSON files. This module loads them back into
:class:`Credential` instances at boot time.

JSON shape (frozen)::

    {
      "format_id": "toy-ed25519",
      "issuer_pubkey_hex": "<32 bytes hex>",
      "subject_pubkey_hex": "<32 bytes hex>",
      "claims": {"role": "agent"},
      "raw_hex": "<format-specific signed bytes, hex>"
    }

The ``raw`` field is the load-bearing part: format plugins (e.g.
:class:`trust.formats.toy.ToyEd25519Format`) re-parse it on every verify.
The other fields are convenience metadata that mirror the
:class:`Credential` dataclass.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from shared.credentials import Credential


def load_credential_from_json(path: str | Path) -> Credential:
    """Read a credential JSON file from disk and return a :class:`Credential`.

    Raises :class:`FileNotFoundError`, :class:`json.JSONDecodeError`, or
    :class:`ValueError` for missing/bad fields.
    """
    p = Path(path).expanduser()
    text = p.read_text(encoding="utf-8")
    data: dict[str, Any] = json.loads(text)

    try:
        format_id = str(data["format_id"])
        issuer_pubkey_hex = str(data["issuer_pubkey_hex"])
        subject_pubkey_hex = str(data["subject_pubkey_hex"])
        claims = data.get("claims", {})
        raw_hex = str(data["raw_hex"])
    except KeyError as exc:
        raise ValueError(f"{p}: credential JSON missing required key {exc}") from exc

    if not isinstance(claims, dict):
        raise ValueError(f"{p}: claims must be an object, got {type(claims).__name__}")

    try:
        issuer_pubkey = bytes.fromhex(issuer_pubkey_hex)
        subject_pubkey = bytes.fromhex(subject_pubkey_hex)
        raw = bytes.fromhex(raw_hex)
    except ValueError as exc:
        raise ValueError(f"{p}: hex decode failed: {exc}") from exc

    return Credential(
        format_id=format_id,
        issuer_pubkey=issuer_pubkey,
        subject_pubkey=subject_pubkey,
        claims=claims,
        raw=raw,
    )


def dump_credential_to_json(credential: Credential, path: str | Path) -> None:
    """Serialise a :class:`Credential` to a JSON file on disk.

    Used by :mod:`integration.mcp_server.issue_vc` to persist freshly
    issued VCs in the format ``vc_loader.load_credential_from_json`` reads.
    """
    p = Path(path).expanduser()
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "format_id": credential.format_id,
        "issuer_pubkey_hex": credential.issuer_pubkey.hex(),
        "subject_pubkey_hex": credential.subject_pubkey.hex(),
        "claims": dict(credential.claims),
        "raw_hex": credential.raw.hex(),
    }
    p.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


__all__ = ["load_credential_from_json", "dump_credential_to_json"]
