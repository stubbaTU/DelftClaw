from __future__ import annotations

from pathlib import Path

from identity.openclaw_identity import OpenClawIdentity
from redteam.primitives.signed_log import SignedAppendOnlyLog
from security.accountability_layer.append_log import AppendOnlyLog


def open_accountability_log(
    log_path: str | Path,
    *,
    network: str = "REGTEST",
    key_path: str | Path | None = None,
) -> SignedAppendOnlyLog | AppendOnlyLog:
    """Open signed DelftClaw logs, with fallback for old unsigned logs."""

    path = Path(log_path)
    if _looks_signed(path):
        identity = OpenClawIdentity(network=network, key_path=key_path)
        return SignedAppendOnlyLog(identity, log_path=path)
    return AppendOnlyLog(str(path))


def _looks_signed(path: Path) -> bool:
    if not path.exists():
        return True
    with path.open("r", encoding="utf-8") as handle:
        for raw in handle:
            if raw.startswith("===") or not raw.strip():
                continue
            return '"signature"' in raw and '"reporter_pubkey"' in raw
    return True
