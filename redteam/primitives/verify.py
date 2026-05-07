"""Standalone signed-log verifier CLI.

This module is an *independent* re-implementation of the canonical-bytes
encoding and entry-hash recomputation used by ``SignedAppendOnlyLog``.
It MUST NOT import from ``redteam.primitives.signed_log`` so that any
producer-side bug surfaces here as a verification failure rather than
silently propagating.

Usage:
    python -m redteam.primitives.verify --log <path> [--network MAINNET]

Exit codes:
    0 — all entries verified (or empty log)
    1 — at least one entry failed any of the three checks (chain /
        signature / identity binding) or a JSON line was malformed
    2 — file/IO error (missing file, unreadable file, directory, binary)

Behavior notes:
    * Scanning stops at the first malformed JSON line; subsequent entries
      are not checked. The chain is unrecoverable past a malformed line,
      so continuing past it would emit confusing cascading errors.
    * After an ``entry_hash`` mismatch on a single entry, the verifier
      advances the chain using the *recomputed* entry_hash (the value
      that *would* have been correct given the entry's contents). This
      keeps downstream chain checks honest: a legitimate downstream
      entry whose ``previous_hash`` was wired correctly to the now-
      tampered entry will still validate, while genuinely tampered
      downstream entries will still fire chain errors. Per-entry
      integrity errors (hash / signature / binding) do *not* abort the
      scan — every entry is independently checked and reported.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def _canonical_bytes(entry: dict) -> bytes:
    """Return canonical JSON bytes of ``entry`` excluding signature/entry_hash."""
    hashable = dict(entry)
    hashable.pop("entry_hash", None)
    hashable.pop("signature", None)
    return json.dumps(hashable, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _recompute_entry_hash(entry: dict) -> str:
    """Recompute the SHA-256 hex digest of an entry's canonical bytes."""
    return hashlib.sha256(_canonical_bytes(entry)).hexdigest()


def _verify_entry(
    index: int, entry: dict, prev_hash: str, network: str
) -> list[str]:
    """Run the three integrity checks for a single entry.

    Returns a list of human-readable error strings (empty if everything
    passed).
    """
    errors: list[str] = []

    # ---- Check 1: Hash chain ------------------------------------------------
    actual_prev = entry.get("previous_hash")
    if actual_prev != prev_hash:
        errors.append(
            f"entry {index}: previous_hash mismatch "
            f"(chain broken; expected {prev_hash!r}, got {actual_prev!r})"
        )

    expected_hash = _recompute_entry_hash(entry)
    stored_hash = entry.get("entry_hash")
    if stored_hash != expected_hash:
        errors.append(
            f"entry {index}: entry_hash mismatch "
            f"(recomputed hash does not match stored entry_hash)"
        )

    # ---- Check 2: Signature -------------------------------------------------
    pubkey_bytes: bytes | None = None
    sig_bytes: bytes | None = None
    sig_decode_failed = False

    pubkey_hex = entry.get("reporter_pubkey")
    sig_hex = entry.get("signature")

    if not isinstance(pubkey_hex, str) or not pubkey_hex:
        errors.append(f"entry {index}: missing reporter_pubkey")
        sig_decode_failed = True
    else:
        try:
            pubkey_bytes = bytes.fromhex(pubkey_hex)
        except ValueError:
            errors.append(
                f"entry {index}: malformed reporter_pubkey hex (cannot decode)"
            )
            sig_decode_failed = True
        else:
            if len(pubkey_bytes) != 32:
                errors.append(
                    f"entry {index}: reporter_pubkey is {len(pubkey_bytes)} bytes, "
                    f"expected 32"
                )
                sig_decode_failed = True

    if not isinstance(sig_hex, str) or not sig_hex:
        errors.append(f"entry {index}: missing signature")
        sig_decode_failed = True
    else:
        try:
            sig_bytes = bytes.fromhex(sig_hex)
        except ValueError:
            errors.append(
                f"entry {index}: malformed signature hex (cannot decode)"
            )
            sig_decode_failed = True
        else:
            if len(sig_bytes) != 64:
                errors.append(
                    f"entry {index}: signature is {len(sig_bytes)} bytes, "
                    f"expected 64"
                )
                sig_decode_failed = True

    if not sig_decode_failed and pubkey_bytes is not None and sig_bytes is not None:
        try:
            verify_key = Ed25519PublicKey.from_public_bytes(pubkey_bytes)
            verify_key.verify(sig_bytes, _canonical_bytes(entry))
        except InvalidSignature:
            errors.append(
                f"entry {index}: signature verification failed "
                f"(invalid Ed25519 signature for reporter_pubkey)"
            )
        except Exception as exc:  # pragma: no cover - defensive
            errors.append(
                f"entry {index}: signature verification error: {exc}"
            )

    # ---- Check 3: Identity binding -----------------------------------------
    if pubkey_bytes is not None and len(pubkey_bytes) == 32:
        expected_id = hashlib.sha256(
            pubkey_bytes + network.encode("utf-8")
        ).hexdigest()
        actual_id = entry.get("reporter_id")
        if actual_id != expected_id:
            errors.append(
                f"entry {index}: identity binding mismatch "
                f"(reporter_id does not derive from reporter_pubkey | {network})"
            )

    return errors


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="redteam.primitives.verify",
        description=(
            "Independently verify a signed append-only log: hash chain, "
            "Ed25519 signatures, and reporter_id <-> reporter_pubkey binding. "
            "Scanning stops at the first malformed JSON line; subsequent "
            "entries are not checked."
        ),
    )
    parser.add_argument(
        "--log",
        required=True,
        help=(
            "Path to the signed append-only log file to verify. "
            "Scanning stops at the first malformed JSON line; subsequent "
            "entries are not checked."
        ),
    )
    parser.add_argument(
        "--network",
        default="MAINNET",
        help="Network name used for the identity-binding check "
        "(default: MAINNET).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    log_path = Path(args.log)
    if not log_path.exists():
        print(f"error: file not found: {log_path}", file=sys.stderr)
        return 2
    if log_path.is_dir():
        print(f"error: path is a directory: {log_path}", file=sys.stderr)
        return 2

    errors: list[str] = []
    prev_hash = "GENESIS"
    index = 0
    malformed_at_line: int | None = None

    # Stream the file line-by-line so multi-GB logs don't OOM.
    try:
        with log_path.open("r", encoding="utf-8") as handle:
            for line_no, raw in enumerate(handle, start=1):
                # Strip only the trailing newline (file might not end in \n).
                if raw.endswith("\r\n"):
                    line = raw[:-2]
                elif raw.endswith("\n"):
                    line = raw[:-1]
                else:
                    line = raw

                if line.startswith("===") or not line.strip():
                    continue
                index += 1
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError as exc:
                    errors.append(
                        f"entry {index}: malformed JSON on line {line_no} "
                        f"(parse/decode error: {exc.msg})"
                    )
                    malformed_at_line = line_no
                    # Chain is broken from this point; stop scanning.
                    break

                if not isinstance(entry, dict):
                    errors.append(
                        f"entry {index}: malformed JSON (expected object, got "
                        f"{type(entry).__name__})"
                    )
                    malformed_at_line = line_no
                    break

                entry_errors = _verify_entry(index, entry, prev_hash, args.network)
                errors.extend(entry_errors)
                # Advance the chain using the *recomputed* entry_hash. Even
                # when the stored entry_hash is wrong, downstream legitimate
                # entries were chained against what the correct value should
                # have been — so using the recomputed value here keeps the
                # chain check meaningful for downstream entries instead of
                # silently masking further tampering.
                prev_hash = _recompute_entry_hash(entry)
    except UnicodeDecodeError as exc:
        print(
            f"error: not a valid UTF-8 file: {log_path} ({exc.reason})",
            file=sys.stderr,
        )
        return 2
    except OSError as exc:
        print(f"error: cannot read file: {exc}", file=sys.stderr)
        return 2

    if errors:
        for err in errors:
            print(err)
        if malformed_at_line is not None:
            # Count remaining non-header, non-blank lines after the malformed
            # one for the forensic marker. We re-stream the file (cheap on
            # small, bounded for huge files since we only count lines after N).
            unverified = 0
            try:
                with log_path.open("r", encoding="utf-8") as handle:
                    for line_no, raw in enumerate(handle, start=1):
                        if line_no <= malformed_at_line:
                            continue
                        stripped = raw.rstrip("\r\n")
                        if stripped.startswith("===") or not stripped.strip():
                            continue
                        unverified += 1
            except (OSError, UnicodeDecodeError):
                unverified = 0
            print(
                f"Scan stopped at line {malformed_at_line} due to malformed "
                f"JSON; {unverified} subsequent lines were not verified."
            )
        return 1

    print(f"Verified {index} entries: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
