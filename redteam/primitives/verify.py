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
    * Every entry must declare an explicit ``kind`` of either ``"self"``
      or ``"witness"``; missing or unknown values fail verification.
      Witness entries get the same four subject-side checks the producer
      runs at write time (decode pubkey/sig, identity binding, claim
      consistency, Ed25519 verify of subject_signature over canonical
      subject_claim) — independently re-implemented here so a producer
      bug surfaces as a verification failure.
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


def _canonical_payload_bytes(payload: dict) -> bytes:
    """Return canonical JSON bytes of ``payload`` verbatim (no field stripping).

    Used for hashing arbitrary payloads (claim envelope, details, evidence)
    where there is no entry_hash/signature to pop.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _recompute_entry_hash(entry: dict) -> str:
    """Recompute the SHA-256 hex digest of an entry's canonical bytes."""
    return hashlib.sha256(_canonical_bytes(entry)).hexdigest()


def _check_chain(index: int, entry: dict, prev_hash: str) -> list[str]:
    """Verify ``previous_hash`` link and recomputed ``entry_hash``."""
    errors: list[str] = []

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
    return errors


def _check_signature(
    index: int,
    entry: dict,
    pubkey_bytes: bytes | None,
    sig_bytes: bytes | None,
) -> list[str]:
    """Verify the Ed25519 signature against the canonical bytes.

    If either field failed to decode, ``_decode_pubkey_and_sig`` already
    reported the reason — skip the verify rather than double-report.
    """
    if pubkey_bytes is None or sig_bytes is None:
        return []
    try:
        Ed25519PublicKey.from_public_bytes(pubkey_bytes).verify(
            sig_bytes, _canonical_bytes(entry)
        )
    except InvalidSignature:
        return [
            f"entry {index}: signature verification failed "
            f"(invalid Ed25519 signature for reporter_pubkey)"
        ]
    except Exception as exc:  # pragma: no cover - defensive
        return [f"entry {index}: signature verification error: {exc}"]
    return []


def _check_identity_binding(
    index: int, entry: dict, pubkey_bytes: bytes | None, network: str
) -> list[str]:
    """Verify ``SHA256(reporter_pubkey || network) == reporter_id``."""
    if pubkey_bytes is None:
        return []
    expected_id = hashlib.sha256(
        pubkey_bytes + network.encode("utf-8")
    ).hexdigest()
    actual_id = entry.get("reporter_id")
    if actual_id != expected_id:
        return [
            f"entry {index}: identity binding mismatch "
            f"(reporter_id does not derive from reporter_pubkey | {network})"
        ]
    return []


def _decode_hex_field(
    entry: dict, name: str, *, expected_len: int, index: int, errors: list[str]
) -> bytes | None:
    """Decode a hex-encoded fixed-length field, appending to ``errors``."""
    raw = entry.get(name)
    if not isinstance(raw, str) or not raw:
        errors.append(f"entry {index}: missing {name}")
        return None
    try:
        decoded = bytes.fromhex(raw)
    except ValueError:
        errors.append(f"entry {index}: malformed {name} hex (cannot decode)")
        return None
    if len(decoded) != expected_len:
        errors.append(
            f"entry {index}: {name} is {len(decoded)} bytes, "
            f"expected {expected_len}"
        )
        return None
    return decoded


def _decode_pubkey_and_sig(
    index: int, entry: dict
) -> tuple[bytes | None, bytes | None, list[str]]:
    """Return ``(pubkey_bytes_or_None, sig_bytes_or_None, errors)``.

    A bytes value is returned only when the field decoded cleanly and has
    the expected length; otherwise the slot is None and the corresponding
    error is in the third element.
    """
    errors: list[str] = []
    pubkey_bytes = _decode_hex_field(
        entry, "reporter_pubkey", expected_len=32, index=index, errors=errors
    )
    sig_bytes = _decode_hex_field(
        entry, "signature", expected_len=64, index=index, errors=errors
    )
    return pubkey_bytes, sig_bytes, errors


def _decode_subject_pubkey_and_sig(
    index: int, entry: dict
) -> tuple[bytes | None, bytes | None, list[str]]:
    """Verifier-side: decode ``subject_pubkey``/``subject_signature`` off entry."""
    errors: list[str] = []
    pubkey_bytes = _decode_hex_field(
        entry, "subject_pubkey", expected_len=32, index=index, errors=errors
    )
    sig_bytes = _decode_hex_field(
        entry, "subject_signature", expected_len=64, index=index, errors=errors
    )
    return pubkey_bytes, sig_bytes, errors


def _check_subject_identity_binding(
    pubkey_bytes: bytes | None, network: str, subject_id
) -> list[str]:
    """Verify ``SHA256(subject_pubkey || network) == subject_id``."""
    if pubkey_bytes is None:
        return []
    expected = hashlib.sha256(
        pubkey_bytes + network.encode("utf-8")
    ).hexdigest()
    if subject_id != expected:
        return [
            "subject identity binding mismatch "
            f"(subject_id does not derive from subject_pubkey | {network})"
        ]
    return []


def _check_claim_consistency(
    subject_claim, *, subject_id, action, details_hash
) -> list[str]:
    """Verify the claim envelope against the entry's bound fields + schema."""
    errors: list[str] = []
    if not isinstance(subject_claim, dict):
        return ["subject_claim missing or not an object"]
    if subject_claim.get("kind") != "claim":
        errors.append(
            "subject_claim kind is not 'claim' "
            f"(got {subject_claim.get('kind')!r})"
        )
    if not isinstance(subject_claim.get("version"), int):
        errors.append("subject_claim version is not an integer")
    nonce = subject_claim.get("nonce")
    if not isinstance(nonce, str):
        errors.append("subject_claim nonce is missing or not a string")
    else:
        try:
            nonce_bytes = bytes.fromhex(nonce)
        except ValueError:
            errors.append("subject_claim nonce is not a hex string")
        else:
            if len(nonce_bytes) != 16:
                errors.append(
                    "subject_claim nonce length mismatch (expected 16 bytes)"
                )
    claim_timestamp = subject_claim.get("claim_timestamp")
    if not isinstance(claim_timestamp, str) or not claim_timestamp:
        errors.append("subject_claim claim_timestamp missing or not a string")
    if subject_claim.get("subject_id") != subject_id:
        errors.append("subject_claim.subject_id does not match entry.subject_id")
    if subject_claim.get("action") != action:
        errors.append("subject_claim.action does not match entry.action")
    if subject_claim.get("details_hash") != details_hash:
        errors.append("subject_claim.details_hash does not match hash(entry.details)")
    return errors


def _check_subject_signature(
    pubkey_bytes: bytes | None,
    sig_bytes: bytes | None,
    subject_claim,
) -> list[str]:
    """Ed25519 verify ``subject_signature`` over canonical(subject_claim)."""
    if pubkey_bytes is None or sig_bytes is None:
        return []
    if not isinstance(subject_claim, dict):
        return ["subject_claim missing or not an object"]
    try:
        Ed25519PublicKey.from_public_bytes(pubkey_bytes).verify(
            sig_bytes, _canonical_payload_bytes(subject_claim)
        )
    except InvalidSignature:
        return ["subject signature verification failed"]
    except Exception as exc:  # pragma: no cover - defensive
        return [f"subject signature verification error: {exc}"]
    return []


def _verify_witness_fields(
    index: int, entry: dict, network: str
) -> list[str]:
    """Run the four subject-side checks on a witness entry."""
    errors: list[str] = []
    if "subject_claim" not in entry:
        errors.append(f"entry {index}: missing subject_claim")
    if "subject_pubkey" not in entry:
        errors.append(f"entry {index}: missing subject_pubkey")
    if "subject_signature" not in entry:
        errors.append(f"entry {index}: missing subject_signature")
    if errors:
        return errors

    sub_pk, sub_sig, decode_errors = _decode_subject_pubkey_and_sig(index, entry)
    errors.extend(decode_errors)

    binding_errors = _check_subject_identity_binding(
        sub_pk, network, entry.get("subject_id")
    )
    errors.extend(f"entry {index}: {e}" for e in binding_errors)

    consistency_errors = _check_claim_consistency(
        entry.get("subject_claim"),
        subject_id=entry.get("subject_id"),
        action=entry.get("action"),
        details_hash=entry.get("details_hash"),
    )
    errors.extend(f"entry {index}: {e}" for e in consistency_errors)

    sig_errors = _check_subject_signature(
        sub_pk, sub_sig, entry.get("subject_claim")
    )
    errors.extend(f"entry {index}: {e}" for e in sig_errors)

    return errors


def _verify_entry(
    index: int, entry: dict, prev_hash: str, network: str
) -> list[str]:
    """Run the integrity checks for a single entry.

    Same three reporter-side checks (chain / signature / binding) plus a
    ``kind`` branch: ``self`` entries must not carry subject-* fields
    (downgrade defense); ``witness`` entries get the four subject-side
    checks (decode, binding, claim consistency, Ed25519 verify); any
    other ``kind`` is rejected.

    Helper names mirror :class:`SignedAppendOnlyLog` so a reviewer can
    diff the two at a glance — the producer-side implementation is
    independent (no shared imports).
    """
    errors: list[str] = []
    errors.extend(_check_chain(index, entry, prev_hash))
    pubkey_bytes, sig_bytes, decode_errors = _decode_pubkey_and_sig(index, entry)
    errors.extend(decode_errors)
    errors.extend(_check_signature(index, entry, pubkey_bytes, sig_bytes))
    errors.extend(_check_identity_binding(index, entry, pubkey_bytes, network))

    kind = entry.get("kind")
    if kind == "self":
        for forbidden in ("subject_pubkey", "subject_claim", "subject_signature"):
            if forbidden in entry:
                errors.append(
                    f"entry {index}: self entry must not carry {forbidden} "
                    "(downgrade defense)"
                )
    elif kind == "witness":
        errors.extend(_verify_witness_fields(index, entry, network))
    else:
        errors.append(
            f"entry {index}: missing or unknown kind {kind!r} "
            "(expected 'self' or 'witness')"
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
