"""Signed append-only log: sign-then-chain wrapper around ``AppendOnlyLog``.

Each entry is signed with the local OpenClaw Ed25519 key before its
``entry_hash`` is computed. The override of ``_entry_hash`` excludes both
``entry_hash`` and ``signature`` from the digest input, so the chain hash
covers the entry contents *and* the signature once written. The reporter's
public key is embedded so any downstream verifier can re-check the
signature without out-of-band key distribution.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from identity.openclaw_identity import OpenClawIdentity
from security.subq2_accountability.append_log import AppendOnlyLog
from shared.logging import get_logger

_logger = get_logger(__name__)


def _canonical_bytes(payload: Any) -> bytes:
    """Return canonical JSON encoding (sorted keys, no whitespace) as bytes."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _stable_hash(payload: Any) -> str:
    """Return SHA-256 of canonical JSON of ``payload`` as hex."""
    return hashlib.sha256(_canonical_bytes(payload)).hexdigest()


class SignedAppendOnlyLog(AppendOnlyLog):
    """Append-only log whose entries are Ed25519-signed before chaining.

    The wrapper preserves the parent's v2 entry shape and chain semantics,
    but adds two fields per entry:

    * ``reporter_pubkey`` — hex-encoded Ed25519 verify key of the signer.
    * ``signature`` — hex-encoded Ed25519 signature over the canonical JSON
      of the entry *prior to* signing (i.e. the dict containing every other
      field except ``signature`` and ``entry_hash``).

    The override of :meth:`_entry_hash` pops ``signature`` in addition to
    ``entry_hash``, so the chain hash binds the signature into the chain.
    Plain :class:`AppendOnlyLog.verify_integrity` will reject these entries
    because its ``_entry_hash`` does not pop ``signature`` — that asymmetry
    is intentional and is documented by ``test_signed_log.py``.
    """

    def __init__(
        self,
        identity: OpenClawIdentity,
        log_path: "str | os.PathLike[str]",
    ) -> None:
        if identity is None:
            raise ValueError("identity must not be None")
        # Accept str or pathlib.Path (or any os.PathLike). Coerce to str so
        # downstream I/O sites work uniformly.
        try:
            coerced = os.fspath(log_path)
        except TypeError as exc:
            raise ValueError(
                "log_path must be a str or os.PathLike object"
            ) from exc
        if not isinstance(coerced, str) or not coerced:
            raise ValueError("log_path must be a non-empty string")
        super().__init__(log_path=coerced)
        self._identity = identity
        # Serialize concurrent appends so latest_hash + write are atomic.
        self._lock = threading.Lock()

    def append_event(
        self,
        reporter_id: str,
        subject_id: str,
        action: str,
        details: dict,
        severity: int = 0,
        evidence: dict | None = None,
    ) -> dict:
        """Append a single signed accountability event to the log."""
        # NOTE: This wrapper deliberately uses
        #   ``evidence if evidence is not None else {}``
        # rather than the parent's ``evidence or {}``. We want to preserve
        # an explicit empty dict from the caller (it's still falsy) so that
        # the signed canonical bytes match what the caller asked us to sign.
        evidence_payload = evidence if evidence is not None else {}

        with self._lock:
            timestamp = datetime.now(timezone.utc).isoformat()
            previous_hash = self.latest_hash()

            entry: dict[str, Any] = {
                "version": 2,
                "timestamp": timestamp,
                "reporter_id": reporter_id,
                "subject_id": subject_id,
                "action": action,
                "severity": severity,
                "details": details,
                "evidence": evidence_payload,
                "details_hash": _stable_hash(details),
                "evidence_hash": _stable_hash(evidence_payload),
                "previous_hash": previous_hash,
                "reporter_pubkey": self._identity.public_key.hex(),
            }

            # Sign the canonical JSON of the entry so far (no signature, no
            # entry_hash). Then attach the signature and finally compute the
            # chain hash, which covers the signature too via the override.
            canonical = _canonical_bytes(entry)
            entry["signature"] = self._identity.sign(canonical).hex()
            entry["entry_hash"] = self._entry_hash(entry)

            with open(self.log_path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry) + "\n")
                handle.flush()
                os.fsync(handle.fileno())

        _logger.debug(
            "signed_log.append",
            reporter_id=reporter_id,
            subject_id=subject_id,
            action=action,
            previous_hash=previous_hash,
            entry_hash=entry["entry_hash"],
        )
        return entry

    @staticmethod
    def _entry_hash(entry: dict) -> str:
        """Hash an entry while excluding both ``entry_hash`` and ``signature``.

        Excluding ``signature`` lets us attach the signature *before*
        computing the chain hash so the chain binds the signature, while
        still allowing a verifier to recompute the same digest deterministically.
        """
        hashable = dict(entry)
        hashable.pop("entry_hash", None)
        hashable.pop("signature", None)
        return hashlib.sha256(_canonical_bytes(hashable)).hexdigest()

    def verify_integrity(self) -> tuple[bool, list[str]]:
        """Verify chain, signatures, and identity binding in a single scan.

        Single-pass scan over the raw log file. For every JSON entry we run:

        1. Chain check — ``previous_hash`` matches the previous entry's
           ``entry_hash`` (or ``"GENESIS"`` for entry 1), AND the stored
           ``entry_hash`` matches what we recompute from the canonical
           bytes of the entry minus signature/entry_hash.
        2. Signature check — Ed25519 verify the stored ``signature``
           against ``reporter_pubkey`` over the canonical bytes.
        3. Identity binding check —
           ``SHA256(reporter_pubkey || network) == reporter_id``.

        Non-v2 entries are not silently skipped — they surface as errors.
        """
        errors: list[str] = []

        if not os.path.exists(self.log_path):
            return False, ["log file does not exist"]

        previous_hash = "GENESIS"
        network = self._identity.network
        index = 0

        with open(self.log_path, "r", encoding="utf-8") as handle:
            for raw in handle:
                if raw.startswith("===") or not raw.strip():
                    continue
                index += 1

                try:
                    entry = json.loads(raw)
                except json.JSONDecodeError:
                    errors.append(f"entry {index}: malformed JSON")
                    # Chain is broken from here; skip remaining checks for
                    # this entry but keep scanning so we surface every issue.
                    continue
                if not isinstance(entry, dict):
                    errors.append(f"entry {index}: malformed JSON (not an object)")
                    continue

                version = entry.get("version")
                if version != 2:
                    errors.append(
                        f"entry {index}: unsupported version {version!r}"
                    )
                    # Don't run downstream checks against an unknown shape.
                    previous_hash = entry.get("entry_hash", previous_hash)
                    continue

                # ---- Chain check ----------------------------------------
                actual_prev = entry.get("previous_hash")
                if actual_prev != previous_hash:
                    errors.append(
                        f"entry {index}: previous_hash mismatch "
                        f"(chain broken; expected {previous_hash!r}, "
                        f"got {actual_prev!r})"
                    )

                expected_entry_hash = self._entry_hash(entry)
                stored_entry_hash = entry.get("entry_hash")
                if stored_entry_hash != expected_entry_hash:
                    errors.append(
                        f"entry {index}: entry_hash mismatch "
                        f"(recomputed hash does not match stored entry_hash)"
                    )

                # ---- Signature check ------------------------------------
                pubkey_bytes, sig_bytes, sig_skip = self._decode_pubkey_and_sig(
                    entry, index, errors
                )
                if not sig_skip and pubkey_bytes is not None and sig_bytes is not None:
                    try:
                        Ed25519PublicKey.from_public_bytes(pubkey_bytes).verify(
                            sig_bytes, _canonical_bytes(self._signed_payload(entry))
                        )
                    except InvalidSignature:
                        errors.append(
                            f"entry {index}: signature verification failed"
                        )
                    except (ValueError, TypeError) as exc:
                        # Malformed key material caught by cryptography.
                        errors.append(
                            f"entry {index}: signature verification error: {exc}"
                        )

                # ---- Identity binding check -----------------------------
                if pubkey_bytes is not None and len(pubkey_bytes) == 32:
                    expected_id = hashlib.sha256(
                        pubkey_bytes + network.encode("utf-8")
                    ).hexdigest()
                    actual_id = entry.get("reporter_id")
                    if actual_id != expected_id:
                        errors.append(
                            f"entry {index}: identity binding mismatch "
                            f"(reporter_id does not derive from reporter_pubkey | "
                            f"{network})"
                        )

                # Advance using the *stored* entry_hash so we still detect
                # downstream chain breaks even if this entry mismatched.
                previous_hash = entry.get("entry_hash", previous_hash)

        return len(errors) == 0, errors

    @staticmethod
    def _signed_payload(entry: dict) -> dict:
        """Return the dict that was canonicalized prior to signing."""
        signed = dict(entry)
        signed.pop("entry_hash", None)
        signed.pop("signature", None)
        return signed

    @staticmethod
    def _decode_pubkey_and_sig(
        entry: dict, index: int, errors: list[str]
    ) -> tuple[bytes | None, bytes | None, bool]:
        """Decode and length-check ``reporter_pubkey`` and ``signature``.

        Returns ``(pubkey_bytes_or_None, sig_bytes_or_None, skip_verify)``.
        ``skip_verify`` is True when at least one of the fields is missing
        or otherwise unusable, signalling the caller to bypass the actual
        Ed25519 verification step (the relevant errors will already be in
        ``errors``).
        """
        skip = False
        pubkey_bytes: bytes | None = None
        sig_bytes: bytes | None = None

        try:
            pubkey_hex = entry["reporter_pubkey"]
        except KeyError:
            errors.append(f"entry {index}: missing reporter_pubkey")
            skip = True
            pubkey_hex = None

        if pubkey_hex is not None:
            if not isinstance(pubkey_hex, str) or not pubkey_hex:
                errors.append(f"entry {index}: missing reporter_pubkey")
                skip = True
            else:
                try:
                    pubkey_bytes = bytes.fromhex(pubkey_hex)
                except ValueError:
                    errors.append(
                        f"entry {index}: malformed reporter_pubkey hex"
                    )
                    skip = True
                else:
                    if len(pubkey_bytes) != 32:
                        errors.append(
                            f"entry {index}: reporter_pubkey is "
                            f"{len(pubkey_bytes)} bytes, expected 32 "
                            f"(length mismatch)"
                        )
                        skip = True

        try:
            sig_hex = entry["signature"]
        except KeyError:
            errors.append(f"entry {index}: missing signature")
            skip = True
            sig_hex = None

        if sig_hex is not None:
            if not isinstance(sig_hex, str) or not sig_hex:
                errors.append(f"entry {index}: missing signature")
                skip = True
            else:
                try:
                    sig_bytes = bytes.fromhex(sig_hex)
                except ValueError:
                    errors.append(
                        f"entry {index}: malformed signature hex"
                    )
                    skip = True
                else:
                    if len(sig_bytes) != 64:
                        errors.append(
                            f"entry {index}: signature is "
                            f"{len(sig_bytes)} bytes, expected 64 "
                            f"(length mismatch)"
                        )
                        skip = True

        return pubkey_bytes, sig_bytes, skip
