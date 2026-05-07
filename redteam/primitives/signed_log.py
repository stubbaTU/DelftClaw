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
        # downstream I/O sites work uniformly. ``os.fspath`` may also return
        # bytes — reject that explicitly so log_path stays str everywhere.
        try:
            coerced = os.fspath(log_path)
        except TypeError as exc:
            raise ValueError(
                "log_path must be a str or os.PathLike object"
            ) from exc
        if not isinstance(coerced, str):
            raise ValueError("log_path must resolve to a string, not bytes")
        if not coerced:
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
        with self._lock:
            entry = self._build_entry(
                reporter_id=reporter_id,
                subject_id=subject_id,
                action=action,
                details=details,
                severity=severity,
                evidence=evidence,
            )
            self._persist(entry)

        _logger.debug(
            "signed_log.append",
            reporter_id=reporter_id,
            subject_id=subject_id,
            action=action,
            previous_hash=entry["previous_hash"],
            entry_hash=entry["entry_hash"],
        )
        return entry

    def _build_entry(
        self,
        reporter_id: str,
        subject_id: str,
        action: str,
        details: dict,
        severity: int,
        evidence: dict | None,
    ) -> dict[str, Any]:
        """Assemble, sign, and chain-hash a complete entry.

        Caller must hold ``self._lock`` so ``latest_hash()`` and the
        eventual append happen atomically.
        """
        # Deliberately ``evidence is not None else {}`` rather than
        # ``evidence or {}`` — we want to preserve an explicit empty dict
        # from the caller so the signed canonical bytes match exactly
        # what the caller asked us to sign.
        evidence_payload = evidence if evidence is not None else {}

        entry: dict[str, Any] = {
            "version": 2,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "reporter_id": reporter_id,
            "subject_id": subject_id,
            "action": action,
            "severity": severity,
            "details": details,
            "evidence": evidence_payload,
            "details_hash": _stable_hash(details),
            "evidence_hash": _stable_hash(evidence_payload),
            "previous_hash": self.latest_hash(),
            "reporter_pubkey": self._identity.public_key.hex(),
        }

        # Sign the canonical JSON of the entry so far (no signature, no
        # entry_hash). Then attach the signature and finally compute the
        # chain hash, which covers the signature too via the override.
        entry["signature"] = self._identity.sign(_canonical_bytes(entry)).hex()
        entry["entry_hash"] = self._entry_hash(entry)
        return entry

    def _persist(self, entry: dict[str, Any]) -> None:
        """Append a fully-formed entry to the log file with an fsync."""
        with open(self.log_path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry) + "\n")
            handle.flush()
            os.fsync(handle.fileno())

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

        Single-pass scan over the raw log file. For every JSON entry we run
        three independent checks via the helpers below:

        1. :meth:`_check_chain` — ``previous_hash`` matches the previous
           entry's ``entry_hash`` (or ``"GENESIS"`` for entry 1), AND the
           stored ``entry_hash`` matches what we recompute.
        2. :meth:`_check_signature` — Ed25519 verify the stored signature
           against ``reporter_pubkey``.
        3. :meth:`_check_identity_binding` —
           ``SHA256(reporter_pubkey || network) == reporter_id``.

        The same three-check structure is mirrored in
        ``redteam.primitives.verify._verify_entry`` (different file, no
        shared imports, same shape — that's deliberate).

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

                errors.extend(self._check_chain(index, entry, previous_hash))
                pubkey_bytes, sig_bytes, decode_errors = self._decode_pubkey_and_sig(
                    index, entry
                )
                errors.extend(decode_errors)
                errors.extend(
                    self._check_signature(index, entry, pubkey_bytes, sig_bytes)
                )
                errors.extend(
                    self._check_identity_binding(index, entry, pubkey_bytes, network)
                )

                # Advance using the *stored* entry_hash so we still detect
                # downstream chain breaks even if this entry mismatched.
                previous_hash = entry.get("entry_hash", previous_hash)

        return len(errors) == 0, errors

    @staticmethod
    def _check_chain(index: int, entry: dict, previous_hash: str) -> list[str]:
        """Verify ``previous_hash`` link and recomputed ``entry_hash``."""
        errors: list[str] = []

        actual_prev = entry.get("previous_hash")
        if actual_prev != previous_hash:
            errors.append(
                f"entry {index}: previous_hash mismatch "
                f"(chain broken; expected {previous_hash!r}, "
                f"got {actual_prev!r})"
            )

        expected_entry_hash = SignedAppendOnlyLog._entry_hash(entry)
        stored_entry_hash = entry.get("entry_hash")
        if stored_entry_hash != expected_entry_hash:
            errors.append(
                f"entry {index}: entry_hash mismatch "
                f"(recomputed hash does not match stored entry_hash)"
            )
        return errors

    @staticmethod
    def _check_signature(
        index: int,
        entry: dict,
        pubkey_bytes: bytes | None,
        sig_bytes: bytes | None,
    ) -> list[str]:
        """Verify the Ed25519 signature against the signed canonical bytes.

        If either ``pubkey_bytes`` or ``sig_bytes`` is None, decode errors
        have already been reported by :meth:`_decode_pubkey_and_sig`; skip
        the actual verify rather than double-reporting.
        """
        if pubkey_bytes is None or sig_bytes is None:
            return []
        try:
            Ed25519PublicKey.from_public_bytes(pubkey_bytes).verify(
                sig_bytes,
                _canonical_bytes(SignedAppendOnlyLog._signed_payload(entry)),
            )
        except InvalidSignature:
            return [f"entry {index}: signature verification failed"]
        except (ValueError, TypeError) as exc:
            # Malformed key material caught by cryptography.
            return [f"entry {index}: signature verification error: {exc}"]
        return []

    @staticmethod
    def _check_identity_binding(
        index: int,
        entry: dict,
        pubkey_bytes: bytes | None,
        network: str,
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
                f"(reporter_id does not derive from reporter_pubkey | "
                f"{network})"
            ]
        return []

    @staticmethod
    def _signed_payload(entry: dict) -> dict:
        """Return the dict that was canonicalized prior to signing."""
        signed = dict(entry)
        signed.pop("entry_hash", None)
        signed.pop("signature", None)
        return signed

    @staticmethod
    def _decode_pubkey_and_sig(
        index: int, entry: dict
    ) -> tuple[bytes | None, bytes | None, list[str]]:
        """Decode and length-check ``reporter_pubkey`` and ``signature``.

        Returns ``(pubkey_bytes_or_None, sig_bytes_or_None, errors)``. A
        bytes value is returned only when the field decoded cleanly and
        has the expected length; otherwise the slot is None and the
        corresponding error is in the third element. Pure function — does
        not mutate any caller state.
        """
        errors: list[str] = []
        pubkey_bytes = SignedAppendOnlyLog._decode_hex_field(
            entry, "reporter_pubkey", expected_len=32, index=index, errors=errors
        )
        sig_bytes = SignedAppendOnlyLog._decode_hex_field(
            entry, "signature", expected_len=64, index=index, errors=errors
        )
        return pubkey_bytes, sig_bytes, errors

    @staticmethod
    def _decode_hex_field(
        entry: dict,
        name: str,
        *,
        expected_len: int,
        index: int,
        errors: list[str],
    ) -> bytes | None:
        """Decode a hex-encoded fixed-length field, appending to ``errors``."""
        raw = entry.get(name)
        if not isinstance(raw, str) or not raw:
            errors.append(f"entry {index}: missing {name}")
            return None
        try:
            decoded = bytes.fromhex(raw)
        except ValueError:
            errors.append(f"entry {index}: malformed {name} hex")
            return None
        if len(decoded) != expected_len:
            errors.append(
                f"entry {index}: {name} is {len(decoded)} bytes, "
                f"expected {expected_len} (length mismatch)"
            )
            return None
        return decoded
