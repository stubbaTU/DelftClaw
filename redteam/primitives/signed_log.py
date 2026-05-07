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

    Every entry carries an explicit ``kind`` field of either ``"self"`` or
    ``"witness"``. ``append_event`` writes self entries (the reporter
    describes its own action). ``append_witness_event`` writes witness
    entries: a *reporter* (B) records an action by a *subject* (A) and
    embeds A's own Ed25519 signature over a fixed-schema "claim" envelope
    as cryptographic proof the underlying claim came from A's key. The
    subject signature is computed by A over the canonical bytes of a
    portable claim object (kind=claim, version=1, subject_id, action,
    details_hash, claim_timestamp, nonce) — not the wrapping entry, so A
    can sign once and have multiple reporters independently witness it.
    The pre-write validations in ``append_witness_event`` raise on
    failure: a witness entry containing an invalid subject signature is
    never written to the log.
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

    def append_witness_event(
        self,
        *,
        reporter_id: str,
        subject_id: str,
        subject_pubkey: bytes | str,
        subject_claim: dict,
        subject_signature: bytes | str,
        action: str,
        details: dict,
        severity: int = 0,
        evidence: dict | None = None,
    ) -> dict:
        """Append a witness entry: B records A's signed claim into B's log.

        Pre-write validations (raise on failure — never write a chain
        entry containing an invalid subject signature):

        1. ``subject_pubkey`` decodes to 32 bytes; ``subject_signature``
           decodes to 64 bytes.
        2. ``SHA256(subject_pubkey || self._identity.network) == subject_id``.
        3. ``subject_claim["subject_id"] == subject_id`` AND
           ``subject_claim["action"] == action`` AND
           ``subject_claim["details_hash"] == _stable_hash(details)``.
        4. Ed25519 verify of ``subject_signature`` over canonical bytes of
           ``subject_claim`` against ``subject_pubkey``.

        Cross-network witnesses are out of scope this iteration: if the
        subject is on a different network the binding check (#2) fails.
        """
        with self._lock:
            entry = self._build_witness_entry(
                reporter_id=reporter_id,
                subject_id=subject_id,
                subject_pubkey=subject_pubkey,
                subject_claim=subject_claim,
                subject_signature=subject_signature,
                action=action,
                details=details,
                severity=severity,
                evidence=evidence,
            )
            self._persist(entry)

        _logger.debug(
            "signed_log.append_witness",
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
            "kind": "self",
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

    def _build_witness_entry(
        self,
        *,
        reporter_id: str,
        subject_id: str,
        subject_pubkey: bytes | str,
        subject_claim: dict,
        subject_signature: bytes | str,
        action: str,
        details: dict,
        severity: int,
        evidence: dict | None,
    ) -> dict[str, Any]:
        """Assemble, validate, sign, and chain-hash a witness entry.

        Caller must hold ``self._lock``. Runs the four pre-write checks;
        any failure raises before persistence.
        """
        # (1) Decode pubkey/sig and length-check. Raises ValueError on
        # malformed/wrong-length inputs.
        pubkey_bytes, sig_bytes = self._decode_subject_pubkey_and_sig_strict(
            subject_pubkey, subject_signature
        )

        # (2) Identity binding: SHA256(pubkey || network) == subject_id.
        binding_errors = self._check_subject_identity_binding(
            pubkey_bytes, self._identity.network, subject_id
        )
        if binding_errors:
            raise ValueError("; ".join(binding_errors))

        # (3) Claim consistency with the entry: subject_id, action, details_hash.
        details_hash = _stable_hash(details)
        consistency_errors = self._check_claim_consistency(
            subject_claim,
            subject_id=subject_id,
            action=action,
            details_hash=details_hash,
        )
        if consistency_errors:
            raise ValueError("; ".join(consistency_errors))

        # (4) Ed25519 verify of subject_signature over canonical(subject_claim).
        sig_errors = self._check_subject_signature(
            pubkey_bytes, sig_bytes, subject_claim
        )
        if sig_errors:
            raise ValueError("; ".join(sig_errors))

        evidence_payload = evidence if evidence is not None else {}

        entry: dict[str, Any] = {
            "version": 2,
            "kind": "witness",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "reporter_id": reporter_id,
            "subject_id": subject_id,
            "action": action,
            "severity": severity,
            "details": details,
            "evidence": evidence_payload,
            "details_hash": details_hash,
            "evidence_hash": _stable_hash(evidence_payload),
            "previous_hash": self.latest_hash(),
            "reporter_pubkey": self._identity.public_key.hex(),
            "subject_pubkey": pubkey_bytes.hex(),
            "subject_claim": subject_claim,
            "subject_signature": sig_bytes.hex(),
        }

        # Reporter signs canonical bytes of entry (sans signature/entry_hash).
        # subject_signature rides along into the reporter signature and the
        # chain hash, so an attacker who later swaps in a different valid
        # subject sig invalidates the reporter sig and the entry_hash.
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

                # Discriminate self vs witness. Reject anything else, and
                # reject self entries that smuggle subject fields (downgrade
                # defense).
                kind = entry.get("kind")
                if kind == "self":
                    for forbidden in (
                        "subject_pubkey",
                        "subject_claim",
                        "subject_signature",
                    ):
                        if forbidden in entry:
                            errors.append(
                                f"entry {index}: self entry must not carry "
                                f"{forbidden} (downgrade defense)"
                            )
                elif kind == "witness":
                    errors.extend(self._verify_witness_fields(index, entry, network))
                else:
                    errors.append(
                        f"entry {index}: missing or unknown kind {kind!r} "
                        "(expected 'self' or 'witness')"
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

    # ------------------------------------------------------------------
    # Witness-entry helpers (mirrored by name in redteam.primitives.verify)
    # ------------------------------------------------------------------

    @staticmethod
    def _coerce_hex_or_bytes(value: bytes | str, *, name: str, expected_len: int) -> bytes:
        """Strict decode: bytes ``value`` of correct length, or hex string thereof.

        Raises ``ValueError`` on type mismatch, hex-decode failure, or
        wrong length. Used by the producer-side strict path.
        """
        if isinstance(value, bytes):
            decoded = value
        elif isinstance(value, str):
            try:
                decoded = bytes.fromhex(value)
            except ValueError as exc:
                raise ValueError(f"malformed {name} hex") from exc
        else:
            raise ValueError(f"{name} must be bytes or hex string")
        if len(decoded) != expected_len:
            raise ValueError(
                f"{name} is {len(decoded)} bytes, expected {expected_len}"
            )
        return decoded

    @classmethod
    def _decode_subject_pubkey_and_sig_strict(
        cls, subject_pubkey: bytes | str, subject_signature: bytes | str
    ) -> tuple[bytes, bytes]:
        """Producer-side: raise on any decode/length failure."""
        pubkey_bytes = cls._coerce_hex_or_bytes(
            subject_pubkey, name="subject_pubkey", expected_len=32
        )
        sig_bytes = cls._coerce_hex_or_bytes(
            subject_signature, name="subject_signature", expected_len=64
        )
        return pubkey_bytes, sig_bytes

    @staticmethod
    def _decode_subject_pubkey_and_sig(
        index: int, entry: dict
    ) -> tuple[bytes | None, bytes | None, list[str]]:
        """Verifier-side: decode hex fields off a witness entry.

        Returns ``(pubkey_or_None, sig_or_None, errors)``. Mirrors the
        shape of :meth:`_decode_pubkey_and_sig` so a reviewer can diff
        the two at a glance.
        """
        errors: list[str] = []
        pubkey_bytes = SignedAppendOnlyLog._decode_hex_field(
            entry, "subject_pubkey", expected_len=32, index=index, errors=errors
        )
        sig_bytes = SignedAppendOnlyLog._decode_hex_field(
            entry, "subject_signature", expected_len=64, index=index, errors=errors
        )
        return pubkey_bytes, sig_bytes, errors

    @staticmethod
    def _check_subject_identity_binding(
        pubkey_bytes: bytes | None, network: str, subject_id: str | None
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

    @staticmethod
    def _check_claim_consistency(
        subject_claim: dict | None,
        *,
        subject_id: str,
        action: str,
        details_hash: str,
    ) -> list[str]:
        """Verify the claim envelope agrees with the entry's bound fields.

        Also enforces the envelope schema (``kind == "claim"``, integer
        ``version``, hex string ``nonce``).
        """
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
            errors.append(
                "subject_claim claim_timestamp missing or not a string"
            )
        if subject_claim.get("subject_id") != subject_id:
            errors.append(
                "subject_claim.subject_id does not match entry.subject_id"
            )
        if subject_claim.get("action") != action:
            errors.append(
                "subject_claim.action does not match entry.action"
            )
        if subject_claim.get("details_hash") != details_hash:
            errors.append(
                "subject_claim.details_hash does not match hash(entry.details)"
            )
        return errors

    @staticmethod
    def _check_subject_signature(
        pubkey_bytes: bytes | None,
        sig_bytes: bytes | None,
        subject_claim: dict | None,
    ) -> list[str]:
        """Ed25519 verify ``subject_signature`` over canonical ``subject_claim``."""
        if pubkey_bytes is None or sig_bytes is None:
            return []
        if not isinstance(subject_claim, dict):
            return ["subject_claim missing or not an object"]
        try:
            Ed25519PublicKey.from_public_bytes(pubkey_bytes).verify(
                sig_bytes, _canonical_bytes(subject_claim)
            )
        except InvalidSignature:
            return ["subject signature verification failed"]
        except (ValueError, TypeError) as exc:
            return [f"subject signature verification error: {exc}"]
        return []

    @staticmethod
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
            # Without these, the rest can't run meaningfully.
            return errors

        sub_pubkey, sub_sig, decode_errors = (
            SignedAppendOnlyLog._decode_subject_pubkey_and_sig(index, entry)
        )
        errors.extend(decode_errors)

        binding_errors = SignedAppendOnlyLog._check_subject_identity_binding(
            sub_pubkey, network, entry.get("subject_id")
        )
        errors.extend(f"entry {index}: {e}" for e in binding_errors)

        consistency_errors = SignedAppendOnlyLog._check_claim_consistency(
            entry.get("subject_claim"),
            subject_id=entry.get("subject_id"),
            action=entry.get("action"),
            details_hash=entry.get("details_hash"),
        )
        errors.extend(f"entry {index}: {e}" for e in consistency_errors)

        sig_errors = SignedAppendOnlyLog._check_subject_signature(
            sub_pubkey, sub_sig, entry.get("subject_claim")
        )
        errors.extend(f"entry {index}: {e}" for e in sig_errors)

        return errors
