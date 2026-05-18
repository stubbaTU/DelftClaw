"""Per-source append-only cache for foreign signed log entries.

The :class:`PeerLog` is the receiver-side counterpart to
:class:`~redteam.primitives.signed_log.SignedAppendOnlyLog`'s producer
side: it accepts already-signed entries from *other* identities,
verifies them in isolation (no chain context required), and persists
each accepted entry to a per-source jsonl file under the configured
peer-log directory.

Storage layout:

    <peer_log_dir>/<source_id>.jsonl

One foreign entry per line, append-only, no header. ``source_id`` is
the entry's ``reporter_id`` (the SHA256 binding hex). One file per
distinct foreign identity that has ever sent an accepted entry.

Verification reuses :meth:`SignedAppendOnlyLog.verify_foreign_entry` so
the rules stay in lockstep with the producer side. Tampering on disk
after acceptance is *not* re-checked on read in this iteration — readers
that need integrity should re-verify at query time.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path

from redteam.primitives.signed_log import SignedAppendOnlyLog
from shared.logging import get_logger

_logger = get_logger(__name__)


class PeerLog:
    """Receiver-side cache of foreign signed entries, partitioned by source.

    Threading: one ``threading.Lock`` covers all writes across all
    sources. The hot path (verify + write) is small, so this is simpler
    than per-source locks and matches the same flush+fsync pattern used
    by ``SignedAppendOnlyLog._persist``.
    """

    def __init__(
        self,
        peer_log_dir: "str | os.PathLike[str]",
        network: str,
        own_id: str | None = None,
        *,
        audit_log: SignedAppendOnlyLog | None = None,
    ) -> None:
        # ``Path`` accepts os.PathLike directly, so no need for os.fspath.
        self._dir = Path(peer_log_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._network = network
        # Footgun warning: ``own_id=None`` disables the same-identity guard
        # in :meth:`accept_entry` — a peer could in principle ship our own
        # signed entries back to us and have them cached. Tests use
        # ``own_id=None`` when the guard isn't relevant; production callers
        # should always pass the receiver's identity hash.
        self._own_id = own_id
        self._audit_log = audit_log
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Write path
    # ------------------------------------------------------------------

    def accept_entry(
        self, entry: dict
    ) -> tuple[bool, str | None, list[str], bool]:
        """Verify and (idempotently) persist a foreign signed entry.

        Returns ``(stored, source_id, errors, duplicate)``:

        * ``stored`` — True iff the entry was newly persisted.
        * ``source_id`` — the entry's ``reporter_id`` (or whatever was
          there if rejection happened before binding-check).
        * ``errors`` — verification errors (empty on success or
          duplicate).
        * ``duplicate`` — True iff the entry was already present in
          the per-source file.

        Same-identity submissions (``reporter_id == self._own_id``) are
        rejected before verification so a peer cannot trick us into
        caching our own chain.
        """
        # Same-identity guard runs *before* ``verify_foreign_entry`` so a
        # malicious same-identity submission surfaces as a same-identity
        # error rather than a sig/binding error. Not a security issue —
        # any of those errors rejects the entry. It's purely diagnostic:
        # an operator looking at logs can immediately tell apart "peer
        # tried to ship me my own chain" from a generic verification
        # failure. Skipped when ``own_id`` is None (see __init__ note).
        reporter_id = entry.get("reporter_id") if isinstance(entry, dict) else None
        if (
            self._own_id is not None
            and isinstance(entry, dict)
            and reporter_id == self._own_id
        ):
            return (
                False,
                reporter_id,
                ["entry rejected: same-identity submission"],
                False,
            )

        ok, errors = SignedAppendOnlyLog.verify_foreign_entry(
            entry, self._network
        )
        if not ok:
            if (
                self._audit_log is not None
                and reporter_id is not None
                and reporter_id != self._own_id
            ):
                self._audit_log.append_event(
                    reporter_id=self._own_id,
                    subject_id=reporter_id,
                    action="log_integrity_failure",
                    details={
                        "errors": errors,
                        "rejected_entry_hash": entry.get("entry_hash"),
                        "rejected_kind": entry.get("kind"),
                    },
                    severity=20,
                    evidence={"entry": entry},
                )
            return False, reporter_id, errors, False

        # Verification passed → reporter_id is a non-empty hex string.
        source_id = entry["reporter_id"]
        entry_hash = entry["entry_hash"]
        source_file = self._dir / f"{source_id}.jsonl"

        with self._lock:
            if self._has_entry_hash(source_file, entry_hash):
                return False, source_id, [], True

            self._append_line(source_file, entry)

        _logger.debug(
            "peer_log.accept",
            source_id=source_id,
            entry_hash=entry_hash,
            kind=entry.get("kind"),
        )
        return True, source_id, [], False

    @staticmethod
    def _has_entry_hash(source_file: Path, entry_hash: str) -> bool:
        """Linear scan of the per-source file for an existing entry_hash."""
        if not source_file.exists():
            return False
        with open(source_file, "r", encoding="utf-8") as handle:
            for raw in handle:
                line = raw.strip()
                if not line:
                    continue
                try:
                    existing = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if existing.get("entry_hash") == entry_hash:
                    return True
        return False

    @staticmethod
    def _append_line(source_file: Path, entry: dict) -> None:
        """Append one JSON line + flush + fsync (matches signed_log._persist)."""
        with open(source_file, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry) + "\n")
            handle.flush()
            os.fsync(handle.fileno())

    # ------------------------------------------------------------------
    # Read path
    # ------------------------------------------------------------------

    def read_entries_for(self, source_id: str) -> list[dict]:
        """Return entries from ``<dir>/<source_id>.jsonl`` in insertion order.

        Missing file → ``[]``. No re-verification — see module docstring.
        """
        source_file = self._dir / f"{source_id}.jsonl"
        if not source_file.exists():
            return []

        out: list[dict] = []
        with open(source_file, "r", encoding="utf-8") as handle:
            for raw in handle:
                line = raw.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(entry, dict):
                    out.append(entry)
        return out

    def list_sources(self) -> list[str]:
        """Return the source ids (filename stems) of every known peer file."""
        if not self._dir.exists():
            return []
        return [path.stem for path in self._dir.glob("*.jsonl")]
