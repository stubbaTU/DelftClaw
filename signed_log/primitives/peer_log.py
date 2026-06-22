"""Per-source append-only cache for foreign signed log entries.

The :class:`PeerLog` is the receiver-side counterpart to
:class:`~signed_log.primitives.signed_log.SignedAppendOnlyLog`'s producer
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

from signed_log.primitives.signed_log import SignedAppendOnlyLog
from identity.logging import get_logger

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
        self._lock = threading.Lock()
        # Per-source dedup index. ``None`` sentinel = file not yet
        # scanned; first ``_has_entry_hash`` for a source lazy-fills
        # by scanning the jsonl once, after which membership is O(1).
        self._seen: dict[str, set[str] | None] = {}
        # Per-source tail-hash cache. Mirrors ``SignedAppendOnlyLog``'s
        # ``_latest_hash``; consumed by ``community_state`` memoisation.
        # ``None`` = not yet read (or source has no entries).
        self._latest_hash: dict[str, str | None] = {}

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
            return False, reporter_id, errors, False

        # Verification passed → reporter_id is a non-empty hex string.
        source_id = entry["reporter_id"]
        entry_hash = entry["entry_hash"]
        source_file = self._dir / f"{source_id}.jsonl"

        with self._lock:
            if self._has_entry_hash(source_file, source_id, entry_hash):
                return False, source_id, [], True

            self._append_line(source_file, entry)
            # Update both per-source caches under the same lock that
            # serialised the write. ``setdefault`` handles the
            # never-scanned case (we know the file is empty-except-this
            # because ``_has_entry_hash`` already populated the set).
            self._seen.setdefault(source_id, set()).add(entry_hash)
            self._latest_hash[source_id] = entry_hash

        _logger.debug(
            "peer_log.accept",
            source_id=source_id,
            entry_hash=entry_hash,
            kind=entry.get("kind"),
        )
        return True, source_id, [], False

    def _has_entry_hash(
        self, source_file: Path, source_id: str, entry_hash: str,
    ) -> bool:
        """O(1) dedup check after first scan of the source file."""
        seen = self._seen.get(source_id)
        if seen is None:
            # First touch for this source: scan once and populate both
            # the seen-set and the tail-hash cache.
            seen = set()
            tail: str | None = None
            if source_file.exists():
                with open(source_file, "r", encoding="utf-8") as handle:
                    for raw in handle:
                        line = raw.strip()
                        if not line:
                            continue
                        try:
                            existing = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        h = existing.get("entry_hash")
                        if isinstance(h, str):
                            seen.add(h)
                            tail = h
            self._seen[source_id] = seen
            self._latest_hash[source_id] = tail
        return entry_hash in seen

    def latest_hash_for(self, source_id: str) -> str | None:
        """Tail entry_hash of ``<dir>/<source_id>.jsonl``, or ``None`` if empty.

        O(1) after first call thanks to the cache populated by
        ``_has_entry_hash``. Reads the file on the very first call for
        a never-seen source. Used by ``community_state`` memoisation
        to detect when a peer chain has advanced.
        """
        if source_id in self._latest_hash:
            return self._latest_hash[source_id]
        # Force a scan via _has_entry_hash with a sentinel that cannot
        # collide with a real sha256 hex digest, populating the caches
        # as a side effect.
        source_file = self._dir / f"{source_id}.jsonl"
        self._has_entry_hash(source_file, source_id, "")
        return self._latest_hash.get(source_id)

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
