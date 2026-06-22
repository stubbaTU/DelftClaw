"""Per-demo, content-addressed archive + ledger for overlay descriptors.

This is the *version-control* half of overlay observability: every overlay
descriptor an agent publishes or receives is archived by its ``community_id``
(= ``sha1(canonicalize_md(md))[:20]`` — a content hash), so for any demo we can
later recover the exact spec bytes, see which versions appeared, where they came
from, and whether agents agreed.

Layout under ``base_dir`` (one archive dir per agent; set via
``OVERLAY_ARCHIVE_DIR`` by ``deploy.scenario_boot``):

    <cid_hex>.md          canonical descriptor bytes (write-once, dedup by hash)
    <cid_hex>.meta.json   {name, identity_version, canonical_sha1, model_id,
                           origin, first_seen_ts, last_seen_ts, provenance:[…]}
    overlay_ledger.jsonl  append-only timeline; one JSON line per lifecycle event

The archive is the object store (git-like blobs keyed by content hash); the
ledger is the history (git-like reflog). Both are views of the one overlay
lifecycle event stream that ``protocol.registry`` emits.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any, Optional

from protocol.compiler import canonicalize_md


class OverlayArchive:
    """Content-addressed store + append-only ledger for one agent's overlays.

    Idempotent and concurrency-tolerant: ``<cid>.md`` is written once
    (content-addressed), so two processes pointed at the same dir converge;
    the ledger is append-only.
    """

    def __init__(
        self,
        base_dir: Path | str,
        *,
        history_dir: Path | str | None = None,
    ) -> None:
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        # Fleet-wide shared history. When set, every authored event also lands
        # in <history_dir>/version_history.jsonl + a rendered version_history.md
        # — the per-scenario artifact ``make trace`` inlines and ``make demo``
        # bundles. None preserves the legacy per-agent-only behaviour every
        # existing test relies on.
        self.history_dir: Path | None = Path(history_dir) if history_dir is not None else None

    # ------------------------------------------------------------------
    # Paths
    # ------------------------------------------------------------------

    def _md_path(self, cid_hex: str) -> Path:
        return self.base_dir / f"{cid_hex}.md"

    def _meta_path(self, cid_hex: str) -> Path:
        return self.base_dir / f"{cid_hex}.meta.json"

    @property
    def ledger_path(self) -> Path:
        return self.base_dir / "overlay_ledger.jsonl"

    # ------------------------------------------------------------------
    # Writers
    # ------------------------------------------------------------------

    def archive_bytes(self, cid_hex: str, canonical_md_bytes: bytes) -> bool:
        """Write ``<cid>.md`` once. Returns True if newly written, else False."""
        path = self._md_path(cid_hex)
        if path.exists():
            return False
        _atomic_write(path, canonical_md_bytes)
        return True

    def write_meta(
        self,
        cid_hex: str,
        *,
        name: str,
        identity_version: str,
        canonical_sha1: str,
        model_id: str,
        origin: str,
        provenance: Optional[str],
        supersedes: str = "",
        author_id: str = "",
        change_summary: str = "",
    ) -> None:
        """Create or update ``<cid>.meta.json``, appending a provenance entry.

        On repeat appearances the immutable fields are kept; ``last_seen_ts``
        advances, ``provenance`` accumulates, and any previously-empty
        name/version/origin/model is backfilled once known (e.g. the first
        sighting was a pre-compile ``seen`` with no parsed identity).

        Evolution fields (``supersedes`` / ``author_id`` / ``change_summary``)
        describe the SPEC and are the same for every holder — they're parsed
        from the in-band ``# Identity`` block. ``authored_ts`` is set ONLY when
        this agent published the spec (``provenance == "published"``); an
        adopter's meta has ``first_seen_ts`` + a ``received_from`` provenance
        tag but no ``authored_ts``, so the archive distinguishes the author
        from adopters per agent.
        """
        path = self._meta_path(cid_hex)
        now = time.time()
        meta: dict[str, Any] = {}
        if path.is_file():
            try:
                meta = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                meta = {}
        if not meta:
            meta = {
                "community_id_hex": cid_hex,
                "canonical_sha1": canonical_sha1,
                "name": name,
                "identity_version": identity_version,
                "origin": origin,
                "model_id": model_id,
                "first_seen_ts": now,
                "provenance": [],
                "supersedes": supersedes or None,
                "author_id": author_id,
                "change_summary": change_summary,
            }
        # Backfill fields that were unknown at first sighting.
        for key, value in (
            ("name", name),
            ("identity_version", identity_version),
            ("origin", origin),
            ("model_id", model_id),
            ("author_id", author_id),
            ("change_summary", change_summary),
        ):
            if value and not meta.get(key):
                meta[key] = value
        if supersedes and not meta.get("supersedes"):
            meta["supersedes"] = supersedes
        meta["last_seen_ts"] = now
        if provenance == "published" and not meta.get("authored_ts"):
            meta["authored_ts"] = now
        if provenance:
            meta.setdefault("provenance", []).append({"ts": now, "tag": provenance})
        _atomic_write(path, json.dumps(meta, indent=2, sort_keys=True).encode("utf-8"))

    def has(self, cid_hex: str) -> bool:
        """Whether this archive holds the canonical ``.md`` for ``cid_hex``.

        Cross-process safe — reads the shared archive dir on disk. True as soon
        as ``_archive_seen`` writes the bytes; does NOT imply the overlay was
        installed into the running registry. Callers that need "ready to use"
        semantics (e.g. ``pending_overlay_offers``) should use ``is_installed``
        instead — otherwise a hung post-compile leaves a stranded ``.md`` and
        the agent never retries the adopt.
        """
        return self._md_path(cid_hex).is_file()

    def is_installed(self, cid_hex: str) -> bool:
        """Whether the overlay finished installing (registry side) — checks for
        a ``meta.json`` with a non-empty identity name.

        ``_archive_install`` writes the meta.json with ``name`` and
        ``identity_version`` populated from the compiled spec. ``_archive_seen``
        writes a meta.json too, but with empty identity fields. If install
        hung (e.g. on a misbehaving LLM-emitted ``started()``), the seen-only
        meta.json stays empty and this returns False — letting the agent
        retry on the next watchdog tick instead of staying idle forever.
        """
        path = self._meta_path(cid_hex)
        try:
            meta = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return False
        return bool(meta.get("name")) and bool(meta.get("identity_version"))

    def self_authored_ids(self, author_id: str) -> list[str]:
        """community_ids this ``author_id`` AUTHORED (published), from disk.

        Scans every ``<cid>.meta.json`` for ``author_id`` match AND a present
        ``authored_ts`` (set only on the publishing agent — see ``write_meta``).
        This is the cross-process signal that "I authored an overlay": the
        authoring tool runs in the MCP process but the watchdog snapshot
        process reads the same shared archive dir, so it sees the authorship.
        """
        out: list[str] = []
        if not author_id:
            return out
        for meta_path in sorted(self.base_dir.glob("*.meta.json")):
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if meta.get("author_id") == author_id and meta.get("authored_ts"):
                out.append(meta.get("community_id_hex") or meta_path.name.split(".")[0])
        return out

    def append_ledger(self, record: dict[str, Any]) -> None:
        """Append one timeline line to ``overlay_ledger.jsonl`` (stamps ``ts``)."""
        line = {"ts": time.time(), **record}
        with open(self.ledger_path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(line, default=str) + "\n")

    # ------------------------------------------------------------------
    # High-level
    # ------------------------------------------------------------------

    def record(
        self,
        md_text: str,
        *,
        compiled: Any = None,
        event: str,
        provenance: Optional[str] = None,
        **extra: Any,
    ) -> str:
        """Archive a descriptor's bytes + meta and append one ledger line.

        cid + canonical bytes are derived from ``md_text`` (NOT from
        ``compiled``), so a received spec is archived even when its compile
        failed and no ``CompiledOverlay`` exists. When ``compiled`` is present
        and markdown-origin, name/version/origin are recorded too.

        Returns the community_id hex.
        """
        canonical = canonicalize_md(md_text)
        canonical_sha1 = hashlib.sha1(canonical).hexdigest()
        cid_hex = canonical_sha1[:40]  # community_id is sha1(canonical)[:20] → first 40 hex chars

        name = identity_version = origin = ""
        supersedes = author_id = change_summary = ""
        if compiled is not None and getattr(compiled, "parsed", None) is not None:
            ident = compiled.parsed.identity
            name = ident.get("name", "")
            identity_version = ident.get("version", "")
            origin = compiled.origin
            # Evolution provenance is carried in-band in the spec's # Identity
            # block (see protocol/schema.md), so every holder of the spec —
            # author and adopters alike — records the same author/lineage.
            supersedes = ident.get("supersedes", "") or ""
            author_id = ident.get("author_id", "") or ""
            change_summary = ident.get("change_summary", "") or ""
        elif compiled is not None:
            origin = getattr(compiled, "origin", "")

        newly = self.archive_bytes(cid_hex, canonical)
        self.write_meta(
            cid_hex,
            name=name,
            identity_version=identity_version,
            canonical_sha1=canonical_sha1,
            model_id=str(extra.get("model_id", "")),
            origin=origin,
            provenance=provenance,
            supersedes=supersedes,
            author_id=author_id,
            change_summary=change_summary,
        )
        rec: dict[str, Any] = {
            "event": event,
            "community_id_hex": cid_hex,
            "name": name,
            "identity_version": identity_version,
            "canonical_sha1": canonical_sha1,
            "origin": origin,
            "newly_archived": newly,
        }
        if provenance:
            rec["provenance"] = provenance
        rec.update(extra)
        self.append_ledger(rec)
        return cid_hex

    def append_authored_event(
        self,
        cid_hex: str,
        *,
        name: str,
        identity_version: str,
        supersedes: Optional[str],
        author_id: str,
        change_summary: str,
    ) -> None:
        """Append the once-per-spec ``authored`` ledger event.

        Distinct from the ``install`` event: ``install`` fires on every agent
        that adopts the spec, but ``authored`` fires exactly once — on the
        originating agent, emitted by the authoring tool right after publish.
        That's what lets the trace renderer reconstruct *who* introduced each
        version and *when*, separate from who later adopted it.
        """
        event = {
            "event": "authored",
            "community_id_hex": cid_hex,
            "name": name,
            "identity_version": identity_version,
            "supersedes": supersedes or None,
            "author_id": author_id,
            "change_summary": change_summary,
        }
        self.append_ledger(event)
        if self.history_dir is not None:
            # Best-effort fleet mirror — every agent's authored event also
            # lands in the per-scenario file, and we re-render the markdown
            # so trace always sees a current artifact. Both calls swallow
            # OSError so a fleet-dir issue can't break the per-agent ledger.
            from protocol.version_history import (
                append_history_event,
                write_markdown_summary,
            )
            append_history_event(self.history_dir, event)
            write_markdown_summary(self.history_dir)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _atomic_write(path: Path, data: bytes) -> None:
    """Write ``data`` to ``path`` via tempfile + os.replace (atomic on POSIX)."""
    fd, tmp = tempfile.mkstemp(prefix=".overlay_arch_", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
