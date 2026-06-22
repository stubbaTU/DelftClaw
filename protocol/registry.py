"""Register overlay classes with a *running* IPv8 instance.

Also owns ``overlay_to_dict`` — the shared converter
``CompiledOverlay`` → JSON-friendly dict used by ``agent.tools.overlays_list``,
``agent.mcp_server.overlays_list``, and ``deploy.state_snapshot._overlays_snapshot``.
Keeps the three callsites consistent across the two overlay origins.

After ``await ipv8.start()`` the static ``extra_communities`` map is no
longer consulted, but ``ipv8.overlays`` is still mutable and the endpoint
will deliver packets to any community whose 20-byte prefix it sees on
the wire (``Community.__init__`` registers the prefix listener
automatically).

Two registration paths:

  * ``load(md_text)`` — v5.1 markdown-overlay flow. Compiles a
    descriptor via ``protocol.compiler.compile_overlay`` (LLM-driven)
    and appends the resulting instance to ``ipv8.overlays``.
  * ``register_community(cls)`` — traditional hand-written Community
    flow. Skips markdown + LLM entirely. The class must declare a
    20-byte ``community_id`` and contain ``@vp_compile``-decorated
    ``VariablePayload`` subclasses in the same module; their msg_id /
    format_list / names are introspected to build the
    ``CompiledOverlay.payload_classes`` table that ``overlay_invoke``
    relies on.

Both paths share the same cache (`_compiled[cid]` / `_instances[cid]`)
and the same IPv8 registration step, so the rest of the tool surface
treats them uniformly — the ``origin`` discriminator on
``CompiledOverlay`` is the only field that diverges.
"""

from __future__ import annotations

import hashlib
import inspect
import logging
import os
import re
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Optional, Type

from ipv8.community import CommunitySettings
from ipv8.messaging.lazy_payload import VariablePayload

from protocol.compiler import (
    CompiledOverlay,
    canonicalize_md,
    community_id_from_md,
    compile_overlay,
)
from protocol.llm import LLMClient
from protocol.overlay_archive import OverlayArchive

from identity.logging import get_logger

_logger = get_logger(__name__)

# Dedicated stdlib logger for the overlay lifecycle event stream. Emits
# one-line, greppable ``OVERLAY …`` records (mirrors
# ``communication.community._log_wire``) so systemd journals capture them
# and ``deploy.trace`` can parse them into the monitor view.
_lifecycle_logger = logging.getLogger("delftclaw.overlay.lifecycle")


def _one_line(text: str, limit: int = 200) -> str:
    """Collapse a (possibly multi-line) error into a single bounded log token."""
    collapsed = " ".join(text.split())
    return collapsed if len(collapsed) <= limit else collapsed[: limit - 1] + "…"


def _stage_of_error(msg: str) -> str:
    """Best-effort compile-failure stage from a ProtocolCompileError message."""
    m = msg.lower()
    if "sandbox" in m:
        return "sandbox"
    if "test vector" in m:
        return "test_vectors"
    if "community_id mismatch" in m or "community_id drift" in m:
        return "community_id"
    if "missing generatedcommunity" in m or "missing class" in m or "ast-parse" in m:
        return "codegen"
    if any(k in m for k in ("# constants", "# runtime state", "lifecycle", "# tasks", "register_task")):
        return "structural"
    if any(k in m for k in ("section", "table", "encoding", "msg_id", "schema", "header")):
        return "schema"
    return "unknown"


class OverlayRegistry:
    """Owns the compiler + cache + IPv8 registration for runtime overlays.

    Idempotent on ``community_id``: registering the same overlay twice
    (via either entry point) returns the cached instance instead of
    registering a duplicate community.
    """

    def __init__(
        self,
        ipv8: Any,
        llm: LLMClient,
        cache_dir: Path | None = None,
        archive_dir: Path | None = None,
        history_dir: Path | None = None,
    ) -> None:
        self._ipv8 = ipv8
        self._llm = llm
        self._compiled: dict[bytes, CompiledOverlay] = {}
        self._instances: dict[bytes, Any] = {}
        # Per-demo content-addressed spec archive + ledger. ``None`` =
        # disabled (tests / ad-hoc runs). When set (via OVERLAY_ARCHIVE_DIR,
        # wired by deploy.scenario_boot), every overlay this agent publishes
        # or receives is archived by community_id and every lifecycle event
        # appended to the ledger. Observability must never break the overlay
        # flow, so all archive calls are best-effort (failures are logged,
        # not raised).
        # ``history_dir``, when set, makes the archive mirror every ``authored``
        # event into a fleet-wide ``version_history.jsonl`` + a rendered
        # ``version_history.md`` — the per-scenario thesis artifact ``make
        # trace`` inlines and ``make demo`` bundles. See
        # protocol.version_history.
        self._archive: OverlayArchive | None = (
            OverlayArchive(archive_dir, history_dir=history_dir)
            if archive_dir is not None else None
        )
        # On-disk cache for LLM-generated overlay source. ``None`` =
        # disabled (matches every existing test that constructs an
        # OverlayRegistry without this kwarg). When set, a (canonical_md,
        # model_id) pair is keyed to a single ``.py`` file so a watchdog
        # restart skips the Anthropic round-trip on every previously
        # compiled overlay. Safety gates (sandbox AST + structural check
        # + test vectors) still run on the cached source.
        self._cache_dir: Path | None = Path(cache_dir) if cache_dir is not None else None
        if self._cache_dir is not None:
            self._cache_dir.mkdir(parents=True, exist_ok=True)
        # Per-agent serialization for aload — see aload() docstring. Lazy bind
        # to the running event loop on first acquire (Python 3.10+ contract);
        # constructing here is safe even if __init__ runs outside an event
        # loop. One lock per registry, so different agents (= different
        # processes) don't share state through this object.
        import asyncio as _asyncio
        self._aload_lock = _asyncio.Lock()

    # ------------------------------------------------------------------
    # Markdown-overlay path (v5.1 default)
    # ------------------------------------------------------------------

    def load(
        self,
        md_text: str,
        *,
        provenance: str | None = None,
        llm_source: str | None = None,
    ) -> Any:
        """Compile + register a markdown overlay descriptor; return the live instance.

        On a second call with the same descriptor, returns the existing
        instance without recompiling or re-registering. The cache check
        runs BEFORE ``compile_overlay`` so a re-load skips the LLM
        round-trip entirely.

        ``provenance`` (e.g. ``"published"`` / ``"received_from:<peer>"``) is
        recorded in the per-demo archive + ledger when one is configured.

        ``llm_source`` lets the caller short-circuit the LLM round-trip with a
        pre-canned compiled Python source (e.g. a ``*_stub.py`` body for the
        seeder boot). The sandbox AST walk, structural-contract check and test
        vectors all still run; the disk cache is bypassed. This is the route
        that makes the seeder appear in the per-demo overlay archive (the
        manual-registration path used to skip both archive and lifecycle).
        """
        # Cheap content-hash derivation; identical canonicalisation as
        # the one ``compile_overlay`` would do internally, so the
        # post-compile community_id matches by construction.
        cid = community_id_from_md(md_text)
        if cid in self._instances:
            return self._instances[cid]

        self._archive_seen(md_text, provenance)
        try:
            compiled = self._compile_with_disk_cache(md_text, llm_source=llm_source)
        except Exception as exc:
            self._archive_compile_fail(cid, exc, provenance)
            raise
        if compiled.community_id != cid:
            raise RuntimeError(
                f"compile_overlay community_id drift: pre-derived {cid.hex()}, "
                f"post-compile {compiled.community_id.hex()}"
            )

        settings = self._build_settings()
        try:
            instance = compiled.community_class(settings)
            with self._ipv8.overlay_lock:
                self._ipv8.overlays.append(instance)
            # Outside the static IPv8 boot path no one will call started() for us.
            if hasattr(instance, "started"):
                instance.started()
            self._compiled[cid] = compiled
            self._instances[cid] = instance
            self._emit_install(compiled)
            self._archive_install(md_text, compiled, provenance)
            return instance
        except Exception as exc:
            self._archive_post_compile_fail(cid, exc, provenance)
            _logger.exception("post-compile publish failed for cid=%s", cid.hex())
            raise

    async def aload(
        self,
        md_text: str,
        *,
        provenance: str | None = None,
        llm_source: str | None = None,
        authored_event: dict | None = None,
    ) -> Any:
        """Async sibling of ``load`` for use from coroutine call sites.

        The compile step (LLM round-trip + AST whitelist + test vectors)
        is run via ``asyncio.to_thread`` so the event loop stays
        responsive during the multi-second LLM call. IPv8 registration
        is dispatched on the event-loop thread — IPv8 mutates shared
        state and is not thread-safe in this codebase.

        Cache hits are O(1) on the calling task and never schedule a
        worker thread.

        ``authored_event`` lets a publisher (overlay_author_and_publish) thread
        its archive ledger event INTO the shielded compile-and-install
        pipeline, so the ``authored`` record (and the fleet-wide
        ``version_history.md`` row it generates) survives an outer
        cancellation.

        **Cancellation resilience:** the inner pipeline runs as a shielded
        task. When the outer caller is cancelled (e.g. watchdog's 240s
        wait_for fires mid-compile), the caller's await raises
        ``CancelledError`` but the inner task continues on the event loop
        to completion — the install lands in the archive, so the next
        snapshot sees a fully-installed overlay instead of a stranded ``.md``.
        """
        import asyncio

        cid = community_id_from_md(md_text)
        if cid in self._instances:
            return self._instances[cid]

        try:
            return await asyncio.shield(self._do_aload(
                cid, md_text, provenance, llm_source, authored_event,
            ))
        except asyncio.CancelledError:
            _logger.warning("aload cancelled mid-pipeline for cid=%s", cid.hex())
            raise

    async def _do_aload(
        self,
        cid: bytes,
        md_text: str,
        provenance: str | None,
        llm_source: str | None,
        authored_event: dict | None,
    ) -> Any:
        """The actual compile-and-install pipeline, designed to be shielded.

        The per-agent lock lives INSIDE this method (not in the outer
        ``aload``) so that when the caller is cancelled the lock is still
        held by the shielded task — preventing a concurrent caller from
        starting a duplicate compile during the brief window before this
        task's post-compile section completes.

        Lock-ordering invariant: ``self._aload_lock`` is always acquired
        strictly BEFORE ``self._ipv8.overlay_lock`` (which is acquired
        inside ``_post_compile_install``). No inverse ordering anywhere.
        """
        import asyncio
        async with self._aload_lock:
            # Re-check after acquiring the lock — another concurrent caller
            # may have just finished installing while we waited.
            if cid in self._instances:
                return self._instances[cid]
            self._archive_seen(md_text, provenance)
            try:
                compiled = await asyncio.to_thread(
                    self._compile_with_disk_cache, md_text, llm_source=llm_source,
                )
            except Exception as exc:
                self._archive_compile_fail(cid, exc, provenance)
                raise
            if compiled.community_id != cid:
                raise RuntimeError(
                    f"compile_overlay community_id drift: pre-derived {cid.hex()}, "
                    f"post-compile {compiled.community_id.hex()}"
                )
            return await self._post_compile_install(
                cid, compiled, md_text, provenance, authored_event,
            )

    async def _post_compile_install(
        self,
        cid: bytes,
        compiled: CompiledOverlay,
        md_text: str,
        provenance: str | None,
        authored_event: dict | None,
    ) -> Any:
        """The synchronous post-compile critical section, in an async wrapper.

        Wrapped in an ``async def`` purely so ``asyncio.shield`` (which needs
        an awaitable) can protect it from outer cancellation. The body itself
        contains no ``await`` — it runs as one atomic event-loop slice, so
        there's no interruption point for a CancelledError to re-enter.
        """
        settings = self._build_settings()
        # Bisect-instrumentation: each line below logs BEFORE the step it
        # describes runs. The LAST line that appears in the journal before
        # the watchdog kills the subprocess identifies which step hung. Cheap
        # (5 log lines per install) and only meaningful in the deployed
        # journal; remove or downgrade to DEBUG once the hang is diagnosed.
        cid_short = cid.hex()[:12]
        try:
            _logger.info("post-compile[%s] step=init", cid_short)
            instance = compiled.community_class(settings)
            _logger.info("post-compile[%s] step=ipv8_lock_acquire", cid_short)
            with self._ipv8.overlay_lock:
                self._ipv8.overlays.append(instance)
            _logger.info("post-compile[%s] step=started", cid_short)
            # Sync on the event-loop thread, matching the pre-fix shape. An
            # earlier attempt wrapped this in ``asyncio.to_thread`` + a 30s
            # timeout to bound a hypothetical hang in LLM-emitted code, but
            # IPv8's ``network.add_peer_observer`` is not safe to call off the
            # event loop — it deadlocked the publish path silently on the
            # deployed VPS (2026-05-30 ~10:55). The try/except below still
            # catches exceptions raised IN ``started()``; the watchdog's
            # per-turn budget (~240s) is the only protection against a stuck
            # synchronous loop inside it.
            if hasattr(instance, "started"):
                instance.started()
            _logger.info("post-compile[%s] step=archive_install", cid_short)
            self._compiled[cid] = compiled
            self._instances[cid] = instance
            self._emit_install(compiled)
            self._archive_install(md_text, compiled, provenance)
            # The authored-ledger write happens HERE (inside the shield) so
            # the version_history.{jsonl,md} row survives an outer
            # cancellation — see aload's authored_event kwarg docstring.
            if authored_event is not None and self._archive is not None:
                try:
                    self._archive.append_authored_event(
                        cid.hex(), **authored_event,
                    )
                except Exception as exc:  # noqa: BLE001
                    _logger.warning(
                        "authored_event_failed cid=%s err=%s", cid.hex(), exc
                    )
            _logger.info("post-compile[%s] step=done", cid_short)
            return instance
        except Exception as exc:
            self._archive_post_compile_fail(cid, exc, provenance)
            _logger.exception("post-compile publish failed for cid=%s", cid.hex())
            raise

    # ------------------------------------------------------------------
    # Traditional Python-Community path
    # ------------------------------------------------------------------

    def register_community(self, cls: Type, *, provenance: str | None = None) -> Any:
        """Register a hand-written ``Community`` subclass directly.

        Requirements on ``cls``:
          - declares a 20-byte ``community_id``
          - lives in a module that also defines its
            ``@vp_compile``-decorated ``VariablePayload`` subclasses
            (one per wire message), each with ``msg_id``, ``format_list``
            and ``names`` set
          - payload subclass names follow ``<MessageName>Payload`` —
            the leading ``MessageName`` is normalised to
            ``SCREAMING_SNAKE_CASE`` to derive the canonical message
            name. An optional ``MESSAGE_NAME`` class attribute on the
            payload overrides the derivation.

        Idempotent: a second call with a class declaring the same
        ``community_id`` returns the cached live instance.
        """
        cid = getattr(cls, "community_id", None)
        if not isinstance(cid, bytes) or len(cid) != 20:
            raise ValueError(
                f"register_community: {cls.__name__}.community_id must be 20 bytes; "
                f"got {type(cid).__name__}={cid!r}"
            )
        if cid in self._instances:
            return self._instances[cid]

        payload_classes = _introspect_payload_classes(cls)

        settings = self._build_settings()
        instance = cls(settings)

        with self._ipv8.overlay_lock:
            self._ipv8.overlays.append(instance)

        if hasattr(instance, "started"):
            instance.started()

        compiled = CompiledOverlay(
            community_id=cid,
            parsed=None,
            canonical_md_bytes=b"",
            community_class=cls,
            payload_classes=payload_classes,
            source="",
            origin="python_class",
        )
        self._compiled[cid] = compiled
        self._instances[cid] = instance
        self._emit_install(compiled)
        # python_class overlays have no canonical .md bytes to archive; record
        # the install in the ledger so the lifecycle/version view still sees it.
        if self._archive is not None:
            try:
                rec: dict[str, Any] = {
                    "event": "install",
                    "community_id_hex": cid.hex(),
                    "name": cls.__name__,
                    "origin": "python_class",
                }
                if provenance:
                    rec["provenance"] = provenance
                self._archive.append_ledger(rec)
            except Exception as exc:  # noqa: BLE001 — observability must not break overlays
                _logger.warning("overlay_archive.install_ledger_failed", error=str(exc))
        return instance

    # ------------------------------------------------------------------
    # Shared read-only surface
    # ------------------------------------------------------------------

    def get(self, community_id: bytes) -> Optional[Any]:
        """Return the live overlay instance for ``community_id``, or None."""
        return self._instances.get(community_id)

    def list_loaded(self) -> list[bytes]:
        return list(self._instances.keys())

    # ------------------------------------------------------------------
    # LLM-output disk cache (optional, opt-in via ``cache_dir``)
    # ------------------------------------------------------------------

    _MODEL_SLUG_RE = re.compile(r"[^A-Za-z0-9_.\-]+")

    def _cache_path_for(self, md_text: str) -> Path | None:
        """Return ``<cache_dir>/<sha1>-<model_slug>.py`` or ``None`` if disabled."""
        if self._cache_dir is None:
            return None
        canonical = canonicalize_md(md_text)
        canon_sha1 = hashlib.sha1(canonical).hexdigest()
        model_id = getattr(self._llm, "model_id", "unknown")
        slug = self._MODEL_SLUG_RE.sub("_", str(model_id))
        return self._cache_dir / f"{canon_sha1}-{slug}.py"

    def _compile_with_disk_cache(
        self,
        md_text: str,
        *,
        llm_source: str | None = None,
    ) -> CompiledOverlay:
        """Compile ``md_text`` reusing cached LLM output when available.

        Three lanes:

        * **Caller-supplied source** (``llm_source`` set, e.g. from
          ``agent.cli._publish_overlays`` routing a ``*_stub.py`` body
          through the standard load path so seeder boots also emit
          lifecycle events + archive). The disk cache is bypassed entirely
          — read AND write — because the cache key is
          ``(canonical_md, self._llm.model_id)`` and the caller's source
          isn't necessarily what THIS LLM would emit.
        * **Cache hit** — disk-cached LLM source is reused; the sandbox
          AST walk, structural check, and test vectors still run.
        * **Cache miss** — fresh ``compile_overlay`` call; the produced
          source is atomically written to the cache for the next process.
        """
        cache_path = self._cache_path_for(md_text)
        cache_hit = bool(cache_path is not None and cache_path.is_file())
        if llm_source is not None:
            src = "caller"
        elif cache_hit:
            src = "cache_hit"
        else:
            src = "llm"
        model_id = str(getattr(self._llm, "model_id", "unknown"))
        t0 = time.perf_counter()
        try:
            cached_source: str | None = None
            if llm_source is None and cache_hit:
                try:
                    cached_source = cache_path.read_text(encoding="utf-8")
                except OSError as exc:
                    _logger.warning(
                        "overlay_cache.read_failed",
                        path=str(cache_path),
                        error=str(exc),
                    )
                    cached_source = None
            if llm_source is not None:
                compiled = compile_overlay(md_text, self._llm, llm_source=llm_source)
            elif cached_source:
                _logger.debug("overlay_cache.hit", path=str(cache_path))
                compiled = compile_overlay(md_text, self._llm, llm_source=cached_source)
            else:
                # True cache miss OR a hit whose source couldn't be read: a
                # fresh LLM compile either way, so the cache should be (re)written.
                src = "llm"
                compiled = compile_overlay(md_text, self._llm)
        except Exception as exc:  # noqa: BLE001 — re-raised after emitting
            ms = int((time.perf_counter() - t0) * 1000)
            _lifecycle_logger.info(
                "OVERLAY compile cid=%s result=fail stage=%s src=%s model=%s ms=%d err=%s",
                community_id_from_md(md_text).hex(),
                _stage_of_error(str(exc)),
                src, model_id, ms, _one_line(str(exc)),
            )
            raise

        ms = int((time.perf_counter() - t0) * 1000)

        if src == "llm" and cache_path is not None:
            try:
                # Atomic write: tempfile in the same dir, then rename.
                fd, tmp_name = tempfile.mkstemp(
                    prefix=".overlay_cache_",
                    suffix=".py.tmp",
                    dir=str(cache_path.parent),
                )
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    handle.write(compiled.source)
                os.replace(tmp_name, cache_path)
                _logger.debug("overlay_cache.write", path=str(cache_path))
            except OSError as exc:
                _logger.warning(
                    "overlay_cache.write_failed",
                    path=str(cache_path),
                    error=str(exc),
                )

        parsed = compiled.parsed
        _lifecycle_logger.info(
            "OVERLAY compile cid=%s result=ok name=%s version=%s origin=%s "
            "msgs=%d vectors=%d src=%s model=%s ms=%d",
            compiled.community_id.hex(),
            parsed.identity.get("name", "") if parsed else compiled.community_class.__name__,
            parsed.identity.get("version", "") if parsed else "",
            compiled.origin,
            len(parsed.messages) if parsed else len(compiled.payload_classes),
            len(parsed.test_vectors) if parsed else 0,
            src, model_id, ms,
        )
        return compiled

    def _build_settings(self) -> CommunitySettings:
        """Crib peer/endpoint/network from any already-loaded overlay.

        IPv8's ``CommunitySettings`` only needs ``my_peer``, ``endpoint``,
        ``network`` — all three are shared across overlays running on
        the same IPv8 instance, so any bootstrap-loaded community is a
        valid template.
        """
        if not self._ipv8.overlays:
            raise RuntimeError(
                "OverlayRegistry: cannot derive settings — IPv8 has no loaded overlays yet"
            )
        template = self._ipv8.overlays[0]
        return CommunitySettings(
            my_peer=template.my_peer,
            endpoint=template.endpoint,
            network=template.network,
        )

    # ------------------------------------------------------------------
    # Overlay lifecycle event stream + per-demo archive (observability)
    # ------------------------------------------------------------------

    def _emit_install(self, compiled: CompiledOverlay) -> None:
        """Emit the ``OVERLAY install`` lifecycle line for a freshly-live overlay."""
        parsed = compiled.parsed
        _lifecycle_logger.info(
            "OVERLAY install cid=%s name=%s version=%s origin=%s",
            compiled.community_id.hex(),
            parsed.identity.get("name", "") if parsed else compiled.community_class.__name__,
            parsed.identity.get("version", "") if parsed else "",
            compiled.origin,
        )

    def _archive_seen(self, md_text: str, provenance: str | None) -> None:
        """Archive a descriptor's bytes the moment it's seen — before compile.

        Guarantees a received spec is captured even when its compile later
        fails. Best-effort: archive errors are logged, never raised.
        """
        if self._archive is None:
            return
        try:
            self._archive.record(md_text, event="seen", provenance=provenance)
        except Exception as exc:  # noqa: BLE001 — observability must not break overlays
            _logger.warning("overlay_archive.seen_failed", error=str(exc))

    def _archive_compile_fail(
        self, cid: bytes, exc: Exception, provenance: str | None,
    ) -> None:
        if self._archive is None:
            return
        try:
            rec: dict[str, Any] = {
                "event": "compile_fail",
                "community_id_hex": cid.hex(),
                "stage": _stage_of_error(str(exc)),
                "error": _one_line(str(exc)),
            }
            if provenance:
                rec["provenance"] = provenance
            self._archive.append_ledger(rec)
        except Exception as exc2:  # noqa: BLE001
            _logger.warning("overlay_archive.compile_fail_failed", error=str(exc2))

    def _archive_post_compile_fail(
        self, cid: bytes, exc: Exception, provenance: str | None,
    ) -> None:
        """Ledger event for a failure AFTER the compile succeeded.

        Distinct from ``_archive_compile_fail`` so the forensic record
        distinguishes "the LLM emitted invalid code" (caught at compile time)
        from "the LLM-emitted code raised on instantiation / started() /
        IPv8 registration / etc." (caught here). Stamps a fixed
        ``stage=post_compile`` rather than running ``_stage_of_error``
        because the message space is wholly different (Python tracebacks
        rather than ProtocolCompileError text)."""
        if self._archive is None:
            return
        try:
            rec: dict[str, Any] = {
                "event": "compile_fail",
                "community_id_hex": cid.hex(),
                "stage": "post_compile",
                "error": _one_line(f"{type(exc).__name__}: {exc}"),
            }
            if provenance:
                rec["provenance"] = provenance
            self._archive.append_ledger(rec)
        except Exception as exc2:  # noqa: BLE001
            _logger.warning("overlay_archive.post_compile_fail_failed", error=str(exc2))

    def _archive_install(
        self, md_text: str, compiled: CompiledOverlay, provenance: str | None,
    ) -> None:
        if self._archive is None:
            return
        try:
            self._archive.record(
                md_text,
                compiled=compiled,
                event="install",
                provenance=provenance,
                model_id=str(getattr(self._llm, "model_id", "")),
            )
        except Exception as exc:  # noqa: BLE001
            _logger.warning("overlay_archive.install_failed", error=str(exc))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def overlay_to_dict(compiled: CompiledOverlay) -> dict[str, Any]:
    """JSON-friendly summary of a CompiledOverlay for the tool / snapshot surface.

    For ``origin="markdown"`` overlays every metadata field is populated
    from the parsed descriptor. For ``origin="python_class"`` overlays
    the prose-only fields (description / handler_text / errors /
    dependencies) come out empty, but the structural surface
    (community_id, name, messages with msg_id + field encodings) is
    intact so ``overlay_invoke`` can still dispatch by message name.
    """
    cid_hex = compiled.community_id.hex()
    parsed = compiled.parsed
    if parsed is not None:
        return {
            "community_id_hex": cid_hex,
            "origin": compiled.origin,
            "name": parsed.identity.get("name", ""),
            "version": parsed.identity.get("version", ""),
            "description": parsed.identity.get("description", ""),
            "messages": [
                {
                    "name": m.name,
                    "msg_id": m.msg_id,
                    "fields": [
                        {
                            "name": f.name,
                            "encoding": f.encoding,
                            "description": f.description,
                        }
                        for f in m.fields
                    ],
                    "handler_text": m.handler_text,
                }
                for m in parsed.messages
            ],
            "errors": [dict(e) for e in parsed.errors],
            "dependencies": list(parsed.dependencies),
        }

    # Python-class origin: synthesise the message table by walking the
    # introspected payload classes the registry already populated.
    cls = compiled.community_class
    description = (cls.__doc__ or "").strip().splitlines()[0:1]
    return {
        "community_id_hex": cid_hex,
        "origin": compiled.origin,
        "name": cls.__name__,
        "version": "",
        "description": description[0] if description else "",
        "messages": [
            {
                "name": msg_name,
                "msg_id": payload_cls.msg_id,
                "fields": [
                    {"name": n, "encoding": fmt, "description": ""}
                    for n, fmt in zip(payload_cls.names, payload_cls.format_list)
                ],
                "handler_text": "",
            }
            for msg_name, payload_cls in compiled.payload_classes.items()
        ],
        "errors": [],
        "dependencies": [],
    }


_CAMEL_RE = re.compile(r"(?<!^)(?=[A-Z])")


def _camel_to_screaming_snake(name: str) -> str:
    """``OverlayDelivery`` -> ``OVERLAY_DELIVERY``. Lone trailing acronyms
    are left as-is (``ECHORequest`` -> ``ECHO_REQUEST``)."""
    return _CAMEL_RE.sub("_", name).upper()


def _introspect_payload_classes(community_cls: Type) -> dict[str, Type]:
    """Discover ``VariablePayload`` subclasses defined in the same module
    as ``community_cls`` and build the ``{message_name: payload_class}``
    table ``overlay_invoke`` expects.

    Message name derivation:
      * if the payload class declares ``MESSAGE_NAME``, use it verbatim
        (must be SCREAMING_SNAKE_CASE; this is the operator's override
        for non-standard naming);
      * else strip a trailing ``Payload`` suffix from the class name
        and convert the remainder to SCREAMING_SNAKE_CASE.

    Raises ``ValueError`` on:
      * no payload classes found in the module;
      * duplicate ``msg_id`` across two payloads;
      * payload class missing ``msg_id``, ``format_list``, or ``names``;
      * two payloads resolving to the same message name (operator
        ambiguity — fail loud rather than silently picking one).
    """
    module = sys.modules.get(community_cls.__module__)
    if module is None:
        raise ValueError(
            f"_introspect_payload_classes: cannot resolve module {community_cls.__module__!r}"
        )

    payloads: dict[str, Type] = {}
    seen_msg_ids: dict[int, str] = {}

    for attr_name, attr in inspect.getmembers(module, inspect.isclass):
        if not issubclass(attr, VariablePayload) or attr is VariablePayload:
            continue
        # Skip payloads imported from third-party modules — we only want
        # the ones declared alongside the community class.
        if attr.__module__ != community_cls.__module__:
            continue

        msg_id = getattr(attr, "msg_id", None)
        format_list = getattr(attr, "format_list", None)
        names = getattr(attr, "names", None)
        if not isinstance(msg_id, int) or format_list is None or names is None:
            # Looks like a base class or partial definition — skip silently.
            continue

        msg_name = getattr(attr, "MESSAGE_NAME", None)
        if msg_name is None:
            stem = attr_name[:-len("Payload")] if attr_name.endswith("Payload") else attr_name
            msg_name = _camel_to_screaming_snake(stem)

        if msg_id in seen_msg_ids:
            raise ValueError(
                f"_introspect_payload_classes: duplicate msg_id {msg_id} "
                f"({seen_msg_ids[msg_id]!r} and {msg_name!r})"
            )
        if msg_name in payloads:
            raise ValueError(
                f"_introspect_payload_classes: duplicate message name {msg_name!r}"
            )
        seen_msg_ids[msg_id] = msg_name
        payloads[msg_name] = attr

    if not payloads:
        raise ValueError(
            f"_introspect_payload_classes: no VariablePayload subclasses found "
            f"in module {community_cls.__module__!r}"
        )
    return payloads
