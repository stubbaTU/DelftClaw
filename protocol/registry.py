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

import inspect
import re
import sys
from typing import Any, Optional, Type

from ipv8.community import CommunitySettings
from ipv8.messaging.lazy_payload import VariablePayload

from protocol.compiler import CompiledOverlay, compile_overlay
from protocol.llm import LLMClient


class OverlayRegistry:
    """Owns the compiler + cache + IPv8 registration for runtime overlays.

    Idempotent on ``community_id``: registering the same overlay twice
    (via either entry point) returns the cached instance instead of
    registering a duplicate community.
    """

    def __init__(self, ipv8: Any, llm: LLMClient) -> None:
        self._ipv8 = ipv8
        self._llm = llm
        self._compiled: dict[bytes, CompiledOverlay] = {}
        self._instances: dict[bytes, Any] = {}

    # ------------------------------------------------------------------
    # Markdown-overlay path (v5.1 default)
    # ------------------------------------------------------------------

    def load(self, md_text: str) -> Any:
        """Compile + register a markdown overlay descriptor; return the live instance.

        On a second call with the same descriptor, returns the existing
        instance without recompiling or re-registering.
        """
        compiled = compile_overlay(md_text, self._llm)
        cid = compiled.community_id
        if cid in self._instances:
            return self._instances[cid]

        settings = self._build_settings()
        instance = compiled.community_class(settings)

        with self._ipv8.overlay_lock:
            self._ipv8.overlays.append(instance)

        # Outside the static IPv8 boot path no one will call started() for us.
        if hasattr(instance, "started"):
            instance.started()

        self._compiled[cid] = compiled
        self._instances[cid] = instance
        return instance

    # ------------------------------------------------------------------
    # Traditional Python-Community path
    # ------------------------------------------------------------------

    def register_community(self, cls: Type) -> Any:
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
        return instance

    # ------------------------------------------------------------------
    # Shared read-only surface
    # ------------------------------------------------------------------

    def get(self, community_id: bytes) -> Optional[Any]:
        """Return the live overlay instance for ``community_id``, or None."""
        return self._instances.get(community_id)

    def list_loaded(self) -> list[bytes]:
        return list(self._instances.keys())

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
