"""Deterministic synthesis of overlay descriptors from structured field specs.

This is the "graduation from natural-language to structured contract" step the
Agora paper describes: an agent *reasons* about the protocol it wants (message
names, fields, handler semantics) and supplies that as structured JSON; these
pure functions turn that intent into a byte-exact ``.md`` descriptor that the
normal compile pipeline accepts first-try.

Why the LLM must NOT write the ``.md`` itself: the ``# Test Vectors`` block
requires contiguous hex that equals ``default_serializer.pack_serializable(...)``
for each message — get one byte wrong and ``compile_overlay`` rejects the spec.
Models cannot reliably produce that hex. So ``compute_test_vectors`` derives it
from the same serializer the compiler validates against, guaranteeing the
synthesized spec's vectors pass by construction.

Two pure functions, no IPv8 instance / no agent needed:

  * ``synthesize_overlay_markdown(...)`` -> canonical ``.md`` text.
  * ``compute_test_vectors(messages, samples)`` -> ``{msg_name: [(fields, hex)]}``.
"""

from __future__ import annotations

import json
from typing import Any

from protocol.compiler import ALLOWED_ENCODINGS, _coerce_field_value


class OverlayAuthoringError(ValueError):
    """Raised when a structured overlay description is malformed."""


# Zero value per encoding, used to synthesize the mandatory "empty" test vector
# for every message (the compiler requires >= 2 vectors per message; we emit a
# zero-valued one + the caller's sample).
_ENCODING_ZERO: dict[str, Any] = {
    "uint8": 0, "uint16-be": 0, "uint32-be": 0, "uint64-be": 0,
    "bool": False,
    "varlenH": b"", "varlenH-utf8": "", "varlenH-msgpack": [],
    "bytes20": b"\x00" * 20, "bytes32": b"\x00" * 32,
    # v1.1 semantic encodings: hash20/hash32 take hex-string samples;
    # the "zero" hash is just 40/64 chars of '0'. timestamp_unix is a
    # plain int alias of uint64-be.
    "hash20": "00" * 20, "hash32": "00" * 32,
    "timestamp_unix": 0,
}


def _format_for(encoding: str) -> str:
    """Map a schema encoding to its IPv8 ``format_list`` token."""
    if encoding not in ALLOWED_ENCODINGS:
        raise OverlayAuthoringError(
            f"unsupported encoding {encoding!r}; allowed: {sorted(ALLOWED_ENCODINGS)}"
        )
    return ALLOWED_ENCODINGS[encoding]


def _build_payload_cls(msg_id: int, fields: list[dict]) -> type:
    """Construct a throwaway ``@vp_compile`` VariablePayload to pack test vectors.

    Identical wire shape to what the compiler will generate for this message,
    so bytes computed here match ``compile_overlay``'s validation exactly.
    """
    from ipv8.messaging.lazy_payload import VariablePayload, vp_compile

    format_list = [_format_for(f["encoding"]) for f in fields]
    names = [f["name"] for f in fields]

    ns = {"msg_id": msg_id, "format_list": format_list, "names": names}
    cls = type("_AuthoringPayload", (VariablePayload,), ns)
    return vp_compile(cls)


def compute_test_vectors(
    messages: list[dict],
    samples: dict[str, dict[str, Any]] | None = None,
) -> dict[str, list[tuple[dict, str]]]:
    """Produce two byte-exact test vectors per message.

    ``messages`` — list of ``{name, msg_id, fields: [{name, encoding, ...}]}``.
    ``samples`` — optional ``{msg_name: {field_name: human_value}}`` giving a
    populated example per message. When absent for a message, a second vector
    is synthesized from per-field "one" values so the two vectors still differ.

    Returns ``{msg_name: [(fields_dict, hex_str), ...]}`` where ``fields_dict``
    holds the human-form values (the form written into the ``.md``) and
    ``hex_str`` is the contiguous lowercase hex they serialize to.
    """
    from ipv8.messaging.serialization import default_serializer

    samples = samples or {}
    out: dict[str, list[tuple[dict, str]]] = {}
    for msg in messages:
        name = msg["name"]
        fields = msg["fields"]
        payload_cls = _build_payload_cls(msg["msg_id"], fields)

        # Vector 1: all-zero. Vector 2: caller sample, or per-field "one".
        zero_fields = {f["name"]: _ENCODING_ZERO[f["encoding"]] for f in fields}
        if name in samples:
            populated = dict(samples[name])
        else:
            populated = {f["name"]: _example_one(f["encoding"]) for f in fields}

        vectors: list[tuple[dict, str]] = []
        for human in (zero_fields, populated):
            # Pass the per-field encoding so the v1.1 semantic encodings
            # (hash20/hash32) route through the hex-aware coercion branch.
            coerced = [
                _coerce_field_value(human[f["name"]], f["encoding"]) for f in fields
            ]
            instance = payload_cls(*coerced)
            raw = default_serializer.pack_serializable(instance)
            vectors.append((human, raw.hex()))

        # Guard against the two vectors colliding (e.g. an all-zero sample) —
        # the cross-LLM determinism rationale wants distinct examples.
        if len(vectors) == 2 and vectors[0][1] == vectors[1][1] and fields:
            # Bump the first field's populated value so the second vector differs.
            f0 = fields[0]
            populated = dict(populated)
            populated[f0["name"]] = _example_two(f0["encoding"])
            coerced = [
                _coerce_field_value(populated[f["name"]], f["encoding"]) for f in fields
            ]
            raw = default_serializer.pack_serializable(payload_cls(*coerced))
            vectors[1] = (populated, raw.hex())

        out[name] = vectors
    return out


def _example_one(encoding: str) -> Any:
    return {
        "uint8": 1, "uint16-be": 1, "uint32-be": 1, "uint64-be": 1,
        "bool": True,
        "varlenH": b"\x01", "varlenH-utf8": "x", "varlenH-msgpack": [1],
        "bytes20": b"\x01" * 20, "bytes32": b"\x01" * 32,
        # hash20/hash32 examples are hex strings — that's the v1.1 sample
        # convention the bytes.fromhex coercion path expects.
        "hash20": "01" * 20, "hash32": "01" * 32,
        "timestamp_unix": 1,
    }[encoding]


def _example_two(encoding: str) -> Any:
    return {
        "uint8": 2, "uint16-be": 2, "uint32-be": 2, "uint64-be": 2,
        "bool": True,
        "varlenH": b"\x02", "varlenH-utf8": "xy", "varlenH-msgpack": [2],
        "bytes20": b"\x02" * 20, "bytes32": b"\x02" * 32,
        "hash20": "02" * 20, "hash32": "02" * 32,
        "timestamp_unix": 2,
    }[encoding]


def _hex_grouped(hexstr: str) -> str:
    """Light readability grouping (8-char chunks). Compiler strips whitespace."""
    return " ".join(hexstr[i:i + 8] for i in range(0, len(hexstr), 8)) or "(empty)"


def synthesize_overlay_markdown(
    *,
    name: str,
    version: str,
    description: str,
    messages: list[dict],
    runtime_state: list[dict] | None = None,
    constants: list[dict] | None = None,
    lifecycle: str = "peer-observer",
    supersedes: str | None = None,
    author_id: str | None = None,
    change_summary: str | None = None,
    samples: dict[str, dict[str, Any]] | None = None,
) -> str:
    """Compose a schema-conformant overlay ``.md`` from structured fields.

    ``messages`` — ``[{name, msg_id, fields: [{name, encoding, description}],
    handler: <prose>}]``. ``runtime_state`` / ``constants`` mirror the schema's
    optional tables. Test vectors are computed (not author-supplied) via
    ``compute_test_vectors`` so the produced spec compiles first-try.

    The output ordering matches ``protocol/schema.md`` exactly:
    Identity, Messages, [Runtime State], [Constants], Errors, Dependencies,
    Test Vectors.
    """
    if not messages:
        raise OverlayAuthoringError("at least one message is required")

    lines: list[str] = []

    # --- Identity ---
    lines += ["# Identity", ""]
    lines += [f"- name: {name}", f"- version: {version}", f"- description: {description}"]
    lines += [f"- lifecycle: {lifecycle}"]
    if supersedes:
        lines += [f"- supersedes: {supersedes}"]
    if author_id:
        lines += [f"- author_id: {author_id}"]
    if change_summary:
        lines += [f"- change_summary: {change_summary}"]
    lines += [""]

    # --- Messages ---
    lines += ["# Messages", ""]
    seen_ids: set[int] = set()
    for msg in messages:
        mid = int(msg["msg_id"])
        if mid in seen_ids:
            raise OverlayAuthoringError(f"duplicate msg_id {mid}")
        seen_ids.add(mid)
        lines += [f"## {msg['name']}", "", f"- msg_id: {mid}", ""]
        lines += ["| name | encoding | description |", "|------|----------|-------------|"]
        for f in msg["fields"]:
            _format_for(f["encoding"])  # validate encoding eagerly
            desc = f.get("description", "")
            lines += [f"| {f['name']} | {f['encoding']} | {desc} |"]
        lines += [""]
        lines += ["### Handler", "", msg.get("handler", "No side effects.").strip(), ""]

    # --- Runtime State (optional) ---
    if runtime_state:
        lines += ["# Runtime State", ""]
        lines += ["| name | type | description |", "|------|------|-------------|"]
        for s in runtime_state:
            lines += [f"| {s['name']} | {s['type']} | {s.get('description', '')} |"]
        lines += [""]

    # --- Constants (optional) ---
    if constants:
        lines += ["# Constants", ""]
        lines += ["| name | type | value | description |",
                  "|------|------|-------|-------------|"]
        for c in constants:
            lines += [
                f"| {c['name']} | {c['type']} | {json.dumps(c['value'])} | "
                f"{c.get('description', '')} |"
            ]
        lines += [""]

    # --- Errors ---
    lines += ["# Errors", "", "| code | name | policy |", "|------|------|--------|",
              "| 1 | malformed_payload | drop |", ""]

    # --- Dependencies ---
    lines += ["# Dependencies", "", "(none)", ""]

    # --- Test Vectors (computed) ---
    vectors = compute_test_vectors(messages, samples)
    lines += ["# Test Vectors", ""]
    for msg in messages:
        lines += [f"## {msg['name']}", ""]
        for human, hexstr in vectors[msg["name"]]:
            lines += [f"- fields: {json.dumps(human, default=_json_default)}",
                      f"  bytes: {_hex_grouped(hexstr)}", ""]

    return "\n".join(lines).rstrip() + "\n"


def _json_default(value: Any) -> Any:
    """JSON-encode bytes sample values as their utf-8 / latin-1 string form.

    Test-vector ``fields:`` lines are JSON; a raw-bytes sample (rare — most
    fields use uint/utf8/msgpack) is rendered as a latin-1 string so the round
    trip through ``_coerce_field_value`` (which re-encodes str -> utf-8) stays
    stable for ASCII. Non-ASCII raw bytes in a hand-authored sample are not
    supported by this path; use varlenH-utf8 for text.
    """
    if isinstance(value, (bytes, bytearray)):
        return value.decode("latin-1")
    raise TypeError(f"cannot JSON-encode {type(value).__name__}")
