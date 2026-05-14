"""Compile an overlay descriptor (`.md`) into a runtime IPv8 ``Community`` class.

Pipeline (see ``protocol/schema.md`` for the canonical descriptor format):

    md_text
      -> parse_md(md_text)            structured dict
      -> validate_schema(parsed)      required sections, encoding allowlist, msg_id uniqueness
      -> canonicalize_md(md_text)     deterministic bytes
      -> community_id = sha1(canonical)[:20]
      -> source = llm.complete(SYSTEM, build_user_prompt(parsed, community_id))
      -> strip_code_fences(source)
      -> safe_exec(source)            AST whitelist + namespaced exec
      -> assert generated class declares the same community_id
      -> run_test_vectors(payload_classes, parsed["test_vectors"])
      -> CompiledOverlay(...)

Failures raise ``ProtocolCompileError`` so the agent can fall back to
natural-language messaging on the bootstrap community, Agora-style.
"""

from __future__ import annotations

import binascii
import hashlib
import json
import re
import struct
from dataclasses import dataclass
from typing import Any, Iterable, Optional, Type


def struct_error():
    return struct.error

from protocol.llm import LLMClient
from protocol.sandbox import SandboxError, safe_exec


class ProtocolCompileError(Exception):
    """Anything that prevents an overlay from being safely activated."""


# ---------------------------------------------------------------------------
# Schema constants
# ---------------------------------------------------------------------------

REQUIRED_SECTIONS = ("Identity", "Messages", "Errors", "Dependencies", "Test Vectors")

ALLOWED_ENCODINGS: dict[str, str] = {
    "uint8":           "B",
    "uint16-be":       "H",
    "uint32-be":       "I",
    "uint64-be":       "Q",
    "bool":            "?",
    "varlenH":         "varlenH",
    "varlenH-utf8":    "varlenH",
    "varlenH-msgpack": "varlenH",
    "bytes20":         "20s",
    "bytes32":         "32s",
}


# ---------------------------------------------------------------------------
# Canonicalization + community_id
# ---------------------------------------------------------------------------

def canonicalize_md(text: str) -> bytes:
    """Apply the canonicalization rule from ``protocol/schema.md``."""
    text = text.replace("\r\n", "\n")
    lines = [line.rstrip() for line in text.split("\n")]
    while lines and lines[-1] == "":
        lines.pop()
    return ("\n".join(lines)).encode("utf-8")


def community_id_from_md(text: str) -> bytes:
    """Derive the 20-byte IPv8 ``community_id`` from a descriptor's `.md` text."""
    return hashlib.sha1(canonicalize_md(text)).digest()[:20]


# ---------------------------------------------------------------------------
# Markdown parser
# ---------------------------------------------------------------------------

@dataclass
class MessageField:
    name: str
    encoding: str
    description: str


@dataclass
class MessageDef:
    name: str               # SCREAMING_SNAKE_CASE
    msg_id: int
    fields: list[MessageField]
    handler_text: str       # free-text operational semantics


@dataclass
class TestVector:
    message: str             # message name
    fields: dict[str, Any]   # decoded field values
    bytes_hex: str           # contiguous lowercase hex (whitespace stripped)


@dataclass
class ParsedOverlay:
    identity: dict[str, str]
    messages: list[MessageDef]
    errors: list[dict[str, str]]
    dependencies: list[str]
    test_vectors: list[TestVector]


def parse_md(text: str) -> ParsedOverlay:
    """Parse an overlay descriptor `.md` into a structured ``ParsedOverlay``."""
    sections = _split_top_sections(text)
    _check_required_sections(sections)

    return ParsedOverlay(
        identity=_parse_identity(sections["Identity"]),
        messages=_parse_messages(sections["Messages"]),
        errors=_parse_errors(sections["Errors"]),
        dependencies=_parse_dependencies(sections["Dependencies"]),
        test_vectors=_parse_test_vectors(sections["Test Vectors"]),
    )


def _split_top_sections(text: str) -> dict[str, str]:
    """Split on level-1 (``# Heading``) markers, preserving body text."""
    sections: dict[str, str] = {}
    current_name: str | None = None
    current_lines: list[str] = []
    for line in text.split("\n"):
        if line.startswith("# ") and not line.startswith("## "):
            if current_name is not None:
                sections[current_name] = "\n".join(current_lines)
            current_name = line[2:].strip()
            current_lines = []
        else:
            current_lines.append(line)
    if current_name is not None:
        sections[current_name] = "\n".join(current_lines)
    return sections


def _check_required_sections(sections: dict[str, str]) -> None:
    missing = [s for s in REQUIRED_SECTIONS if s not in sections]
    if missing:
        raise ProtocolCompileError(f"missing required sections: {missing}")


_KV_RE = re.compile(r"^\s*-\s*([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.+?)\s*$")


def _parse_kv_list(body: str) -> dict[str, str]:
    """Parse ``- key: value`` bullet lines; ignore prose and table noise."""
    out: dict[str, str] = {}
    for line in body.split("\n"):
        m = _KV_RE.match(line)
        if m:
            out[m.group(1)] = m.group(2)
    return out


def _parse_identity(body: str) -> dict[str, str]:
    kv = _parse_kv_list(body)
    for required in ("name", "version", "description"):
        if required not in kv:
            raise ProtocolCompileError(f"# Identity missing key: {required!r}")
    return kv


def _parse_messages(body: str) -> list[MessageDef]:
    """Each ``## NAME`` header begins one message definition."""
    defs: list[MessageDef] = []
    msg_lines: list[str] = []
    msg_name: str | None = None

    def flush() -> None:
        if msg_name is not None:
            defs.append(_parse_one_message(msg_name, "\n".join(msg_lines)))

    for line in body.split("\n"):
        if line.startswith("## ") and not line.startswith("### "):
            flush()
            msg_name = line[3:].strip()
            msg_lines = []
        else:
            msg_lines.append(line)
    flush()

    if not defs:
        raise ProtocolCompileError("# Messages section contained no ## subheadings")

    seen: set[int] = set()
    for d in defs:
        if d.msg_id in seen:
            raise ProtocolCompileError(f"duplicate msg_id {d.msg_id} in # Messages")
        seen.add(d.msg_id)
    return defs


_MSGID_RE = re.compile(r"^\s*-\s*msg_id\s*:\s*(\d+)\s*$")


def _parse_one_message(name: str, body: str) -> MessageDef:
    if not re.match(r"^[A-Z][A-Z0-9_]*$", name):
        raise ProtocolCompileError(f"message name not SCREAMING_SNAKE_CASE: {name!r}")

    msg_id: int | None = None
    handler_lines: list[str] = []
    in_handler = False
    table_lines: list[str] = []
    in_table = False

    for line in body.split("\n"):
        if in_handler:
            handler_lines.append(line)
            continue
        if line.startswith("### Handler"):
            in_handler = True
            continue
        m = _MSGID_RE.match(line)
        if m:
            msg_id = int(m.group(1))
            continue
        if line.lstrip().startswith("|"):
            table_lines.append(line.strip())
            in_table = True
        elif in_table and line.strip() == "":
            in_table = False  # end of table

    if msg_id is None:
        raise ProtocolCompileError(f"message {name}: missing 'msg_id' bullet")
    if not 0 <= msg_id <= 255:
        raise ProtocolCompileError(f"message {name}: msg_id {msg_id} not in [0, 255]")
    if not table_lines:
        raise ProtocolCompileError(f"message {name}: missing wire-format table")

    fields = _parse_field_table(table_lines, name)
    return MessageDef(
        name=name,
        msg_id=msg_id,
        fields=fields,
        handler_text="\n".join(handler_lines).strip(),
    )


def _parse_field_table(table_lines: list[str], message_name: str) -> list[MessageField]:
    """Expects a 3-column markdown table (name | encoding | description)."""
    rows: list[list[str]] = []
    for ln in table_lines:
        cells = [c.strip() for c in ln.strip("|").split("|")]
        if len(cells) != 3:
            continue
        rows.append(cells)
    if len(rows) < 2:
        raise ProtocolCompileError(f"message {message_name}: table needs header + ≥1 data row")
    header = [c.lower() for c in rows[0]]
    if header != ["name", "encoding", "description"]:
        raise ProtocolCompileError(
            f"message {message_name}: table header must be name|encoding|description, got {header}"
        )

    fields: list[MessageField] = []
    seen_names: set[str] = set()
    for row in rows[1:]:
        if all(set(c) <= set("- ") for c in row):
            continue  # the |---|---|---| separator row
        name, enc, desc = row
        if not re.match(r"^[a-z][a-z0-9_]*$", name):
            raise ProtocolCompileError(
                f"message {message_name}: field name not snake_case: {name!r}"
            )
        if name in seen_names:
            raise ProtocolCompileError(
                f"message {message_name}: duplicate field name {name!r}"
            )
        seen_names.add(name)
        if enc not in ALLOWED_ENCODINGS:
            raise ProtocolCompileError(
                f"message {message_name}: encoding {enc!r} not in allowlist"
            )
        fields.append(MessageField(name=name, encoding=enc, description=desc))
    if not fields:
        raise ProtocolCompileError(f"message {message_name}: at least one field is required")
    return fields


def _parse_errors(body: str) -> list[dict[str, str]]:
    rows = []
    for line in body.split("\n"):
        ln = line.strip()
        if not ln.startswith("|"):
            continue
        cells = [c.strip() for c in ln.strip("|").split("|")]
        if len(cells) >= 3 and not all(set(c) <= set("- ") for c in cells):
            rows.append(cells)
    if len(rows) < 2:
        return []
    header = [c.lower() for c in rows[0]]
    if header[:3] != ["code", "name", "policy"]:
        raise ProtocolCompileError(
            f"# Errors table header must start with code|name|policy, got {header}"
        )
    return [dict(zip(header, row)) for row in rows[1:]]


def _parse_dependencies(body: str) -> list[str]:
    deps: list[str] = []
    for line in body.split("\n"):
        m = re.match(r"^\s*-\s*sha1\s*:\s*([0-9a-fA-F]+)", line)
        if m:
            deps.append(m.group(1).lower())
    return deps


_TV_FIELDS_RE = re.compile(r"^\s*-\s*fields:\s*(\{.*\})\s*$")
_TV_BYTES_RE = re.compile(r"^\s*bytes\s*:\s*(.+?)\s*$")


def _parse_test_vectors(body: str) -> list[TestVector]:
    """Each `## MSG_NAME` heading begins a block of `- fields:` / `bytes:` pairs."""
    vectors: list[TestVector] = []
    current_msg: str | None = None
    pending_fields: dict | None = None

    for line in body.split("\n"):
        if line.startswith("## ") and not line.startswith("### "):
            current_msg = line[3:].strip()
            pending_fields = None
            continue
        m = _TV_FIELDS_RE.match(line)
        if m:
            try:
                pending_fields = json.loads(m.group(1))
            except json.JSONDecodeError as exc:
                raise ProtocolCompileError(
                    f"# Test Vectors / {current_msg}: bad JSON in fields: {exc}"
                ) from exc
            continue
        m = _TV_BYTES_RE.match(line)
        if m and current_msg is not None and pending_fields is not None:
            hexstr = re.sub(r"\s+", "", m.group(1)).lower()
            try:
                bytes.fromhex(hexstr)
            except ValueError as exc:
                raise ProtocolCompileError(
                    f"# Test Vectors / {current_msg}: bad hex: {exc}"
                ) from exc
            vectors.append(TestVector(message=current_msg, fields=pending_fields, bytes_hex=hexstr))
            pending_fields = None
    if not vectors:
        raise ProtocolCompileError("# Test Vectors section produced no vectors")
    return vectors


# ---------------------------------------------------------------------------
# Schema validation (post-parse cross-checks)
# ---------------------------------------------------------------------------

def validate_schema(parsed: ParsedOverlay) -> None:
    """Cross-section consistency checks beyond per-section parsing."""
    msg_names = {m.name for m in parsed.messages}
    for tv in parsed.test_vectors:
        if tv.message not in msg_names:
            raise ProtocolCompileError(
                f"# Test Vectors references unknown message {tv.message!r}"
            )
    for err in parsed.errors:
        policy = err.get("policy", "")
        if policy.startswith("reply:"):
            target = policy.split(":", 1)[1]
            if target not in msg_names:
                raise ProtocolCompileError(
                    f"# Errors policy {policy!r} targets unknown message"
                )
    if "name" in parsed.identity and not re.match(r"^[a-z][a-z0-9_]*$", parsed.identity["name"]):
        raise ProtocolCompileError(
            f"# Identity name not snake_case: {parsed.identity['name']!r}"
        )


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """\
You are a strict Python code generator. Given a parsed IPv8 overlay
descriptor, you emit ONE Python module that defines:

  * One ``VariablePayload`` subclass per message (name = the message
    SCREAMING_SNAKE_CASE name + "Payload").
  * One ``GeneratedCommunity(Community, PeerObserver)`` subclass.

Constraints:

  * Emit Python source ONLY, with no commentary. Wrap the source in a
    triple-backtick fenced ```python ... ``` block.
  * Use exactly these imports (no others):
        from ipv8.community import Community, CommunitySettings
        from ipv8.lazy_community import lazy_wrapper
        from ipv8.messaging.lazy_payload import VariablePayload, vp_compile
        from ipv8.peer import Peer
        from ipv8.peerdiscovery.network import PeerObserver
  * Do NOT call eval/exec/open/__import__/subprocess/os.* and do NOT
    access __class__/__bases__/__dict__/__globals__/__builtins__.
  * The generated class MUST declare:
        community_id = bytes.fromhex("<the community_id_hex value given to you>")
  * For each message the user describes, emit a ``@vp_compile``-decorated
    ``VariablePayload`` subclass with the documented msg_id and a
    ``format_list`` derived from the field encodings using this map:
        uint8 -> "B", uint16-be -> "H", uint32-be -> "I", uint64-be -> "Q",
        bool -> "?", varlenH -> "varlenH", varlenH-utf8 -> "varlenH",
        varlenH-msgpack -> "varlenH", bytes20 -> "20s", bytes32 -> "32s".
  * For ``varlenH-utf8`` and ``varlenH-msgpack`` fields the wire
    representation is bytes; the handler is responsible for utf-8 / msgpack
    encoding at the boundary.
  * Register every message handler in ``__init__`` via
    ``self.add_message_handler(<PayloadCls>, self.<handler_name>)``.
  * For each message described, define a handler method
    ``on_<lowercase_msg_name>`` decorated with ``@lazy_wrapper(<PayloadCls>)``
    that implements the operational semantics from the descriptor.
  * Implement ``started`` to call ``self.network.add_peer_observer(self)``
    and define ``on_peer_added``/``on_peer_removed`` as no-ops unless the
    descriptor says otherwise.
"""


def _build_user_prompt(parsed: ParsedOverlay, community_id: bytes) -> str:
    cid_hex = community_id.hex()
    msgs_repr = []
    for m in parsed.messages:
        fields_repr = "\n".join(
            f"      - {f.name}: {f.encoding}  # {f.description}"
            for f in m.fields
        )
        msgs_repr.append(
            f"  * {m.name} (msg_id={m.msg_id})\n"
            f"    fields:\n{fields_repr}\n"
            f"    handler_semantics:\n      {m.handler_text}"
        )
    return (
        f"community_id_hex={cid_hex}\n"
        f"name={parsed.identity['name']}\n"
        f"version={parsed.identity['version']}\n"
        f"description={parsed.identity['description']}\n\n"
        f"Messages:\n" + "\n".join(msgs_repr) + "\n"
    )


# ---------------------------------------------------------------------------
# Code-fence stripping
# ---------------------------------------------------------------------------

_FENCE_RE = re.compile(r"^```(?:python)?\s*\n(.*?)\n```\s*$", re.DOTALL | re.MULTILINE)


def strip_code_fences(text: str) -> str:
    """If ``text`` is a fenced ```python ... ``` block, return the inner source."""
    m = _FENCE_RE.search(text)
    return m.group(1) if m else text


# ---------------------------------------------------------------------------
# Test-vector execution
# ---------------------------------------------------------------------------

def _payload_class_for(message_name: str, namespace: dict) -> Type:
    """Locate ``<MessageName>Payload`` (SCREAMING_SNAKE -> CamelCase)."""
    parts = message_name.split("_")
    camel = "".join(p.capitalize() for p in parts) + "Payload"
    if camel not in namespace:
        raise ProtocolCompileError(f"generated module is missing class {camel!r}")
    return namespace[camel]


def _coerce_field_value(value: Any) -> Any:
    """JSON test-vector values into the bytes/int the wire-format expects.

    `varlenH-utf8` declares Python type ``str`` but is wire-encoded as
    bytes (utf-8); `varlenH-msgpack` declares ``list``/``dict`` but is
    wire-encoded as msgpack. The `.md` test-vector lines write the human
    form (string, list, dict); the test harness coerces them here.
    """
    if isinstance(value, str):
        return value.encode("utf-8")
    if isinstance(value, (list, dict)):
        import msgpack
        return msgpack.packb(value, use_bin_type=True)
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    return value


def _run_test_vector(payload_cls: Type, tv: TestVector) -> None:
    from ipv8.messaging.serialization import default_serializer, PackError

    expected = bytes.fromhex(tv.bytes_hex)
    coerced = [_coerce_field_value(v) for v in tv.fields.values()]
    try:
        instance = payload_cls(*coerced)
        actual = default_serializer.pack_serializable(instance)
    except (PackError, TypeError, struct_error()) as exc:
        raise ProtocolCompileError(
            f"test vector encode failed for {tv.message}: {exc}"
        ) from exc

    if actual != expected:
        raise ProtocolCompileError(
            f"test vector encode mismatch for {tv.message}: "
            f"expected {expected.hex()}, got {actual.hex()}"
        )

    decoded, consumed = default_serializer.unpack_serializable(payload_cls, expected)
    if consumed != len(expected):
        raise ProtocolCompileError(
            f"test vector decode for {tv.message} left "
            f"{len(expected) - consumed} trailing bytes"
        )
    decoded_values = [getattr(decoded, name) for name in payload_cls.names]
    if decoded_values != coerced:
        raise ProtocolCompileError(
            f"test vector decode mismatch for {tv.message}: "
            f"expected {coerced!r}, got {decoded_values!r}"
        )


# ---------------------------------------------------------------------------
# Top-level entry
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CompiledOverlay:
    """A live overlay's metadata + payload classes, in one of two shapes.

    ``origin == "markdown"`` (v5.1 default): every field is populated.
    ``parsed`` is the rich schema parsed from the descriptor, and
    ``canonical_md_bytes`` holds the exact bytes that hashed to
    ``community_id``.

    ``origin == "python_class"`` (traditional hand-written Community):
    ``parsed`` is None and ``canonical_md_bytes`` is empty — there is
    no canonical text representation of a Python class. The tool
    surface uses ``origin`` to emit metadata-light overlay entries that
    omit the (absent) handler-text / description prose.
    """

    community_id: bytes
    parsed: Optional[ParsedOverlay]
    canonical_md_bytes: bytes
    community_class: Type
    payload_classes: dict[str, Type]
    source: str
    origin: str = "markdown"


def compile_overlay(md_text: str, llm: LLMClient) -> CompiledOverlay:
    """End-to-end compile of an overlay descriptor `.md` to an importable Community class."""
    parsed = parse_md(md_text)
    validate_schema(parsed)
    canonical = canonicalize_md(md_text)
    community_id = hashlib.sha1(canonical).digest()[:20]

    user_prompt = _build_user_prompt(parsed, community_id)
    raw = llm.complete(SYSTEM_PROMPT, user_prompt)
    source = strip_code_fences(raw).strip()

    try:
        ns = safe_exec(source)
    except SandboxError as exc:
        raise ProtocolCompileError(f"sandbox rejected generated source: {exc}") from exc

    if "GeneratedCommunity" not in ns:
        raise ProtocolCompileError("generated module is missing GeneratedCommunity")
    community_cls = ns["GeneratedCommunity"]

    declared = getattr(community_cls, "community_id", None)
    if declared != community_id:
        raise ProtocolCompileError(
            f"community_id mismatch: descriptor says {community_id.hex()}, "
            f"generated class says {(declared or b'').hex()}"
        )

    payload_classes: dict[str, Type] = {
        m.name: _payload_class_for(m.name, ns) for m in parsed.messages
    }

    for tv in parsed.test_vectors:
        _run_test_vector(payload_classes[tv.message], tv)

    return CompiledOverlay(
        community_id=community_id,
        parsed=parsed,
        canonical_md_bytes=canonical,
        community_class=community_cls,
        payload_classes=payload_classes,
        source=source,
    )
