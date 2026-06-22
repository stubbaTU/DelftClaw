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

import ast
import hashlib
import json
import re
import struct
from dataclasses import dataclass, field
from typing import Any, Optional, Type


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
OPTIONAL_SECTIONS = ("Runtime State", "Constants", "Tasks")

ALLOWED_LIFECYCLES = ("peer-observer", "passive")
DEFAULT_LIFECYCLE = "peer-observer"

# Type → zero-value Python initialiser the LLM is told to emit for
# `# Runtime State` slots. Element/inner types in `list[...]`/`dict[...]`
# are documentation only; the structural check only verifies the slot
# name is assigned in __init__.
_RUNTIME_STATE_ZERO_VALUE: dict[str, str] = {
    "int":   "0",
    "str":   '""',
    "bool":  "False",
    "bytes": 'b""',
    "list":  "[]",
    "dict":  "{}",
    "set":   "set()",
}

# JSON-decodable Python scalar types accepted in `# Constants` values.
_CONSTANT_PY_TYPES: dict[str, tuple[type, ...]] = {
    "int":   (int,),
    "float": (int, float),
    "bool":  (bool,),
    "str":   (str,),
    "bytes": (str,),       # bytes constants are hex-encoded in the .md
    "list":  (list,),
    "dict":  (dict,),
}

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
    # Schema v1.1 semantic encodings — wire-identical to the row above but
    # carry intent. The synthesizer's sample-coercion path knows to call
    # ``bytes.fromhex`` on string samples for hash20/hash32, so LLM authors
    # can describe hashes the way humans naturally do (40/64 hex chars)
    # instead of having to think in raw bytes. ``timestamp_unix`` is a pure
    # naming alias of ``uint64-be``; samples are integers.
    "hash20":          "20s",
    "hash32":          "32s",
    "timestamp_unix":  "Q",
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
class RuntimeStateSlot:
    """One public mutable attribute the generated class must initialise."""
    name: str                # snake_case
    type_str: str            # raw type as written in the .md (e.g. "list[dict]")
    base_type: str           # collapsed to "list" / "dict" / "int" / ...
    description: str


@dataclass
class ConstantDef:
    """One class-level tunable the generated class must declare."""
    name: str                # SCREAMING_SNAKE_CASE
    type_str: str
    base_type: str
    value: Any               # JSON-decoded literal
    description: str


@dataclass
class PeriodicTaskDef:
    """One ``self.register_task(...)`` call the generated class must perform."""
    name: str                # snake_case task name (first positional arg)
    interval_s: int          # interval= keyword value
    handler: str             # snake_case method name on the class
    description: str


@dataclass
class ParsedOverlay:
    identity: dict[str, str]
    messages: list[MessageDef]
    errors: list[dict[str, str]]
    dependencies: list[str]
    test_vectors: list[TestVector]
    runtime_state: list[RuntimeStateSlot] = field(default_factory=list)
    constants: list[ConstantDef] = field(default_factory=list)
    tasks: list[PeriodicTaskDef] = field(default_factory=list)
    lifecycle: str = DEFAULT_LIFECYCLE


def parse_md(text: str) -> ParsedOverlay:
    """Parse an overlay descriptor `.md` into a structured ``ParsedOverlay``."""
    sections = _split_top_sections(text)
    _check_required_sections(sections)

    identity = _parse_identity(sections["Identity"])
    return ParsedOverlay(
        identity=identity,
        messages=_parse_messages(sections["Messages"]),
        errors=_parse_errors(sections["Errors"]),
        dependencies=_parse_dependencies(sections["Dependencies"]),
        test_vectors=_parse_test_vectors(sections["Test Vectors"]),
        runtime_state=_parse_runtime_state(sections.get("Runtime State", "")),
        constants=_parse_constants(sections.get("Constants", "")),
        tasks=_parse_tasks(sections.get("Tasks", "")),
        lifecycle=identity.get("lifecycle", DEFAULT_LIFECYCLE),
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


_SUPERSEDES_RE = re.compile(r"^[0-9a-f]{40}$")


def _parse_identity(body: str) -> dict[str, str]:
    kv = _parse_kv_list(body)
    for required in ("name", "version", "description"):
        if required not in kv:
            raise ProtocolCompileError(f"# Identity missing key: {required!r}")
    if "lifecycle" in kv and kv["lifecycle"] not in ALLOWED_LIFECYCLES:
        raise ProtocolCompileError(
            f"# Identity lifecycle must be one of {ALLOWED_LIFECYCLES}, "
            f"got {kv['lifecycle']!r}"
        )
    # Optional evolution-provenance keys (v5.3). Carried in-band so that
    # ``community_id = sha1(canonical_md)`` stays content-pure while still
    # binding authorship + lineage into the spec bytes. All optional — a
    # spec with none of them is a fresh, anonymously-authored overlay.
    #   supersedes      — 40-char lowercase hex of the predecessor's
    #                     community_id (same overlay name, older version).
    #   author_id       — the authoring agent's wallet address (free-form
    #                     here; the wallet layer validates its own format).
    #   change_summary  — 1-2 sentence human description of what changed.
    if "supersedes" in kv and not _SUPERSEDES_RE.match(kv["supersedes"]):
        raise ProtocolCompileError(
            f"# Identity supersedes must be 40-char lowercase hex "
            f"(a community_id); got {kv['supersedes']!r}"
        )
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


_TYPE_BASE_RE = re.compile(r"^\s*([a-z]+)(?:\s*\[.*\])?\s*$")


def _base_type(type_str: str) -> str:
    """Strip generic parameters off a type — ``list[dict]`` → ``list``."""
    m = _TYPE_BASE_RE.match(type_str)
    if not m:
        return type_str.strip()
    return m.group(1)


def _parse_runtime_state(body: str) -> list[RuntimeStateSlot]:
    """Parse the optional `# Runtime State` table. Empty body → []."""
    rows = _collect_table_rows(body)
    if not rows:
        return []
    header = [c.lower() for c in rows[0]]
    if header[:3] != ["name", "type", "description"]:
        raise ProtocolCompileError(
            f"# Runtime State table header must be name|type|description, got {header}"
        )
    slots: list[RuntimeStateSlot] = []
    seen: set[str] = set()
    for row in rows[1:]:
        if all(set(c) <= set("- ") for c in row):
            continue
        name, type_str, description = row[0], row[1], row[2]
        if not re.match(r"^[a-z][a-z0-9_]*$", name):
            raise ProtocolCompileError(
                f"# Runtime State slot name not snake_case: {name!r}"
            )
        if name in seen:
            raise ProtocolCompileError(
                f"# Runtime State duplicate slot name: {name!r}"
            )
        seen.add(name)
        base = _base_type(type_str)
        if base not in _RUNTIME_STATE_ZERO_VALUE:
            allowed = ", ".join(sorted(_RUNTIME_STATE_ZERO_VALUE))
            raise ProtocolCompileError(
                f"# Runtime State slot {name!r} has unsupported type "
                f"{type_str!r}; allowed bases: {allowed}"
            )
        slots.append(RuntimeStateSlot(
            name=name, type_str=type_str, base_type=base, description=description,
        ))
    return slots


def _parse_constants(body: str) -> list[ConstantDef]:
    """Parse the optional `# Constants` table. Empty body → []."""
    rows = _collect_table_rows(body)
    if not rows:
        return []
    header = [c.lower() for c in rows[0]]
    if header[:4] != ["name", "type", "value", "description"]:
        raise ProtocolCompileError(
            f"# Constants table header must be name|type|value|description, got {header}"
        )
    consts: list[ConstantDef] = []
    seen: set[str] = set()
    for row in rows[1:]:
        if all(set(c) <= set("- ") for c in row):
            continue
        name, type_str, value_str, description = row[0], row[1], row[2], row[3]
        if not re.match(r"^[A-Z][A-Z0-9_]*$", name):
            raise ProtocolCompileError(
                f"# Constants name not SCREAMING_SNAKE_CASE: {name!r}"
            )
        if name in seen:
            raise ProtocolCompileError(f"# Constants duplicate name: {name!r}")
        seen.add(name)
        base = _base_type(type_str)
        if base not in _CONSTANT_PY_TYPES:
            allowed = ", ".join(sorted(_CONSTANT_PY_TYPES))
            raise ProtocolCompileError(
                f"# Constants {name!r} has unsupported type {type_str!r}; "
                f"allowed bases: {allowed}"
            )
        try:
            value = json.loads(value_str)
        except json.JSONDecodeError as exc:
            raise ProtocolCompileError(
                f"# Constants {name!r}: value {value_str!r} is not a JSON literal: {exc}"
            ) from exc
        if not isinstance(value, _CONSTANT_PY_TYPES[base]):
            raise ProtocolCompileError(
                f"# Constants {name!r}: value {value!r} is not a {base}"
            )
        consts.append(ConstantDef(
            name=name, type_str=type_str, base_type=base,
            value=value, description=description,
        ))
    return consts


def _parse_tasks(body: str) -> list[PeriodicTaskDef]:
    """Parse the optional `# Tasks` table. Empty body → []."""
    rows = _collect_table_rows(body)
    if not rows:
        return []
    header = [c.lower() for c in rows[0]]
    if header[:4] != ["name", "interval_s", "handler", "description"]:
        raise ProtocolCompileError(
            f"# Tasks table header must be name|interval_s|handler|description, "
            f"got {header}"
        )
    tasks: list[PeriodicTaskDef] = []
    seen_names: set[str] = set()
    seen_handlers: set[str] = set()
    for row in rows[1:]:
        if all(set(c) <= set("- ") for c in row):
            continue
        name, interval_s_str, handler, description = row[0], row[1], row[2], row[3]
        if not re.match(r"^[a-z][a-z0-9_]*$", name):
            raise ProtocolCompileError(
                f"# Tasks task name not snake_case: {name!r}"
            )
        if name in seen_names:
            raise ProtocolCompileError(f"# Tasks duplicate task name: {name!r}")
        seen_names.add(name)
        # Handler names follow Python's snake_case method convention,
        # which permits a single leading underscore for "private" methods
        # like ``_send_heartbeat`` (a common pattern when the method is
        # called only from inside the class).
        if not re.match(r"^_?[a-z][a-z0-9_]*$", handler):
            raise ProtocolCompileError(
                f"# Tasks handler name not snake_case: {handler!r}"
            )
        if handler in seen_handlers:
            raise ProtocolCompileError(
                f"# Tasks duplicate handler {handler!r} — each periodic task "
                f"needs its own method to avoid interval interference"
            )
        seen_handlers.add(handler)
        try:
            interval_s = int(interval_s_str)
        except ValueError as exc:
            raise ProtocolCompileError(
                f"# Tasks {name!r} interval_s {interval_s_str!r} is not an int: {exc}"
            ) from exc
        if interval_s <= 0:
            raise ProtocolCompileError(
                f"# Tasks {name!r} interval_s must be a positive integer (got {interval_s})"
            )
        tasks.append(PeriodicTaskDef(
            name=name, interval_s=interval_s, handler=handler, description=description,
        ))
    return tasks


def _collect_table_rows(body: str) -> list[list[str]]:
    """Walk a section body, return every markdown-table row as a cell list."""
    rows: list[list[str]] = []
    for line in body.split("\n"):
        ln = line.strip()
        if not ln.startswith("|"):
            continue
        cells = [c.strip() for c in ln.strip("|").split("|")]
        rows.append(cells)
    return rows


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

  * One ``VariablePayload`` subclass per message. Name it by converting the
    message's SCREAMING_SNAKE_CASE name to CamelCase and appending "Payload":
    SEARCH_REQUEST -> SearchRequestPayload, ECHO_RESPONSE -> EchoResponsePayload.
    Drop the underscores — ``SEARCH_REQUESTPayload`` (keeping them) is WRONG and
    will fail to compile.
  * One ``GeneratedCommunity`` subclass.

Constraints:

  * Emit Python source ONLY, with no commentary. Wrap the source in a
    triple-backtick fenced ```python ... ``` block.
  * Use ONLY these imports from ipv8:
        from ipv8.community import Community, CommunitySettings
        from ipv8.lazy_community import lazy_wrapper
        from ipv8.messaging.lazy_payload import VariablePayload, vp_compile
        from ipv8.peer import Peer
        from ipv8.peerdiscovery.network import PeerObserver
    You MAY additionally ``import msgpack``, ``import struct``, ``import
    hashlib``, and/or ``import time`` when a handler needs them. In particular,
    ``import msgpack`` whenever the descriptor declares any ``varlenH-msgpack``
    field, ``import hashlib`` whenever a handler must compute or verify a hash
    (e.g. ``hashlib.sha256(data).digest()`` or ``hashlib.sha1(md).digest()[:20]``),
    and ``import time`` when a handler needs a current timestamp
    (e.g. ``int(time.time())``). No other imports are permitted by the sandbox.
  * Do NOT call eval/exec/open/__import__/subprocess/os.* and do NOT
    access __class__/__bases__/__dict__/__globals__/__builtins__.
  * The generated class MUST declare:
        community_id = bytes.fromhex("<the community_id_hex value given to you>")
  * For each message the user describes, emit a ``@vp_compile``-decorated
    ``VariablePayload`` subclass declaring EXACTLY these three class
    attributes — and do NOT write an ``__init__`` (``@vp_compile`` generates
    the constructor from ``names``; a hand-written ``__init__`` breaks it):
        msg_id      = <the documented msg_id>
        format_list = [<one entry per field, in declared order>]
        names       = [<the field-name strings, same order, same length
                        as format_list>]
    Map each field's encoding to its ``format_list`` entry using this map:
        uint8 -> "B", uint16-be -> "H", uint32-be -> "I", uint64-be -> "Q",
        bool -> "?", varlenH -> "varlenH", varlenH-utf8 -> "varlenH",
        varlenH-msgpack -> "varlenH", bytes20 -> "20s", bytes32 -> "32s",
        hash20 -> "20s", hash32 -> "32s", timestamp_unix -> "Q".
    Notes on the semantic encodings (wire-identical to a primitive above
    but carry intent for handler-prose generation):
      * hash20 / hash32 are 20-/32-byte raw hashes on the wire; samples for
        these are HEX STRINGS (40 / 64 chars), which the synthesizer converts.
      * timestamp_unix is a uint64 holding seconds since 1970-01-01 UTC;
        samples are integers (e.g. ``int(time.time())`` values).
    ``names`` MUST have exactly as many entries as ``format_list``; omitting
    it (or leaving it short) makes ``@vp_compile`` raise IndexError at
    import time. Construct instances positionally, e.g.
    ``SearchResponsePayload(results_bytes)``.
  * For ``varlenH-utf8`` and ``varlenH-msgpack`` fields the wire
    representation is bytes; the handler does the boundary conversion:
    ``value.encode("utf-8")`` / ``payload_bytes.decode("utf-8")`` for utf-8,
    and ``msgpack.packb(value, use_bin_type=True)`` /
    ``msgpack.unpackb(payload_bytes, raw=False)`` for msgpack.
  * Register every message handler in ``__init__`` via
    ``self.add_message_handler(<PayloadCls>, self.<handler_name>)``.
  * For each message described, define a handler method
    ``on_<lowercase_msg_name>`` decorated with ``@lazy_wrapper(<PayloadCls>)``
    that implements the operational semantics from the descriptor.
  * To SEND a message to a peer, call
    ``self.ez_send(peer, <PayloadCls>(...))`` — construct the payload inline.
    This is the ONLY send primitive; it is provided by ``Community``. Do NOT
    call ``ez_send_to``, ``send_message``, ``self.send`` or any other name —
    they do not exist and will raise ``AttributeError`` at runtime.

Lifecycle (driven by the descriptor's ``lifecycle`` key in ``# Identity``):

  * ``lifecycle: peer-observer`` (default) — subclass BOTH ``Community``
    and ``PeerObserver``. Define ``started(self)`` calling
    ``self.network.add_peer_observer(self)``. Define
    ``on_peer_added(self, peer)`` and ``on_peer_removed(self, peer)``
    as no-ops unless the descriptor's handler prose specifies behaviour.
  * ``lifecycle: passive`` — subclass ``Community`` only; do NOT mix in
    ``PeerObserver`` and do NOT define peer observer methods.

Runtime State (the descriptor's ``# Runtime State`` table):

  * In ``GeneratedCommunity.__init__`` (after ``super().__init__(...)``),
    initialise EVERY listed slot via ``self.<name> = <zero-value>`` where
    the zero-value is decided by the slot's base type:
        list  -> []           dict  -> {}           set   -> set()
        int   -> 0            str   -> ""           bool  -> False
        bytes -> b""
    Initialise these BEFORE registering message handlers so handlers
    that fire on the same tick see consistent state. Do not add any
    runtime-state slot that is not listed in the descriptor.

Constants (the descriptor's ``# Constants`` table):

  * For every listed constant, declare it at class scope (NOT inside
    ``__init__``) as ``<NAME> = <literal>``. Use the literal value
    exactly as given. Constants come before ``__init__`` in source
    order.

Tasks (the descriptor's ``# Tasks`` table):

  * For every listed task, add a call inside ``__init__`` of the exact
    shape ``self.register_task("<name>", self.<handler>,
    interval=<interval_s>)``. The task name is a string literal (NOT
    an f-string, NOT a variable). The handler is a method on this
    class — define it (as ``def`` or ``async def``, taking ``self``
    only) somewhere in the class body and let it implement the
    descriptor's task description prose. ``register_task`` is provided
    by ``Community`` via its ``TaskManager`` mixin; do NOT import
    anything new for it.
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
    parts = [
        f"community_id_hex={cid_hex}",
        f"name={parsed.identity['name']}",
        f"version={parsed.identity['version']}",
        f"description={parsed.identity['description']}",
        f"lifecycle={parsed.lifecycle}",
        "",
        "Messages:",
        "\n".join(msgs_repr),
    ]
    if parsed.constants:
        const_lines = [
            f"  * {c.name}: {c.type_str} = {json.dumps(c.value)}  # {c.description}"
            for c in parsed.constants
        ]
        parts.extend(["", "Constants (declare at class scope):", "\n".join(const_lines)])
    if parsed.runtime_state:
        state_lines = [
            f"  * self.{s.name} = {_RUNTIME_STATE_ZERO_VALUE[s.base_type]}  "
            f"# {s.type_str} — {s.description}"
            for s in parsed.runtime_state
        ]
        parts.extend([
            "",
            "Runtime state (initialise in __init__ after super().__init__):",
            "\n".join(state_lines),
        ])
    if parsed.tasks:
        task_lines = [
            f'  * self.register_task("{t.name}", self.{t.handler}, '
            f"interval={t.interval_s})  # {t.description}"
            for t in parsed.tasks
        ]
        parts.extend([
            "",
            "Periodic tasks (register in __init__; each handler is a method on the class):",
            "\n".join(task_lines),
        ])
    return "\n".join(parts) + "\n"


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

def _payload_class_for(message: MessageDef, namespace: dict) -> Type:
    """Locate the generated ``VariablePayload`` subclass for ``message``.

    Matches by ``msg_id`` first — the canonical wire identifier, which the
    descriptor's test vectors independently validate — so the lookup is robust
    to however the LLM named the class (``SearchRequestPayload`` vs the literal
    ``SEARCH_REQUESTPayload`` some models emit). Falls back to the documented
    CamelCase name (``SEARCH_REQUEST`` -> ``SearchRequestPayload``) when no
    msg_id match is found.
    """
    from ipv8.messaging.lazy_payload import VariablePayload

    by_id = [
        v for v in namespace.values()
        if isinstance(v, type)
        and issubclass(v, VariablePayload)
        and v is not VariablePayload
        and getattr(v, "msg_id", None) == message.msg_id
    ]
    if len(by_id) == 1:
        return by_id[0]

    camel = "".join(p.capitalize() for p in message.name.split("_")) + "Payload"
    if camel in namespace:
        return namespace[camel]

    if len(by_id) > 1:
        raise ProtocolCompileError(
            f"message {message.name}: {len(by_id)} payload classes declare "
            f"msg_id {message.msg_id}; cannot disambiguate"
        )
    raise ProtocolCompileError(
        f"message {message.name}: generated module has no VariablePayload "
        f"subclass with msg_id {message.msg_id}, and no class named {camel!r}"
    )


def _coerce_field_value(value: Any, encoding: str | None = None) -> Any:
    """JSON test-vector values into the bytes/int the wire-format expects.

    `varlenH-utf8` declares Python type ``str`` but is wire-encoded as
    bytes (utf-8); `varlenH-msgpack` declares ``list``/``dict`` but is
    wire-encoded as msgpack. The `.md` test-vector lines write the human
    form (string, list, dict); the test harness coerces them here.

    ``encoding`` (optional, schema v1.1+) tells the coercer the field's
    declared encoding so it can branch on the ergonomic semantic encodings
    that share a wire format with a primitive one. Currently:

      * ``hash20`` / ``hash32`` — string input is treated as hex
        (``bytes.fromhex(value)``) so LLM-authored samples can be 40/64-char
        hex strings the way humans describe hashes. Wire-identical to
        ``bytes20`` / ``bytes32``.

    Pre-v1.1 callers (no ``encoding`` arg) keep the original behaviour —
    strings become utf-8 bytes, exactly as before.
    """
    if encoding in ("hash20", "hash32") and isinstance(value, str):
        try:
            return bytes.fromhex(value)
        except ValueError as exc:
            raise ProtocolCompileError(
                f"{encoding} sample must be a hex string "
                f"({'40' if encoding == 'hash20' else '64'} chars); got {value!r} ({exc})"
            ) from exc
    if isinstance(value, str):
        return value.encode("utf-8")
    if isinstance(value, (list, dict)):
        import msgpack
        return msgpack.packb(value, use_bin_type=True)
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    return value


def _run_test_vector(payload_cls: Type, tv: TestVector, encodings: list[str] | None = None) -> None:
    from ipv8.messaging.serialization import default_serializer, PackError

    expected = bytes.fromhex(tv.bytes_hex)
    # ``encodings`` aligns with tv.fields.values() by position; when the
    # caller passes it (the v1.1 compile path always does) we route the
    # ergonomic encodings through the hex-aware coercion branch.
    field_values = list(tv.fields.values())
    if encodings is not None and len(encodings) == len(field_values):
        coerced = [_coerce_field_value(v, enc) for v, enc in zip(field_values, encodings)]
    else:
        coerced = [_coerce_field_value(v) for v in field_values]
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
# Structural check (constants + runtime state + lifecycle)
# ---------------------------------------------------------------------------

def _init_self_assignments(
    source: str,
    class_name: str = "GeneratedCommunity",
    *,
    tree: ast.AST | None = None,
) -> set[str]:
    """Walk ``source``'s AST, return the set of names ``X`` assigned via
    ``self.X = ...`` (any kind of assignment) anywhere inside
    ``<class_name>.__init__``.

    The AST whitelist has already run; this is just structural
    introspection on trusted-ish source. Accepts a pre-parsed ``tree``
    so ``_check_structural_contract`` can parse once and reuse.
    """
    if tree is None:
        try:
            tree = ast.parse(source)
        except SyntaxError as exc:
            raise ProtocolCompileError(f"cannot AST-parse generated source: {exc}") from exc

    init_body: list[ast.stmt] | None = None
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == "__init__":
                    init_body = item.body
                    break
            break

    names: set[str] = set()
    if init_body is None:
        return names

    def _record(target: ast.AST) -> None:
        if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) and target.value.id == "self":
            names.add(target.attr)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                _record(elt)

    for stmt in ast.walk(ast.Module(body=init_body, type_ignores=[])):
        if isinstance(stmt, ast.Assign):
            for t in stmt.targets:
                _record(t)
        elif isinstance(stmt, (ast.AugAssign, ast.AnnAssign)):
            _record(stmt.target)
    return names


def _init_register_task_calls(
    source: str,
    class_name: str = "GeneratedCommunity",
    *,
    tree: ast.AST | None = None,
) -> list[dict]:
    """Walk ``source``'s AST, return one record per ``self.register_task(...)``
    call inside ``<class_name>.__init__``.

    Each record: ``{"name": <str|None>, "handler": <str|None>, "interval_s": <int|None>}``.
    Fields are ``None`` if they couldn't be statically extracted (e.g. a
    non-literal task name or a handler that wasn't ``self.<attr>``); the
    structural check treats missing fields as a no-match. Accepts a
    pre-parsed ``tree`` for caller-side reuse.
    """
    if tree is None:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return []

    init_body: list[ast.stmt] | None = None
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == "__init__":
                    init_body = item.body
                    break
            break
    if init_body is None:
        return []

    out: list[dict] = []
    for stmt in ast.walk(ast.Module(body=init_body, type_ignores=[])):
        if not isinstance(stmt, ast.Call):
            continue
        # self.register_task(...)
        fn = stmt.func
        if not (
            isinstance(fn, ast.Attribute)
            and fn.attr == "register_task"
            and isinstance(fn.value, ast.Name)
            and fn.value.id == "self"
        ):
            continue
        # First positional arg = task name string literal
        name_val: str | None = None
        if stmt.args:
            first = stmt.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                name_val = first.value
        # Second positional arg = self.<handler> bound method reference
        handler_val: str | None = None
        if len(stmt.args) >= 2:
            second = stmt.args[1]
            if (
                isinstance(second, ast.Attribute)
                and isinstance(second.value, ast.Name)
                and second.value.id == "self"
            ):
                handler_val = second.attr
        # interval=<int> keyword
        interval_val: int | None = None
        for kw in stmt.keywords:
            if kw.arg == "interval" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, (int, float)):
                interval_val = int(kw.value.value)
                break
        out.append({"name": name_val, "handler": handler_val, "interval_s": interval_val})
    return out


def _class_bases(
    source: str,
    class_name: str = "GeneratedCommunity",
    *,
    tree: ast.AST | None = None,
) -> set[str]:
    """Return the base-class names referenced by ``class_name``'s definition.

    Accepts a pre-parsed ``tree`` for caller-side reuse.
    """
    if tree is None:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return set()
    bases: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            for b in node.bases:
                if isinstance(b, ast.Name):
                    bases.add(b.id)
                elif isinstance(b, ast.Attribute):
                    bases.add(b.attr)
            break
    return bases


def _check_structural_contract(
    parsed: ParsedOverlay,
    community_cls: type,
    source: str,
    *,
    class_name: str = "GeneratedCommunity",
) -> None:
    """Enforce the schema's `# Constants` / `# Runtime State` / lifecycle clauses.

    ``class_name`` is the actual community class name in ``source`` (which may
    differ from the documented ``GeneratedCommunity`` — the name carries no
    wire significance), so the AST-introspection helpers locate the right
    ``ClassDef``.
    """

    # Parse the AST once and reuse across the three structural helpers.
    # Each helper used to call ``ast.parse(source)`` independently — that
    # tripled the parse cost on every overlay compile.
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        raise ProtocolCompileError(f"cannot AST-parse generated source: {exc}") from exc

    # 1. Constants — must exist at class level with the declared value.
    for c in parsed.constants:
        if not hasattr(community_cls, c.name):
            raise ProtocolCompileError(
                f"generated class is missing constant {c.name!r} "
                f"(declared in # Constants)"
            )
        actual = getattr(community_cls, c.name)
        if actual != c.value:
            raise ProtocolCompileError(
                f"constant {c.name!r} value mismatch: descriptor declares "
                f"{c.value!r}, generated class has {actual!r}"
            )

    # 2. Runtime state — every slot must be assigned in __init__.
    if parsed.runtime_state:
        assigned = _init_self_assignments(source, class_name, tree=tree)
        missing = [s.name for s in parsed.runtime_state if s.name not in assigned]
        if missing:
            raise ProtocolCompileError(
                f"generated __init__ does not assign these # Runtime State "
                f"slots: {missing}"
            )

    # 3. Periodic tasks — every declared task must have a matching
    # `self.register_task("name", self.handler, interval=N)` in __init__,
    # and the handler method must exist on the class.
    if parsed.tasks:
        registered = _init_register_task_calls(source, class_name, tree=tree)
        for task in parsed.tasks:
            match = next(
                (
                    r for r in registered
                    if r["name"] == task.name
                    and r["handler"] == task.handler
                    and r["interval_s"] == task.interval_s
                ),
                None,
            )
            if match is None:
                raise ProtocolCompileError(
                    f"# Tasks task {task.name!r} has no matching "
                    f"self.register_task({task.name!r}, self.{task.handler}, "
                    f"interval={task.interval_s}) call in __init__"
                )
            if not callable(getattr(community_cls, task.handler, None)):
                raise ProtocolCompileError(
                    f"# Tasks task {task.name!r} references handler "
                    f"method {task.handler!r} which is not callable on the class"
                )

    # 4. Lifecycle — peer-observer must subclass PeerObserver and define
    # the three hooks; passive must NOT subclass PeerObserver.
    bases = _class_bases(source, class_name, tree=tree)
    if parsed.lifecycle == "peer-observer":
        if "PeerObserver" not in bases:
            raise ProtocolCompileError(
                "lifecycle is peer-observer but generated class does not "
                "subclass PeerObserver"
            )
        for hook in ("started", "on_peer_added", "on_peer_removed"):
            if not callable(getattr(community_cls, hook, None)):
                raise ProtocolCompileError(
                    f"lifecycle is peer-observer but generated class is "
                    f"missing method {hook!r}"
                )
    elif parsed.lifecycle == "passive":
        if "PeerObserver" in bases:
            raise ProtocolCompileError(
                "lifecycle is passive but generated class subclasses "
                "PeerObserver"
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
    # Populated only when compile_overlay runs with defer_vector_check=True
    # (the SQ3 measurement path). ``None`` means vectors were enforced inline
    # and a failure would have raised — the default, deployed behavior.
    test_vectors_passed: Optional[bool] = None
    test_vector_error: Optional[str] = None


def compile_overlay(
    md_text: str,
    llm: LLMClient,
    *,
    llm_source: str | None = None,
    defer_vector_check: bool = False,
) -> CompiledOverlay:
    """End-to-end compile of an overlay descriptor `.md` to an importable Community class.

    When ``llm_source`` is provided (e.g. from the registry's disk
    cache), the LLM round-trip is skipped and that source is used in
    its place. All downstream safety gates (sandbox AST whitelist,
    structural-contract check, test vectors) still run unchanged —
    those are the wire-safety boundary, not the cache.

    When ``defer_vector_check`` is True (the SQ3 measurement path), a
    test-vector failure is recorded on the returned ``CompiledOverlay``
    (``test_vectors_passed`` / ``test_vector_error``) instead of raising.
    This lets a caller measure "code loaded and validated" separately from
    "test vectors passed". The default (False) preserves the deployed
    behavior: a vector mismatch raises ``ProtocolCompileError`` before any
    overlay is returned. The earlier gates (sandbox, structural contract,
    community_id match) always raise regardless of this flag.
    """
    parsed = parse_md(md_text)
    validate_schema(parsed)
    canonical = canonicalize_md(md_text)
    community_id = hashlib.sha1(canonical).digest()[:20]

    if llm_source is None:
        user_prompt = _build_user_prompt(parsed, community_id)
        raw = llm.complete(SYSTEM_PROMPT, user_prompt)
        source = strip_code_fences(raw).strip()
    else:
        source = strip_code_fences(llm_source).strip()

    try:
        ns = safe_exec(source)
    except SandboxError as exc:
        raise ProtocolCompileError(f"sandbox rejected generated source: {exc}") from exc

    # Locate the community class. Its name is a convention with no wire
    # significance --- P6 identity is the community_id --- so prefer the
    # documented ``GeneratedCommunity`` but accept any class declaring the
    # expected community_id (some models name it after the protocol, e.g.
    # ``ContentCommunity``). The community_id itself stays strictly enforced.
    community_cls = ns.get("GeneratedCommunity")
    if community_cls is None:
        candidates = [
            v for v in ns.values()
            if isinstance(v, type) and getattr(v, "community_id", None) == community_id
        ]
        if len(candidates) == 1:
            community_cls = candidates[0]
        elif len(candidates) > 1:
            names = ", ".join(sorted(c.__name__ for c in candidates))
            raise ProtocolCompileError(
                f"ambiguous community class: multiple classes declare "
                f"community_id {community_id.hex()} ({names})"
            )
        else:
            raise ProtocolCompileError(
                "generated module defines no class named GeneratedCommunity "
                f"nor any class declaring community_id {community_id.hex()}"
            )

    declared = getattr(community_cls, "community_id", None)
    if declared != community_id:
        raise ProtocolCompileError(
            f"community_id mismatch: descriptor says {community_id.hex()}, "
            f"generated class says {(declared or b'').hex()}"
        )

    _check_structural_contract(
        parsed, community_cls, source, class_name=community_cls.__name__,
    )

    payload_classes: dict[str, Type] = {
        m.name: _payload_class_for(m, ns) for m in parsed.messages
    }
    # Map each message to the ordered list of its field encodings so the
    # test-vector runner can apply the v1.1 semantic-encoding coercions
    # (e.g. hash20 hex-string -> raw bytes).
    field_encodings_by_msg: dict[str, list[str]] = {
        m.name: [f.encoding for f in m.fields] for m in parsed.messages
    }

    tv_passed: Optional[bool] = None
    tv_error: Optional[str] = None
    if defer_vector_check:
        # SQ3 path: record conformance as an observation rather than raising,
        # so the caller can separate "code loaded" from "test vectors passed".
        tv_passed = True
        for tv in parsed.test_vectors:
            try:
                _run_test_vector(
                    payload_classes[tv.message], tv,
                    field_encodings_by_msg.get(tv.message),
                )
            except Exception as exc:  # noqa: BLE001
                tv_passed = False
                tv_error = f"{type(exc).__name__}: {str(exc)[:300]}"
                break
    else:
        # Default, deployed path: a vector mismatch is a hard compile error.
        for tv in parsed.test_vectors:
            _run_test_vector(
                payload_classes[tv.message], tv,
                field_encodings_by_msg.get(tv.message),
            )

    return CompiledOverlay(
        community_id=community_id,
        parsed=parsed,
        canonical_md_bytes=canonical,
        community_class=community_cls,
        payload_classes=payload_classes,
        source=source,
        test_vectors_passed=tv_passed,
        test_vector_error=tv_error,
    )
