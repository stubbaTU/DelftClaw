"""Flow B row 1 — turning a prose goal into a protocol document.

In a live run an agent **authors** an overlay mid-session from a goal in prose: it
invents the messages, picks an encoding per field, writes the handler logic in
prose, and supplies samples; ``agent.overlay_authoring`` synthesizes the
byte-exact ``.md``. This module reproduces exactly that step as a measurement
primitive — ``author_document`` — leaving the downstream faithfulness gate
(``sq3.faithfulness``), compilation (``sq3.outcomes``), and reference-free
adoption interop (``sq3.adoption``) to the runner.

The authoring prompt mirrors the deployed agent's ``overlay_author_and_publish``
tool schema (``agent/tools.py::P_AUTHOR_OVERLAY``), including the same encoding
menu, so the measurement faces the same design surface the agent does.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from protocol.compiler import ProtocolCompileError, parse_md
from protocol.llm import LLMClient

from agent.overlay_authoring import OverlayAuthoringError, synthesize_overlay_markdown


# ---------------------------------------------------------------------------
# The authoring task: what the model is asked to design, in prose
# ---------------------------------------------------------------------------
#
# Descriptions name the BEHAVIOUR and the data each message carries, but leave
# the encoding choice, message structure, handler wording, and samples to the
# model, exactly as a mission goal does. They climb the same complexity ladder
# as the protocols the channel actually uses.

DESCRIPTIONS: dict[str, str] = {
    "echo": (
        "An echo protocol. One peer sends a short text message; the receiver "
        "replies with the same text but with an exclamation mark appended, and "
        "keeps a list of the replies it has received."
    ),
    "content_community": (
        "A file-search protocol. One peer sends a search query (a text term). "
        "The receiver searches a local catalogue of items it advertises, where "
        "each item has a magnet link, a name, a size in bytes, and a content "
        "type, and replies with the matching items, matched case-insensitively "
        "on the name, up to a fixed maximum, as a single structured list. The "
        "requester caches the result lists it receives."
    ),
    "payment": (
        "A payment-request protocol. A peer can: ask another peer for a payment "
        "(an amount in satoshis plus a short memo); offer an unsolicited "
        "payment (amount plus memo); notify that a payment was sent (amount plus "
        "a transaction id string); or decline a request (with a short reason). "
        "The receiver keeps pending requests keyed by the requester so a "
        "duplicate request from the same peer is ignored, and records the "
        "offers, notifications, and declines it receives."
    ),
    "file_transfer": (
        "A chunked file-transfer protocol. A fetcher requests content by a "
        "20-byte content id. The seeder replies with a manifest carrying the "
        "content id, the total number of chunks, and a 32-byte content hash, "
        "then streams the content as numbered chunks, each carrying the content "
        "id, a sequence number, and the chunk bytes. The fetcher buffers the "
        "chunks, tolerating out-of-order and duplicate arrival, reassembles "
        "them in sequence order, verifies the reassembled content against the "
        "announced hash, and records whether the transfer succeeded."
    ),
}

# Ladder order, simplest first.
RUNG_ORDER: tuple[str, ...] = ("echo", "content_community", "payment", "file_transfer")


AUTHORING_SYSTEM = """\
You are designing a peer-to-peer wire protocol that will run as an IPv8 overlay
community. Given a description of what the protocol must do, output a JSON object
specifying its messages and fields. A tool turns your JSON into a formal protocol
document and compiles it. Output ONLY one JSON object, with no prose and no code
fences:

{
  "name": "<snake_case name>",
  "version": "1.0.0",
  "description": "<one line>",
  "change_summary": "<one line>",
  "messages": [
    {"name": "<SCREAMING_SNAKE_CASE>", "msg_id": <unique integer 1..255>,
     "fields": [{"name": "<snake_case>", "encoding": "<allowed encoding>",
                 "description": "<short>"}],
     "handler": "<prose: what the receiver does on receipt; name the runtime_state it updates>"}
  ],
  "runtime_state": [{"name": "<snake_case>", "type": "list[dict]|dict|int|str|bool|set",
                     "description": "<short>"}],
  "samples": {"<MESSAGE_NAME>": {"<field>": <example value>}}
}

Allowed encodings (use EXACTLY these strings):
  uint8, uint16-be, uint32-be, uint64-be   unsigned integers
  bool
  varlenH-utf8        a UTF-8 text string
  varlenH-msgpack     a list or a dict
  varlenH             raw variable-length bytes
  bytes20, bytes32    fixed 20- or 32-byte raw byte strings
  hash20, hash32      20-/32-byte hashes; samples are 40-/64-char hex strings

For every message give a realistic sample in "samples": a string for
varlenH-utf8, an integer for uint*, a list or dict for varlenH-msgpack, a 20- or
32-character string for bytes20/bytes32, a hex string for hash20/hash32. Declare
a runtime_state entry for every list or dict a handler appends to or reads.
"""


class AuthoringParseError(ValueError):
    """The model's authoring response could not be parsed into args."""


def _extract_json_object(text: str) -> str:
    """Pull the first ``{...}`` JSON object out of a model response, tolerating
    code fences and surrounding prose."""
    t = text.strip()
    if t.startswith("```"):
        body = t[3:]
        if body[:4].lower() == "json":
            body = body[4:]
        t = body.split("```", 1)[0]
    i, j = t.find("{"), t.rfind("}")
    if i == -1 or j == -1 or j < i:
        raise AuthoringParseError("no JSON object in response")
    return t[i : j + 1]


def parse_authoring_args(raw: str) -> dict[str, Any]:
    """Parse + minimally validate a model authoring response into args for
    ``synthesize_overlay_markdown``. Raises ``AuthoringParseError`` if the
    response is not a usable tool call (itself a row-1 failure)."""
    try:
        args = json.loads(_extract_json_object(raw))
    except (json.JSONDecodeError, AuthoringParseError) as exc:
        raise AuthoringParseError(f"json: {exc}") from exc
    if not isinstance(args, dict):
        raise AuthoringParseError("top level is not an object")
    for key in ("name", "messages"):
        if key not in args:
            raise AuthoringParseError(f"missing required key {key!r}")
    if not isinstance(args["messages"], list) or not args["messages"]:
        raise AuthoringParseError("messages must be a non-empty list")
    return args


def build_authoring_prompt(description: str) -> str:
    """The user-side prompt for a genesis (from-scratch) task: the goal in prose."""
    return f"Design a protocol for the following requirement.\n\n{description}"


def _render_base_spec(parsed: Any) -> str:
    """Render a v1.0.0 base spec as compact prose for an evolution prompt."""
    ident = parsed.identity
    lines = [
        f"Protocol name: {ident.get('name')}  (version {ident.get('version', '1.0.0')})",
        f"Purpose: {ident.get('description', '')}",
        "Messages:",
    ]
    for m in parsed.messages:
        lines.append(f"  - {m.name} (msg_id {m.msg_id}):")
        for f in m.fields:
            lines.append(f"      {f.name}: {f.encoding}  ({f.description})")
        if getattr(m, "handler_text", ""):
            lines.append(f"      handler: {m.handler_text.strip()[:200]}")
    if parsed.runtime_state:
        lines.append("Runtime state:")
        for s in parsed.runtime_state:
            lines.append(f"  - {s.name}: {s.type_str}  ({s.description})")
    return "\n".join(lines)


def build_evolution_prompt(parsed: Any) -> str:
    """The user-side prompt for an evolution task: a fixed v1.0.0 base spec plus
    the instruction to design v1.1.0 by adding exactly one new field (charlie's
    mission). Mirrors the demo's autonomous-evolution step."""
    base = _render_base_spec(parsed)
    return (
        "Here is version 1.0.0 of an existing protocol:\n\n"
        f"{base}\n\n"
        "Design version 1.1.0 of this SAME protocol. Add EXACTLY ONE new, useful "
        "field to one of its messages (you choose which message and what field "
        "would help: a timestamp, a status flag, an integrity value, a counter, "
        "and so on). Keep every existing message and every existing field with "
        "the same name, encoding, and order, and append your new field after "
        "that message's existing fields. Keep the same runtime_state. Output the "
        "FULL version 1.1.0 args: all messages with all their fields (the "
        "originals plus your one new field), and a sample per message that "
        "includes a value for your new field."
    )


# ---------------------------------------------------------------------------
# author_document — one authoring step (Flow B row 1)
# ---------------------------------------------------------------------------

@dataclass
class AuthoredDoc:
    """The outcome of one authoring step. ``ok`` means a parseable, synthesizable
    document was produced; ``parsed`` is its ``ParsedOverlay``. A non-ok result
    carries the authoring error (a row-1 failure). Infrastructure errors are NOT
    caught here — they propagate so the runner classifies them as infra."""
    ok: bool
    rung: str
    task_type: str
    md: str | None = None
    parsed: Any | None = None
    name: str | None = None
    error: str | None = None


def author_prompt_for(rung: str, task_type: str, base_parsed: Any | None) -> str:
    """The user prompt for ``(rung, task_type)``. Evolution needs the rung's
    parsed v1.0.0 base."""
    if task_type == "evolution":
        if base_parsed is None:
            raise ValueError("evolution authoring requires a base spec")
        return build_evolution_prompt(base_parsed)
    return build_authoring_prompt(DESCRIPTIONS[rung])


def author_document(
    rung: str,
    client: LLMClient,
    *,
    task_type: str = "genesis",
    base_parsed: Any | None = None,
    base_community_id_hex: str | None = None,
) -> AuthoredDoc:
    """Author one document for ``rung``. Calls the model (infra errors propagate),
    then parses + synthesizes; authoring/synthesis faults fold into ``ok=False``.

    For evolution, ``base_parsed`` (the fixed v1.0.0 spec) and its
    ``base_community_id_hex`` are injected so the document takes the base's name
    and a 1.1.0 lineage and the trial isolates the field-design step."""
    forced_name = base_parsed.identity.get("name") if task_type == "evolution" else None
    forced_version = "1.1.0" if task_type == "evolution" else None
    forced_supersedes = base_community_id_hex if task_type == "evolution" else None

    user_prompt = author_prompt_for(rung, task_type, base_parsed)
    raw = client.complete(AUTHORING_SYSTEM, user_prompt)  # infra errors propagate
    try:
        args = parse_authoring_args(raw)
        md = synthesize_overlay_markdown(
            name=forced_name or str(args["name"]),
            version=forced_version or str(args.get("version", "1.0.0")),
            description=str(args.get("description", "")),
            messages=args["messages"],
            runtime_state=args.get("runtime_state"),
            constants=args.get("constants"),
            samples=args.get("samples"),
            change_summary=str(args.get("change_summary", "")),
            supersedes=forced_supersedes,
            author_id="dclaw1study",
        )
        parsed = parse_md(md)
    except (AuthoringParseError, OverlayAuthoringError, ProtocolCompileError,
            KeyError, TypeError, ValueError) as exc:
        # A malformed sample/field the model authored (e.g. a 65-char hash32) is a
        # row-1 authoring failure, not a harness crash — fold it in like the rest.
        return AuthoredDoc(
            ok=False, rung=rung, task_type=task_type,
            error=f"{type(exc).__name__}: {str(exc)[:240]}")
    return AuthoredDoc(
        ok=True, rung=rung, task_type=task_type, md=md, parsed=parsed,
        name=parsed.identity.get("name"))
