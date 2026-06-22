"""Flow B — the authoring arm's faithfulness rubric.

When an agent *authors* a new protocol from a prose goal (the deployed
genesis/evolution step), there is no human-written reference to score it against:
the document does not exist until the model writes it. That removes the
conformance oracle, and it opens a gaming hole — a model can "climb the ladder"
by emitting a trivially simple protocol that omits the very structure the rung is
about (a file-transfer with no hash field is easy to compile and easy to make two
copies agree on, but it is not a file-transfer).

The rubric closes that hole with a *model-independent, rule-based* gate over the
parsed document: for each rung, the structural features the prose requires must
be present, whatever the model chose to name them. It does not check behaviour
(that is the adoption-interop step) and it does not check wording — only that the
declared messages, field encodings, and runtime-state shapes can *carry* the
behaviour. Naming is deliberately not enforced; the checks key off encodings and
state base-types so a model is free to call a chunk a "segment".
"""

from __future__ import annotations

from dataclasses import dataclass

from protocol.compiler import ParsedOverlay

_UINT_ENCODINGS = {"uint8", "uint16-be", "uint32-be", "uint64-be", "timestamp_unix"}
_BLOB_ENCODINGS = {"varlenH", "varlenH-msgpack"}


def _field_encodings(parsed: ParsedOverlay) -> set[str]:
    return {f.encoding for m in parsed.messages for f in m.fields}


def _state_base_types(parsed: ParsedOverlay) -> set[str]:
    return {s.base_type for s in parsed.runtime_state}


def _has_enc(parsed: ParsedOverlay, *encodings: str) -> bool:
    return bool(_field_encodings(parsed) & set(encodings))


def _has_seq_and_data_message(parsed: ParsedOverlay) -> bool:
    """A message carrying both an unsigned integer and a variable-length blob —
    the structural signature of a numbered data chunk (seq + payload), regardless
    of what the author named the fields."""
    for m in parsed.messages:
        encs = {f.encoding for f in m.fields}
        if encs & _UINT_ENCODINGS and encs & _BLOB_ENCODINGS:
            return True
    return False


# Per-rung requirements: (human-readable requirement, predicate over the parsed
# document). All must hold for the authored protocol to count as faithful.
_RUBRICS: dict[str, list[tuple[str, object]]] = {
    "echo": [
        ("at least two messages (a request and a reply)", lambda p: len(p.messages) >= 2),
        ("a utf-8 text field", lambda p: _has_enc(p, "varlenH-utf8")),
        ("a list runtime-state slot to record replies", lambda p: "list" in _state_base_types(p)),
    ],
    "content_community": [
        ("a utf-8 query field", lambda p: _has_enc(p, "varlenH-utf8")),
        ("a structured-list (msgpack) results field", lambda p: _has_enc(p, "varlenH-msgpack")),
        ("a list runtime-state slot for the result cache", lambda p: "list" in _state_base_types(p)),
    ],
    "payment": [
        ("at least three message types (request/offer/notify/decline)",
         lambda p: len(p.messages) >= 3),
        ("an unsigned-integer amount field", lambda p: _has_enc(p, *_UINT_ENCODINGS)),
        ("a dict runtime-state slot keyed by requester (enables de-duplication)",
         lambda p: "dict" in _state_base_types(p)),
    ],
    "file_transfer": [
        ("at least three messages (request/manifest/chunk)", lambda p: len(p.messages) >= 3),
        ("a 20-byte content-id field", lambda p: _has_enc(p, "hash20", "bytes20")),
        ("a 32-byte content-hash field (enables whole-content verification)",
         lambda p: _has_enc(p, "hash32", "bytes32")),
        ("a chunk message carrying a sequence number and a data blob",
         _has_seq_and_data_message),
        ("a dict runtime-state slot for in-progress transfers",
         lambda p: "dict" in _state_base_types(p)),
    ],
}


@dataclass(frozen=True)
class RubricResult:
    rung: str
    ok: bool
    missing: list[str]


def check_faithfulness(rung: str, parsed: ParsedOverlay) -> RubricResult:
    """Score an authored document against its rung's structural rubric. An
    unknown rung has no rubric and passes vacuously (the caller decides whether
    that is allowed)."""
    checks = _RUBRICS.get(rung, [])
    missing = [desc for desc, pred in checks if not pred(parsed)]  # type: ignore[operator]
    return RubricResult(rung=rung, ok=not missing, missing=missing)
