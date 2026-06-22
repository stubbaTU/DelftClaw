"""Pairwise cross-roundtrip — the SQ3 interop measurement.

Given two LLM-emitted Python sources from independent compiles of the SAME
schema-conformant spec, the question is: does a payload built by one side's
``VariablePayload`` subclass deserialize correctly via the OTHER side's? The
spec's embedded test vectors (mandatory ≥ 2 per message; pre-registered) are
the conformance battery.

A pair counts as "interoperable" iff every test vector round-trips in BOTH
directions (A → wire → B and B → wire → A). Granular per-vector results are
kept for diagnostics in the JSONL.

Why not IPv8: the doc considers a real two-node IPv8 round-trip *stronger*
but explicitly out of scope — the substrate question is whether two
independent compiles agree on the byte-level wire format. The IPv8 transport
itself isn't varying across SQ3 runs, so adding it to the loop would just add
noise and confound the measurement (and triple the runtime).
"""

from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass, field
from typing import Any

from protocol.compiler import (
    MessageDef,
    ParsedOverlay,
    _coerce_field_value,
    _payload_class_for,
    strip_code_fences,
)
from protocol.sandbox import SandboxError, safe_exec


@dataclass(frozen=True)
class VectorOutcome:
    """One direction (A → wire → B) of one test vector. ``ok=True`` iff the
    bytes packed by A's payload class deserialize via B's payload class into
    the same coerced field values."""
    vector_index: int
    direction: str            # "A->B" or "B->A"
    ok: bool
    error: str | None = None


@dataclass(frozen=True)
class InteropResult:
    """One pair's verdict. ``overall_pass`` iff every per-vector outcome
    succeeded in both directions. ``source_a_sha`` / ``source_b_sha`` let the
    report cross-reference the underlying compile RunRecords."""
    pair_id: str
    source_a_sha: str
    source_b_sha: str
    per_vector: list[VectorOutcome] = field(default_factory=list)

    @property
    def overall_pass(self) -> bool:
        return bool(self.per_vector) and all(o.ok for o in self.per_vector)


def _sha256(source: str) -> str:
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


def _load_namespace(source: str) -> dict[str, Any]:
    """Run a generated source through the AST sandbox + safe_exec; return the
    resulting module namespace. Raises SandboxError on a violation, which the
    caller surfaces as a failed-load interop pair."""
    return safe_exec(strip_code_fences(source))


def _roundtrip_one_direction(
    src_namespace: dict[str, Any],
    dst_namespace: dict[str, Any],
    message: MessageDef,
    field_values: list[Any],
    encodings: list[str],
) -> tuple[bool, str | None]:
    """Pack via ``src``, unpack via ``dst``, compare. Returns ``(ok, error_text)``.

    Mirrors ``compiler._run_test_vector``'s pack/unpack semantics exactly so
    the interop measurement is consistent with the compile-time test-vector
    arm of the same vector battery.
    """
    from ipv8.messaging.serialization import default_serializer, PackError

    try:
        src_payload_cls = _payload_class_for(message, src_namespace)
        dst_payload_cls = _payload_class_for(message, dst_namespace)
    except Exception as exc:  # noqa: BLE001
        return False, f"payload_class_lookup: {type(exc).__name__}: {exc}"

    coerced = [_coerce_field_value(v, enc) for v, enc in zip(field_values, encodings)]
    try:
        src_instance = src_payload_cls(*coerced)
        wire_bytes = default_serializer.pack_serializable(src_instance)
    except (PackError, TypeError, Exception) as exc:  # noqa: BLE001
        return False, f"pack: {type(exc).__name__}: {exc}"

    try:
        decoded, consumed = default_serializer.unpack_serializable(dst_payload_cls, wire_bytes)
    except (PackError, TypeError, Exception) as exc:  # noqa: BLE001
        return False, f"unpack: {type(exc).__name__}: {exc}"

    if consumed != len(wire_bytes):
        return False, f"trailing_bytes: {len(wire_bytes) - consumed} left after decode"

    expected_values = coerced
    actual_values = [getattr(decoded, n) for n in dst_payload_cls.names]
    if expected_values != actual_values:
        return False, f"field_mismatch: expected {expected_values!r}, got {actual_values!r}"
    return True, None


def pair_interoperates(
    source_a: str,
    source_b: str,
    spec: ParsedOverlay,
    *,
    pair_id: str | None = None,
) -> InteropResult:
    """The interop arm's primitive: given two independent generated sources
    for ``spec``, run every test vector in both directions and return one
    consolidated result. Failure to load either side is surfaced as a single
    per-vector failure tagged ``namespace_load`` so a degenerate compile (e.g.
    sandbox violation) shows up rather than being silently dropped.
    """
    a_sha = _sha256(source_a)
    b_sha = _sha256(source_b)
    pid = pair_id or f"{a_sha[:12]}_{b_sha[:12]}"

    try:
        ns_a = _load_namespace(source_a)
    except SandboxError as exc:
        return InteropResult(
            pair_id=pid, source_a_sha=a_sha, source_b_sha=b_sha,
            per_vector=[VectorOutcome(0, "A->B", False, f"namespace_load_a: {exc}")],
        )
    try:
        ns_b = _load_namespace(source_b)
    except SandboxError as exc:
        return InteropResult(
            pair_id=pid, source_a_sha=a_sha, source_b_sha=b_sha,
            per_vector=[VectorOutcome(0, "A->B", False, f"namespace_load_b: {exc}")],
        )

    msg_by_name = {m.name: m for m in spec.messages}
    outcomes: list[VectorOutcome] = []
    for i, tv in enumerate(spec.test_vectors):
        msg = msg_by_name.get(tv.message)
        if msg is None:
            outcomes.append(VectorOutcome(i, "A->B", False, f"unknown_message:{tv.message}"))
            continue
        encodings = [f.encoding for f in msg.fields]
        values = list(tv.fields.values())

        ok_ab, err_ab = _roundtrip_one_direction(ns_a, ns_b, msg, values, encodings)
        outcomes.append(VectorOutcome(i, "A->B", ok_ab, err_ab))

        ok_ba, err_ba = _roundtrip_one_direction(ns_b, ns_a, msg, values, encodings)
        outcomes.append(VectorOutcome(i, "B->A", ok_ba, err_ba))

    return InteropResult(
        pair_id=pid, source_a_sha=a_sha, source_b_sha=b_sha, per_vector=outcomes,
    )


def reference_interoperates(
    llm_source: str,
    reference_source: str,
    spec: ParsedOverlay,
    *,
    pair_id: str | None = None,
) -> InteropResult:
    """Interop between an LLM-compiled source and a hand-coded reference.

    This is the echo-only ``reference_interop_rate`` arm of the study: instead
    of pairing two independent LLM compiles, it pairs one LLM compile against
    the hand-written reference implementation (``echo_traditional.py``). The
    round-trip machinery is identical to ``pair_interoperates`` — the reference
    exposes the same ``VariablePayload`` subclasses, so the spec's test vectors
    are driven across the two in both directions. Named separately so the report
    can keep the reference arm distinct from the cross-compile arm.
    """
    return pair_interoperates(
        llm_source, reference_source, spec, pair_id=pair_id,
    )


def sample_pairs(
    n_compiles: int,
    k: int = 20,
    seed: int | None = None,
) -> list[tuple[int, int]]:
    """Pick ``k`` index-pairs uniformly at random from ``range(n_compiles)``,
    with the constraint that every surviving compile appears in at least one
    pair (so the sample graph over compiles is connected — a soft requirement
    the doc names but doesn't formalize; we operationalise it as "every index
    appears in at least one returned pair").

    Returns ``[]`` for n < 2 (no pairs possible). When ``k`` exceeds the
    number of distinct unordered pairs, returns every pair without
    duplication. Self-pairs are excluded.

    Deterministic when ``seed`` is supplied; useful in tests and for resume-
    safe pair regeneration in the harness.
    """
    if n_compiles < 2:
        return []
    rng = random.Random(seed)
    all_pairs = [(i, j) for i in range(n_compiles) for j in range(i + 1, n_compiles)]
    if k >= len(all_pairs):
        rng.shuffle(all_pairs)
        return all_pairs
    # Step 1: ensure coverage — every index gets at least one pair.
    chosen: set[tuple[int, int]] = set()
    indices = list(range(n_compiles))
    rng.shuffle(indices)
    for i in indices:
        if any(i in pair for pair in chosen):
            continue
        partners = [j for j in range(n_compiles) if j != i]
        j = rng.choice(partners)
        a, b = (i, j) if i < j else (j, i)
        chosen.add((a, b))
        if len(chosen) >= k:
            break
    # Step 2: fill the rest with uniform random pairs (no duplicates).
    remaining = [p for p in all_pairs if p not in chosen]
    rng.shuffle(remaining)
    while len(chosen) < k and remaining:
        chosen.add(remaining.pop())
    return sorted(chosen)
