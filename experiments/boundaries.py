"""Generic boundary / adversarial inputs derived from a message's field encodings.

An *authored* protocol's messages are model-chosen, so we cannot hand-write edge
cases per protocol the way we do for the four fixed specs. Instead we derive
demanding inputs from each field's declared encoding — empty / min / max values,
and (at the exchange level) duplicate sends — and require two independent compiles
to agree on ALL of them, not merely on the document's own sample. This is what
turns the adoption check from "do they agree on the easy case the model already
saw" into "do they agree everywhere a handler could plausibly diverge".

Values are FIXED (not random) so an ``adopt`` verdict is reproducible run to run,
and every value is in range for its encoding so it packs cleanly (an input that
still will not pack is handled defensively at the send site, not here).
"""

from __future__ import annotations

from typing import Any

from protocol.compiler import MessageDef

# Unsigned-integer ceilings — the max that still fits the wire width.
_UINT_MAX: dict[str, int] = {
    "uint8": 0xFF, "uint16-be": 0xFFFF, "uint32-be": 0xFFFFFFFF,
    "uint64-be": 0xFFFFFFFFFFFFFFFF, "timestamp_unix": 0xFFFFFFFFFFFFFFFF,
}

# Boundary values per encoding, in the "human" form ``net.send`` coerces
# (str for utf8, list/dict for msgpack, bytes for raw/fixed, hex str for hashes).
_BOUNDARY: dict[str, list[Any]] = {
    "bool": [False, True],
    "varlenH-utf8": ["", "café", "x" * 256],            # empty, multibyte, long
    "varlenH-msgpack": [[], {}, [1, 2, 3], {"k": "v"}],  # empty + populated shapes
    "varlenH": [b"", b"\x00", b"\xff" * 256],            # empty, null byte, long
    "bytes20": [b"\x00" * 20, b"\xff" * 20],
    "bytes32": [b"\x00" * 32, b"\xff" * 32],
    "hash20": ["00" * 20, "ff" * 20],
    "hash32": ["00" * 32, "ff" * 32],
}
for _enc, _mx in _UINT_MAX.items():
    _BOUNDARY[_enc] = [0, 1, _mx]                        # min, one, max

# One "neutral" value per encoding, used to hold the other fields fixed while a
# single field is swept across its boundaries.
_DEFAULT: dict[str, Any] = {
    "bool": False, "varlenH-utf8": "x", "varlenH-msgpack": [1],
    "varlenH": b"x", "bytes20": b"\x11" * 20, "bytes32": b"\x11" * 32,
    "hash20": "11" * 20, "hash32": "11" * 32,
}
for _enc in _UINT_MAX:
    _DEFAULT[_enc] = 1


def values_for(encoding: str) -> list[Any]:
    return _BOUNDARY.get(encoding, [_DEFAULT.get(encoding, b"")])


def default_for(encoding: str) -> Any:
    return _DEFAULT.get(encoding, values_for(encoding)[0])


def boundary_payloads(message: MessageDef) -> list[dict[str, Any]]:
    """Field-dicts that span each field's encoding boundaries.

    Baseline (all neutral), then one variant per ``(field, boundary value)`` that
    sweeps that field while the rest stay neutral, plus an all-min and an all-max
    combo. Bounded at ``1 + Σ_field |values(field)| + 2`` — never the full
    Cartesian product — and de-duplicated so identical dicts are not re-sent."""
    fields = message.fields
    if not fields:
        return [{}]
    baseline = {f.name: default_for(f.encoding) for f in fields}
    payloads: list[dict[str, Any]] = [dict(baseline)]
    for f in fields:
        for v in values_for(f.encoding):
            variant = dict(baseline)
            variant[f.name] = v
            payloads.append(variant)
    payloads.append({f.name: values_for(f.encoding)[0] for f in fields})    # all-min
    payloads.append({f.name: values_for(f.encoding)[-1] for f in fields})   # all-max

    seen: set = set()
    unique: list[dict[str, Any]] = []
    for p in payloads:
        key = tuple(sorted((k, repr(v)) for k, v in p.items()))
        if key not in seen:
            seen.add(key)
            unique.append(p)
    return unique
