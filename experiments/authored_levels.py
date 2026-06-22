"""Authored-protocol interoperability at two levels (SQ4 / Table IV), offline.

The distribution arm scores conformance + interop on the FOUR FIXED reference
protocols (``sq3.levels``). This module scores the *authoring* arm's headline
measure, the one Table IV reports: do two independent compilations of a protocol
a **model itself authored** reach the same observable state when run against each
other — by the **same** model (``self``) or a **different** model (``cross``) —
at two levels:

  * **functional** — agreement on the state the document's *messages* name (the
    data that crosses the wire), ignoring compile-invented internal metadata;
  * **representational** — agreement on the full stored state, byte for byte.

An authored document has no hand-written reference, and the faithfulness rubric
deliberately does not fix field/slot *names* (a model may call a chunk a
"segment"). So the functional projection cannot be the slot-keyed ``_CONTRACT``
the fixed arm uses; it is derived from the document itself: a record field counts
as *contract* iff some message in the document declares a field of that name.
This reproduces the fixed arm's hand-written contract projection for the two
protocols whose state records are message-shaped (content, payment); where a
model names its internal bookkeeping with words no message uses, the functional
level collapses toward representational, and we report that as measured rather
than inventing a per-protocol projection.

Per-pair agreement reuses the authoring arm's boundary battery
(``sq3.adoption._exchange_states``): every declared message is swept across its
encoding's empty/min/max values in both directions plus a duplicate probe, and
*both* nodes' state is read, so a divergence in a reply handler is caught on the
side that receives the reply. Two compiles agree iff, with their roles swapped,
each reaches the same state in each role (the symmetric test ``sq3.levels``
applies to the fixed arm, here on declared slots instead of checkpoints).

Input is what ``run_authoring_trial`` saves per trial under ``authored/<rung>/``:
the document ``<run_id>.md`` plus up to three compiles — ``<run_id>.author.py``
and ``<run_id>.author2.py`` (two independent compiles by the AUTHOR's model, the
``self`` pair) and ``<run_id>.adopter.py`` (one compile by a DIFFERENT model, the
``cross`` pair). Only compiles the run classified ``OK`` are paired — a vector-
fail source is known-defective and dropped, as in the distribution arm. Scoring
is pure post-processing over saved sources: no LLM, safe to re-run.
"""

from __future__ import annotations

import asyncio
import json
import os
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass
from itertools import combinations, product
from pathlib import Path
from typing import Any, Callable

from protocol.compiler import community_id_from_md, parse_md
from experiments.adoption import _exchange_states
from experiments.authoring import RUNG_ORDER
from experiments.live_interop import load_overlay

RUNGS: tuple[str, ...] = tuple(RUNG_ORDER)


# ---------------------------------------------------------------------------
# Generic, document-derived functional projection
# ---------------------------------------------------------------------------

def declared_fields(parsed: Any) -> frozenset[str]:
    """Every field name any message in the document declares — the document's own
    statement of the data it puts on the wire, hence its *contract*."""
    return frozenset(f.name for m in parsed.messages for f in m.fields)


def functional_project(value: Any, fields: frozenset[str]) -> Any:
    """Drop, from every *record* dict, the keys no message declares (incidental
    metadata a compile attached), keeping the rest.

    A dict counts as a record iff at least one of its keys is a declared message
    field; then only its declared-field keys survive. A dict whose keys are none
    of them is treated as an identity / index map (e.g. a per-peer or per-id
    container): its keys are kept and its values recursed into. Lists recurse
    element-wise; scalars (and the ``"<undeclared>"`` sentinel) pass through.

    Projection only ever removes keys, so functional agreement is always at least
    as lenient as representational (``repr_ok ⟹ func_ok``)."""
    if isinstance(value, dict):
        if any(k in fields for k in value):
            return {k: functional_project(v, fields) for k, v in value.items() if k in fields}
        return {k: functional_project(v, fields) for k, v in value.items()}
    if isinstance(value, list):
        return [functional_project(v, fields) for v in value]
    return value


# ---------------------------------------------------------------------------
# Two-level agreement between one pair of compiles
# ---------------------------------------------------------------------------

async def agree_two_levels(
    a: Any, b: Any, parsed: Any, community_id: bytes,
) -> tuple[bool, bool]:
    """``(functional_ok, representational_ok)`` for compiles ``a`` and ``b``.

    Runs the boundary battery twice with the implementations in swapped roles and
    requires each compile to reach the same state in each role: ``a``-as-A must
    match ``b``-as-A and ``b``-as-B must match ``a``-as-B. Representational
    compares the full canonicalized state; functional compares it after dropping
    undeclared metadata."""
    fields = declared_fields(parsed)
    sab = await _exchange_states(a, b, parsed, community_id)   # A=a, B=b
    sba = await _exchange_states(b, a, parsed, community_id)   # A=b, B=a

    repr_ok = sab["A"] == sba["A"] and sab["B"] == sba["B"]

    def proj(role_state: dict[str, Any]) -> dict[str, Any]:
        return {slot: functional_project(v, fields) for slot, v in role_state.items()}

    func_ok = proj(sab["A"]) == proj(sba["A"]) and proj(sab["B"]) == proj(sba["B"])
    return func_ok, repr_ok


# ---------------------------------------------------------------------------
# Scoring one authored document (its self + cross pairs)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DocTally:
    """Pair counts for one authored document, by pairing."""
    rung: str
    n_self: int = 0
    self_func_ok: int = 0
    self_repr_ok: int = 0
    n_cross: int = 0
    cross_func_ok: int = 0
    cross_repr_ok: int = 0


async def _score_doc(rung: str, md_text: str, srcs_by_short: dict[str, list[str]]) -> DocTally:
    """Form the self pairs (same model) and cross pairs (different models) among a
    document's compiles, and score each at both levels.

    ``srcs_by_short`` maps a model code (``H``/``S``/``O``) to the source strings
    of that model's compiles of this document. Self pairs are within-model
    combinations; cross pairs are products across distinct models."""
    parsed = parse_md(md_text)
    cid = community_id_from_md(md_text)
    loaded = {short: [load_overlay(src, cid) for src in srcs] for short, srcs in srcs_by_short.items()}

    self_pairs = [(a, b) for srcs in loaded.values() for a, b in combinations(srcs, 2)]
    cross_pairs = [
        (a, b)
        for sa, sb in combinations(sorted(loaded), 2)
        for a, b in product(loaded[sa], loaded[sb])
    ]

    nsf = nsr = ncf = ncr = 0
    for a, b in self_pairs:
        f, r = await agree_two_levels(a, b, parsed, cid)
        nsf += int(f); nsr += int(r)
    for a, b in cross_pairs:
        f, r = await agree_two_levels(a, b, parsed, cid)
        ncf += int(f); ncr += int(r)

    return DocTally(rung, len(self_pairs), nsf, nsr, len(cross_pairs), ncf, ncr)


# Top-level (picklable) worker: score one document in its own process, which
# gets its own copy of IPv8's process-global mock ``internet`` (see sq3.levels).
def _dispatch_doc(job: tuple) -> DocTally:
    rung, md_text, srcs_by_short = job
    return asyncio.run(_score_doc(rung, md_text, srcs_by_short))


# ---------------------------------------------------------------------------
# Discovering documents + their compiles on disk
# ---------------------------------------------------------------------------

_SHORT = {"claude-haiku-4-5-20251001": "H", "claude-sonnet-4-6": "S", "claude-opus-4-6": "O"}


def _short(model: str | None) -> str | None:
    return _SHORT.get(model or "", None)


def _runs_by_id(session: Path) -> dict[str, dict]:
    path = session / "runs.jsonl"
    if not path.is_file():
        return {}
    out: dict[str, dict] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        if r.get("arm") == "authoring" and r.get("run_id"):
            out[r["run_id"]] = r
    return out


def _doc_jobs(session: Path, *, faithful_only: bool) -> list[tuple]:
    """One job per authored document that has ≥2 compiles on disk (so it can form
    at least one pair). Maps each compile file to its model code via runs.jsonl;
    the two author compiles share the author's code, the adopter its own."""
    runs = _runs_by_id(session)
    base = session / "authored"
    jobs: list[tuple] = []
    for rung in RUNGS:
        rung_dir = base / rung
        if not rung_dir.is_dir():
            continue
        for md_path in sorted(rung_dir.glob("*.md")):
            run_id = md_path.stem
            rec = runs.get(run_id)
            if rec is None:
                continue
            if faithful_only and not rec.get("faithful"):
                continue
            author_short, adopter_short = _short(rec.get("model")), _short(rec.get("adopter_model"))
            srcs: dict[str, list[str]] = defaultdict(list)
            # Pair only USABLE compiles: the record must classify this compile as
            # OK. A vector-fail source loaded but failed the document's own worked
            # examples, so it is excluded here just as the distribution arm
            # excludes it (``levels.usable_sources_by_model``).
            for suffix, short, outcome_field in (
                ("author", author_short, "author_compile_outcome"),
                ("author2", author_short, "author2_compile_outcome"),
                ("adopter", adopter_short, "adopter_compile_outcome"),
            ):
                py = rung_dir / f"{run_id}.{suffix}.py"
                if short is not None and rec.get(outcome_field) == "ok" and py.is_file():
                    srcs[short].append(py.read_text(encoding="utf-8"))
            if sum(len(v) for v in srcs.values()) < 2:
                continue  # need at least one pair
            jobs.append((rung, md_path.read_text(encoding="utf-8"), dict(srcs)))
    return jobs


# ---------------------------------------------------------------------------
# Session-level aggregation
# ---------------------------------------------------------------------------

@dataclass
class AuthoredLevelResult:
    """Pooled self/cross agreement for one rung, both levels. Each value is
    ``(ok, total_pairs)``."""
    rung: str
    func_self: tuple[int, int]
    func_cross: tuple[int, int]
    repr_self: tuple[int, int]
    repr_cross: tuple[int, int]


def score_authored_session(
    session: Path, *, faithful_only: bool = False, workers: int | None = None,
    on_progress: Callable[[DocTally], None] | None = None,
) -> list[AuthoredLevelResult]:
    """Score every authored document's self + cross interop at both levels, pooled
    per rung over tasks, temperatures, and models. ``workers=1`` runs serially in
    process (used by tests); otherwise documents are fanned across a process pool,
    each worker isolated with its own mock ``internet``."""
    jobs = _doc_jobs(session, faithful_only=faithful_only)

    agg: dict[str, dict[str, int]] = defaultdict(
        lambda: {"ns": 0, "sf": 0, "sr": 0, "nc": 0, "cf": 0, "cr": 0})

    def absorb(t: DocTally) -> None:
        a = agg[t.rung]
        a["ns"] += t.n_self; a["sf"] += t.self_func_ok; a["sr"] += t.self_repr_ok
        a["nc"] += t.n_cross; a["cf"] += t.cross_func_ok; a["cr"] += t.cross_repr_ok
        if on_progress is not None:
            on_progress(t)

    n_workers = workers if workers is not None else min(os.cpu_count() or 1, 16)
    if n_workers <= 1:
        for job in jobs:
            absorb(_dispatch_doc(job))
    else:
        with ProcessPoolExecutor(max_workers=n_workers) as ex:
            for fut in as_completed([ex.submit(_dispatch_doc, j) for j in jobs]):
                absorb(fut.result())

    results: list[AuthoredLevelResult] = []
    for rung in RUNGS:
        if rung not in agg:
            continue
        a = agg[rung]
        results.append(AuthoredLevelResult(
            rung,
            func_self=(a["sf"], a["ns"]), func_cross=(a["cf"], a["nc"]),
            repr_self=(a["sr"], a["ns"]), repr_cross=(a["cr"], a["nc"]),
        ))
    return results


def results_to_json(results: list[AuthoredLevelResult]) -> dict:
    return {
        r.rung: {
            "functional": {"self": list(r.func_self), "cross": list(r.func_cross)},
            "representational": {"self": list(r.repr_self), "cross": list(r.repr_cross)},
        }
        for r in results
    }
