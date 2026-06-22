"""Two levels of behavioural agreement, scored from saved compiles (offline).

The conformance battery (``sq3.scenarios``) checks each protocol, but not at the
*same* level across protocols. This module re-scores all four, on the same
scenario battery, at two explicit, uniform levels:

  * **functional** — does an independent compilation reach the protocol's
    *contract* state (the documented fields), ignoring extra metadata it attaches
    to a record? Each observed slot is projected to its contract fields first.
  * **representational** — does it reach byte-identical observable state, every
    field of every record included?

Both run the real battery scenarios on the saved sources (no LLM). Conformance
compares a compile to the hand-written reference; interop compares two
independent compiles to each other.

Performance. Two things make a naive version slow: the mock network's settle
heuristic waits a fixed timeout per exchange (defeated by the communities'
background periodic tasks), and the work is serial. We fix both: ``_settle``
pumps the event loop only until the observed state stops changing (tens of ms,
not 500), and ``score_session`` fans the independent (rung, model) /
(rung, model-pair) jobs across a process pool — each worker process gets its own
copy of IPv8's process-global mock ``internet``, so they cannot collide.
"""

from __future__ import annotations

import json
import os
import random
from asyncio import sleep
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass
from itertools import combinations, product
from pathlib import Path
from typing import Any, Callable
import asyncio

from experiments.driver import ProgrammableNetwork
from experiments.fixtures import get_spec
from experiments.live_interop import LoadedOverlay, load_overlay
from experiments.oracle import ROLE_TO_IDX, Checkpoint, Seed, Send, canonicalize, reference_overlay, state_delta
from experiments.scenarios import Scenario, scenarios_for

RUNGS = ("echo", "content_community", "payment", "file_transfer")
CODES = ("HH", "SS", "OO", "HS", "HO", "SO")
_MODEL_SHORT = {"claude-haiku-4-5-20251001": "H", "claude-sonnet-4-6": "S",
                "claude-opus-4-6": "O"}
_RANK = {"H": 0, "S": 1, "O": 2}


# ---------------------------------------------------------------------------
# Contract projection per runtime-state slot (functional level).
# ---------------------------------------------------------------------------

def _keep_each(keys: tuple[str, ...], container: str) -> Callable[[Any], Any]:
    def proj(state: Any) -> Any:
        if container == "list":
            return [{k: r.get(k) for k in keys} if isinstance(r, dict) else r for r in state]
        return {mk: ({k: v.get(k) for k in keys} if isinstance(v, dict) else v)
                for mk, v in state.items()}
    return proj


_IDENTITY: Callable[[Any], Any] = lambda s: s

_CONTRACT: dict[str, Callable[[Any], Any]] = {
    "received_responses": _IDENTITY,
    "response_cache": _keep_each(("magnet", "name", "size", "mime"), "list"),
    "pending_requests": _keep_each(("amount_sats", "memo"), "map"),
    "received_offers": _keep_each(("amount_sats", "memo"), "list"),
    "received_payments": _keep_each(("amount_sats", "txid"), "list"),
    "declined": _keep_each(("reason",), "list"),
    "transfers": _keep_each(("complete", "ok"), "map"),
    "completed": _IDENTITY,
}


# ---------------------------------------------------------------------------
# Settle-until-stable: pump the loop only until observed state stops changing.
# ---------------------------------------------------------------------------

async def _settle(net: ProgrammableNetwork, slots: list[str],
                  *, max_s: float = 0.4, stable_needed: int = 3, step: float = 0.004) -> None:
    n = len(net.nodes)
    prev = None
    stable = 0
    t = 0.0
    while t < max_s:
        await sleep(step)
        t += step
        snap = tuple(repr(getattr(net.nodes[i].overlay, s, None))
                     for i in range(n) for s in slots)
        if snap == prev:
            stable += 1
            if stable >= stable_needed:
                return
        else:
            stable = 0
        prev = snap


async def _capture(impl_a: LoadedOverlay, impl_b: LoadedOverlay, scenario: Scenario,
                   extra: list[LoadedOverlay] | None = None,
                   *, settle_max: float = 0.4) -> dict[tuple[str, str], dict[str, Any]]:
    """Run the scenario's Seed/Send steps, then read every checkpointed (role,
    slot) at both levels. Each send settles via ``_settle`` rather than a fixed
    timeout."""
    spec = get_spec(scenario.rung).parsed
    msg_by_name = {m.name: m for m in spec.messages}
    overlays = [impl_a, impl_b, *(extra or [])]
    cid = impl_a.community_cls.community_id
    state_names = [s.name for s in spec.runtime_state]
    targets = {(c.role, c.attr) for c in scenario.steps if isinstance(c, Checkpoint)}

    async with ProgrammableNetwork(overlays, cid) as net:
        mid = {net.nodes[i].my_peer.mid.hex(): r for r, i in ROLE_TO_IDX.items() if i < len(net.nodes)}
        base: dict[tuple[int, str], Any] = {}

        def snap() -> None:
            for i in range(len(overlays)):
                for s in state_names:
                    base[(i, s)] = canonicalize(getattr(net.nodes[i].overlay, s, None), mid_to_role=mid)

        snapped = False
        for step in scenario.steps:
            if isinstance(step, Seed):
                setattr(net.overlay(ROLE_TO_IDX[step.role]), step.attr, step.value)
            elif isinstance(step, Send):
                if not snapped:
                    snap(); snapped = True
                src = ROLE_TO_IDX[step.src_role]
                dst = ROLE_TO_IDX[step.dst_role] if step.dst_role else 1 - src
                await net.send(src, dst, msg_by_name[step.message], step.fields, settle=False)
                await _settle(net, state_names, max_s=settle_max)

        out: dict[tuple[str, str], dict[str, Any]] = {}
        for role, slot in targets:
            i = ROLE_TO_IDX[role]
            cur = canonicalize(getattr(net.nodes[i].overlay, slot, None), mid_to_role=mid)
            b = base.get((i, slot))
            effect = state_delta(b, cur) if b is not None else cur
            out[(role, slot)] = {"full": effect, "func": _CONTRACT.get(slot, _IDENTITY)(effect)}
        return out


def _scenario_extra(rung: str, sc: Scenario) -> list[LoadedOverlay] | None:
    return [reference_overlay(rung) for _ in range(sc.n_roles - 2)] or None


async def _agree_both(x: LoadedOverlay, y: LoadedOverlay, rung: str,
                      *, settle_max: float = 0.4) -> tuple[bool, bool]:
    """Do x and y reach the same observable state across the whole battery?
    Returns ``(functional, representational)`` in one pass."""
    func = full = True
    for sc in scenarios_for(rung):
        xa = await _capture(x, y, sc, _scenario_extra(rung, sc), settle_max=settle_max)
        yb = await _capture(y, x, sc, _scenario_extra(rung, sc), settle_max=settle_max)
        for key in xa:
            other = yb.get(key, {})
            if xa[key]["func"] != other.get("func"):
                func = False
            if xa[key]["full"] != other.get("full"):
                full = False
        if not func and not full:
            break
    return func, full


async def _golden(rung: str, settle_max: float) -> dict[str, dict]:
    out = {}
    for sc in scenarios_for(rung):
        out[sc.name] = await _capture(reference_overlay(rung), reference_overlay(rung),
                                      sc, _scenario_extra(rung, sc), settle_max=settle_max)
    return out


async def _conformant_both(c: LoadedOverlay, rung: str, golden: dict[str, dict],
                           *, settle_max: float = 0.4) -> tuple[bool, bool]:
    ref = reference_overlay(rung)
    func = full = True
    for sc in scenarios_for(rung):
        gs = golden[sc.name]
        for cap in (await _capture(c, ref, sc, _scenario_extra(rung, sc), settle_max=settle_max),
                    await _capture(ref, c, sc, _scenario_extra(rung, sc), settle_max=settle_max)):
            for key in gs:
                if cap.get(key, {}).get("func") != gs[key]["func"]:
                    func = False
                if cap.get(key, {}).get("full") != gs[key]["full"]:
                    full = False
        if not func and not full:
            break
    return func, full


# ---------------------------------------------------------------------------
# Per-job async scorers (one (rung, model) or (rung, model-pair) unit of work)
# ---------------------------------------------------------------------------

async def _score_conf(rung: str, sources: list[str], settle_max: float) -> tuple[int, int, int, int]:
    cid = bytes.fromhex(get_spec(rung).community_id_hex)
    golden = await _golden(rung, settle_max)
    fok = rok = tot = 0
    for src in sources:
        try:
            f, r = await _conformant_both(load_overlay(src, cid), rung, golden, settle_max=settle_max)
        except Exception:  # noqa: BLE001
            f = r = False
        tot += 1; fok += int(f); rok += int(r)
    return fok, tot, rok, tot


async def _score_interop(rung: str, A: list[str], B: list[str], same: bool,
                         k: int, seed: int, settle_max: float) -> tuple[int, int, int, int]:
    cid = bytes.fromhex(get_spec(rung).community_id_hex)
    cand = list(combinations(range(len(A)), 2)) if same else list(product(range(len(A)), range(len(B))))
    random.Random(seed).shuffle(cand)
    fok = rok = tot = 0
    for i, j in cand[:k]:
        try:
            f, r = await _agree_both(load_overlay(A[i], cid), load_overlay(B[j], cid),
                                     rung, settle_max=settle_max)
        except Exception:  # noqa: BLE001
            f = r = False
        tot += 1; fok += int(f); rok += int(r)
    return fok, tot, rok, tot


# Top-level (picklable) dispatch run inside each worker process.
def _dispatch(job: tuple) -> tuple:
    kind = job[0]
    if kind == "conf":
        _, rung, model, srcs, sm = job
        return ("conf", rung, model) + asyncio.run(_score_conf(rung, srcs, sm))
    _, rung, code, A, B, same, k, seed, sm = job
    return ("interop", rung, code) + asyncio.run(_score_interop(rung, A, B, same, k, seed, sm))


# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------

@dataclass
class LevelResult:
    rung: str
    functional_conf: dict[str, tuple[int, int]]
    representational_conf: dict[str, tuple[int, int]]
    functional_interop: dict[str, tuple[int, int]]
    representational_interop: dict[str, tuple[int, int]]


def _pair_code(a: str, b: str) -> str:
    return a + b if _RANK[a] <= _RANK[b] else b + a


def usable_sources_by_model(session: Path, rung: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = defaultdict(list)
    for line in (session / "runs.jsonl").read_text().splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        if (r.get("arm") == "distribution" and r.get("rung") == rung
                and r.get("outcome") == "ok" and r.get("source_sha")):
            out[_MODEL_SHORT[r["model"]]].append(
                (session / "sources" / rung / f"{r['run_id']}.py").read_text())
    return dict(out)


def usable_sources_by_temperature(session: Path, rung: str) -> dict[float, list[str]]:
    """Like ``usable_sources_by_model`` but keyed by sampling temperature, pooling
    the models — the grouping the temperature table needs."""
    out: dict[float, list[str]] = defaultdict(list)
    for line in (session / "runs.jsonl").read_text().splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        if (r.get("arm") == "distribution" and r.get("rung") == rung
                and r.get("outcome") == "ok" and r.get("source_sha")):
            out[r["temperature"]].append(
                (session / "sources" / rung / f"{r['run_id']}.py").read_text())
    return dict(out)


def score_session(
    session: Path, *, k_per_pair: int = 12, seed: int = 0, settle_max: float = 0.4,
    workers: int | None = None, on_progress: Callable[[str, str, str, tuple], None] | None = None,
) -> list[LevelResult]:
    """Score every rung at both levels, fanning the independent (rung, model)
    conformance jobs and (rung, model-pair) interop jobs across a process pool.
    Each worker process is isolated (its own mock ``internet``). ``workers=1``
    runs serially in-process. ``on_progress(kind, rung, key, (fok,ftot,rok,rtot))``
    fires as each job completes."""
    by: dict[str, dict[str, list[str]]] = {}
    for rung in RUNGS:
        m = usable_sources_by_model(session, rung)
        if m:
            by[rung] = m

    jobs: list[tuple] = []
    for rung, models in by.items():
        for model, srcs in models.items():
            jobs.append(("conf", rung, model, srcs, settle_max))
        for ma in "HSO":
            for mb in "HSO":
                if _RANK[ma] > _RANK[mb] or ma not in models or mb not in models:
                    continue
                jobs.append(("interop", rung, _pair_code(ma, mb),
                             models[ma], models[mb], ma == mb, k_per_pair, seed, settle_max))

    fc: dict[tuple[str, str], tuple] = {}
    rc: dict[tuple[str, str], tuple] = {}
    fi: dict[tuple[str, str], tuple] = {}
    ri: dict[tuple[str, str], tuple] = {}

    def absorb(res: tuple) -> None:
        kind, rung, key, fok, ftot, rok, rtot = res
        if kind == "conf":
            fc[(rung, key)] = (fok, ftot); rc[(rung, key)] = (rok, rtot)
        else:
            fi[(rung, key)] = (fok, ftot); ri[(rung, key)] = (rok, rtot)
        if on_progress is not None:
            on_progress(kind, rung, key, (fok, ftot, rok, rtot))

    n_workers = workers if workers is not None else min(os.cpu_count() or 1, 16)
    if n_workers <= 1:
        for job in jobs:
            absorb(_dispatch(job))
    else:
        with ProcessPoolExecutor(max_workers=n_workers) as ex:
            for fut in as_completed([ex.submit(_dispatch, j) for j in jobs]):
                absorb(fut.result())

    results: list[LevelResult] = []
    for rung in [r for r in RUNGS if r in by]:
        results.append(LevelResult(
            rung,
            {m: fc[(rung, m)] for m in "HSO" if (rung, m) in fc},
            {m: rc[(rung, m)] for m in "HSO" if (rung, m) in rc},
            {c: fi[(rung, c)] for c in CODES if (rung, c) in fi},
            {c: ri[(rung, c)] for c in CODES if (rung, c) in ri},
        ))
    return results


@dataclass
class TemperatureResult:
    """Conformance pooled over all protocols and models at one sampling
    temperature; each value is ``(ok, total)``."""
    temperature: float
    functional: tuple[int, int]
    representational: tuple[int, int]


def score_by_temperature(
    session: Path, *, settle_max: float = 0.4, workers: int | None = None,
    on_progress: Callable[[float, tuple], None] | None = None,
) -> list[TemperatureResult]:
    """Score distribution conformance per sampling temperature, pooled over all
    four reference protocols and three models (the temperature table). Reuses the
    same per-(rung) conformance scorer as ``score_session``; only the grouping
    differs (by temperature instead of by model). Offline; ``workers=1`` runs
    serially in-process."""
    jobs: list[tuple] = []
    for rung in RUNGS:
        for temp, srcs in usable_sources_by_temperature(session, rung).items():
            jobs.append(("conf", rung, repr(temp), srcs, settle_max))

    agg: dict[float, list[int]] = defaultdict(lambda: [0, 0, 0, 0])

    def absorb(res: tuple) -> None:
        _, _rung, key, fok, ftot, rok, rtot = res
        a = agg[float(key)]
        a[0] += fok; a[1] += ftot; a[2] += rok; a[3] += rtot
        if on_progress is not None:
            on_progress(float(key), (fok, ftot, rok, rtot))

    n_workers = workers if workers is not None else min(os.cpu_count() or 1, 16)
    if n_workers <= 1:
        for job in jobs:
            absorb(_dispatch(job))
    else:
        with ProcessPoolExecutor(max_workers=n_workers) as ex:
            for fut in as_completed([ex.submit(_dispatch, j) for j in jobs]):
                absorb(fut.result())

    return [TemperatureResult(t, (agg[t][0], agg[t][1]), (agg[t][2], agg[t][3]))
            for t in sorted(agg)]
