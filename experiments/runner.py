"""Factorial orchestrator for the SQ3 study (both arms), resume-safe.

The runner visits each compile cell ``N`` times and appends one JSONL line per
trial. There are two record kinds, by arm:

  * **distribution** — compile the rung's FIXED descriptor, classify the compile
    (``sq3.outcomes``), and if it is usable score it for conformance against the
    reference (``sq3.conformance``). The usable sources are saved to disk so the
    separate pairing pass can score interop across them.
  * **authoring** — author a document from the prose goal (``sq3.authoring``),
    gate it with the faithfulness rubric (``sq3.faithfulness``), compile it with
    both the author's model and a different adopter's model, and score
    reference-free adoption interop (``sq3.adoption``).

Only the LLM calls cost money; everything else (conformance, interop, adoption)
runs on the in-memory mock network. The pairing pass (``score_pairs``) is pure
post-processing over saved sources and can be re-run offline any time.

Resume semantics: ``run_factorial`` reads the existing ``runs.jsonl`` and skips
cells already at ``N`` trials. A client *factory* is injected so tests can drive
the whole pipeline with stub clients and no network.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from hashlib import sha256
from itertools import combinations, product
from pathlib import Path
from random import Random
from typing import Callable

from protocol import OpenAICompatibleClient
from protocol.compiler import community_id_from_md
from protocol.llm import LLMClient

from experiments.adoption import adoption_interop
from experiments.authoring import author_document
from experiments.conformance import evaluate_conformance, evaluate_interop
from experiments.config import Cell, adopter_model, cells_for_profile, pairing_of
from experiments.faithfulness import check_faithfulness
from experiments.fixtures import fixture_sha, get_spec
from experiments.live_interop import load_overlay
from experiments.outcomes import INFRA_EXCEPTIONS, Outcome, compile_classified

# (model_id, temperature) -> client. Injected so tests can stub the LLM.
ClientFactory = Callable[[str, float], LLMClient]


@dataclass
class RunRecord:
    """One line of ``runs.jsonl``. Fields not relevant to the arm are left at
    their defaults (None / False), so one schema covers both arms."""
    ts: float
    arm: str
    cell_id: str
    rung: str
    model: str
    temperature: float
    seed: int
    run_id: str
    task_type: str = "na"
    duration_ms: int = 0
    fixture_sha: str | None = None
    error: str | None = None

    # distribution arm
    outcome: str | None = None          # sq3.outcomes.Outcome value
    conformant: bool | None = None
    vectors_passed: bool | None = None
    source_sha: str | None = None

    # authoring arm
    adopter_model: str | None = None
    author_ok: bool | None = None
    faithful: bool | None = None
    faithful_missing: list[str] = field(default_factory=list)
    author_compile_outcome: str | None = None
    author2_compile_outcome: str | None = None   # 2nd same-model compile -> self pair
    adopter_compile_outcome: str | None = None
    adoption_ok: bool | None = None
    overlay_name: str | None = None


def default_client_factory(base_url: str, api_key: str) -> ClientFactory:
    def factory(model: str, temperature: float) -> LLMClient:
        return OpenAICompatibleClient(
            base_url=base_url, model_id=model, api_key=api_key, temperature=temperature)
    return factory


def _run_id(cell: Cell, seed: int, t0: float) -> str:
    return sha256(f"{cell.cell_id}|{seed}|{t0}".encode()).hexdigest()[:16]


def _save_source(output_dir: Path, rung: str, run_id: str, source: str) -> None:
    path = output_dir / "sources" / rung / f"{run_id}.py"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")


def _save_authored(output_dir: Path, rung: str, run_id: str, *,
                   md: str | None = None, author_src: str | None = None,
                   author2_src: str | None = None,
                   adopter_src: str | None = None) -> None:
    """Persist an authoring trial's artifacts so its interop can be re-scored
    offline (at both levels, self + cross) later: the model-authored document and
    three independent compiles of it. Layout mirrors the distribution arm's
    ``sources/`` so the offline scorer (``sq3.authored_levels``) finds them by
    run_id::

        authored/<rung>/<run_id>.md
        authored/<rung>/<run_id>.author.py    # compile 1, author's model
        authored/<rung>/<run_id>.author2.py   # compile 2, author's model  -> SELF pair
        authored/<rung>/<run_id>.adopter.py   # compile by a DIFFERENT model -> CROSS pair

    Two same-model author compiles are what let the offline scorer form a
    same-model (``self``) pair; the adopter (a different tier) forms the
    cross-model pair. Each piece is written only if its argument is present; the
    caller passes a source only for an ``OK`` compile (a vector-fail one is
    known-defective and dropped), so the scorer pairs only usable compiles.
    """
    base = output_dir / "authored" / rung
    base.mkdir(parents=True, exist_ok=True)
    if md is not None:
        (base / f"{run_id}.md").write_text(md, encoding="utf-8")
    if author_src is not None:
        (base / f"{run_id}.author.py").write_text(author_src, encoding="utf-8")
    if author2_src is not None:
        (base / f"{run_id}.author2.py").write_text(author2_src, encoding="utf-8")
    if adopter_src is not None:
        (base / f"{run_id}.adopter.py").write_text(adopter_src, encoding="utf-8")


# ---------------------------------------------------------------------------
# One trial per arm
# ---------------------------------------------------------------------------

async def run_distribution_trial(
    cell: Cell, seed: int, *, factory: ClientFactory, output_dir: Path,
    mock_lock: asyncio.Lock | None = None,
    _now: Callable[[], float] = time.time,
) -> RunRecord:
    """Compile the rung's fixed descriptor once, classify, and (if usable) score
    conformance. Saves a usable source for the pairing pass.

    The blocking LLM compile runs in a worker thread (``to_thread``) so the event
    loop can drive other trials concurrently; the mock-network conformance scoring
    runs under ``mock_lock`` because IPv8's mock ``internet`` registry is process
    global and cannot be exercised by two trials at once."""
    lock = mock_lock or asyncio.Lock()
    t0 = _now()
    rec = RunRecord(
        ts=t0, arm="distribution", cell_id=cell.cell_id, rung=cell.rung,
        model=cell.model, temperature=cell.temperature, seed=seed,
        run_id=_run_id(cell, seed, t0), fixture_sha=fixture_sha())
    spec = get_spec(cell.rung)
    client = factory(cell.model, cell.temperature)

    result = await asyncio.to_thread(compile_classified, spec.md_text, client)
    rec.outcome = result.outcome.value
    rec.vectors_passed = result.vectors_passed
    rec.error = result.error
    if result.outcome is Outcome.OK and result.source is not None:
        rec.source_sha = sha256(result.source.encode()).hexdigest()[:16]
        _save_source(output_dir, cell.rung, rec.run_id, result.source)
        overlay = load_overlay(result.source, bytes.fromhex(spec.community_id_hex))
        async with lock:
            conf = await evaluate_conformance(overlay, cell.rung)
        rec.conformant = conf.ok
        if not conf.ok:
            rec.error = f"init:{conf.as_initiator.failed} resp:{conf.as_responder.failed}"
    rec.duration_ms = int((_now() - t0) * 1000)
    return rec


async def run_authoring_trial(
    cell: Cell, seed: int, *, factory: ClientFactory,
    output_dir: Path | None = None,
    mock_lock: asyncio.Lock | None = None,
    _now: Callable[[], float] = time.time,
) -> RunRecord:
    """Author a document, gate it on the rubric, compile it with the author and a
    different adopter model, and score reference-free adoption interop.

    The three blocking LLM calls (author + two compiles) run in worker threads so
    the event loop can interleave other trials; the mock-network adoption scoring
    runs under ``mock_lock`` (process-global IPv8 mock state)."""
    lock = mock_lock or asyncio.Lock()
    t0 = _now()
    adopter = adopter_model(cell.model)
    rec = RunRecord(
        ts=t0, arm="authoring", cell_id=cell.cell_id, rung=cell.rung,
        model=cell.model, temperature=cell.temperature, seed=seed, task_type=cell.task_type,
        adopter_model=adopter, run_id=_run_id(cell, seed, t0), fixture_sha=fixture_sha())

    base = get_spec(cell.rung)
    author_client = factory(cell.model, cell.temperature)
    try:
        doc = await asyncio.to_thread(
            author_document, cell.rung, author_client, task_type=cell.task_type,
            base_parsed=base.parsed if cell.task_type == "evolution" else None,
            base_community_id_hex=base.community_id_hex if cell.task_type == "evolution" else None)
    except INFRA_EXCEPTIONS as exc:
        rec.outcome = Outcome.INFRA_ERROR.value
        rec.error = f"author: {type(exc).__name__}: {exc}"
        rec.duration_ms = int((_now() - t0) * 1000)
        return rec

    rec.author_ok = doc.ok
    if not doc.ok:
        rec.outcome = "author_invalid"
        rec.error = doc.error
        rec.duration_ms = int((_now() - t0) * 1000)
        return rec
    rec.overlay_name = doc.name

    faith = check_faithfulness(cell.rung, doc.parsed)
    rec.faithful = faith.ok
    rec.faithful_missing = faith.missing

    cid = community_id_from_md(doc.md)
    # Three independent compiles of the authored document: the author's model
    # twice (an independent same-model pair -> SELF interop) and a different
    # adopter model once (-> CROSS interop). All score offline in authored_levels.
    author_compile = await asyncio.to_thread(compile_classified, doc.md, author_client)
    author_compile_2 = await asyncio.to_thread(
        compile_classified, doc.md, factory(cell.model, cell.temperature))
    adopter_compile = await asyncio.to_thread(compile_classified, doc.md, factory(adopter, cell.temperature))
    rec.author_compile_outcome = author_compile.outcome.value
    rec.author2_compile_outcome = author_compile_2.outcome.value
    rec.adopter_compile_outcome = adopter_compile.outcome.value

    # Persist the authored document and the USABLE compiles so interop can be
    # re-scored offline (functional + representational, self + cross) without
    # re-authoring or re-compiling. Only an OK compile is saved — a vector-fail
    # source loaded but failed the document's own worked examples, so it is
    # already known defective and excluded from scoring, exactly as the
    # distribution arm excludes it (``_save_source`` / ``distribution.usable``).
    def _ok_src(c: object) -> str | None:
        return c.source if c.outcome is Outcome.OK else None  # type: ignore[attr-defined]

    if output_dir is not None:
        _save_authored(output_dir, cell.rung, rec.run_id, md=doc.md,
                       author_src=_ok_src(author_compile), author2_src=_ok_src(author_compile_2),
                       adopter_src=_ok_src(adopter_compile))

    if (author_compile.outcome is Outcome.OK and adopter_compile.outcome is Outcome.OK
            and author_compile.source and adopter_compile.source):
        a = load_overlay(author_compile.source, cid)
        b = load_overlay(adopter_compile.source, cid)
        async with lock:
            result = await adoption_interop(a, b, doc.parsed, cid)
        rec.adoption_ok = result.ok
        if not result.ok:
            rec.error = result.detail
    rec.duration_ms = int((_now() - t0) * 1000)
    return rec


async def run_one(
    cell: Cell, seed: int, *, factory: ClientFactory, output_dir: Path,
    mock_lock: asyncio.Lock | None = None,
) -> RunRecord:
    if cell.arm == "authoring":
        return await run_authoring_trial(
            cell, seed, factory=factory, output_dir=output_dir, mock_lock=mock_lock)
    return await run_distribution_trial(
        cell, seed, factory=factory, output_dir=output_dir, mock_lock=mock_lock)


# ---------------------------------------------------------------------------
# JSONL append + resume
# ---------------------------------------------------------------------------

def append_run(output_dir: Path, record: RunRecord) -> None:
    runs_path = output_dir / "runs.jsonl"
    runs_path.parent.mkdir(parents=True, exist_ok=True)
    with open(runs_path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(asdict(record), default=str) + "\n")


def load_runs(output_dir: Path) -> list[dict]:
    runs_path = output_dir / "runs.jsonl"
    if not runs_path.is_file():
        return []
    out: list[dict] = []
    for line in runs_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def completed_runs_per_cell(output_dir: Path) -> dict[str, int]:
    counts: dict[str, int] = {}
    for rec in load_runs(output_dir):
        cid = rec.get("cell_id")
        if cid:
            counts[cid] = counts.get(cid, 0) + 1
    return counts


async def run_factorial(
    profile_name: str,
    *,
    output_dir: Path,
    factory: ClientFactory,
    max_runs: int | None = None,
    on_progress: Callable[[RunRecord], None] | None = None,
    concurrency: int = 1,
) -> int:
    """Drive the profile to completion (or ``max_runs`` this invocation). Returns
    trials attempted this invocation. Resume-safe per cell.

    ``concurrency`` bounds how many trials are in flight at once. Each trial's
    blocking LLM/compile work runs in a worker thread, so >1 lets the (network-
    bound) LLM calls overlap — the dominant cost — while a shared lock keeps the
    sub-second mock-network scoring serialized. ``concurrency=1`` reproduces the
    original sequential behaviour exactly. Trials are independent, so results do
    not depend on the value; only wall-clock does."""
    output_dir.mkdir(parents=True, exist_ok=True)
    cells, n_target = cells_for_profile(profile_name)
    already = completed_runs_per_cell(output_dir)

    # Flatten to a work list (cheapest cells first, already ordered) so a single
    # bounded pool drains it; resume already excluded completed trials via counts.
    work: list[tuple[Cell, int]] = []
    for cell in cells:
        remaining = n_target - already.get(cell.cell_id, 0)
        work.extend((cell, seed) for seed in range(remaining))
    if max_runs is not None:
        work = work[:max_runs]
    if not work:
        return 0

    mock_lock = asyncio.Lock()       # serializes the process-global mock network
    io_lock = asyncio.Lock()         # serializes JSONL append + progress callback
    sem = asyncio.Semaphore(max(1, concurrency))
    attempted = 0

    async def worker(cell: Cell, seed: int) -> None:
        nonlocal attempted
        async with sem:
            record = await run_one(
                cell, seed, factory=factory, output_dir=output_dir, mock_lock=mock_lock)
        async with io_lock:
            append_run(output_dir, record)
            attempted += 1
            if on_progress is not None:
                on_progress(record)

    await asyncio.gather(*(worker(cell, seed) for cell, seed in work))
    return attempted


# ---------------------------------------------------------------------------
# Pairing pass — distribution interop over saved sources (offline)
# ---------------------------------------------------------------------------

@dataclass
class PairRecord:
    rung: str
    a_run_id: str
    b_run_id: str
    a_model: str
    b_model: str
    pairing: str           # self | cross
    interop_ok: bool
    detail: str | None = None


def _usable_distribution_runs(runs: list[dict]) -> dict[str, list[dict]]:
    """Conformance-usable distribution compiles, grouped by rung."""
    by_rung: dict[str, list[dict]] = {}
    for r in runs:
        if (r.get("arm") == "distribution" and r.get("outcome") == Outcome.OK.value
                and r.get("source_sha")):
            by_rung.setdefault(r["rung"], []).append(r)
    return by_rung


def sample_pairs_per_model_pair(
    recs: list[dict], k: int, *, seed: int = 0,
) -> list[tuple[int, int]]:
    """Up to ``k`` index pairs over ``recs`` for EACH unordered pair of models
    present, so every same-model and cross-model combination is covered equally.

    For a same-model cell the candidates are the unordered pairs within that
    model's compiles (``combinations``); for a cross-model cell they are the
    product of the two models' compiles. Candidates are shuffled with a seeded
    RNG and the first ``k`` taken, so the sample is uniform-without-replacement
    and reproducible. Returns a flat, sorted list of ``(i, j)`` indices into
    ``recs``. This balanced design is what the figure's model-by-model matrix
    needs; a stratified self-vs-cross sample leaves some model pairs empty."""
    rng = Random(seed)
    by_model: dict[str, list[int]] = {}
    for idx, r in enumerate(recs):
        by_model.setdefault(r["model"], []).append(idx)
    models = sorted(by_model)
    chosen: set[tuple[int, int]] = set()
    for a in range(len(models)):
        for b in range(a, len(models)):
            if models[a] == models[b]:
                cand = list(combinations(by_model[models[a]], 2))
            else:
                cand = list(product(by_model[models[a]], by_model[models[b]]))
            rng.shuffle(cand)
            for i, j in cand[:k]:
                chosen.add((i, j) if i <= j else (j, i))
    return sorted(chosen)


async def score_pairs(
    output_dir: Path, *, k_per_model_pair: int = 12, seed: int = 0,
) -> int:
    """Score distribution interop over saved sources and write ``pairs.jsonl``.
    Samples ``k_per_model_pair`` pairs for each model combination per rung
    (``sample_pairs_per_model_pair``). Pure post-processing — safe to re-run.
    Returns pairs written."""
    runs = load_runs(output_dir)
    by_rung = _usable_distribution_runs(runs)
    pairs_path = output_dir / "pairs.jsonl"
    written = 0
    with open(pairs_path, "w", encoding="utf-8") as handle:
        for rung, recs in by_rung.items():
            cid = bytes.fromhex(get_spec(rung).community_id_hex)
            for i, j in sample_pairs_per_model_pair(recs, k_per_model_pair, seed=seed):
                a, b = recs[i], recs[j]
                src_a = (output_dir / "sources" / rung / f"{a['run_id']}.py").read_text()
                src_b = (output_dir / "sources" / rung / f"{b['run_id']}.py").read_text()
                inter = await evaluate_interop(load_overlay(src_a, cid), load_overlay(src_b, cid), rung)
                pr = PairRecord(
                    rung=rung, a_run_id=a["run_id"], b_run_id=b["run_id"],
                    a_model=a["model"], b_model=b["model"],
                    pairing=pairing_of(a["model"], b["model"]),
                    interop_ok=inter.ok,
                    detail=None if inter.ok else f"ab:{inter.a_to_b.failed} ba:{inter.b_to_a.failed}")
                handle.write(json.dumps(asdict(pr)) + "\n")
                written += 1
    return written


# ---------------------------------------------------------------------------
# Per-execution session management (timestamped dirs + active pointer)
# ---------------------------------------------------------------------------

_SESSION_RE = re.compile(r"^\d{4}-\d{2}-\d{2}_\d{6}$")


def _active_pointer(results_root: Path) -> Path:
    return results_root / ".active"


def active_session(results_root: Path) -> Path | None:
    ptr = _active_pointer(results_root)
    if not ptr.is_file():
        return None
    cand = results_root / ptr.read_text(encoding="utf-8").strip()
    return cand if cand.is_dir() else None


def set_active_session(results_root: Path, session_dir: Path) -> None:
    results_root.mkdir(parents=True, exist_ok=True)
    _active_pointer(results_root).write_text(session_dir.name, encoding="utf-8")


def clear_active_session(results_root: Path) -> None:
    ptr = _active_pointer(results_root)
    if ptr.is_file():
        ptr.unlink()


def new_session(results_root: Path, _now: Callable[[], float] = time.time) -> Path:
    session = results_root / datetime.fromtimestamp(_now()).strftime("%Y-%m-%d_%H%M%S")
    session.mkdir(parents=True, exist_ok=True)
    return session


def most_recent_session(results_root: Path) -> Path | None:
    if not results_root.is_dir():
        return None
    sessions = sorted(d for d in results_root.iterdir()
                      if d.is_dir() and _SESSION_RE.match(d.name))
    return sessions[-1] if sessions else None


def profile_complete(session_dir: Path, profile_name: str) -> bool:
    cells, n_target = cells_for_profile(profile_name)
    counts = completed_runs_per_cell(session_dir)
    return all(counts.get(c.cell_id, 0) >= n_target for c in cells)


def resolve_run_session(results_root: Path, profile_name: str) -> Path:
    active = active_session(results_root)
    if active is not None and not profile_complete(active, profile_name):
        return active
    session = new_session(results_root)
    set_active_session(results_root, session)
    return session


def resolve_read_session(results_root: Path) -> Path | None:
    return active_session(results_root) or most_recent_session(results_root)
