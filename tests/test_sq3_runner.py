"""Step 6 gate: the factorial runner, pairing pass, and report, fully offline.

A stub client factory makes the LLM-dependent half deterministic, so the whole
distribution pipeline — compile, classify, conformance, save source, pair, score
interop, render — runs with no network. The authoring arm's record path is
exercised directly. Also checks resume (a second run attempts nothing) and that
the rendered summary carries the new conformance / interop / source-diversity
columns rather than the retired ladder.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from _echo_sources import GOOD
from experiments.config import Cell
from experiments.report import render_summary
from experiments.runner import (
    completed_runs_per_cell,
    run_authoring_trial,
    run_factorial,
    sample_pairs_per_model_pair,
    score_pairs,
)


def test_sample_pairs_per_model_pair_covers_every_combination() -> None:
    """Three models x 4 compiles each; k=3 must yield pairs for all six model
    combinations (HH, SS, OO, HS, HO, SO), none missing, and be deterministic."""
    recs = [{"model": m} for m in ("H", "H", "H", "H",
                                   "S", "S", "S", "S",
                                   "O", "O", "O", "O")]
    pairs = sample_pairs_per_model_pair(recs, 3, seed=0)
    combos = {tuple(sorted((recs[i]["model"], recs[j]["model"]))) for i, j in pairs}
    assert combos == {("H", "H"), ("S", "S"), ("O", "O"),
                      ("H", "S"), ("H", "O"), ("O", "S")}
    assert pairs == sample_pairs_per_model_pair(recs, 3, seed=0)   # reproducible
    assert all(i < j for i, j in pairs)                            # normalized, no self-pair


class _SourceClient:
    """Stub LLM that always returns the canned good echo source (for compiles)."""
    model_id = "stub"

    def complete(self, system: str, user: str, *, max_tokens: int = 4096) -> str:
        return GOOD


def _good_echo_factory(model: str, temperature: float):
    return _SourceClient()


# ---------------------------------------------------------------------------
# Concurrency: LLM calls overlap; results are unchanged
# ---------------------------------------------------------------------------

class _ConcurrencyProbe:
    """Stub LLM whose (blocking, thread-run) complete() records the peak number
    of simultaneous in-flight calls, so a test can prove trials actually overlap."""

    def __init__(self) -> None:
        import threading
        self._lock = threading.Lock()
        self.now = 0
        self.peak = 0

    def client(self):
        probe = self

        class _C:
            model_id = "stub"

            def complete(self, system, user, *, max_tokens=4096):
                import time as _t
                with probe._lock:
                    probe.now += 1
                    probe.peak = max(probe.peak, probe.now)
                _t.sleep(0.15)
                with probe._lock:
                    probe.now -= 1
                return GOOD
        return _C()


def test_concurrency_overlaps_llm_calls(tmp_path) -> None:
    """smoke = 3 trials of one cell; at concurrency 3 the blocking compiles must
    run in parallel (peak in-flight >= 2)."""
    probe = _ConcurrencyProbe()
    attempted = asyncio.run(run_factorial(
        "smoke", output_dir=tmp_path, factory=lambda m, t: probe.client(), concurrency=3))
    assert attempted == 3
    assert probe.peak >= 2, f"expected overlap, peak in-flight was {probe.peak}"


def test_concurrency_one_is_sequential(tmp_path) -> None:
    """The default (concurrency=1) must never overlap — peak in-flight == 1."""
    probe = _ConcurrencyProbe()
    asyncio.run(run_factorial(
        "smoke", output_dir=tmp_path, factory=lambda m, t: probe.client(), concurrency=1))
    assert probe.peak == 1


def test_concurrent_results_match_sequential(tmp_path) -> None:
    """Same trials, same outcomes regardless of concurrency — only wall-clock
    differs. All 3 smoke compiles are usable + conformant either way."""
    seq, conc = tmp_path / "seq", tmp_path / "conc"
    asyncio.run(run_factorial("smoke", output_dir=seq, factory=_good_echo_factory, concurrency=1))
    asyncio.run(run_factorial("smoke", output_dir=conc, factory=_good_echo_factory, concurrency=4))

    def summary(d):
        rows = [json.loads(l) for l in (d / "runs.jsonl").read_text().splitlines()]
        return (len(rows),
                sum(r["outcome"] == "ok" for r in rows),
                sum(bool(r["conformant"]) for r in rows))
    assert summary(seq) == summary(conc) == (3, 3, 3)


# ---------------------------------------------------------------------------
# Distribution arm end-to-end (smoke profile: distribution/echo/haiku/T=0, N=3)
# ---------------------------------------------------------------------------

def test_distribution_smoke_run_and_report(tmp_path) -> None:
    attempted = asyncio.run(run_factorial(
        "smoke", output_dir=tmp_path, factory=_good_echo_factory))
    assert attempted == 3

    runs = [json.loads(l) for l in (tmp_path / "runs.jsonl").read_text().splitlines()]
    assert len(runs) == 3
    assert all(r["arm"] == "distribution" and r["outcome"] == "ok" for r in runs)
    assert all(r["conformant"] is True for r in runs)
    assert len(list((tmp_path / "sources" / "echo").glob("*.py"))) == 3

    # report renders the (kept) distribution reliability + diversity table; the
    # legacy score/pairs interop section is gone (superseded by `levels`).
    summary = render_summary(tmp_path)
    assert "Distribution arm — compile reliability" in summary
    assert "conformant" in summary and "div" in summary
    assert "self vs cross-model" not in summary
    assert "0.33" in summary                              # diversity: 3 identical sources


def test_score_pairs_still_samples_per_model_pair(tmp_path) -> None:
    """`score_pairs` is retired from the CLI/report but kept as a tested helper."""
    asyncio.run(run_factorial("smoke", output_dir=tmp_path, factory=_good_echo_factory))
    written = asyncio.run(score_pairs(tmp_path, k_per_model_pair=12))
    assert written == 3                                   # one model: C(3,2) self pairs
    pairs = [json.loads(l) for l in (tmp_path / "pairs.jsonl").read_text().splitlines()]
    assert all(p["interop_ok"] and p["pairing"] == "self" for p in pairs)


def test_distribution_run_is_resume_safe(tmp_path) -> None:
    asyncio.run(run_factorial("smoke", output_dir=tmp_path, factory=_good_echo_factory))
    again = asyncio.run(run_factorial("smoke", output_dir=tmp_path, factory=_good_echo_factory))
    assert again == 0
    assert sum(completed_runs_per_cell(tmp_path).values()) == 3


# ---------------------------------------------------------------------------
# Authoring arm record path
# ---------------------------------------------------------------------------

class _AuthorThenJunkClient:
    """Returns authoring JSON on the authoring system prompt, junk otherwise (so
    the compile step fails to load and adoption is not scored)."""
    model_id = "stub"

    def __init__(self) -> None:
        import json as _json
        self._args = _json.dumps({
            "name": "ping", "version": "1.0.0", "description": "d",
            "messages": [
                {"name": "PING", "msg_id": 1,
                 "fields": [{"name": "text", "encoding": "varlenH-utf8", "description": "t"}],
                 "handler": "append text to received"},
                {"name": "PONG", "msg_id": 2,
                 "fields": [{"name": "text", "encoding": "varlenH-utf8", "description": "t"}],
                 "handler": "append text to received"},
            ],
            "runtime_state": [{"name": "received", "type": "list[dict]", "description": "r"}],
            "samples": {"PING": {"text": "hi"}, "PONG": {"text": "yo"}},
        })

    def complete(self, system: str, user: str, *, max_tokens: int = 4096) -> str:
        if "designing a peer-to-peer wire protocol" in system:
            return self._args
        return "not valid python !!!"


def test_save_authored_writes_present_artifacts_only(tmp_path) -> None:
    """The authoring artifact saver writes the doc + each compile that exists, and
    silently skips a compile whose source is absent (a failed compile)."""
    from experiments.runner import _save_authored
    _save_authored(tmp_path, "payment", "abc123",
                   md="# doc", author_src="a=1", adopter_src="b=2")
    base = tmp_path / "authored" / "payment"
    assert (base / "abc123.md").read_text() == "# doc"
    assert (base / "abc123.author.py").read_text() == "a=1"
    assert (base / "abc123.adopter.py").read_text() == "b=2"
    # only the doc present -> only the .md is written
    _save_authored(tmp_path, "echo", "xyz", md="# only doc")
    assert (tmp_path / "authored" / "echo" / "xyz.md").is_file()
    assert not (tmp_path / "authored" / "echo" / "xyz.author.py").exists()


def test_authoring_trial_records_author_and_compile_outcome(tmp_path) -> None:
    cell = Cell(arm="authoring", rung="echo",
                model="claude-haiku-4-5-20251001", temperature=0.0, task_type="genesis")
    factory = lambda model, temp: _AuthorThenJunkClient()  # noqa: E731
    rec = asyncio.run(run_authoring_trial(cell, 0, factory=factory, output_dir=tmp_path))
    assert rec.arm == "authoring"
    assert rec.author_ok is True
    assert rec.overlay_name == "ping"
    assert rec.faithful is True                       # 2 messages + utf8 + list state
    assert rec.author_compile_outcome == "compile_load_fail"
    assert rec.adoption_ok is None                    # not scored: a compile failed

    # The authored document is persisted for offline re-scoring; the compiles
    # failed to load here, so their sources are correctly absent.
    authored = tmp_path / "authored" / "echo"
    assert (authored / f"{rec.run_id}.md").is_file()
    assert not (authored / f"{rec.run_id}.author.py").exists()


def test_authoring_record_renders_in_report(tmp_path) -> None:
    cell = Cell(arm="authoring", rung="echo",
                model="claude-haiku-4-5-20251001", temperature=0.0, task_type="genesis")
    factory = lambda model, temp: _AuthorThenJunkClient()  # noqa: E731
    from experiments.runner import append_run
    append_run(tmp_path, asyncio.run(run_authoring_trial(cell, 0, factory=factory)))
    summary = render_summary(tmp_path)
    assert "Authoring arm — faithfulness + adoption interop" in summary
