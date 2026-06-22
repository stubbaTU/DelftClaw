"""Render the SQ3 results into summary.md.

Descriptive: we run the experiment, read rates off each cell, and draw a
conclusion. No hypothesis test, no thresholding rule. The summary has three
parts:

  * **Behavioural agreement** (from ``levels.json``, written by ``sq3.cli
    levels``) — the authoritative measure: conformance and interop scored at two
    uniform levels, *functional* (the protocol's contract state) and
    *representational* (byte-identical stored state), every protocol the same way.
  * **Distribution arm — compile reliability** (from ``runs.jsonl``) — the data
    ``levels.json`` does not carry: how often the pipeline produced usable code,
    the load-fail / vector-fail split, and source diversity.
  * **Authoring arm** (from ``runs.jsonl``) — author / faithful / adopt rates.

The legacy ``score`` / ``pairs.jsonl`` interop pass is superseded by ``levels``
and no longer rendered.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from experiments.authoring import RUNG_ORDER
from experiments.config import MODELS, short_model
from experiments.metrics import source_diversity
from experiments.outcomes import Outcome


def _load_jsonl(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    out: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def _pct(num: int, den: int) -> str:
    return "—/0" if den == 0 else f"{num}/{den} ({num / den * 100:.0f}%)"


def _ordered(values: set[str], order: tuple[str, ...]) -> list[str]:
    known = [v for v in order if v in values]
    return known + sorted(values - set(known))


def _distribution_section(runs: list[dict]) -> list[str]:
    dist = [r for r in runs if r.get("arm") == "distribution"]
    if not dist:
        return []

    # (rung, model) -> tallies
    agg: dict[tuple[str, str], dict] = defaultdict(
        lambda: {"n": 0, "load_fail": 0, "vector_fail": 0, "infra": 0,
                 "usable": 0, "conformant": 0, "shas": []})
    for r in dist:
        cell = agg[(r["rung"], r["model"])]
        cell["n"] += 1
        outcome = r.get("outcome")
        if outcome == Outcome.INFRA_ERROR.value:
            cell["infra"] += 1
        elif outcome == Outcome.COMPILE_LOAD_FAIL.value:
            cell["load_fail"] += 1
        elif outcome == Outcome.COMPILE_VECTOR_FAIL.value:
            cell["vector_fail"] += 1
        elif outcome == Outcome.OK.value:
            cell["usable"] += 1
            if r.get("source_sha"):
                cell["shas"].append(r["source_sha"])
            if r.get("conformant"):
                cell["conformant"] += 1

    rungs = _ordered({k[0] for k in agg}, RUNG_ORDER)
    models = _ordered({k[1] for k in agg}, MODELS)

    lines = [
        "## Distribution arm — compile reliability",
        "",
        "Per (rung, model): `usable` = loaded and passed its own vectors "
        "(denominator excludes infrastructure errors); `load_fail` / `vec_fail` = "
        "compiles that did not load / failed their own vectors; `div` = distinct "
        "sources / usable. `conformant` is the legacy single-level measure (file_"
        "transfer projected, others full-record); the authoritative behavioural "
        "result is the functional/representational split above. Temperatures folded.",
        "",
        "| rung | model | usable | conformant | load_fail | vec_fail | infra | div |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for rung in rungs:
        for model in models:
            if (rung, model) not in agg:
                continue
            c = agg[(rung, model)]
            lines.append(
                f"| {rung} | {short_model(model)} | "
                f"{_pct(c['usable'], c['n'])} | {_pct(c['conformant'], c['usable'])} | "
                f"{c['load_fail']} | {c['vector_fail']} | {c['infra']} | "
                f"{source_diversity(c['shas']):.2f} |")
    return lines




def _authoring_section(runs: list[dict]) -> list[str]:
    auth = [r for r in runs if r.get("arm") == "authoring"]
    if not auth:
        return []
    # (task_type, rung, model) -> tallies
    agg: dict[tuple[str, str, str], dict] = defaultdict(
        lambda: {"n": 0, "author_ok": 0, "faithful": 0, "adopt_n": 0, "adopt_ok": 0})
    for r in auth:
        cell = agg[(r.get("task_type", "genesis"), r["rung"], r["model"])]
        cell["n"] += 1
        cell["author_ok"] += 1 if r.get("author_ok") else 0
        cell["faithful"] += 1 if r.get("faithful") else 0
        if r.get("adoption_ok") is not None:
            cell["adopt_n"] += 1
            cell["adopt_ok"] += 1 if r.get("adoption_ok") else 0

    tasks = _ordered({k[0] for k in agg}, ("genesis", "evolution"))
    rungs = _ordered({k[1] for k in agg}, RUNG_ORDER)
    models = _ordered({k[2] for k in agg}, MODELS)
    lines = [
        "## Authoring arm — faithfulness + adoption interop",
        "",
        "Per (task, rung, model): `author` = produced a synthesizable document; "
        "`faithful` = of all trials, the share whose document met the rung's "
        "structural rubric; `adopt` = of trials where both author and adopter "
        "compiled, the share where the adopter reproduced the author's behaviour.",
        "",
        "| task | rung | model | author | faithful | adopt |",
        "|---|---|---|---|---|---|",
    ]
    for task in tasks:
        for rung in rungs:
            for model in models:
                if (task, rung, model) not in agg:
                    continue
                c = agg[(task, rung, model)]
                lines.append(
                    f"| {task} | {rung} | {short_model(model)} | "
                    f"{_pct(c['author_ok'], c['n'])} | {_pct(c['faithful'], c['n'])} | "
                    f"{_pct(c['adopt_ok'], c['adopt_n'])} |")
    return lines


def _levels_section(output_dir: Path) -> list[str]:
    """Functional vs representational conformance + interop, from levels.json
    (written by `sq3.cli levels`). The authoritative behavioural measure: every
    protocol scored at the SAME level, unlike the single-level distribution
    section below."""
    path = output_dir / "levels.json"
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    rungs = _ordered(set(data), RUNG_ORDER)
    models, self_codes, cross_codes = ("H", "S", "O"), ("HH", "SS", "OO"), ("HS", "HO", "SO")

    def conf_cells(d: dict) -> str:
        return " | ".join(_pct(*d.get(m, [0, 0])) for m in models)

    def interop_cells(d: dict) -> str:
        return " | ".join(_pct(*d.get(c, [0, 0])) for c in self_codes + cross_codes)

    lines = [
        "## Behavioural agreement — functional vs representational",
        "",
        "Every protocol scored on the same battery at two levels. **Functional** = "
        "reaches the protocol's contract state (documented fields, metadata "
        "ignored); **representational** = byte-identical stored state. Conformance "
        "is vs the reference; interop is between two independent compiles. H/S/O = "
        "Haiku/Sonnet/Opus; self = HH SS OO, cross = HS HO SO.",
    ]
    for level in ("functional", "representational"):
        lines += [
            "", f"### {level.capitalize()}", "",
            "| rung | conf H | conf S | conf O | HH | SS | OO | HS | HO | SO |",
            "|---|---|---|---|---|---|---|---|---|---|",
        ]
        for rung in rungs:
            blk = data[rung].get(level, {})
            lines.append(f"| {rung} | {conf_cells(blk.get('conf', {}))} | "
                         f"{interop_cells(blk.get('interop', {}))} |")
    return lines


def render_summary(output_dir: Path) -> str:
    runs = _load_jsonl(output_dir / "runs.jsonl")
    if not runs:
        return ("# SQ3 results — empty\n\nNo trials in "
                f"{output_dir / 'runs.jsonl'}. Run `python -m sq3.cli run` first.\n")

    lines = ["# SQ3 results — agent compilation to interoperation", ""]
    levels = _levels_section(output_dir)
    if levels:
        lines += levels + [""]
    lines += _distribution_section(runs)
    dist_present = any(r.get("arm") == "distribution" for r in runs)
    auth_present = any(r.get("arm") == "authoring" for r in runs)
    if dist_present and auth_present:
        lines += [""]
    lines += _authoring_section(runs)
    return "\n".join(lines) + "\n"


def write_summary(output_dir: Path) -> Path:
    target = output_dir / "summary.md"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_summary(output_dir), encoding="utf-8")
    return target
