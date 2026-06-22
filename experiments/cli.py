"""Operator surface for the SQ3 study.

Subcommands::

    python -m sq3.cli run [--profile NAME] [--max-runs N]   # the factorial (LLM)
    python -m sq3.cli levels [--k-per-pair N]              # conformance, two levels (Table III)
    python -m sq3.cli temperature                          # conformance by temperature (Table V)
    python -m sq3.cli authored-levels [--faithful-only]    # authored self/cross interop (Table IV)
    python -m sq3.cli report                                # render summary.md
    python -m sq3.cli preflight                             # 1 compile / model (LLM)
    python -m sq3.cli rungs                                 # list rungs/specs

A ``run`` visits each compile cell N times: the distribution arm compiles a fixed
descriptor and scores conformance; the authoring arm authors a document and
scores adoption interop. ``score`` is offline post-processing over the saved
sources. Endpoint config matches the live-LLM test pattern: ``LLM_BASE_URL`` /
``LLM_API_KEY`` from env (source ``configs/.env`` first). ``--profile``
(distribution / authoring / full / smoke) selects the cell set.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

from experiments import config as sq3_config
from experiments import report as sq3_report
from experiments.authoring import DESCRIPTIONS, RUNG_ORDER
from experiments.runner import (
    RunRecord,
    clear_active_session,
    completed_runs_per_cell,
    default_client_factory,
    profile_complete,
    resolve_read_session,
    resolve_run_session,
    run_factorial,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
RESULTS_ROOT = REPO_ROOT / "results"


def _resolve_endpoint() -> tuple[str, str]:
    base = os.environ.get("LLM_BASE_URL")
    api_key = os.environ.get("LLM_API_KEY") or os.environ.get("ANTHROPIC_API_KEY") or ""
    if not base:
        print("ERROR: set LLM_BASE_URL. Source configs/.env first.", file=sys.stderr)
        raise SystemExit(2)
    return base, api_key


def _row_flags(rec: RunRecord) -> str:
    if rec.arm == "distribution":
        return (f"outcome={rec.outcome} "
                f"conformant={'Y' if rec.conformant else ('.' if rec.conformant is False else '-')}")
    return (f"author={'Y' if rec.author_ok else '.'} "
            f"faithful={'Y' if rec.faithful else '.'} "
            f"adopt={'Y' if rec.adoption_ok else ('.' if rec.adoption_ok is False else '-')}")


def cmd_run(args: argparse.Namespace) -> int:
    base_url, api_key = _resolve_endpoint()
    profile = args.profile
    if args.output_dir:
        session = Path(args.output_dir).resolve()
        session.mkdir(parents=True, exist_ok=True)
        managed = False
    else:
        session = resolve_run_session(RESULTS_ROOT, profile)
        managed = True
    print(f"session: {session}")

    cells, n_target = sq3_config.cells_for_profile(profile)
    total_target = len(cells) * n_target
    counter = {"i": sum(completed_runs_per_cell(session).values())}
    if args.concurrency > 1:
        print(f"concurrency={args.concurrency} (LLM calls overlap; progress lines "
              f"arrive as trials finish, not in cell order)")

    def on_progress(rec: RunRecord) -> None:
        counter["i"] += 1
        err = f" err={rec.error[:70]}" if rec.error else ""
        print(f"[{counter['i']}/{total_target}] {rec.cell_id} seed={rec.seed} "
              f"{_row_flags(rec)} dur={rec.duration_ms}ms{err}",
              file=sys.stderr, flush=True)

    attempted = asyncio.run(run_factorial(
        profile_name=profile, output_dir=session,
        factory=default_client_factory(base_url, api_key),
        max_runs=args.max_runs, on_progress=on_progress,
        concurrency=args.concurrency))
    if managed and profile_complete(session, profile):
        clear_active_session(RESULTS_ROOT)
        print("session complete; next run starts a new session.")
    total = sum(completed_runs_per_cell(session).values())
    print(f"\nattempted={attempted} this invocation; total_on_disk={total}")
    print(f"results in {session}\nnext: `score` then `report`")
    return 0


def cmd_levels(args: argparse.Namespace) -> int:
    """Score conformance + interop at BOTH levels (functional vs representational)
    from saved sources, write levels.json, and print the two-level tables.
    Offline — no LLM. Functional projects each record to its documented contract
    fields; representational compares the full stored state."""
    import json
    from experiments.levels import score_session
    session = Path(args.output_dir).resolve() if args.output_dir else resolve_read_session(RESULTS_ROOT)
    if session is None:
        print("no session found; run `sq3 run` first", file=sys.stderr)
        return 2

    def pct(t: tuple[int, int]) -> str:
        return f"{round(100 * t[0] / t[1]) if t[1] else 0:>3}"

    n_jobs = {"i": 0}

    def on_progress(kind: str, rung: str, key: str, t: tuple) -> None:
        n_jobs["i"] += 1
        fok, ftot, rok, rtot = t
        print(f"  [{n_jobs['i']:2d}] {kind:7s} {rung:18s} {key:3s}  "
              f"func={pct((fok, ftot))}% repr={pct((rok, rtot))}%", file=sys.stderr, flush=True)

    workers = args.workers if args.workers is not None else None
    print(f"scoring {session.name} with {'serial' if workers == 1 else 'parallel'} "
          f"workers (k_per_pair={args.k_per_pair})...", file=sys.stderr, flush=True)
    results = score_session(session, k_per_pair=args.k_per_pair,
                            workers=workers, on_progress=on_progress)
    out: dict = {}
    print(f"\n{'rung':18s} | {'level':16s} | conf H/S/O      | interop HH SS OO | HS HO SO")
    print("-" * 78)
    for r in results:
        out[r.rung] = {
            "functional": {"conf": r.functional_conf, "interop": r.functional_interop},
            "representational": {"conf": r.representational_conf, "interop": r.representational_interop},
        }
        for label, conf, inter in (
            ("functional", r.functional_conf, r.functional_interop),
            ("representational", r.representational_conf, r.representational_interop),
        ):
            c = " ".join(pct(conf.get(m, (0, 0))) for m in "HSO")
            self_i = " ".join(pct(inter.get(x, (0, 0))) for x in ("HH", "SS", "OO"))
            cross_i = " ".join(pct(inter.get(x, (0, 0))) for x in ("HS", "HO", "SO"))
            print(f"{r.rung:18s} | {label:16s} | {c}    | {self_i}   | {cross_i}")
    (session / "levels.json").write_text(json.dumps(out, indent=1), encoding="utf-8")
    print(f"\nwrote {session / 'levels.json'}")
    return 0


def cmd_temperature(args: argparse.Namespace) -> int:
    """Score distribution conformance per sampling temperature, pooled over all
    four protocols and three models (Table V), write temperature.json, and print
    the grid. Offline — no LLM. Functional vs representational, one row per
    temperature; the same conformance scoring as `levels`, grouped by temperature
    instead of by model."""
    import json
    from experiments.levels import score_by_temperature
    session = Path(args.output_dir).resolve() if args.output_dir else resolve_read_session(RESULTS_ROOT)
    if session is None:
        print("no session found; run `sq3 run` first", file=sys.stderr)
        return 2

    def pct(t: tuple[int, int]) -> str:
        return f"{round(100 * t[0] / t[1]) if t[1] else 0:>3}"

    def on_progress(temp: float, t: tuple) -> None:
        fok, ftot, rok, rtot = t
        print(f"  T={temp}: func={pct((fok, ftot))}% repr={pct((rok, rtot))}% (n={ftot})",
              file=sys.stderr, flush=True)

    print(f"scoring conformance by temperature for {session.name}...", file=sys.stderr, flush=True)
    results = score_by_temperature(session, workers=args.workers, on_progress=on_progress)
    if not results:
        print("no usable distribution sources found", file=sys.stderr)
        return 1

    out: dict = {}
    print(f"\n{'temperature':12s} | functional | representational |   n")
    print("-" * 54)
    for r in results:
        out[f"{r.temperature}"] = {
            "functional": list(r.functional), "representational": list(r.representational)}
        print(f"{r.temperature:<12} | {pct(r.functional)}%       | "
              f"{pct(r.representational)}%             | {r.functional[1]}")
    (session / "temperature.json").write_text(json.dumps(out, indent=1), encoding="utf-8")
    print(f"\nwrote {session / 'temperature.json'}")
    return 0


def cmd_authored_levels(args: argparse.Namespace) -> int:
    """Score the authoring arm's self/cross interop at both levels from the saved
    authored documents + compiles, write authored_levels.json, and print the
    Table IV grid. Offline — no LLM. This is the SQ4 measure: two independent
    compilations of a MODEL-AUTHORED protocol, same model (self) vs different
    (cross), functional vs representational."""
    import json
    from experiments.authored_levels import (
        DocTally, results_to_json, score_authored_session,
    )
    session = Path(args.output_dir).resolve() if args.output_dir else resolve_read_session(RESULTS_ROOT)
    if session is None:
        print("no session found; run `sq3 run --profile authoring` first", file=sys.stderr)
        return 2

    def pct(t: tuple[int, int]) -> str:
        return "  -" if t[1] == 0 else f"{round(100 * t[0] / t[1]):>3}"

    n = {"i": 0}

    def on_progress(t: DocTally) -> None:
        n["i"] += 1
        print(f"  [{n['i']:4d}] {t.rung:18s} self={t.n_self} cross={t.n_cross}",
              file=sys.stderr, flush=True)

    print(f"scoring authored interop for {session.name} "
          f"(faithful_only={args.faithful_only})...", file=sys.stderr, flush=True)
    results = score_authored_session(
        session, faithful_only=args.faithful_only, workers=args.workers, on_progress=on_progress)
    if not results:
        print("no scorable authored documents found (need .md + >=2 compiles per "
              "doc under authored/<rung>/). Re-run the authoring arm with the "
              "current runner to persist them.", file=sys.stderr)
        return 1

    print(f"\n{'protocol':18s} | func self | func cross | repr self | repr cross | pairs s/c")
    print("-" * 84)
    for r in results:
        print(f"{r.rung:18s} | {pct(r.func_self)}%      | {pct(r.func_cross)}%       | "
              f"{pct(r.repr_self)}%      | {pct(r.repr_cross)}%       | "
              f"{r.func_self[1]}/{r.func_cross[1]}")
    (session / "authored_levels.json").write_text(
        json.dumps(results_to_json(results), indent=1), encoding="utf-8")
    print(f"\nwrote {session / 'authored_levels.json'}")
    print("Table IV (tab4_sq3_secondary.tex) columns are: self/cross under "
          "Functional, then self/cross under Representational.")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    session = Path(args.output_dir).resolve() if args.output_dir else resolve_read_session(RESULTS_ROOT)
    if session is None:
        print("no session found; run `sq3 run` first", file=sys.stderr)
        return 2
    print(f"wrote {sq3_report.write_summary(session)}")
    return 0


def cmd_preflight(args: argparse.Namespace) -> int:
    """One distribution-echo compile per model, to confirm every model id
    resolves against the live endpoint before a full run."""
    base_url, api_key = _resolve_endpoint()
    from experiments.fixtures import get_spec
    from experiments.outcomes import Outcome, compile_classified

    factory = default_client_factory(base_url, api_key)
    md = get_spec("echo").md_text
    all_ok = True
    for alias, model in sq3_config.MODEL_ALIASES.items():
        result = compile_classified(md, factory(model, 0.0), infra_retries=0)
        resolved = result.outcome is not Outcome.INFRA_ERROR
        all_ok = all_ok and resolved
        status = "resolved  " if resolved else "UNREACHABLE"
        extra = f" err={result.error[:90]}" if result.error else ""
        print(f"[{status}] {alias:7s} {model:26s} outcome={result.outcome.value}{extra}", flush=True)
    if all_ok:
        print("\nAll model ids resolved — safe to start the full run.")
        return 0
    print("\nAt least one model did NOT resolve; fix the ids in sq3/config.py.", file=sys.stderr)
    return 1


def cmd_rungs(args: argparse.Namespace) -> int:
    from experiments.fixtures import loaded_spec_names
    print("Rungs (ladder order) + genesis descriptions:")
    for rung in RUNG_ORDER:
        print(f"  {rung:18s} {DESCRIPTIONS[rung][:80]}...")
    print(f"\nFixed specs loaded (distribution arm + evolution bases): "
          f"{', '.join(loaded_spec_names()) or '(none)'}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m sq3.cli")
    parser.add_argument("--output-dir", default=None,
                        help="explicit session dir; default resolves a per-execution "
                             "session under results/ (resume active, else fresh)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_run = sub.add_parser("run", help="run the factorial (LLM)")
    p_run.add_argument("--profile", default="distribution", choices=sorted(sq3_config.PROFILES))
    p_run.add_argument("--max-runs", type=int, default=None,
                       help="stop after N trials this invocation (resume-safe)")
    p_run.add_argument("--concurrency", type=int, default=1,
                       help="trials in flight at once (LLM calls overlap; default 1 "
                            "= sequential). Try 6-8 to stay under rate limits.")
    p_run.set_defaults(func=cmd_run)

    p_lvl = sub.add_parser("levels",
                           help="score both levels (functional vs representational), offline")
    p_lvl.add_argument("--k-per-pair", type=int, default=12,
                       help="interop pairs sampled per model combination per rung")
    p_lvl.add_argument("--workers", type=int, default=None,
                       help="parallel worker processes (default: min(cpu, 16); 1 = serial)")
    p_lvl.set_defaults(func=cmd_levels)

    p_temp = sub.add_parser(
        "temperature",
        help="score conformance per sampling temperature (Table V), offline")
    p_temp.add_argument("--workers", type=int, default=None,
                        help="parallel worker processes (default: min(cpu, 16); 1 = serial)")
    p_temp.set_defaults(func=cmd_temperature)

    p_auth = sub.add_parser(
        "authored-levels",
        help="score authored-protocol self/cross interop at both levels (SQ4 / Table IV), offline")
    p_auth.add_argument("--faithful-only", action="store_true",
                        help="score only documents that passed the faithfulness rubric")
    p_auth.add_argument("--workers", type=int, default=None,
                        help="parallel worker processes (default: min(cpu, 16); 1 = serial)")
    p_auth.set_defaults(func=cmd_authored_levels)

    p_rep = sub.add_parser("report", help="render summary.md")
    p_rep.set_defaults(func=cmd_report)

    p_pre = sub.add_parser("preflight", help="1 compile per model on echo — confirm ids resolve")
    p_pre.set_defaults(func=cmd_preflight)

    p_rungs = sub.add_parser("rungs", help="list rungs + specs")
    p_rungs.set_defaults(func=cmd_rungs)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
