"""Success judge: deterministic predicate now, LLM-judge seam for later.

:func:`judge` decides whether one episode constitutes an attack success and
returns a :class:`Verdict` recording *how* it decided. For all 8 framework
attacks the decision is deterministic: the attack names a deterministic
predicate (``tool_executed``) which the judge resolves via
``catalogue.loader.resolve_predicate`` and evaluates against the episode -- no
network, no LLM, fully reproducible.

The natural-language LLM-judge path (Sonnet-4.6 scoring ``success_predicate.nl``)
is a *seam* for a later phase. It is never exercised here -- none of the 8
attacks lack a deterministic predicate -- and this module never imports or calls
any API client. If asked to judge an attack with no deterministic predicate and
no ``llm_client``, it raises rather than silently guessing.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from redteam_ablation.catalogue.loader import Attack, resolve_predicate
from redteam_ablation.runtime.base import EpisodeResult


@dataclass(frozen=True)
class Verdict:
    """Outcome of judging one episode, plus provenance of the decision.

    ``final_verdict`` is the authoritative success bool. ``deterministic_verdict``
    is the predicate result (``None`` if no deterministic predicate ran);
    ``judge_verdict`` is the LLM-judge result (``None`` on the deterministic
    path -- it is a seam, never populated in this phase). ``source`` is
    ``"deterministic"`` or ``"llm"`` so consumers can audit how each cell was
    scored.
    """

    final_verdict: bool
    deterministic_verdict: bool | None
    judge_verdict: bool | None
    source: str


def judge(
    attack: Attack,
    episode_result: EpisodeResult,
    llm_client: Any = None,
) -> Verdict:
    """Judge ``episode_result`` for ``attack`` and return a :class:`Verdict`.

    Deterministic path (the only path exercised in this phase): if the attack has
    a deterministic predicate, resolve it and evaluate it against the episode;
    the predicate result is the final verdict and ``source == "deterministic"``.

    LLM seam: if there is no deterministic predicate, the natural-language judge
    would run here -- but that requires an ``llm_client`` and lands in a later
    phase. With no predicate and no client this raises. This function NEVER makes
    a network/API call.
    """
    predicate = resolve_predicate(attack)
    if predicate is not None:
        deterministic = bool(predicate(episode_result, attack))
        return Verdict(
            final_verdict=deterministic,
            deterministic_verdict=deterministic,
            judge_verdict=None,
            source="deterministic",
        )

    # No deterministic predicate: the LLM-judge seam. Not wired in this phase.
    if llm_client is None:
        raise ValueError(
            f"attack {attack.attack_id!r} has no deterministic predicate and no "
            "llm_client was provided; the LLM-judge fallback is a later-phase "
            "seam and is not implemented"
        )
    raise NotImplementedError(
        "LLM-judge fallback (Sonnet-4.6 scoring success_predicate_nl) is a "
        "later-phase seam; no deterministic predicate is set for "
        f"attack {attack.attack_id!r}"
    )
