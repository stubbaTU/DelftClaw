"""Factorial-cell configuration for the SQ3 study.

The study has two arms, mirroring the two things the deployed agents do:

  * **distribution** — the headline. A *fixed* descriptor (one of the four
    examples) is compiled independently across models and randomness settings;
    each compile is scored for conformance against the hand-written reference,
    and pairs of compiles are scored for interoperability. Interop pairs are
    tagged ``self`` (same model) or ``cross`` (different models), the
    heterogeneous case the real network actually runs.

  * **authoring** — the secondary arm. A model *authors* a new descriptor from a
    prose goal (genesis) or by evolving a fixed base (evolution); the authored
    document is gated by a structural faithfulness rubric and then scored for
    reference-free adoption interop between the author's model and a different
    adopter's model.

A *compile cell* is one ``(arm, task_type, rung, model, temperature)`` the runner
visits ``N`` times. Models are Anthropic's exact ``model_id`` strings — the
load-bearing label in every JSONL line; don't abbreviate.
"""

from __future__ import annotations

from dataclasses import dataclass

from experiments.authoring import RUNG_ORDER

ARMS: tuple[str, ...] = ("distribution", "authoring")

# genesis = design from a prose description; evolution = add one field to a fixed
# v1.0.0 base. Only meaningful for the authoring arm; distribution uses "na".
TASK_TYPES: tuple[str, ...] = ("genesis", "evolution")

MODELS: tuple[str, ...] = (
    "claude-haiku-4-5-20251001",
    "claude-sonnet-4-6",
    "claude-opus-4-6",
)

MODEL_ALIASES: dict[str, str] = {
    "haiku": "claude-haiku-4-5-20251001",
    "sonnet": "claude-sonnet-4-6",
    "opus": "claude-opus-4-6",
}

TEMPERATURES: tuple[float, ...] = (0.0, 0.3, 0.7)

N_PER_CELL: int = 10  # trials per cell; 10 is sufficient for these (mostly
# saturated) descriptive rates and keeps interop pairing healthy (C(10,2)=45
# same-model pairs/cell). Was 20; halved to cut cost/runtime.


def short_model(model: str) -> str:
    return next((a for a, m in MODEL_ALIASES.items() if m == model), model)


def pairing_of(model_a: str, model_b: str) -> str:
    """``self`` if two compiles came from the same model, else ``cross``."""
    return "self" if model_a == model_b else "cross"


def adopter_model(author_model: str) -> str:
    """The model that adopts an author's document in the authoring arm: a
    *different* tier (the next model, wrapping around), so adoption interop is
    genuinely cross-model and never grades a model against itself."""
    idx = MODELS.index(author_model) if author_model in MODELS else 0
    return MODELS[(idx + 1) % len(MODELS)]


@dataclass(frozen=True)
class Cell:
    """One compile cell of the factorial."""
    arm: str
    rung: str
    model: str
    temperature: float
    task_type: str = "na"   # genesis | evolution for authoring; na for distribution

    @property
    def cell_id(self) -> str:
        """Stable, filesystem-safe id used in JSONL + progress lines."""
        tt = "" if self.task_type == "na" else f"{self.task_type}_"
        return f"{self.arm}_{tt}{self.rung}_{short_model(self.model)}_T{self.temperature:.1f}"


@dataclass(frozen=True)
class Profile:
    """A named selection of compile cells the runner iterates over."""
    name: str
    arms: tuple[str, ...]
    task_types: tuple[str, ...]
    rungs: tuple[str, ...]
    models: tuple[str, ...]
    temperatures: tuple[float, ...]
    n_per_cell: int = N_PER_CELL
    notes: str = ""

    def cells(self) -> list[Cell]:
        """Enumerate cells cheapest-first (smaller models / lower temps / simpler
        rungs early) so a budget cap hits the informative cells first."""
        rung_rank = {s: i for i, s in enumerate(RUNG_ORDER)}
        model_rank = {m: i for i, m in enumerate(MODELS)}
        out: list[Cell] = []
        for arm in self.arms:
            task_types = self.task_types if arm == "authoring" else ("na",)
            for tt in task_types:
                for m in self.models:
                    for t in self.temperatures:
                        for r in self.rungs:
                            out.append(Cell(arm=arm, rung=r, model=m, temperature=t, task_type=tt))
        out.sort(key=lambda c: (
            c.arm, c.task_type, model_rank.get(c.model, 9),
            c.temperature, rung_rank.get(c.rung, 9),
        ))
        return out


PROFILES: dict[str, Profile] = {
    "distribution": Profile(
        name="distribution",
        arms=("distribution",),
        task_types=("na",),
        rungs=RUNG_ORDER,
        models=MODELS,
        temperatures=TEMPERATURES,
        notes="headline: 4 rung x 3 model x 3 temp x 10 = 360 compiles, scored "
              "for conformance + self/cross interop",
    ),
    "authoring": Profile(
        name="authoring",
        arms=("authoring",),
        task_types=TASK_TYPES,
        rungs=RUNG_ORDER,
        models=MODELS,
        temperatures=TEMPERATURES,
        notes="2 task x 4 rung x 3 model x 3 temp x 10 = 720 author trials "
              "(each authors + compiles author + adopter models)",
    ),
    "full": Profile(
        name="full",
        arms=ARMS,
        task_types=TASK_TYPES,
        rungs=RUNG_ORDER,
        models=MODELS,
        temperatures=TEMPERATURES,
        notes="both arms",
    ),
    "smoke": Profile(
        name="smoke",
        arms=("distribution",),
        task_types=("na",),
        rungs=("echo",),
        models=(MODELS[0],),
        temperatures=(0.0,),
        n_per_cell=3,
        notes="3 compiles of (distribution, echo, haiku, T=0) — wiring test",
    ),
}


def cells_for_profile(profile_name: str) -> tuple[list[Cell], int]:
    """Return ``(cells, n_per_cell)`` for the named profile. KeyError on an
    unknown profile name (CLI surfaces it)."""
    if profile_name not in PROFILES:
        known = ", ".join(sorted(PROFILES))
        raise KeyError(f"unknown profile {profile_name!r}; known: {known}")
    prof = PROFILES[profile_name]
    return prof.cells(), prof.n_per_cell


def resolve_model_alias(name: str) -> str:
    """Accept 'haiku'/'sonnet'/'opus' or a full model_id; return the full id."""
    if name in MODEL_ALIASES:
        return MODEL_ALIASES[name]
    if name in MODELS:
        return name
    raise ValueError(
        f"unknown model {name!r}; known aliases: {list(MODEL_ALIASES)}, "
        f"full ids: {list(MODELS)}"
    )
