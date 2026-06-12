"""Static attack-catalogue loader.

Parses ``catalogue/shapira.yaml`` (the 8 surviving Shapira-derived attacks) into
``Attack`` fixtures and exposes ``catalogue_commit`` for deterministic seeding.

The deterministic success predicate is referenced by *name* in the YAML (e.g.
``tool_executed``). It is resolved lazily to a callable in
``redteam_ablation.predicates`` -- that registry is built in the Core phase, so
this loader must NOT hard-fail if ``predicates.py`` is absent yet. It keeps the
predicate *name* on the ``Attack`` and only resolves it on demand via
``resolve_predicate`` (the judge calls this at judge-time).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import yaml

# The five pre-hoc attack classes (methodology §4.3). Kept here so the loader is
# the single authority on the allowed set; the catalogue is validated against it.
ATTACK_CLASSES = frozenset(
    {"Identity", "Audit-trail", "Configuration", "Behaviour", "Mixed"}
)


@dataclass(frozen=True)
class Attack:
    """One Shapira-derived attack fixture.

    ``deterministic_predicate`` is the *name* of a predicate in
    ``redteam_ablation.predicates`` (or ``None`` if the attack has no
    deterministic post-condition and must fall back to the LLM judge). Resolve
    it to a callable with :func:`resolve_predicate`.
    """

    attack_id: str
    attack_class: str
    target_tool: str
    payload_template: str
    deterministic_predicate: str | None
    success_predicate_nl: str
    shapira_ref: str
    # Pre-registered attack-mechanism descriptors (the ``vectors`` mapping in the
    # YAML). They describe what the attack DOES to the structured inputs the
    # integrity primitives read -- NOT an expected outcome. ``spoofs_identity`` is
    # True iff the attack forges the principal (Identity class);
    # ``tampers_constitution`` is True iff it mutates the constitution/config
    # (Configuration class). The same interceptor code consumes these offline and
    # against the live agent. Both default to False (backward compatible).
    spoofs_identity: bool = False
    tampers_constitution: bool = False


def _require(fixture: dict[str, Any], key: str, attack_id: str) -> Any:
    if key not in fixture:
        raise ValueError(f"attack {attack_id!r}: missing required key {key!r}")
    return fixture[key]


def load_catalogue(path: str | Path) -> list[Attack]:
    """Load and validate the attack catalogue at ``path`` into ``Attack``s."""
    path = Path(path)
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError(
            f"catalogue {path} must be a YAML list of attack fixtures"
        )

    attacks: list[Attack] = []
    for fixture in raw:
        if not isinstance(fixture, dict):
            raise ValueError(f"catalogue {path}: each fixture must be a mapping")
        attack_id = fixture.get("attack_id", "<unknown>")

        attack_class = _require(fixture, "attack_class", attack_id)
        if attack_class not in ATTACK_CLASSES:
            raise ValueError(
                f"attack {attack_id!r}: attack_class {attack_class!r} not in "
                f"allowed set {sorted(ATTACK_CLASSES)}"
            )

        target_tool = _require(fixture, "target_tool", attack_id)
        if not str(target_tool).strip():
            raise ValueError(f"attack {attack_id!r}: empty target_tool")

        success = _require(fixture, "success_predicate", attack_id)
        if not isinstance(success, dict):
            raise ValueError(
                f"attack {attack_id!r}: success_predicate must be a mapping"
            )

        # The ``vectors`` mapping is the attack-mechanism descriptor consumed by
        # the integrity-primitive interceptors. It is optional for backward
        # compatibility: a fixture without it (or with an empty mapping) yields
        # both flags False.
        vectors = fixture.get("vectors", {}) or {}
        if not isinstance(vectors, dict):
            raise ValueError(
                f"attack {attack_id!r}: vectors must be a mapping"
            )

        attacks.append(
            Attack(
                attack_id=str(_require(fixture, "attack_id", attack_id)),
                attack_class=str(attack_class),
                target_tool=str(target_tool),
                payload_template=str(_require(fixture, "payload_template", attack_id)),
                deterministic_predicate=(
                    None
                    if success.get("deterministic") is None
                    else str(success["deterministic"])
                ),
                success_predicate_nl=str(success.get("nl", "")),
                shapira_ref=str(_require(fixture, "shapira_ref", attack_id)),
                spoofs_identity=bool(vectors.get("spoofs_identity", False)),
                tampers_constitution=bool(
                    vectors.get("tampers_constitution", False)
                ),
            )
        )
    return attacks


def resolve_predicate(attack: Attack) -> Callable[..., bool] | None:
    """Resolve ``attack.deterministic_predicate`` to a callable, lazily.

    Returns ``None`` when the attack has no deterministic predicate. Imports the
    predicate registry on demand so the catalogue still loads if
    ``predicates.py`` is not present yet.

    TODO(core-phase): once ``redteam_ablation.predicates`` ships its registry,
    this is the single resolution point the judge depends on. If the named
    predicate is missing from the registry, raise a clear error here.
    """
    if attack.deterministic_predicate is None:
        return None
    # Defensive lazy import: the predicates registry lands in the Core phase.
    from redteam_ablation import predicates  # noqa: PLC0415

    return predicates.get_predicate(attack.deterministic_predicate)


def catalogue_commit(path: str | Path) -> str:
    """Return ``sha256`` (hex) of the catalogue file bytes.

    In this framework phase the catalogue commit is the SHA-256 of the
    ``shapira.yaml`` bytes. It becomes the git commit hash of the catalogue once
    the file is committed; until then the content hash is a stable stand-in that
    feeds the per-trial seed (see ``redteam_ablation.seeds.trial_seed``).
    """
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()
