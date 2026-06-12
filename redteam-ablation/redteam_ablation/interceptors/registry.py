"""Arm -> interceptor-set registry: the 7-arm enforcement-mode ladder.

An *arm* (plan 2026-06-10 §1.3) is not a code fork: it is a named, ordered set
of mode-tagged interceptors the :class:`~redteam_ablation.runtime.base.Dispatcher`
runs over each proposed :class:`~redteam_ablation.contracts.ToolDecision`. This
module is the single authority on which interceptors an arm carries and on the
canonical arm order, so the runner / CLI iterate the grid once and consistently.

The ladder composes the three real interceptor bodies, with *mode* as a
branch-on-failure parameter (audit = detect + allow; strict = deny):

    V0:         [] -- vanilla, no defence; a DANGEROUS tool fires unimpeded.
    P1-audit:   [P1(audit)]  -- flags non-owner senders, never denies.
    P1-strict:  [P1(strict)] -- denies non-owner senders (the old V1).
    P2-audit:   [P2] -- audit by construction (no strict twin): signs every
                executed call via ``on_execute`` but NEVER denies (ASR == V0).
    P3-audit:   [P3(audit)]  -- flags a diverged constitution, never denies.
    P3-strict:  [P3(strict)] -- denies a diverged constitution (the old V3).
    ALL-strict: [P1(strict), P2, P3(strict)] -- the full strict stack, same
                P1, P2, P3 order as the old V4.

Legacy aliases are kept so old call sites keep meaning: V1 -> P1-strict,
V2 -> P2-audit, V3 -> P3-strict, V4 -> ALL-strict. Each alias resolves to the
SAME interceptor instances as its arm twin. ``VARIANT_ORDER`` is re-pointed to
``ARM_ORDER`` (the grid the runner / CLI iterate is the 7 arms).

Every interceptor is STATELESS: it reads the owner identity / constitution
hashes / per-run signed-log path from the per-episode dispatch ``context``
(which the runtime / runner supplies), so the registry holds one shared
instance per (body, mode) and hands the same object to every dispatcher.
``interceptors_for`` returns a fresh *list* each call so a caller mutating the
list never corrupts the registry.
"""

from __future__ import annotations

from redteam_ablation.interceptors.base import Interceptor
from redteam_ablation.interceptors.constitution_check import (
    ConstitutionHashInterceptor,
)
from redteam_ablation.interceptors.identity_check import (
    OwnerAnchoredIdentityInterceptor,
)
from redteam_ablation.interceptors.signed_log_audit import (
    SignedLogAuditInterceptor,
)

# Canonical order of the ablation grid's arms (plan §1.3). The runner / CLI
# iterate this list so every consumer agrees on row order.
ARM_ORDER: list[str] = [
    "V0",
    "P1-audit",
    "P1-strict",
    "P2-audit",
    "P3-audit",
    "P3-strict",
    "ALL-strict",
]

# Re-pointed to the 7-arm ladder (plan §1.3): old call sites iterating
# VARIANT_ORDER now iterate the arms.
VARIANT_ORDER: list[str] = ARM_ORDER

# Shared, stateless, mode-tagged interceptor singletons. Each reads its
# run-specific inputs from the dispatch context, so one instance per
# (body, mode) is safe to share across every dispatcher / episode in a run.
_P1_AUDIT: Interceptor = OwnerAnchoredIdentityInterceptor(mode="audit")
_P1_STRICT: Interceptor = OwnerAnchoredIdentityInterceptor(mode="strict")
_P2_SIGNED_LOG: Interceptor = SignedLogAuditInterceptor()  # no mode axis (§1.1)
_P3_AUDIT: Interceptor = ConstitutionHashInterceptor(mode="audit")
_P3_STRICT: Interceptor = ConstitutionHashInterceptor(mode="strict")

# Per-arm interceptor sets. The legacy aliases share the SAME set objects as
# their arm twins so alias resolution is identity-preserving.
_SET_V0: list[Interceptor] = []
_SET_P1_AUDIT: list[Interceptor] = [_P1_AUDIT]
_SET_P1_STRICT: list[Interceptor] = [_P1_STRICT]
_SET_P2_AUDIT: list[Interceptor] = [_P2_SIGNED_LOG]
_SET_P3_AUDIT: list[Interceptor] = [_P3_AUDIT]
_SET_P3_STRICT: list[Interceptor] = [_P3_STRICT]
_SET_ALL_STRICT: list[Interceptor] = [_P1_STRICT, _P2_SIGNED_LOG, _P3_STRICT]

# Arm (or legacy alias) name -> its ordered interceptor set.
VARIANTS: dict[str, list[Interceptor]] = {
    "V0": _SET_V0,  # vanilla: no defence -- the dangerous tool fires unimpeded.
    "P1-audit": _SET_P1_AUDIT,
    "P1-strict": _SET_P1_STRICT,
    "P2-audit": _SET_P2_AUDIT,
    "P3-audit": _SET_P3_AUDIT,
    "P3-strict": _SET_P3_STRICT,
    "ALL-strict": _SET_ALL_STRICT,
    # Legacy aliases (plan §1.3): same instances/sets as their arm twins.
    "V1": _SET_P1_STRICT,
    "V2": _SET_P2_AUDIT,
    "V3": _SET_P3_STRICT,
    "V4": _SET_ALL_STRICT,
}

# The legacy alias names, for the unknown-name error message.
_LEGACY_ALIASES: list[str] = ["V1", "V2", "V3", "V4"]


def interceptors_for(variant: str) -> list[Interceptor]:
    """Return the (fresh) ordered interceptor list for an arm or legacy alias.

    A *new* list is returned each call so a caller mutating it (or a dispatcher
    copying it) can never corrupt the registry. Raises :class:`KeyError` for an
    unknown name -- a typo in the grid should fail loudly, not silently run an
    empty defence set -- listing the known arms and aliases.
    """
    if variant not in VARIANTS:
        raise KeyError(
            f"unknown arm {variant!r}; known arms: {ARM_ORDER}; "
            f"legacy aliases: {_LEGACY_ALIASES}"
        )
    return list(VARIANTS[variant])
