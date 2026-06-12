"""Registry: the 7-arm enforcement ladder (plan 2026-06-10 §1.3).

The grid is no longer V0-V4: it is the 7-arm ladder

    ARM_ORDER = ["V0", "P1-audit", "P1-strict", "P2-audit",
                 "P3-audit", "P3-strict", "ALL-strict"]

with mode-tagged shared singletons per arm, ``VARIANT_ORDER`` re-pointed to
``ARM_ORDER``, legacy aliases (V1->P1-strict, V2->P2-audit, V3->P3-strict,
V4->ALL-strict) kept so old call sites keep meaning, and ``interceptors_for``
raising ``KeyError`` (listing known names) on anything unknown.
"""

from __future__ import annotations

import pytest

from redteam_ablation.interceptors.registry import (
    ARM_ORDER,
    VARIANT_ORDER,
    VARIANTS,
    interceptors_for,
)

SEVEN_ARMS = [
    "V0",
    "P1-audit",
    "P1-strict",
    "P2-audit",
    "P3-audit",
    "P3-strict",
    "ALL-strict",
]

# arm -> the exact ordered (mode-tagged) interceptor names it carries (§1.3).
ARM_COMPOSITION = {
    "V0": [],
    "P1-audit": ["P1-owner-identity[audit]"],
    "P1-strict": ["P1-owner-identity[strict]"],
    "P2-audit": ["P2-signed-log"],  # P2 has no mode axis (§1.1)
    "P3-audit": ["P3-constitution-hash[audit]"],
    "P3-strict": ["P3-constitution-hash[strict]"],
    "ALL-strict": [
        "P1-owner-identity[strict]",
        "P2-signed-log",
        "P3-constitution-hash[strict]",
    ],  # same P1, P2, P3 order as old V4
}

LEGACY_ALIASES = {
    "V1": "P1-strict",
    "V2": "P2-audit",
    "V3": "P3-strict",
    "V4": "ALL-strict",
}


def test_arm_order_is_exactly_the_seven_arm_ladder():
    assert ARM_ORDER == SEVEN_ARMS
    assert len(ARM_ORDER) == 7


def test_variant_order_repointed_to_arm_order():
    """The grid the runner / CLI iterate is the 7 arms."""
    assert VARIANT_ORDER == ARM_ORDER


def test_legacy_aliases_are_not_arms():
    """Aliases resolve but do NOT appear in the canonical grid order."""
    for alias in LEGACY_ALIASES:
        assert alias not in ARM_ORDER


@pytest.mark.parametrize("arm", SEVEN_ARMS)
def test_arm_composition_names(arm):
    """Each arm carries exactly its mode-tagged interceptor set, in order."""
    assert [i.name for i in interceptors_for(arm)] == ARM_COMPOSITION[arm]


def test_all_strict_shares_the_singletons_of_the_single_arms():
    """§1.3: composition uses shared stateless singletons -- ALL-strict holds
    the SAME objects as P1-strict / P2-audit / P3-strict, in that order."""
    p1_strict = interceptors_for("P1-strict")[0]
    p2 = interceptors_for("P2-audit")[0]
    p3_strict = interceptors_for("P3-strict")[0]
    all_strict = interceptors_for("ALL-strict")
    assert all_strict[0] is p1_strict
    assert all_strict[1] is p2
    assert all_strict[2] is p3_strict


@pytest.mark.parametrize("alias, arm", sorted(LEGACY_ALIASES.items()))
def test_legacy_alias_resolves_to_its_arm_set(alias, arm):
    """V1/V2/V3/V4 resolve to the SAME interceptor objects as their arm."""
    alias_set = interceptors_for(alias)
    arm_set = interceptors_for(arm)
    assert len(alias_set) == len(arm_set)
    for via_alias, via_arm in zip(alias_set, arm_set):
        assert via_alias is via_arm


def test_arms_present_in_variants_mapping():
    for arm in SEVEN_ARMS:
        assert arm in VARIANTS


def test_unknown_name_raises_keyerror_listing_known_names():
    with pytest.raises(KeyError) as excinfo:
        interceptors_for("V99")
    message = str(excinfo.value)
    # The error names the known grid so a typo is diagnosable in place.
    assert "V0" in message
    assert "ALL-strict" in message


def test_interceptors_for_returns_fresh_list():
    """Mutating a returned list never corrupts the registry."""
    first = interceptors_for("ALL-strict")
    first.clear()
    assert [i.name for i in interceptors_for("ALL-strict")] == ARM_COMPOSITION[
        "ALL-strict"
    ]
