"""Variant -> interceptor-set registry.

An *arm* names an ordered, mode-tagged interceptor set the dispatcher runs.
The grid is the 7-arm enforcement ladder (plan 2026-06-10 §1.3); the legacy
V1-V4 aliases keep resolving so old call sites keep meaning. The registry is
the single authority on the arm order so the runner / CLI iterate it once, and
on which interceptors each arm carries.
"""

import pytest

from redteam_ablation.interceptors.base import Interceptor
from redteam_ablation.interceptors.registry import (
    VARIANT_ORDER,
    VARIANTS,
    interceptors_for,
)

# Plan 2026-06-10 §1.3: the canonical 7-arm ladder (was the 5-variant V0-V4 grid).
SEVEN_ARMS = [
    "V0",
    "P1-audit",
    "P1-strict",
    "P2-audit",
    "P3-audit",
    "P3-strict",
    "ALL-strict",
]


def test_variant_order_is_the_seven_arm_ladder():
    # Plan §1.3: VARIANT_ORDER is re-pointed to the 7-arm ARM_ORDER.
    assert VARIANT_ORDER == SEVEN_ARMS
    assert len(VARIANT_ORDER) == 7


def test_all_arm_keys_present():
    # Plan §1.3: every canonical arm composes from the registry.
    for arm in SEVEN_ARMS:
        assert arm in VARIANTS


def test_variants_keys_cover_the_arm_order():
    # Plan §1.3: legacy aliases (V1-V4) may also be registry keys, so VARIANTS
    # is a superset of the canonical order rather than exactly equal to it.
    assert set(VARIANT_ORDER) <= set(VARIANTS.keys())


def test_v0_is_empty_interceptor_list():
    assert VARIANTS["V0"] == []
    assert interceptors_for("V0") == []


def test_v1_through_v4_aliases_carry_mode_tagged_bodies():
    # Plan §1.3: legacy aliases resolve (V1->P1-strict, V2->P2-audit,
    # V3->P3-strict, V4->ALL-strict); plan §1.1: names carry the mode tag.
    assert [i.name for i in interceptors_for("V1")] == [
        "P1-owner-identity[strict]"
    ]
    assert [i.name for i in interceptors_for("V2")] == ["P2-signed-log"]
    assert [i.name for i in interceptors_for("V3")] == [
        "P3-constitution-hash[strict]"
    ]
    assert [i.name for i in interceptors_for("V4")] == [
        "P1-owner-identity[strict]",
        "P2-signed-log",
        "P3-constitution-hash[strict]",
    ]


def test_interceptors_for_returns_list():
    result = interceptors_for("V0")
    assert isinstance(result, list)


def test_interceptors_for_unknown_variant_raises():
    with pytest.raises((KeyError, ValueError)):
        interceptors_for("V99")


def test_interceptors_satisfy_protocol():
    # Every registered interceptor across all variants must be an Interceptor.
    for variant in VARIANT_ORDER:
        for interceptor in interceptors_for(variant):
            assert isinstance(interceptor, Interceptor)
