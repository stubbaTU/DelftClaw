"""Step 3 gate: the identity-aware comparator (I4) and append-only delta (I5).

Pure unit tests over hand-built state values — no network. These pin the two
rules the conformance/interop metrics rest on: peer identity is canonicalized so
ephemeral mids don't defeat comparison, and only the handler-driven delta (not
seeded or init state) is judged.
"""

from __future__ import annotations

from experiments.oracle import canonicalize, state_delta

MID_A = "aa" * 20
MID_B = "bb" * 20
MID_C = "cc" * 20
ROLES = {MID_A: "A", MID_B: "B", MID_C: "C"}


# ---------------------------------------------------------------------------
# canonicalize — identity remap (I4)
# ---------------------------------------------------------------------------

def test_remaps_multiple_peer_keys() -> None:
    raw = {
        MID_A: {"amount_sats": 5000, "memo": "rent"},
        MID_C: {"amount_sats": 3000, "memo": "food"},
    }
    assert canonicalize(raw, mid_to_role=ROLES) == {
        "A": {"amount_sats": 5000, "memo": "rent"},
        "C": {"amount_sats": 3000, "memo": "food"},
    }


def test_non_mid_string_keys_are_left_intact() -> None:
    raw = {"deadbeefcid": True}
    assert canonicalize(raw, mid_to_role=ROLES) == {"deadbeefcid": True}


def test_dict_comparison_is_order_insensitive() -> None:
    a = canonicalize({MID_A: 1, MID_B: 2}, mid_to_role=ROLES)
    b = canonicalize({MID_B: 2, MID_A: 1}, mid_to_role=ROLES)
    assert a == b


# ---------------------------------------------------------------------------
# canonicalize — representation artifacts vs. real differences
# ---------------------------------------------------------------------------

def test_bytearray_collapses_to_bytes_and_tuple_to_list() -> None:
    assert canonicalize(bytearray(b"\x01\x02"), mid_to_role={}) == b"\x01\x02"
    assert canonicalize(("x", "y"), mid_to_role={}) == ["x", "y"]
    # nested
    assert canonicalize({"k": (bytearray(b"z"),)}, mid_to_role={}) == {"k": [b"z"]}


def test_bytes_and_str_stay_distinct() -> None:
    # a real conformance defect (undecoded memo) must NOT be normalized away
    assert canonicalize(b"rent", mid_to_role={}) != canonicalize("rent", mid_to_role={})


def test_full_value_preserved_no_len_reduction() -> None:
    raw = [{"name": "x", "size": 1}, {"name": "y", "size": 2}]
    assert canonicalize(raw, mid_to_role={}) == raw
    assert canonicalize(raw, mid_to_role={}) != [{"name": "x", "size": 1}]


# ---------------------------------------------------------------------------
# state_delta — append-only exclusion of baseline (I5)
# ---------------------------------------------------------------------------

def test_dict_delta_excludes_seeded_keys() -> None:
    baseline = {"seeded": {"v": 1}}
    current = {"seeded": {"v": 1}, "A": {"amount_sats": 5000}}
    assert state_delta(baseline, current) == {"A": {"amount_sats": 5000}}


def test_dict_delta_reports_changed_value() -> None:
    assert state_delta({"k": 1}, {"k": 2}) == {"k": 2}


def test_empty_baseline_delta_is_full_current() -> None:
    current = {"A": {"amount_sats": 5000, "memo": "rent"}}
    assert state_delta({}, current) == current


def test_list_delta_returns_appended_suffix() -> None:
    assert state_delta(["seed"], ["seed", "new1", "new2"]) == ["new1", "new2"]


def test_list_delta_non_prefix_returns_full_current() -> None:
    # history rewritten (not append-only) -> conservative: judge the whole list
    assert state_delta(["a"], ["b", "c"]) == ["b", "c"]


def test_scalar_delta_is_current() -> None:
    assert state_delta(0, 7) == 7


def test_delta_then_canonicalize_compose_for_multi_peer() -> None:
    """The run_scenario pipeline: canonicalize both sides, then delta. A second
    requester's entry survives; a duplicate from an existing requester does not
    change that requester's recorded (first) value."""
    baseline = canonicalize({}, mid_to_role=ROLES)
    current = canonicalize({
        MID_A: {"amount_sats": 5000, "memo": "rent"},   # first-wins kept
        MID_C: {"amount_sats": 3000, "memo": "food"},
    }, mid_to_role=ROLES)
    assert state_delta(baseline, current) == {
        "A": {"amount_sats": 5000, "memo": "rent"},
        "C": {"amount_sats": 3000, "memo": "food"},
    }
