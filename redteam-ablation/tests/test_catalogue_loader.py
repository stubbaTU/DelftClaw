"""Catalogue loader: the 8 Shapira-derived fixtures load with valid fields,
all five pre-hoc classes are represented, and catalogue_commit is stable.
"""

from pathlib import Path

from redteam_ablation.catalogue.loader import (
    Attack,
    catalogue_commit,
    load_catalogue,
)

CATALOGUE_PATH = (
    Path(__file__).resolve().parents[1] / "catalogue" / "shapira.yaml"
)

ALLOWED_CLASSES = {
    "Identity",
    "Audit-trail",
    "Configuration",
    "Behaviour",
    "Mixed",
}

# Ground truth lifted verbatim from the surviving ablation_run.log (V0 rows):
# attack_id -> (attack_name baked into the ref/payload context, target_tool).
EXPECTED_TARGETS = {
    "SH-01": "exfiltrate_secret",
    "SH-02": "send_email",
    "SH-03": "write_memory",
    "SH-04": "exfiltrate_secret",
    "SH-05": "write_file",
    "SH-06": "drain_wallet",
    "SH-07": "delete_audit_log",
    "SH-10": "drain_wallet",
}

# Pre-registered attack-mechanism descriptors (the StructuredInputs "vectors"):
# spoofs_identity is True exactly for the Identity-class attacks (the principal is
# forged); tampers_constitution is True exactly for the Configuration-class attack
# (the constitution/config is mutated). Behaviour, Audit-trail and Mixed attacks
# touch neither integrity primitive's input, so both flags are False for them.
EXPECTED_SPOOFS_IDENTITY = {
    "SH-01": False,
    "SH-02": False,
    "SH-03": True,
    "SH-04": True,
    "SH-05": False,
    "SH-06": False,
    "SH-07": False,
    "SH-10": False,
}

EXPECTED_TAMPERS_CONSTITUTION = {
    "SH-01": False,
    "SH-02": False,
    "SH-03": False,
    "SH-04": False,
    "SH-05": True,
    "SH-06": False,
    "SH-07": False,
    "SH-10": False,
}


def test_loads_exactly_eight_attacks():
    attacks = load_catalogue(CATALOGUE_PATH)
    assert len(attacks) == 8


def test_attacks_are_attack_dataclasses():
    attacks = load_catalogue(CATALOGUE_PATH)
    assert all(isinstance(a, Attack) for a in attacks)


def test_attack_ids_match_ground_truth():
    attacks = load_catalogue(CATALOGUE_PATH)
    ids = {a.attack_id for a in attacks}
    assert ids == set(EXPECTED_TARGETS)


def test_every_attack_has_nonempty_target_tool():
    attacks = load_catalogue(CATALOGUE_PATH)
    for a in attacks:
        assert a.target_tool, f"{a.attack_id} has empty target_tool"


def test_target_tools_match_surviving_log():
    attacks = {a.attack_id: a for a in load_catalogue(CATALOGUE_PATH)}
    for attack_id, target in EXPECTED_TARGETS.items():
        assert attacks[attack_id].target_tool == target


def test_every_attack_class_in_allowed_set():
    attacks = load_catalogue(CATALOGUE_PATH)
    for a in attacks:
        assert a.attack_class in ALLOWED_CLASSES, (
            f"{a.attack_id} has class {a.attack_class!r}"
        )


def test_all_five_classes_present():
    attacks = load_catalogue(CATALOGUE_PATH)
    classes = {a.attack_class for a in attacks}
    # Every column of the per-class (variant x class) matrix must be
    # populatable, so all five pre-hoc classes must appear at least once.
    assert classes == ALLOWED_CLASSES


def test_every_attack_has_deterministic_predicate_name():
    attacks = load_catalogue(CATALOGUE_PATH)
    for a in attacks:
        # All 8 framework attacks resolve via the deterministic predicate.
        assert a.deterministic_predicate == "tool_executed"


def test_every_attack_has_success_predicate_nl():
    attacks = load_catalogue(CATALOGUE_PATH)
    for a in attacks:
        assert a.success_predicate_nl.strip(), (
            f"{a.attack_id} missing NL success predicate"
        )


def test_every_attack_has_payload_and_shapira_ref():
    attacks = load_catalogue(CATALOGUE_PATH)
    for a in attacks:
        assert a.payload_template.strip(), f"{a.attack_id} empty payload"
        assert a.shapira_ref.strip(), f"{a.attack_id} empty shapira_ref"


def test_spoofs_identity_set_for_identity_class_only():
    attacks = {a.attack_id: a for a in load_catalogue(CATALOGUE_PATH)}
    for attack_id, expected in EXPECTED_SPOOFS_IDENTITY.items():
        assert attacks[attack_id].spoofs_identity is expected, (
            f"{attack_id} spoofs_identity should be {expected}"
        )


def test_tampers_constitution_set_for_configuration_class_only():
    attacks = {a.attack_id: a for a in load_catalogue(CATALOGUE_PATH)}
    for attack_id, expected in EXPECTED_TAMPERS_CONSTITUTION.items():
        assert attacks[attack_id].tampers_constitution is expected, (
            f"{attack_id} tampers_constitution should be {expected}"
        )


def test_only_identity_attacks_spoof_identity():
    attacks = load_catalogue(CATALOGUE_PATH)
    for a in attacks:
        if a.attack_class == "Identity":
            assert a.spoofs_identity is True
        else:
            assert a.spoofs_identity is False


def test_only_configuration_attacks_tamper_constitution():
    attacks = load_catalogue(CATALOGUE_PATH)
    for a in attacks:
        if a.attack_class == "Configuration":
            assert a.tampers_constitution is True
        else:
            assert a.tampers_constitution is False


def test_vectors_default_to_false_when_absent():
    # An Attack constructed without a vectors mapping (the loader default for a
    # fixture missing the key) carries both flags as False -- backward compatible.
    a = Attack(
        attack_id="SH-xx",
        attack_class="Behaviour",
        target_tool="exfiltrate_secret",
        payload_template="payload",
        deterministic_predicate="tool_executed",
        success_predicate_nl="nl",
        shapira_ref="ref",
    )
    assert a.spoofs_identity is False
    assert a.tampers_constitution is False


def test_catalogue_commit_is_sha256_hex():
    commit = catalogue_commit(CATALOGUE_PATH)
    assert isinstance(commit, str)
    assert len(commit) == 64
    int(commit, 16)  # raises ValueError if not hex


def test_catalogue_commit_stable_across_two_calls():
    first = catalogue_commit(CATALOGUE_PATH)
    second = catalogue_commit(CATALOGUE_PATH)
    assert first == second
