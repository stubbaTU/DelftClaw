"""Per-trial seed derivation: determinism and sensitivity to every argument.

The seed is ``int(sha256(repr((catalogue_commit, variant, attack_id, i))
.encode()).hexdigest()[:16], 16)``. It must be (a) reproducible for identical
inputs and (b) different when any one of the four inputs changes, so that no two
cells (or trials within a cell) share a seed. The structured ``repr`` encoding
(rather than a flat ``"|"``-joined string) means an in-band delimiter cannot make
two distinct input tuples collide.
"""

import hashlib

from redteam_ablation.seeds import trial_seed

COMMIT = "a" * 64  # stand-in catalogue_commit (sha256 hex)


def test_seed_is_int():
    assert isinstance(trial_seed(COMMIT, "V0", "SH-01", 0), int)


def test_seed_is_deterministic():
    first = trial_seed(COMMIT, "V0", "SH-01", 3)
    second = trial_seed(COMMIT, "V0", "SH-01", 3)
    assert first == second


def test_seed_matches_documented_formula():
    expected = int(
        hashlib.sha256(
            repr((COMMIT, "V0", "SH-01", 7)).encode("utf-8")
        ).hexdigest()[:16],
        16,
    )
    assert trial_seed(COMMIT, "V0", "SH-01", 7) == expected


def test_seed_is_64_bit_nonnegative():
    seed = trial_seed(COMMIT, "V4", "SH-10", 9)
    assert 0 <= seed < 2**64


def test_seed_sensitive_to_catalogue_commit():
    a = trial_seed("a" * 64, "V0", "SH-01", 0)
    b = trial_seed("b" * 64, "V0", "SH-01", 0)
    assert a != b


def test_seed_sensitive_to_variant():
    a = trial_seed(COMMIT, "V0", "SH-01", 0)
    b = trial_seed(COMMIT, "V1", "SH-01", 0)
    assert a != b


def test_seed_sensitive_to_attack_id():
    a = trial_seed(COMMIT, "V0", "SH-01", 0)
    b = trial_seed(COMMIT, "V0", "SH-02", 0)
    assert a != b


def test_seed_sensitive_to_trial_index():
    a = trial_seed(COMMIT, "V0", "SH-01", 0)
    b = trial_seed(COMMIT, "V0", "SH-01", 1)
    assert a != b


def test_distinct_trials_in_one_cell_have_distinct_seeds():
    seeds = [trial_seed(COMMIT, "V0", "SH-01", i) for i in range(10)]
    assert len(set(seeds)) == len(seeds)


def test_in_band_delimiter_does_not_collide():
    """Two distinct input tuples that collided under the old ``"|"`` join differ.

    Under the previous ``f"{commit}|{variant}|{attack_id}|{i}"`` encoding the
    pair below both flattened to ``"{COMMIT}|V0|SH-01|x|0"`` and shared a seed.
    The structured ``repr`` encoding (Finding 7) keeps them distinct.
    """
    # Sanity: these genuinely collide under the OLD flat-join formula.
    old_a = f"{COMMIT}|{'V0|SH-01'}|{'x'}|{0}"
    old_b = f"{COMMIT}|{'V0'}|{'SH-01|x'}|{0}"
    assert old_a == old_b  # the bug the new encoding fixes

    a = trial_seed(COMMIT, "V0|SH-01", "x", 0)
    b = trial_seed(COMMIT, "V0", "SH-01|x", 0)
    assert a != b
