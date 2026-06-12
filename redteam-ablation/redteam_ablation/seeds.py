"""Deterministic per-trial seed derivation.

Every trial of the Phase A grid (variant x attack x trial-index) gets a stable,
distinct seed so the fake runtime is reproducible and no two cells collide. The
seed is a function of the catalogue commit, the variant name, the attack id, and
the trial index ``i``.

In this framework phase the ``catalogue_commit`` is the SHA-256 of the
``shapira.yaml`` bytes (see ``redteam_ablation.catalogue.loader.catalogue_commit``);
it becomes the git commit hash once the catalogue is committed. Either way it is
an opaque string fed verbatim into the seed hash, so this module is agnostic to
which form it takes.
"""

from __future__ import annotations

import hashlib


def trial_seed(catalogue_commit: str, variant: str, attack_id: str, i: int) -> int:
    """Return the 64-bit seed for one trial.

    ``int(sha256(repr((catalogue_commit, variant, attack_id, i)).encode())
    .hexdigest()[:16], 16)`` -- deterministic in all four inputs and sensitive
    to each, so distinct trials (and distinct cells) never share a seed.

    A structured ``repr`` of the four-tuple is hashed rather than a flat
    ``"a|b|c|d"`` join (Finding 7): an in-band ``"|"`` in any string field could
    otherwise let two genuinely distinct tuples encode to the same byte string
    and collide on a seed (e.g. ``("a|b", "c")`` vs ``("a", "b|c")``). The
    ``repr`` quotes and comma-separates the fields, so distinct tuples always
    produce distinct encodings.
    """
    key = repr((catalogue_commit, variant, attack_id, i)).encode("utf-8")
    return int(hashlib.sha256(key).hexdigest()[:16], 16)
