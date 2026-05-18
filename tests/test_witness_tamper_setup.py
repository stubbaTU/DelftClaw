"""TDD tests for the witness-tamper demo bootstrap."""

from __future__ import annotations

import os
from pathlib import Path

from redteam.demo.witness_tamper.setup import BootstrapResult, bootstrap
from redteam.primitives.signed_log import SignedAppendOnlyLog


def _count_entries(path: Path) -> int:
    if not path.exists():
        return 0
    n = 0
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            if line.startswith("===") or not line.strip():
                continue
            n += 1
    return n


def test_bootstrap_creates_three_distinct_identities(tmp_path: Path) -> None:
    result = bootstrap(tmp_path)
    assert isinstance(result, BootstrapResult)
    ids = {
        result.a_identity.identity_hash,
        result.b_identity.identity_hash,
        result.c_identity.identity_hash,
    }
    assert len(ids) == 3


def test_bootstrap_creates_three_logs(tmp_path: Path) -> None:
    result = bootstrap(tmp_path)
    assert result.a_log_path.exists()
    assert result.b_log_path.exists()
    assert result.c_log_path.exists()
    assert _count_entries(result.a_log_path) == 0
    assert _count_entries(result.c_log_path) == 0
    assert _count_entries(result.b_log_path) == 1


def test_b_witness_entry_kind_and_ids(tmp_path: Path) -> None:
    result = bootstrap(tmp_path)
    entry = result.witness_entry
    assert entry["kind"] == "witness"
    assert entry["reporter_id"] == result.b_identity.identity_hash
    assert entry["subject_id"] == result.a_identity.identity_hash


def test_b_witness_entry_verifies(tmp_path: Path) -> None:
    result = bootstrap(tmp_path)
    ok, errors = SignedAppendOnlyLog.verify_foreign_entry(
        result.witness_entry, result.b_identity.network
    )
    assert ok, errors
    assert errors == []


def test_b_witness_entry_details_match_amount_5(tmp_path: Path) -> None:
    result = bootstrap(tmp_path)
    assert result.witness_entry["details"]["amount"] == 5
    assert result.witness_entry["details"]["recipient"] == "community_alpha"
    assert result.witness_entry["action"] == "donation"


def test_shared_network(tmp_path: Path) -> None:
    result = bootstrap(tmp_path)
    net = result.network
    # All three identities resolve to the same network string.
    assert result.a_identity.network == result.b_identity.network == result.c_identity.network
    # And that string matches the result.network field.
    assert result.a_identity.network == net
    # The network is bound into each identity hash:
    # SHA256(pubkey || network) == identity_hash.
    import hashlib
    for ident in (result.a_identity, result.b_identity, result.c_identity):
        expected = hashlib.sha256(
            ident.public_key + ident.network.encode("utf-8")
        ).hexdigest()
        assert ident.identity_hash == expected
