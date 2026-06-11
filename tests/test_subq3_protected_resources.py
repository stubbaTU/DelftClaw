from __future__ import annotations

from pathlib import Path

from redteam.primitives.signed_log import SignedAppendOnlyLog

from security.containment_layer.infrastructure.protected_resources import (
    create_protected_fixture,
    destroy_fixture,
    verify_fixture_integrity,
)


def test_protected_fixture_creates_all_mock_resources(tmp_path: Path) -> None:
    fixture = create_protected_fixture("trial_a", tmp_path)

    try:
        for path in fixture.paths.values():
            assert path.exists()
        assert (fixture.agent_workspace / "input").exists()
        assert (fixture.agent_workspace / "output").exists()
        assert (fixture.agent_workspace / "tmp").exists()
        assert fixture.proxy_dir.exists()
    finally:
        destroy_fixture(fixture)


def test_canaries_are_unique_per_trial(tmp_path: Path) -> None:
    a = create_protected_fixture("trial_a", tmp_path)
    b = create_protected_fixture("trial_b", tmp_path)

    try:
        assert set(a.canaries.values()).isdisjoint(set(b.canaries.values()))
    finally:
        destroy_fixture(a)
        destroy_fixture(b)


def test_integrity_checker_detects_file_modification(tmp_path: Path) -> None:
    fixture = create_protected_fixture("trial_mod", tmp_path)

    try:
        fixture.paths["wallet_state"].write_text("tampered\n", encoding="utf-8")
        result = verify_fixture_integrity(fixture)
        assert result.ok is False
        assert "wallet_state" in result.modified_files
    finally:
        destroy_fixture(fixture)


def test_integrity_checker_detects_file_deletion(tmp_path: Path) -> None:
    fixture = create_protected_fixture("trial_delete", tmp_path)

    try:
        fixture.paths["seedbox_acl"].unlink()
        result = verify_fixture_integrity(fixture)
        assert result.ok is False
        assert "seedbox_acl" in result.deleted_files
    finally:
        destroy_fixture(fixture)


def test_signed_log_verifies_before_and_fails_after_tampering(tmp_path: Path) -> None:
    fixture = create_protected_fixture("trial_log", tmp_path)

    try:
        log = SignedAppendOnlyLog(fixture.signing_identity, fixture.paths["accountability_log"])
        ok, errors = log.verify_integrity()
        assert (ok, errors) == (True, [])

        with fixture.paths["accountability_log"].open("a", encoding="utf-8") as handle:
            handle.write('{"forged": true}\n')
        result = verify_fixture_integrity(fixture)
        assert result.log_chain_valid is False
    finally:
        destroy_fixture(fixture)

