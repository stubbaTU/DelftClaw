"""Tests for the standalone signed-log verifier CLI.

These tests drive the verifier through ``subprocess`` so the test suite
never imports producer-side encoding helpers (the verifier is meant to
be an *independent* re-implementation of canonical-bytes encoding).
The hand-crafted entries below also duplicate the canonical-bytes
encoding locally rather than importing from ``signed_log`` or
``verify`` — that independence is the whole point of the verifier.

The verifier contract under test:
    python -m signed_log.primitives.verify --log <path> [--network MAINNET]

Exit codes:
    0 — all checks pass
    1 — integrity failure (chain / signature / identity binding) or
        malformed JSON line
    2 — file/IO error (missing file, directory, non-UTF-8 bytes)
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from identity.agent_identity import AgentIdentity
from identity.seed import KeyfileSeedSource


REPO_ROOT = Path(__file__).resolve().parent


# ---------------------------------------------------------------------------
# Subprocess + log-construction helpers
# ---------------------------------------------------------------------------


def _run_verify(log_path: str, *extra: str) -> subprocess.CompletedProcess:
    """Invoke the verifier CLI with ``--log <log_path>`` plus extras."""
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "signed_log.primitives.verify",
            "--log",
            log_path,
            *extra,
        ],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        timeout=30,
    )


def _make_identity(
    tmp_path: Path, name: str = "key.pem", network: str = "MAINNET"
) -> AgentIdentity:
    """Create a fresh AgentIdentity backed by a seed file in tmp_path."""
    seed = KeyfileSeedSource(str(tmp_path / name)).load()
    return AgentIdentity.from_seed(seed, network=network)


def _produce_log(
    identity: AgentIdentity,
    log_path: str,
    n: int = 3,
) -> list[dict]:
    """Write ``n`` entries via SignedAppendOnlyLog and return the list."""
    from signed_log.primitives.signed_log import SignedAppendOnlyLog

    log = SignedAppendOnlyLog(identity, log_path)
    reporter = str(identity.network_hash)
    entries: list[dict] = []
    for i in range(n):
        entry = log.append_event(
            reporter_id=reporter,
            subject_id=reporter,
            action=f"action_{i}",
            details={"index": i},
        )
        entries.append(entry)
    return entries


def _read_lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines(keepends=True)


def _write_lines(path: Path, lines: list[str]) -> None:
    path.write_text("".join(lines), encoding="utf-8")


def _mutate_entry_field(
    path: Path,
    entry_index: int,
    key: str,
    new_value,
) -> None:
    """Mutate a single field of the ``entry_index``-th entry (1-indexed).

    Header lines (starting with ``===``) and blank lines are skipped while
    counting entries.
    """
    lines = _read_lines(path)
    out: list[str] = []
    seen = 0
    for line in lines:
        if line.startswith("===") or not line.strip():
            out.append(line)
            continue
        seen += 1
        if seen == entry_index:
            entry = json.loads(line)
            entry[key] = new_value
            line = json.dumps(entry) + "\n"
        out.append(line)
    _write_lines(path, out)


def _combined_output(result: subprocess.CompletedProcess) -> str:
    """Return stdout + stderr (case-preserved, joined for substring search)."""
    return (result.stdout or "") + "\n" + (result.stderr or "")


# ---------------------------------------------------------------------------
# Independent canonical-bytes / hand-crafted entry helpers
#
# These intentionally duplicate the encoding rather than importing from
# ``signed_log`` or ``verify`` — the test must remain independent of both
# the producer and the verifier's internals.
# ---------------------------------------------------------------------------


def _canonical_bytes_local(entry: dict) -> bytes:
    """Local copy of the canonical-bytes encoding (no import dependency)."""
    hashable = dict(entry)
    hashable.pop("entry_hash", None)
    hashable.pop("signature", None)
    return json.dumps(hashable, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def _hand_crafted_entry_with_wrong_reporter_id(
    identity: AgentIdentity,
    wrong_reporter_id: str,
    previous_hash: str = "GENESIS",
) -> dict:
    """Construct a fully-valid signed entry whose reporter_id does NOT
    derive from (pubkey | network).

    The signature covers the canonical bytes (which include the wrong
    reporter_id), and entry_hash covers those same canonical bytes — so
    chain and signature checks pass, but the binding check fails.
    """
    entry: dict = {
        "version": 2,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "reporter_id": wrong_reporter_id,
        "reporter_pubkey": identity.ipv8.raw_pubkey.hex(),
        "subject_id": wrong_reporter_id,
        "action": "test",
        "severity": 0,
        "details": {},
        "evidence": {},
        "details_hash": hashlib.sha256(b"{}").hexdigest(),
        "evidence_hash": hashlib.sha256(b"{}").hexdigest(),
        "previous_hash": previous_hash,
    }
    canonical = _canonical_bytes_local(entry)
    entry["signature"] = identity.ipv8.sign(canonical).hex()
    # entry_hash is computed over the same canonical bytes (signature and
    # entry_hash both popped) — must match the verifier's recompute exactly.
    entry["entry_hash"] = hashlib.sha256(canonical).hexdigest()
    return entry


def _write_hand_crafted_log(path: Path, entries: list[dict]) -> None:
    """Write a header + a list of hand-crafted entries as a JSONL log."""
    with path.open("w", encoding="utf-8") as handle:
        handle.write("=== OpenClaw Append-Only Security Log v2 ===\n")
        for entry in entries:
            handle.write(json.dumps(entry) + "\n")


# ---------------------------------------------------------------------------
# Mutation helpers used by the parametrized exit-code matrix.
# Each takes a log_path Path and applies one specific mutation.
# ---------------------------------------------------------------------------


def _flip_details_entry_2(log_path: Path) -> None:
    _mutate_entry_field(
        log_path,
        entry_index=2,
        key="details",
        new_value={"index": 1, "tampered": True},
    )


def _zero_sig_entry_1(log_path: Path) -> None:
    _mutate_entry_field(
        log_path, entry_index=1, key="signature", new_value="00" * 64
    )


def _swap_pubkey_entry_1(log_path: Path) -> None:
    # Replace with a syntactically valid but unrelated 32-byte hex pubkey.
    # This makes the stored entry_hash mismatch the recomputed hash.
    _mutate_entry_field(
        log_path,
        entry_index=1,
        key="reporter_pubkey",
        new_value="aa" * 32,
    )


def _bad_reporter_id_entry_1(log_path: Path) -> None:
    _mutate_entry_field(
        log_path, entry_index=1, key="reporter_id", new_value="a" * 64
    )


# ---------------------------------------------------------------------------
# Tests — clean / basic
# ---------------------------------------------------------------------------


def test_clean_log_exits_zero(tmp_path: Path) -> None:
    identity = _make_identity(tmp_path)
    log_path = tmp_path / "log.jsonl"
    _produce_log(identity, str(log_path), n=3)

    result = _run_verify(str(log_path))

    assert result.returncode == 0, (
        f"expected 0, got {result.returncode}; "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    output = _combined_output(result)
    # Tightened: explicit "Verified N entries: OK" phrase, case-insensitive.
    assert re.search(
        r"verified\s+3\s+entries.*ok", output, re.IGNORECASE
    ), f"expected 'Verified 3 entries: OK' phrase in output; got {output!r}"


def test_tampered_details_exits_one(tmp_path: Path) -> None:
    identity = _make_identity(tmp_path)
    log_path = tmp_path / "log.jsonl"
    _produce_log(identity, str(log_path), n=3)

    # Mutate the second entry's details — this breaks both the entry hash
    # and (transitively) the chain.
    _flip_details_entry_2(log_path)

    result = _run_verify(str(log_path))

    assert result.returncode == 1, (
        f"expected 1, got {result.returncode}; "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    output_lower = _combined_output(result).lower()
    # Tightened: must mention entry 2 specifically AND a hash/chain reason.
    assert "entry 2" in output_lower, (
        f"expected 'entry 2' in output; got {output_lower!r}"
    )
    assert ("hash" in output_lower) or ("chain" in output_lower), (
        f"expected 'hash' or 'chain' in output; got {output_lower!r}"
    )


def test_missing_file_exits_two(tmp_path: Path) -> None:
    missing = tmp_path / "does_not_exist.jsonl"
    result = _run_verify(str(missing))

    assert result.returncode == 2, (
        f"expected 2, got {result.returncode}; "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    assert result.stderr and result.stderr.strip(), (
        "expected non-empty stderr for missing file"
    )


def test_empty_log_exits_zero(tmp_path: Path) -> None:
    log_path = tmp_path / "empty.jsonl"
    log_path.write_text(
        "=== OpenClaw Append-Only Security Log v2 ===\n",
        encoding="utf-8",
    )

    result = _run_verify(str(log_path))

    assert result.returncode == 0, (
        f"expected 0, got {result.returncode}; "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    output = _combined_output(result)
    assert "0" in output


def test_signature_swap_exits_one(tmp_path: Path) -> None:
    identity = _make_identity(tmp_path)
    log_path = tmp_path / "log.jsonl"
    _produce_log(identity, str(log_path), n=3)

    # Replace entry 1's signature with 64 zero bytes (128 hex chars).
    _zero_sig_entry_1(log_path)

    result = _run_verify(str(log_path))

    assert result.returncode == 1, (
        f"expected 1, got {result.returncode}; "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    output_lower = _combined_output(result).lower()
    # Tightened: explicitly mention "signature" (not just "sign").
    assert "signature" in output_lower, (
        f"expected 'signature' in output; got {output_lower!r}"
    )


def test_identity_pubkey_mismatch_exits_one(tmp_path: Path) -> None:
    identity = _make_identity(tmp_path)
    log_path = tmp_path / "log.jsonl"
    _produce_log(identity, str(log_path), n=3)

    # Replace reporter_id with a 64-hex value that cannot equal
    # SHA256(reporter_pubkey | NETWORK).
    _bad_reporter_id_entry_1(log_path)

    result = _run_verify(str(log_path))

    assert result.returncode == 1, (
        f"expected 1, got {result.returncode}; "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    output_lower = _combined_output(result).lower()
    assert any(
        token in output_lower
        for token in ("identity", "binding", "reporter_id", "reporter id")
    )


def test_missing_log_argument_errors(tmp_path: Path) -> None:
    result = subprocess.run(
        [sys.executable, "-m", "signed_log.primitives.verify"],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        timeout=30,
    )

    assert result.returncode != 0, (
        f"expected non-zero exit; got {result.returncode}; "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    stderr_lower = (result.stderr or "").lower()
    assert "--log" in stderr_lower or "required" in stderr_lower, (
        f"expected stderr to mention --log or 'required'; "
        f"stderr={result.stderr!r}"
    )


def test_truncated_last_line_exits_one(tmp_path: Path) -> None:
    """Truncated/malformed JSON returns exit 1 (per the docstring contract)."""
    identity = _make_identity(tmp_path)
    log_path = tmp_path / "log.jsonl"
    _produce_log(identity, str(log_path), n=3)

    # Append a partial JSON fragment without a trailing newline.
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write('{"version":2,')

    result = _run_verify(str(log_path))

    # Tightened: pin to exit 1 (malformed JSON path), no exit-2 fallback.
    assert result.returncode == 1, (
        f"expected 1, got {result.returncode}; "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    output_lower = _combined_output(result).lower()
    assert any(
        token in output_lower
        for token in ("json", "parse", "malformed", "decode")
    )


# ---------------------------------------------------------------------------
# Tests — critical coverage gaps
# ---------------------------------------------------------------------------


def test_network_flag_used_for_binding(tmp_path: Path) -> None:
    """The --network flag controls the binding check.

    A log produced under STAGING must verify under --network STAGING and
    fail under --network MAINNET (because reporter_id is bound to the
    network at production time).
    """
    identity = _make_identity(tmp_path, network="STAGING")
    log_path = tmp_path / "log.jsonl"
    _produce_log(identity, str(log_path), n=2)

    # Correct network → exit 0.
    result_ok = _run_verify(str(log_path), "--network", "STAGING")
    assert result_ok.returncode == 0, (
        f"expected 0 for matching network; got {result_ok.returncode}; "
        f"stdout={result_ok.stdout!r} stderr={result_ok.stderr!r}"
    )

    # Wrong network → exit 1, output mentions binding/identity.
    result_bad = _run_verify(str(log_path), "--network", "MAINNET")
    assert result_bad.returncode == 1, (
        f"expected 1 for mismatched network; got {result_bad.returncode}; "
        f"stdout={result_bad.stdout!r} stderr={result_bad.stderr!r}"
    )
    output_lower = _combined_output(result_bad).lower()
    assert any(
        token in output_lower
        for token in ("binding", "identity", "reporter_id", "derive")
    ), f"expected binding/identity hint in output; got {output_lower!r}"


def test_pure_binding_only_break(tmp_path: Path) -> None:
    """A hand-crafted entry that breaks ONLY the binding check.

    Chain (previous_hash=GENESIS, entry_hash recomputed over canonical
    bytes) and signature (signed by identity_a over the same canonical
    bytes) both pass. Only reporter_id is wrong (does not derive from
    pubkey|network). This proves the binding check is independently
    exercised.
    """
    identity = _make_identity(tmp_path, network="MAINNET")
    bad_entry = _hand_crafted_entry_with_wrong_reporter_id(
        identity=identity,
        wrong_reporter_id="a" * 64,
        previous_hash="GENESIS",
    )
    log_path = tmp_path / "log.jsonl"
    _write_hand_crafted_log(log_path, [bad_entry])

    result = _run_verify(str(log_path), "--network", "MAINNET")

    assert result.returncode == 1, (
        f"expected 1 (only binding broken); got {result.returncode}; "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    output_lower = _combined_output(result).lower()
    assert ("binding" in output_lower) or ("derive" in output_lower), (
        f"expected 'binding' or 'derive' in output; got {output_lower!r}"
    )
    # Sanity: chain and signature errors should NOT appear, since this
    # test isolates the binding failure.
    assert "previous_hash mismatch" not in output_lower, (
        f"chain check should not have fired; got {output_lower!r}"
    )
    assert "entry_hash mismatch" not in output_lower, (
        f"entry_hash check should not have fired; got {output_lower!r}"
    )
    assert "signature verification failed" not in output_lower, (
        f"signature check should not have fired; got {output_lower!r}"
    )


def test_pure_chain_break_only(tmp_path: Path) -> None:
    """Mutate ONLY entry 2's previous_hash. Exit 1, output mentions chain."""
    identity = _make_identity(tmp_path)
    log_path = tmp_path / "log.jsonl"
    _produce_log(identity, str(log_path), n=3)

    _mutate_entry_field(
        log_path, entry_index=2, key="previous_hash", new_value="a" * 64
    )

    result = _run_verify(str(log_path))

    assert result.returncode == 1, (
        f"expected 1, got {result.returncode}; "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    output_lower = _combined_output(result).lower()
    assert ("chain" in output_lower) or ("previous_hash" in output_lower), (
        f"expected 'chain' or 'previous_hash' in output; got {output_lower!r}"
    )


# ---------------------------------------------------------------------------
# Better signature attack
# ---------------------------------------------------------------------------


def test_signature_swap_to_real_sig_for_different_message(
    tmp_path: Path,
) -> None:
    """Swap entry 1's signature with a real Ed25519 sig over different bytes.

    This is a stronger attack than zero-bytes: the signature is well-formed
    and was produced by the legitimate identity, but it does not bind to
    the entry's canonical bytes. Verifier must still reject.
    """
    identity = _make_identity(tmp_path)
    log_path = tmp_path / "log.jsonl"
    _produce_log(identity, str(log_path), n=3)

    wrong_sig = identity.ipv8.sign(b"different content").hex()
    _mutate_entry_field(
        log_path, entry_index=1, key="signature", new_value=wrong_sig
    )

    result = _run_verify(str(log_path))

    assert result.returncode == 1, (
        f"expected 1, got {result.returncode}; "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    output_lower = _combined_output(result).lower()
    assert "signature" in output_lower, (
        f"expected 'signature' in output; got {output_lower!r}"
    )


# ---------------------------------------------------------------------------
# Multi-entry tampering
# ---------------------------------------------------------------------------


def test_multi_entry_tampering_reported(tmp_path: Path) -> None:
    """Tamper entries 2 AND 4. Both should be reported (not just the first).

    Per the verifier's contract: integrity errors do NOT abort scanning
    (only malformed JSON does). So mutations on entries 2 and 4 must each
    surface in the output.
    """
    identity = _make_identity(tmp_path)
    log_path = tmp_path / "log.jsonl"
    _produce_log(identity, str(log_path), n=5)

    _mutate_entry_field(
        log_path,
        entry_index=2,
        key="details",
        new_value={"index": 1, "tampered": True},
    )
    _mutate_entry_field(
        log_path,
        entry_index=4,
        key="details",
        new_value={"index": 3, "tampered": True},
    )

    result = _run_verify(str(log_path))

    assert result.returncode == 1, (
        f"expected 1, got {result.returncode}; "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    output_lower = _combined_output(result).lower()
    assert "entry 2" in output_lower, (
        f"expected 'entry 2' in output; got {output_lower!r}"
    )
    assert "entry 4" in output_lower, (
        f"expected 'entry 4' in output; got {output_lower!r}"
    )


# ---------------------------------------------------------------------------
# File handling
# ---------------------------------------------------------------------------


def test_directory_path_exits_two(tmp_path: Path) -> None:
    """Pointing --log at a directory must return exit 2."""
    target_dir = tmp_path / "a_directory"
    target_dir.mkdir()

    result = _run_verify(str(target_dir))

    assert result.returncode == 2, (
        f"expected 2, got {result.returncode}; "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    assert result.stderr and result.stderr.strip(), (
        "expected non-empty stderr for directory path"
    )


def test_binary_file_exits_two(tmp_path: Path) -> None:
    """Random non-UTF-8 bytes as a 'log' must return exit 2."""
    log_path = tmp_path / "binary.bin"
    log_path.write_bytes(bytes(range(256)))

    result = _run_verify(str(log_path))

    assert result.returncode == 2, (
        f"expected 2, got {result.returncode}; "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    assert result.stderr and result.stderr.strip(), (
        "expected non-empty stderr for binary file"
    )


def test_zero_byte_file_handles_gracefully(tmp_path: Path) -> None:
    """A 0-byte file is treated as 0 entries and exits 0.

    No header, no entries — vacuously valid. The verifier reports
    "Verified 0 entries: OK".
    """
    log_path = tmp_path / "empty.jsonl"
    log_path.write_bytes(b"")

    result = _run_verify(str(log_path))

    assert result.returncode == 0, (
        f"expected 0, got {result.returncode}; "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    output = _combined_output(result)
    assert "0" in output


# ---------------------------------------------------------------------------
# Parametrized exit-code matrix
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "mutation_name, mutation_fn, expected_exit, expected_substring",
    [
        ("clean", lambda log_path: None, 0, "ok"),
        ("flip_details", _flip_details_entry_2, 1, "entry 2"),
        ("zero_signature", _zero_sig_entry_1, 1, "signature"),
        ("swap_pubkey", _swap_pubkey_entry_1, 1, "hash"),
        ("bad_reporter_id", _bad_reporter_id_entry_1, 1, "binding"),
    ],
)
def test_verifier_exit_code_matrix(
    tmp_path: Path,
    mutation_name: str,
    mutation_fn,
    expected_exit: int,
    expected_substring: str,
) -> None:
    """Bundle several mutation patterns + expected outcomes in one matrix."""
    identity = _make_identity(tmp_path)
    log_path = tmp_path / "log.jsonl"
    _produce_log(identity, str(log_path), n=3)

    mutation_fn(log_path)

    result = _run_verify(str(log_path))

    assert result.returncode == expected_exit, (
        f"[{mutation_name}] expected exit {expected_exit}, got "
        f"{result.returncode}; stdout={result.stdout!r} "
        f"stderr={result.stderr!r}"
    )
    output_lower = _combined_output(result).lower()
    assert expected_substring.lower() in output_lower, (
        f"[{mutation_name}] expected substring "
        f"{expected_substring!r} in output; got {output_lower!r}"
    )
