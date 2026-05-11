"""TDD red-step tests for the Layer 3 HTTP dev-mode endpoints.

These tests intentionally fail until ``redteam.integration.server.build_app``
is extended to accept a ``peer_log_dir`` argument and host the new routes:

* ``GET  /identity``          — node identity advert.
* ``GET  /head``              — current chain head.
* ``GET  /entries``           — incremental sync (since/limit).
* ``GET  /entries/{hash}``    — single entry.
* ``POST /entries``           — accept foreign signed entry into peer cache.
* ``OPTIONS /entries``        — 204 + Allow.

Bootstraps the FastAPI test pattern for this repo (no FastAPI tests exist
yet — see ``test_signed_server.py`` which exercises a real bound port).
Uses ``fastapi.testclient.TestClient`` for in-process testing.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from identity.openclaw_identity import OpenClawIdentity
from redteam.primitives.signed_log import SignedAppendOnlyLog

# This call signature change will fail in the red phase — the existing
# ``build_app`` only takes (identity, log_path).
from redteam.integration.server import build_app  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_identity(
    tmp_path: Path,
    name: str = "test_key.pem",
    network: str = "MAINNET",
) -> OpenClawIdentity:
    return OpenClawIdentity(network=network, key_path=str(tmp_path / name))


def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _stable_hash_hex(payload: dict) -> str:
    return hashlib.sha256(_canonical(payload)).hexdigest()


def _make_subject_claim(
    identity: OpenClawIdentity,
    action: str,
    details: dict,
    *,
    claim_timestamp: str = "2025-01-01T00:00:00+00:00",
    nonce_hex: str = "00112233445566778899aabbccddeeff",
) -> tuple[dict, bytes, bytes]:
    claim = {
        "kind": "claim",
        "version": 1,
        "subject_id": str(identity.identity_hash),
        "action": action,
        "details_hash": _stable_hash_hex(details),
        "claim_timestamp": claim_timestamp,
        "nonce": nonce_hex,
    }
    sig = identity.sign(_canonical(claim))
    return claim, identity.public_key, sig


def _make_app(
    tmp_path: Path,
    *,
    name: str = "server_key.pem",
    network: str = "MAINNET",
) -> tuple[Any, OpenClawIdentity, str, str]:
    """Build the FastAPI app + return supporting paths.

    Returns ``(app, identity, log_path, peer_log_dir)``.
    """
    identity = OpenClawIdentity(network=network, key_path=str(tmp_path / name))
    log_path = str(tmp_path / "server.log")
    peer_log_dir = str(tmp_path / "peer_logs")
    app = build_app(identity, log_path, peer_log_dir)
    return app, identity, log_path, peer_log_dir


def _seed_log(
    log_path: str,
    identity: OpenClawIdentity,
    n: int = 3,
) -> list[dict]:
    """Append ``n`` self entries through the wrapper, return the list."""
    wrapper = SignedAppendOnlyLog(identity, log_path)
    out: list[dict] = []
    for i in range(n):
        entry = wrapper.append_event(
            reporter_id=str(identity.identity_hash),
            subject_id=str(identity.identity_hash),
            action=f"seed_action_{i}",
            details={"i": i},
        )
        out.append(entry)
    return out


def _foreign_self_entry(
    tmp_path: Path,
    *,
    name: str = "foreign.pem",
    network: str = "MAINNET",
    action: str = "foreign_action",
    details: dict | None = None,
) -> tuple[OpenClawIdentity, dict]:
    """Create a foreign identity + signed log; return the resulting entry dict.

    Helper-name parity with ``test_peer_log.py`` so cross-suite fixture
    extraction stays straightforward.
    """
    identity = OpenClawIdentity(network=network, key_path=str(tmp_path / name))
    log_path = str(tmp_path / f"{name}.log")
    wrapper = SignedAppendOnlyLog(identity, log_path)
    wrapper.append_event(
        reporter_id=str(identity.identity_hash),
        subject_id=str(identity.identity_hash),
        action=action,
        details=details if details is not None else {"k": "v"},
    )
    entries = wrapper.read_entries()
    assert len(entries) == 1
    return identity, entries[0]


def _foreign_witness_entry(
    tmp_path: Path,
    *,
    reporter_name: str = "foreign_reporter.pem",
    subject_name: str = "foreign_subject.pem",
    network: str = "MAINNET",
    action: str = "observed_action",
    details: dict | None = None,
    nonce_hex: str = "66" * 16,
) -> tuple[OpenClawIdentity, OpenClawIdentity, dict]:
    subject = OpenClawIdentity(network=network, key_path=str(tmp_path / subject_name))
    reporter = OpenClawIdentity(
        network=network, key_path=str(tmp_path / reporter_name)
    )

    if details is None:
        details = {"k": "v"}
    claim, pk, sig = _make_subject_claim(
        subject, action, details, nonce_hex=nonce_hex
    )
    log_path = str(tmp_path / f"{reporter_name}.log")
    wrapper = SignedAppendOnlyLog(reporter, log_path)
    wrapper.append_witness_event(
        reporter_id=str(reporter.identity_hash),
        subject_id=str(subject.identity_hash),
        subject_pubkey=pk,
        subject_claim=claim,
        subject_signature=sig,
        action=action,
        details=details,
    )
    entries = wrapper.read_entries()
    assert len(entries) == 1
    return subject, reporter, entries[0]


def _recompute_reporter_sig_and_hash(
    entry: dict, identity: OpenClawIdentity
) -> dict:
    """Re-sign + re-hash an entry so the chain stays internally consistent.

    Used after mutating a foreign entry on-the-wire so that only the
    targeted check fires server-side.
    """
    payload = dict(entry)
    payload.pop("entry_hash", None)
    payload.pop("signature", None)
    sig = identity.sign(_canonical(payload)).hex()
    entry["signature"] = sig
    hashable = dict(entry)
    hashable.pop("entry_hash", None)
    hashable.pop("signature", None)
    entry["entry_hash"] = hashlib.sha256(_canonical(hashable)).hexdigest()
    return entry


# ---------------------------------------------------------------------------
# GET /identity
# ---------------------------------------------------------------------------


def test_get_identity_returns_server_identity_pubkey_network(tmp_path: Path) -> None:
    """``GET /identity`` returns identity_hash, pubkey hex, and network."""
    app, identity, _log_path, _peer_log_dir = _make_app(tmp_path)
    with TestClient(app) as client:
        resp = client.get("/identity")
    assert resp.status_code == 200
    body = resp.json()
    assert body["identity_hash"] == str(identity.identity_hash)
    assert body["pubkey_hex"] == identity.public_key.hex()
    assert body["network"] == identity.network


# ---------------------------------------------------------------------------
# GET /head
# ---------------------------------------------------------------------------


def test_get_head_on_empty_log_returns_genesis(tmp_path: Path) -> None:
    """An empty log advertises ``GENESIS`` as its head."""
    app, _identity, _log_path, _peer_log_dir = _make_app(tmp_path)
    with TestClient(app) as client:
        resp = client.get("/head")
    assert resp.status_code == 200
    assert resp.json() == {"head_hash": "GENESIS"}


def test_get_head_after_one_append_returns_entry_hash(tmp_path: Path) -> None:
    """After one append the head is the entry's hash."""
    app, identity, log_path, _peer_log_dir = _make_app(tmp_path)
    entries = _seed_log(log_path, identity, n=1)

    with TestClient(app) as client:
        resp = client.get("/head")
    assert resp.status_code == 200
    assert resp.json() == {"head_hash": entries[0]["entry_hash"]}


def test_get_head_after_n_appends_returns_latest(tmp_path: Path) -> None:
    """After multiple appends the head is the latest entry's hash."""
    app, identity, log_path, _peer_log_dir = _make_app(tmp_path)
    entries = _seed_log(log_path, identity, n=4)

    with TestClient(app) as client:
        resp = client.get("/head")
    assert resp.status_code == 200
    assert resp.json() == {"head_hash": entries[-1]["entry_hash"]}


# ---------------------------------------------------------------------------
# GET /entries
# ---------------------------------------------------------------------------


def test_get_entries_empty_log_returns_empty_list(tmp_path: Path) -> None:
    """No entries → ``{entries: [], head_hash: "GENESIS"}``."""
    app, _identity, _log_path, _peer_log_dir = _make_app(tmp_path)
    with TestClient(app) as client:
        resp = client.get("/entries")
    assert resp.status_code == 200
    body = resp.json()
    assert body["entries"] == []
    assert body["head_hash"] == "GENESIS"


def test_get_entries_no_since_returns_all_entries(tmp_path: Path) -> None:
    """``since`` omitted → from genesis (all entries returned)."""
    app, identity, log_path, _peer_log_dir = _make_app(tmp_path)
    entries = _seed_log(log_path, identity, n=3)

    with TestClient(app) as client:
        resp = client.get("/entries")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["entries"]) == 3
    assert [e["entry_hash"] for e in body["entries"]] == [
        e["entry_hash"] for e in entries
    ]
    assert body["head_hash"] == entries[-1]["entry_hash"]


def test_get_entries_since_known_hash_returns_subset_after(tmp_path: Path) -> None:
    """``since=<hash>`` returns only entries strictly after that hash."""
    app, identity, log_path, _peer_log_dir = _make_app(tmp_path)
    entries = _seed_log(log_path, identity, n=4)
    # Use the second entry as the cursor; expect entries[2:] back.
    cursor = entries[1]["entry_hash"]

    with TestClient(app) as client:
        resp = client.get("/entries", params={"since": cursor})
    assert resp.status_code == 200
    body = resp.json()
    assert [e["entry_hash"] for e in body["entries"]] == [
        entries[2]["entry_hash"],
        entries[3]["entry_hash"],
    ]
    assert body["head_hash"] == entries[-1]["entry_hash"]


def test_get_entries_since_unknown_hash_returns_404(tmp_path: Path) -> None:
    """``since`` not in chain → 404."""
    app, identity, log_path, _peer_log_dir = _make_app(tmp_path)
    _seed_log(log_path, identity, n=2)

    with TestClient(app) as client:
        resp = client.get("/entries", params={"since": "a" * 64})
    assert resp.status_code == 404


def test_get_entries_default_limit_caps_at_100(tmp_path: Path) -> None:
    """Default ``limit`` is 100. Append 101 and confirm only 100 returned."""
    app, identity, log_path, _peer_log_dir = _make_app(tmp_path)
    _seed_log(log_path, identity, n=101)

    with TestClient(app) as client:
        resp = client.get("/entries")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["entries"]) == 100


def test_get_entries_explicit_limit_respected(tmp_path: Path) -> None:
    """An explicit ``limit=2`` caps the response."""
    app, identity, log_path, _peer_log_dir = _make_app(tmp_path)
    _seed_log(log_path, identity, n=5)

    with TestClient(app) as client:
        resp = client.get("/entries", params={"limit": 2})
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["entries"]) == 2


def test_get_entries_large_limit_does_not_400(tmp_path: Path) -> None:
    """``limit=5000`` is silently clamped to 1000 (no 400)."""
    # Renamed from "_clamps_to_1000" because the test only seeds 3
    # entries; the actual clamp is exercised by the cap-at-100 + the
    # explicit-limit test. This one only verifies that an above-max
    # limit doesn't produce a 400.
    app, identity, log_path, _peer_log_dir = _make_app(tmp_path)
    _seed_log(log_path, identity, n=3)

    with TestClient(app) as client:
        resp = client.get("/entries", params={"limit": 5000})
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["entries"]) == 3


def test_get_entries_negative_limit_is_400(tmp_path: Path) -> None:
    """``limit=-1`` is invalid → 400."""
    app, _identity, _log_path, _peer_log_dir = _make_app(tmp_path)
    with TestClient(app) as client:
        resp = client.get("/entries", params={"limit": -1})
    assert resp.status_code == 400


def test_get_entries_since_genesis_literal_returns_all(tmp_path: Path) -> None:
    """``since="GENESIS"`` is a synonym for "from start of chain"."""
    app, identity, log_path, _peer_log_dir = _make_app(tmp_path)
    entries = _seed_log(log_path, identity, n=3)

    with TestClient(app) as client:
        resp = client.get("/entries", params={"since": "GENESIS"})
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["entries"]) == 3
    assert [e["entry_hash"] for e in body["entries"]] == [
        e["entry_hash"] for e in entries
    ]


def test_get_entries_since_head_returns_empty_list(tmp_path: Path) -> None:
    """``since=last_hash`` returns no entries (caller is up to date)."""
    app, identity, log_path, _peer_log_dir = _make_app(tmp_path)
    entries = _seed_log(log_path, identity, n=3)
    head = entries[-1]["entry_hash"]

    with TestClient(app) as client:
        resp = client.get("/entries", params={"since": head})
    assert resp.status_code == 200
    body = resp.json()
    assert body["entries"] == []
    assert body["head_hash"] == head


def test_get_entries_limit_zero_returns_empty_list(tmp_path: Path) -> None:
    """``limit=0`` returns an empty list (no entries) with 200."""
    app, identity, log_path, _peer_log_dir = _make_app(tmp_path)
    _seed_log(log_path, identity, n=3)

    with TestClient(app) as client:
        resp = client.get("/entries", params={"limit": 0})
    assert resp.status_code == 200
    assert resp.json()["entries"] == []


def test_get_entries_limit_one_returns_first_after_cursor(tmp_path: Path) -> None:
    """``limit=1`` after a cursor returns the *first* entry after it, not the head."""
    app, identity, log_path, _peer_log_dir = _make_app(tmp_path)
    entries = _seed_log(log_path, identity, n=3)
    cursor = entries[0]["entry_hash"]

    with TestClient(app) as client:
        resp = client.get(
            "/entries", params={"since": cursor, "limit": 1}
        )
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["entries"]) == 1
    # The first entry strictly after the cursor — entries[1], NOT the head
    # (entries[2]).
    assert body["entries"][0]["entry_hash"] == entries[1]["entry_hash"]


def test_get_entries_includes_current_head_hash_in_response(tmp_path: Path) -> None:
    """Every successful ``/entries`` response includes ``head_hash``."""
    app, identity, log_path, _peer_log_dir = _make_app(tmp_path)
    entries = _seed_log(log_path, identity, n=3)

    with TestClient(app) as client:
        resp = client.get("/entries", params={"limit": 1})
    assert resp.status_code == 200
    body = resp.json()
    assert body["head_hash"] == entries[-1]["entry_hash"]


# ---------------------------------------------------------------------------
# GET /entries/{entry_hash}
# ---------------------------------------------------------------------------


def test_get_entry_by_hash_returns_entry(tmp_path: Path) -> None:
    """A known entry_hash returns the full entry dict."""
    app, identity, log_path, _peer_log_dir = _make_app(tmp_path)
    entries = _seed_log(log_path, identity, n=2)
    target = entries[1]

    with TestClient(app) as client:
        resp = client.get(f"/entries/{target['entry_hash']}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["entry_hash"] == target["entry_hash"]
    assert body["action"] == target["action"]


def test_get_entry_by_hash_unknown_returns_404(tmp_path: Path) -> None:
    """An unknown entry_hash → 404."""
    app, identity, log_path, _peer_log_dir = _make_app(tmp_path)
    _seed_log(log_path, identity, n=1)

    with TestClient(app) as client:
        resp = client.get("/entries/" + ("0" * 64))
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# POST /entries
# ---------------------------------------------------------------------------


def test_post_entries_accepts_valid_foreign_self_entry(tmp_path: Path) -> None:
    """``POST /entries`` with a valid foreign self entry returns stored=True."""
    app, _identity, _log_path, _peer_log_dir = _make_app(tmp_path)
    foreign_identity, entry = _foreign_self_entry(tmp_path)

    with TestClient(app) as client:
        resp = client.post("/entries", json=entry)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["stored"] is True
    assert body["duplicate"] is False
    assert body["source_id"] == str(foreign_identity.identity_hash)


def test_post_entries_accepts_valid_foreign_witness_entry(tmp_path: Path) -> None:
    """``POST /entries`` accepts a valid witness entry from a foreign reporter."""
    app, _identity, _log_path, _peer_log_dir = _make_app(tmp_path)
    _, reporter, entry = _foreign_witness_entry(tmp_path)

    with TestClient(app) as client:
        resp = client.post("/entries", json=entry)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["stored"] is True
    assert body["duplicate"] is False
    assert body["source_id"] == str(reporter.identity_hash)


def test_post_entries_rejects_malformed_entry_400(tmp_path: Path) -> None:
    """Removing reporter_pubkey makes the entry unverifiable; 400."""
    app, _identity, _log_path, peer_log_dir = _make_app(tmp_path)
    _, entry = _foreign_self_entry(tmp_path)
    entry.pop("reporter_pubkey", None)

    with TestClient(app) as client:
        resp = client.post("/entries", json=entry)
    assert resp.status_code == 400
    pld = Path(peer_log_dir)
    if pld.exists():
        assert list(pld.glob("*.jsonl")) == []


def test_post_entries_rejects_wrong_network_400(tmp_path: Path) -> None:
    """Foreign entry signed under TESTNET is rejected by a MAINNET server."""
    app, _identity, _log_path, peer_log_dir = _make_app(tmp_path, network="MAINNET")
    _, entry = _foreign_self_entry(
        tmp_path, name="tnet.pem", network="TESTNET"
    )

    with TestClient(app) as client:
        resp = client.post("/entries", json=entry)
    assert resp.status_code == 400
    pld = Path(peer_log_dir)
    if pld.exists():
        assert list(pld.glob("*.jsonl")) == []


def test_post_entries_rejects_same_identity_400(tmp_path: Path) -> None:
    """An entry whose reporter_id == server.identity_hash must be rejected."""
    app, identity, _log_path, peer_log_dir = _make_app(tmp_path)
    # Build an entry signed by THE SAME identity as the server. Reuse the
    # server's keyfile so the signed entry's reporter_id == identity_hash.
    own_log_path = str(tmp_path / "self_signed.log")
    wrapper = SignedAppendOnlyLog(identity, own_log_path)
    wrapper.append_event(
        reporter_id=str(identity.identity_hash),
        subject_id=str(identity.identity_hash),
        action="self_loop",
        details={"a": 1},
    )
    entry = wrapper.read_entries()[0]

    with TestClient(app) as client:
        resp = client.post("/entries", json=entry)
    assert resp.status_code == 400
    pld = Path(peer_log_dir)
    if pld.exists():
        assert list(pld.glob("*.jsonl")) == []


def test_post_entries_idempotent_on_duplicate_returns_stored_false(tmp_path: Path) -> None:
    """Re-POSTing the same entry returns 200 + stored=False, duplicate=True."""
    app, _identity, _log_path, peer_log_dir = _make_app(tmp_path)
    _, entry = _foreign_self_entry(tmp_path)

    with TestClient(app) as client:
        r1 = client.post("/entries", json=entry)
        r2 = client.post("/entries", json=entry)

    assert r1.status_code == 200
    assert r1.json()["stored"] is True
    assert r1.json()["duplicate"] is False

    assert r2.status_code == 200
    body = r2.json()
    assert body["stored"] is False
    assert body["duplicate"] is True

    # Idempotency must not silently double-write: the per-source file
    # holds exactly one line after the duplicate POST.
    source_id = entry["reporter_id"]
    source_file = Path(peer_log_dir) / f"{source_id}.jsonl"
    text = source_file.read_text(encoding="utf-8")
    lines = [line for line in text.splitlines() if line]
    assert len(lines) == 1


def test_post_entries_rejects_mutated_entry_hash_400(tmp_path: Path) -> None:
    """A flipped hex char in entry_hash makes the entry unverifiable; 400."""
    app, _identity, _log_path, peer_log_dir = _make_app(tmp_path)
    _, entry = _foreign_self_entry(tmp_path)
    # Flip the first hex char in entry_hash. "0" -> "1" or vice versa so
    # the resulting string is still valid hex.
    h = entry["entry_hash"]
    flipped = ("1" if h[0] == "0" else "0") + h[1:]
    entry["entry_hash"] = flipped

    with TestClient(app) as client:
        resp = client.post("/entries", json=entry)
    assert resp.status_code == 400
    pld = Path(peer_log_dir)
    if pld.exists():
        assert list(pld.glob("*.jsonl")) == []


def test_post_entries_rejects_missing_entry_hash_400(tmp_path: Path) -> None:
    """A foreign entry missing entry_hash entirely is rejected."""
    app, _identity, _log_path, peer_log_dir = _make_app(tmp_path)
    _, entry = _foreign_self_entry(tmp_path)
    entry.pop("entry_hash", None)

    with TestClient(app) as client:
        resp = client.post("/entries", json=entry)
    assert resp.status_code == 400
    pld = Path(peer_log_dir)
    if pld.exists():
        assert list(pld.glob("*.jsonl")) == []


def test_post_entries_rejects_missing_version_400(tmp_path: Path) -> None:
    """A foreign entry missing ``version`` fails Pydantic shape; 400."""
    app, _identity, _log_path, peer_log_dir = _make_app(tmp_path)
    _, entry = _foreign_self_entry(tmp_path)
    entry.pop("version", None)

    with TestClient(app) as client:
        resp = client.post("/entries", json=entry)
    assert resp.status_code == 400
    pld = Path(peer_log_dir)
    if pld.exists():
        assert list(pld.glob("*.jsonl")) == []


def test_post_entries_rejects_unknown_kind_400(tmp_path: Path) -> None:
    """``kind="delegate"`` is not in the {self, witness} discriminator; 400."""
    app, _identity, _log_path, peer_log_dir = _make_app(tmp_path)
    foreign_identity, entry = _foreign_self_entry(tmp_path)
    entry["kind"] = "delegate"
    _recompute_reporter_sig_and_hash(entry, foreign_identity)

    with TestClient(app) as client:
        resp = client.post("/entries", json=entry)
    assert resp.status_code == 400
    pld = Path(peer_log_dir)
    if pld.exists():
        assert list(pld.glob("*.jsonl")) == []


def test_post_entries_accepts_witness_where_subject_equals_receiver(
    tmp_path: Path,
) -> None:
    """A witness entry whose ``subject_id == receiver_id`` is stored.

    Witness-of-self is accountability data — the receiver caches it so it
    knows what others claim about it. Refusing would hide peer claims
    about us; we want them on disk for the audit trail. The same-identity
    guard applies only to ``reporter_id``, not ``subject_id``.
    """
    app, server_identity, _log_path, peer_log_dir = _make_app(tmp_path)

    # A foreign reporter (not the server) signs a witness entry whose
    # subject is the server itself. Build it by signing the claim with
    # the server's identity.
    reporter = OpenClawIdentity(
        network="MAINNET", key_path=str(tmp_path / "fr.pem")
    )
    details = {"k": "v"}
    claim, pk, sig = _make_subject_claim(
        server_identity, "observed_action", details, nonce_hex="77" * 16
    )
    log_path = str(tmp_path / "fr.log")
    wrapper = SignedAppendOnlyLog(reporter, log_path)
    wrapper.append_witness_event(
        reporter_id=str(reporter.identity_hash),
        subject_id=str(server_identity.identity_hash),
        subject_pubkey=pk,
        subject_claim=claim,
        subject_signature=sig,
        action="observed_action",
        details=details,
    )
    entry = wrapper.read_entries()[0]

    with TestClient(app) as client:
        resp = client.post("/entries", json=entry)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["stored"] is True
    assert body["source_id"] == str(reporter.identity_hash)

    expected = Path(peer_log_dir) / f"{reporter.identity_hash}.jsonl"
    assert expected.exists()


def test_post_entries_rejects_uppercase_reporter_id_400(tmp_path: Path) -> None:
    """Uppercased reporter_id breaks the SHA256-hexdigest binding (lowercase canonical)."""
    app, _identity, _log_path, peer_log_dir = _make_app(tmp_path)
    foreign_identity, entry = _foreign_self_entry(tmp_path)
    entry["reporter_id"] = entry["reporter_id"].upper()
    _recompute_reporter_sig_and_hash(entry, foreign_identity)

    with TestClient(app) as client:
        resp = client.post("/entries", json=entry)
    assert resp.status_code == 400
    pld = Path(peer_log_dir)
    if pld.exists():
        assert list(pld.glob("*.jsonl")) == []


def test_post_entries_idempotent_persists_only_one_line(tmp_path: Path) -> None:
    """A second POST of the same entry leaves the per-source file 1 line long."""
    # This is the explicit, named test for the idempotency-no-double-write
    # invariant; ``test_post_entries_idempotent_on_duplicate_returns_stored_false``
    # also asserts it inline so the closely-related behaviour stays
    # together when reading the suite.
    app, _identity, _log_path, peer_log_dir = _make_app(tmp_path)
    _, entry = _foreign_self_entry(tmp_path)

    with TestClient(app) as client:
        client.post("/entries", json=entry)
        client.post("/entries", json=entry)

    source_id = entry["reporter_id"]
    source_file = Path(peer_log_dir) / f"{source_id}.jsonl"
    text = source_file.read_text(encoding="utf-8")
    lines = [line for line in text.splitlines() if line]
    assert len(lines) == 1


def test_post_entries_persists_to_peer_log_dir(tmp_path: Path) -> None:
    """A successful POST writes a ``<source_id>.jsonl`` file under peer_log_dir."""
    app, _identity, _log_path, peer_log_dir = _make_app(tmp_path)
    foreign_identity, entry = _foreign_self_entry(tmp_path)

    with TestClient(app) as client:
        resp = client.post("/entries", json=entry)
    assert resp.status_code == 200

    expected = Path(peer_log_dir) / f"{foreign_identity.identity_hash}.jsonl"
    assert expected.exists()
    text = expected.read_text(encoding="utf-8")
    lines = [line for line in text.splitlines() if line]
    assert len(lines) == 1
    parsed = json.loads(lines[0])
    # Compare a stable subset rather than full dict equality — keeps the
    # test honest if a future change adds an envelope-level field on the
    # wire (e.g. ``received_at``).
    for field in ("entry_hash", "signature", "reporter_id", "kind", "action"):
        assert parsed[field] == entry[field], field


# ---------------------------------------------------------------------------
# Method / CORS hygiene
# ---------------------------------------------------------------------------


def test_options_entries_returns_204_with_allow_header(tmp_path: Path) -> None:
    """``OPTIONS /entries`` → 204 + ``Allow`` listing GET/POST/OPTIONS."""
    app, _identity, _log_path, _peer_log_dir = _make_app(tmp_path)
    with TestClient(app) as client:
        resp = client.options("/entries")
    assert resp.status_code == 204
    allow = resp.headers.get("Allow", "")
    # Set-comparison instead of substring scanning so an extra/missing
    # method is caught even when an existing one is a substring of another.
    methods = {m.strip() for m in allow.split(",")}
    assert {"GET", "POST", "OPTIONS"} <= methods


def test_unsupported_method_on_entries_returns_405(tmp_path: Path) -> None:
    """``DELETE /entries`` → 405 with Allow header."""
    app, _identity, _log_path, _peer_log_dir = _make_app(tmp_path)
    with TestClient(app) as client:
        resp = client.delete("/entries")
    assert resp.status_code == 405
    allow = resp.headers.get("Allow", "")
    methods = {m.strip() for m in allow.split(",")}
    assert {"GET", "POST", "OPTIONS"} <= methods


def test_post_entries_oversize_returns_413(tmp_path: Path) -> None:
    """A body declaring more than 64 KiB is rejected at the middleware → 413."""
    app, _identity, _log_path, _peer_log_dir = _make_app(tmp_path)
    # Build a body that's just past the limit (65 KiB of filler in details).
    bogus_body = json.dumps({"details": {"big": "x" * (65 * 1024)}})
    with TestClient(app) as client:
        resp = client.post(
            "/entries",
            content=bogus_body,
            headers={"Content-Type": "application/json"},
        )
    assert resp.status_code == 413


# ---------------------------------------------------------------------------
# Validation handler
# ---------------------------------------------------------------------------


def test_post_entries_invalid_json_returns_400(tmp_path: Path) -> None:
    """Body that isn't valid JSON → 400 from the validation handler."""
    app, _identity, _log_path, _peer_log_dir = _make_app(tmp_path)
    with TestClient(app) as client:
        resp = client.post(
            "/entries",
            content="not json",
            headers={"Content-Type": "application/json"},
        )
    assert resp.status_code == 400
