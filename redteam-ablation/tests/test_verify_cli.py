"""Vendored verify CLI: OK on a fresh signed log; failure when a byte flips."""

from redteam_ablation.primitives import verify
from redteam_ablation.primitives.identity import Ed25519Identity
from redteam_ablation.primitives.signed_log import SignedAppendOnlyLog


def _write_log(tmp_path, network="MAINNET"):
    identity = Ed25519Identity(network=network)
    log_path = tmp_path / "verify_me.log"
    log = SignedAppendOnlyLog(identity, log_path)
    rid = identity.reporter_id
    log.append_event(reporter_id=rid, subject_id=rid, action="a", details={"i": 1})
    log.append_event(reporter_id=rid, subject_id=rid, action="b", details={"i": 2})
    return identity, log_path


def test_verify_main_ok_on_fresh_log(tmp_path, capsys):
    _identity, log_path = _write_log(tmp_path)
    rc = verify.main(["--log", str(log_path), "--network", "MAINNET"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Verified 2 entries: OK" in out


def test_verify_main_missing_file_returns_2(tmp_path):
    rc = verify.main(["--log", str(tmp_path / "nope.log")])
    assert rc == 2


def test_verify_main_detects_single_byte_tamper(tmp_path, capsys):
    _identity, log_path = _write_log(tmp_path)

    lines = log_path.read_text(encoding="utf-8").splitlines(keepends=True)
    # lines[0] is the header; lines[1] is the first entry. Flip one char in a
    # signature hex digit so the signature no longer verifies.
    entry_line = lines[1]
    idx = entry_line.index('"signature": "') + len('"signature": "')
    original_char = entry_line[idx]
    replacement = "0" if original_char != "0" else "1"
    tampered_line = entry_line[:idx] + replacement + entry_line[idx + 1:]
    lines[1] = tampered_line
    log_path.write_text("".join(lines), encoding="utf-8")

    rc = verify.main(["--log", str(log_path), "--network", "MAINNET"])
    out = capsys.readouterr().out
    assert rc == 1
    assert "entry 1" in out
