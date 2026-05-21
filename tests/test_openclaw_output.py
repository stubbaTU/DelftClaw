from __future__ import annotations

from deploy.openclaw_output import parse_openclaw_json_stdout


def test_parse_openclaw_json_extracts_texts() -> None:
    summary = parse_openclaw_json_stdout(
        '{"payloads":[{"text":"hello"},{"text":"world","mediaUrl":null}]}'
    )
    assert summary.texts == ("hello", "world")
    assert summary.assistant_text == "hello\nworld"
    assert summary.semantic_error is None
    assert summary.parse_error is None


def test_parse_openclaw_json_allows_empty_payloads() -> None:
    summary = parse_openclaw_json_stdout('{"payloads":[]}')
    assert summary.texts == ()
    assert summary.assistant_text == ""
    assert summary.semantic_error is None
    assert summary.parse_error is None


def test_parse_openclaw_json_flags_literal_error() -> None:
    summary = parse_openclaw_json_stdout('{"payloads":[{"text":"ERROR"}]}')
    assert summary.semantic_error == "openclaw_semantic_error:literal_ERROR"


def test_parse_openclaw_json_reports_malformed_json() -> None:
    summary = parse_openclaw_json_stdout("{not json")
    assert summary.texts == ()
    assert summary.semantic_error is None
    assert summary.parse_error is not None
    assert summary.parse_error.startswith("json_decode_error:")
