"""Bounded 429/503 retry in OpenAICompatibleClient.complete.

The overlay author path makes one real-LLM call per watchdog tick; a single
transient 429 used to fail the whole authoring action (the agent only retried
~240s later, sometimes going off-script). These tests pin the in-call retry:
retry on 429/503, honour a sane Retry-After, give up after max_retries, and
NEVER retry a non-throttling error. urlopen + sleep are mocked — no network.
"""

from __future__ import annotations

import io
import json
import urllib.error

import pytest

from protocol.llm import OpenAICompatibleClient


def _ok_response():
    body = json.dumps({"choices": [{"message": {"content": "ok-body"}}]}).encode("utf-8")
    resp = io.BytesIO(body)
    resp.__enter__ = lambda self=resp: self  # type: ignore[attr-defined]
    resp.__exit__ = lambda *a, **k: False    # type: ignore[attr-defined]
    return resp


def _http_error(code: int, headers: dict | None = None):
    return urllib.error.HTTPError(
        url="http://x/v1/chat/completions", code=code, msg="boom",
        hdrs=headers or {}, fp=io.BytesIO(b""),
    )


def _client(**kw):
    return OpenAICompatibleClient(base_url="http://x/v1", model_id="m", **kw)


def test_retries_then_succeeds_on_transient_429(monkeypatch):
    sleeps: list[float] = []
    monkeypatch.setattr("time.sleep", lambda s: sleeps.append(s))

    calls = {"n": 0}

    def fake_urlopen(req, timeout=None):
        calls["n"] += 1
        if calls["n"] < 3:           # first two attempts 429
            raise _http_error(429)
        return _ok_response()         # third succeeds

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    out = _client(max_retries=4).complete("sys", "usr")
    assert out == "ok-body"
    assert calls["n"] == 3
    assert len(sleeps) == 2           # slept before each of the 2 retries


def test_gives_up_after_max_retries(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda s: None)
    monkeypatch.setattr("urllib.request.urlopen",
                        lambda req, timeout=None: (_ for _ in ()).throw(_http_error(429)))
    with pytest.raises(urllib.error.HTTPError) as ei:
        _client(max_retries=2).complete("sys", "usr")
    assert ei.value.code == 429


def test_non_throttling_error_is_not_retried(monkeypatch):
    calls = {"n": 0}

    def fake_urlopen(req, timeout=None):
        calls["n"] += 1
        raise _http_error(400)        # validation/auth — must NOT retry

    monkeypatch.setattr("time.sleep", lambda s: None)
    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    with pytest.raises(urllib.error.HTTPError):
        _client(max_retries=4).complete("sys", "usr")
    assert calls["n"] == 1


def test_retry_after_header_is_honoured_and_capped():
    c = _client(retry_cap_s=15.0)
    # Numeric Retry-After within cap is used verbatim.
    assert c._retry_delay(_http_error(429, {"Retry-After": "7"}), attempt=0) == 7.0
    # Oversized Retry-After is clamped to the cap.
    assert c._retry_delay(_http_error(429, {"Retry-After": "600"}), attempt=0) == 15.0
    # No header -> exponential backoff (also capped).
    assert c._retry_delay(_http_error(429, {}), attempt=0) == 1.5
    assert c._retry_delay(_http_error(429, {}), attempt=10) == 15.0
