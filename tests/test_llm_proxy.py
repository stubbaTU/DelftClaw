from __future__ import annotations

import json

from scripts.llm_proxy import _normalise_chat_completion_body


def test_llm_proxy_normalises_null_message_content() -> None:
    body = json.dumps({
        "model": "deepseek/deepseek-v4-flash:free",
        "messages": [
            {"role": "system", "content": "sys"},
            {"role": "assistant", "content": None},
        ],
    }).encode("utf-8")

    out = json.loads(_normalise_chat_completion_body(body))

    assert out["messages"][1]["content"] == ""


def test_llm_proxy_normalises_structured_message_content() -> None:
    body = json.dumps({
        "messages": [
            {"role": "tool", "content": {"address": "bcrt1qabc"}},
        ],
    }).encode("utf-8")

    out = json.loads(_normalise_chat_completion_body(body))

    assert out["messages"][0]["content"] == '{"address": "bcrt1qabc"}'


def test_llm_proxy_preserves_valid_string_and_part_content() -> None:
    body = json.dumps({
        "messages": [
            {"role": "user", "content": "hello"},
            {"role": "user", "content": [{"type": "text", "text": "hello"}]},
        ],
    }).encode("utf-8")

    assert _normalise_chat_completion_body(body) == body


def test_llm_proxy_leaves_non_chat_payloads_unchanged() -> None:
    body = b'{"data":[{"id":"model"}]}'

    assert _normalise_chat_completion_body(body) == body
