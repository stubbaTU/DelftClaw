"""RED tests for ``redteam_ablation.live.trace`` (plan 2026-06-11 §1.2 / §4).

Contracts these tests pin (Green must honour them):

* ``parse_session_jsonl(path) -> SessionTrace`` where ``SessionTrace`` has
  ``tool_calls: list`` (each element has ``id``, ``name``, ``input``,
  ``result_text``, ``is_error``) and ``final_text: str | None``.
* ``find_session_jsonl(home, session_id) -> Path`` globs
  ``<home>/.claude/projects/*/<session_id>.jsonl``.

Schema is the verbatim Claude Code session JSONL shape documented in plan §0.1.
Assumptions (documented because the plan leaves the field NAMES, not the shape,
to Green): the per-tool-call record exposes attribute access ``.id``, ``.name``,
``.input``, ``.result_text``, ``.is_error`` (the plan names these fields). The
``SessionTrace`` exposes ``.tool_calls`` and ``.final_text``.
"""

from __future__ import annotations

import json

import pytest

from redteam_ablation.live.trace import (
    find_session_jsonl,
    parse_session_jsonl,
)


# --- fixture builders (verbatim §0.1 shapes) -------------------------------


def _assistant_tool_use(tool_id, name, tool_input, *, with_caller=True):
    block = {
        "type": "tool_use",
        "id": tool_id,
        "name": name,
        "input": tool_input,
    }
    if with_caller:
        block["caller"] = {"type": "direct"}
    return {
        "type": "assistant",
        "isSidechain": False,
        "message": {"content": [block]},
    }


def _user_tool_result(tool_use_id, content, *, is_error=None):
    block = {
        "type": "tool_result",
        "tool_use_id": tool_use_id,
        "content": content,
    }
    if is_error is not None:
        block["is_error"] = is_error
    return {"type": "user", "message": {"content": [block]}}


def _assistant_text(text, *, sidechain=False):
    return {
        "type": "assistant",
        "isSidechain": sidechain,
        "message": {"content": [{"type": "text", "text": text}]},
    }


def _write_jsonl(path, objects):
    path.write_text(
        "\n".join(json.dumps(obj) for obj in objects) + "\n",
        encoding="utf-8",
    )
    return path


# --- parse_session_jsonl ---------------------------------------------------


def test_parse_returns_tool_calls_in_order(tmp_path):
    path = _write_jsonl(
        tmp_path / "s.jsonl",
        [
            {"type": "mode", "mode": "default"},  # bookkeeping; skipped
            _assistant_tool_use("toolu_A", "mcp__harness__send_email", {"to": "x"}),
            _user_tool_result("toolu_A", "ok"),
            _assistant_tool_use("toolu_B", "mcp__harness__write_file", {"path": "p"}),
            _user_tool_result("toolu_B", "wrote"),
        ],
    )
    trace = parse_session_jsonl(path)
    assert [tc.id for tc in trace.tool_calls] == ["toolu_A", "toolu_B"]
    assert [tc.name for tc in trace.tool_calls] == [
        "mcp__harness__send_email",
        "mcp__harness__write_file",
    ]


def test_parse_preserves_mcp_tool_names_and_input(tmp_path):
    path = _write_jsonl(
        tmp_path / "s.jsonl",
        [
            _assistant_tool_use(
                "toolu_A", "mcp__harness__send_email", {"to": "victim@x"}
            ),
            _user_tool_result("toolu_A", "ok"),
        ],
    )
    trace = parse_session_jsonl(path)
    assert trace.tool_calls[0].name == "mcp__harness__send_email"
    assert trace.tool_calls[0].input == {"to": "victim@x"}


def test_parse_tolerates_missing_caller(tmp_path):
    path = _write_jsonl(
        tmp_path / "s.jsonl",
        [
            _assistant_tool_use(
                "toolu_A", "mcp__harness__send_email", {"to": "x"},
                with_caller=False,
            ),
            _user_tool_result("toolu_A", "ok"),
        ],
    )
    trace = parse_session_jsonl(path)
    assert len(trace.tool_calls) == 1
    assert trace.tool_calls[0].id == "toolu_A"


def test_parse_normalises_string_content(tmp_path):
    path = _write_jsonl(
        tmp_path / "s.jsonl",
        [
            _assistant_tool_use("toolu_A", "mcp__harness__send_email", {}),
            _user_tool_result("toolu_A", "plain string result"),
        ],
    )
    trace = parse_session_jsonl(path)
    assert trace.tool_calls[0].result_text == "plain string result"


def test_parse_normalises_list_content(tmp_path):
    path = _write_jsonl(
        tmp_path / "s.jsonl",
        [
            _assistant_tool_use("toolu_A", "mcp__harness__send_email", {}),
            _user_tool_result(
                "toolu_A",
                [{"type": "text", "text": "block one"}],
            ),
        ],
    )
    trace = parse_session_jsonl(path)
    assert "block one" in trace.tool_calls[0].result_text


def test_parse_surfaces_is_error_true(tmp_path):
    path = _write_jsonl(
        tmp_path / "s.jsonl",
        [
            _assistant_tool_use("toolu_A", "mcp__harness__drain_wallet", {}),
            _user_tool_result("toolu_A", "DENIED: nope", is_error=True),
        ],
    )
    trace = parse_session_jsonl(path)
    assert trace.tool_calls[0].is_error is True


def test_parse_is_error_falsy_when_absent(tmp_path):
    path = _write_jsonl(
        tmp_path / "s.jsonl",
        [
            _assistant_tool_use("toolu_A", "mcp__harness__send_email", {}),
            _user_tool_result("toolu_A", "ok"),  # no is_error key
        ],
    )
    trace = parse_session_jsonl(path)
    assert not trace.tool_calls[0].is_error


def test_parse_pairs_result_to_use_by_id(tmp_path):
    # Results arrive out of order relative to uses; pairing is by id.
    path = _write_jsonl(
        tmp_path / "s.jsonl",
        [
            _assistant_tool_use("toolu_A", "mcp__harness__send_email", {}),
            _assistant_tool_use("toolu_B", "mcp__harness__write_file", {}),
            _user_tool_result("toolu_B", "result-for-B"),
            _user_tool_result("toolu_A", "result-for-A"),
        ],
    )
    trace = parse_session_jsonl(path)
    by_id = {tc.id: tc for tc in trace.tool_calls}
    assert by_id["toolu_A"].result_text == "result-for-A"
    assert by_id["toolu_B"].result_text == "result-for-B"


def test_parse_excludes_sidechain_lines(tmp_path):
    path = _write_jsonl(
        tmp_path / "s.jsonl",
        [
            _assistant_tool_use("toolu_A", "mcp__harness__send_email", {}),
            _user_tool_result("toolu_A", "ok"),
            # subagent traffic: must NOT appear in the trace.
            {
                "type": "assistant",
                "isSidechain": True,
                "message": {
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "toolu_SIDE",
                            "name": "mcp__harness__drain_wallet",
                            "input": {},
                        }
                    ]
                },
            },
            {
                "type": "user",
                "isSidechain": True,
                "message": {
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "toolu_SIDE",
                            "content": "side ok",
                        }
                    ]
                },
            },
        ],
    )
    trace = parse_session_jsonl(path)
    assert [tc.id for tc in trace.tool_calls] == ["toolu_A"]


def test_final_text_is_last_main_chain_text(tmp_path):
    path = _write_jsonl(
        tmp_path / "s.jsonl",
        [
            _assistant_text("first answer"),
            _assistant_tool_use("toolu_A", "mcp__harness__send_email", {}),
            _user_tool_result("toolu_A", "ok"),
            _assistant_text("final answer"),
        ],
    )
    trace = parse_session_jsonl(path)
    assert trace.final_text == "final answer"


def test_final_text_excludes_sidechain_text(tmp_path):
    path = _write_jsonl(
        tmp_path / "s.jsonl",
        [
            _assistant_text("main answer"),
            _assistant_text("sidechain answer", sidechain=True),
        ],
    )
    trace = parse_session_jsonl(path)
    assert trace.final_text == "main answer"


def test_final_text_none_when_no_text(tmp_path):
    path = _write_jsonl(
        tmp_path / "s.jsonl",
        [
            _assistant_tool_use("toolu_A", "mcp__harness__send_email", {}),
            _user_tool_result("toolu_A", "ok"),
        ],
    )
    trace = parse_session_jsonl(path)
    assert trace.final_text is None


def test_parse_skips_bookkeeping_types(tmp_path):
    path = _write_jsonl(
        tmp_path / "s.jsonl",
        [
            {"type": "system", "subtype": "init"},
            {"type": "mode", "mode": "default"},
            {"type": "permission-mode", "mode": "bypassPermissions"},
            {"type": "file-history-snapshot", "messageId": "m"},
            {"type": "attachment", "id": "a"},
            {"type": "ai-title", "title": "t"},
            {"type": "last-prompt", "prompt": "p"},
            _assistant_tool_use("toolu_A", "mcp__harness__send_email", {}),
            _user_tool_result("toolu_A", "ok"),
        ],
    )
    trace = parse_session_jsonl(path)
    assert len(trace.tool_calls) == 1


def test_parse_raises_on_malformed_line(tmp_path):
    path = tmp_path / "s.jsonl"
    good = json.dumps(_assistant_text("hello"))
    path.write_text(good + "\n" + "{not valid json\n", encoding="utf-8")
    with pytest.raises(Exception):
        parse_session_jsonl(path)


# --- find_session_jsonl ----------------------------------------------------


def _make_session_file(home, hash_dir, session_id):
    projects = home / ".claude" / "projects" / hash_dir
    projects.mkdir(parents=True, exist_ok=True)
    f = projects / f"{session_id}.jsonl"
    f.write_text("{}\n", encoding="utf-8")
    return f


def test_find_session_jsonl_globs_by_id(tmp_path):
    home = tmp_path / "home"
    target = _make_session_file(home, "-some-path-hash", "sess-123")
    found = find_session_jsonl(home, "sess-123")
    assert str(found) == str(target)


def test_find_session_jsonl_raises_on_zero_matches(tmp_path):
    home = tmp_path / "home"
    (home / ".claude" / "projects").mkdir(parents=True, exist_ok=True)
    with pytest.raises(Exception):
        find_session_jsonl(home, "no-such-session")


def test_find_session_jsonl_raises_on_multiple_matches(tmp_path):
    home = tmp_path / "home"
    _make_session_file(home, "-hash-dir-one", "dup-session")
    _make_session_file(home, "-hash-dir-two", "dup-session")
    with pytest.raises(Exception):
        find_session_jsonl(home, "dup-session")
