"""Tests for ``deploy.scenario_boot._load_host_env``.

The per-host config file ``configs/.env`` is gitignored — every dev sets
their own. These tests pin the dotenv-light parser so the behaviour stays
predictable across machines:

  * KEY=VALUE pairs roundtrip.
  * blank lines + ``#`` comments are skipped.
  * KEY= (empty value) is treated as "unset".
  * missing file yields {} (no error).
  * env var on the process wins over the file (resolution order matters).
  * LLM_* / LLM_API_PROVIDER are required: absent everywhere -> fail loud.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from deploy import scenario_boot


def test_load_host_env_returns_empty_when_missing(tmp_path):
    assert scenario_boot._load_host_env(tmp_path / "nope.env") == {}


def test_load_host_env_parses_basic_pairs(tmp_path):
    (tmp_path / "host.env").write_text("FOO=bar\nBAZ=qux\n", encoding="utf-8")
    assert scenario_boot._load_host_env(tmp_path / "host.env") == {
        "FOO": "bar",
        "BAZ": "qux",
    }


def test_load_host_env_ignores_comments_and_blank_lines(tmp_path):
    body = (
        "# comment line\n"
        "\n"
        "KEY1=val1\n"
        "   # indented comment\n"
        "KEY2=val2\n"
    )
    (tmp_path / "host.env").write_text(body, encoding="utf-8")
    assert scenario_boot._load_host_env(tmp_path / "host.env") == {
        "KEY1": "val1",
        "KEY2": "val2",
    }


def test_load_host_env_empty_value_is_dropped(tmp_path):
    """``KEY=`` with no value is treated as unset (dropped from the dict)."""
    (tmp_path / "host.env").write_text("KEY=\nOTHER=hello\n", encoding="utf-8")
    assert scenario_boot._load_host_env(tmp_path / "host.env") == {"OTHER": "hello"}


def test_load_host_env_handles_whitespace(tmp_path):
    (tmp_path / "host.env").write_text("  KEY  =  spaced value  \n", encoding="utf-8")
    assert scenario_boot._load_host_env(tmp_path / "host.env") == {
        "KEY": "spaced value",
    }


# Every _resolve_llm test clears the three LLM_* vars from the process env first
# so the result depends only on the fixture file, never on a configs/.env the
# developer happened to source into their shell.
def _clear_llm(monkeypatch):
    for name in ("LLM_BASE_URL", "LLM_MODEL", "LLM_API_KEY"):
        monkeypatch.delenv(name, raising=False)


def test_llm_resolution_env_var_wins_over_host_env(monkeypatch, tmp_path):
    """Process env wins over the file."""
    _clear_llm(monkeypatch)
    host_env = tmp_path / "host.env"
    host_env.write_text(
        "LLM_BASE_URL=http://host-env-url:9999/v1\n"
        "LLM_MODEL=host-env-model\n"
        "LLM_API_KEY=host-key\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("LLM_BASE_URL", "http://env-var-url:8000/v1")
    monkeypatch.setenv("LLM_MODEL", "env-var-model")

    base, model, _api_key = scenario_boot._resolve_llm(host_env)
    assert base == "http://env-var-url:8000/v1"
    assert model == "env-var-model"


def test_llm_resolution_uses_host_env_when_no_process_env(monkeypatch, tmp_path):
    """With nothing in the process env, all three come from the file."""
    _clear_llm(monkeypatch)
    host_env = tmp_path / "host.env"
    host_env.write_text(
        "LLM_BASE_URL=http://host-env-only/v1\n"
        "LLM_MODEL=host-env-model\n"
        "LLM_API_KEY=host-key\n",
        encoding="utf-8",
    )
    base, model, api_key = scenario_boot._resolve_llm(host_env)
    assert base == "http://host-env-only/v1"
    assert model == "host-env-model"
    assert api_key == "host-key"


def test_llm_resolution_errors_when_unset(monkeypatch, tmp_path):
    """No defaults: missing LLM_* in both process env AND the file is a
    fail-loud configuration error, not a silent fallback."""
    _clear_llm(monkeypatch)
    with pytest.raises(SystemExit):
        scenario_boot._resolve_llm(tmp_path / "no_such.env")


def test_llm_api_key_resolution(monkeypatch, tmp_path):
    """LLM_API_KEY follows the same env > file order (base/model present)."""
    _clear_llm(monkeypatch)
    host_env = tmp_path / "host.env"
    host_env.write_text(
        "LLM_BASE_URL=http://h/v1\nLLM_MODEL=m\nLLM_API_KEY=from-host-env\n",
        encoding="utf-8",
    )
    _b, _m, key = scenario_boot._resolve_llm(host_env)
    assert key == "from-host-env"

    monkeypatch.setenv("LLM_API_KEY", "from-process-env")
    _b, _m, key = scenario_boot._resolve_llm(host_env)
    assert key == "from-process-env"


def test_resolve_llm_partial_config_errors(monkeypatch, tmp_path):
    """A partial file (only one of the three set) is an error — we don't
    backfill the missing ones from defaults."""
    _clear_llm(monkeypatch)
    host_env = tmp_path / "host.env"
    host_env.write_text("LLM_MODEL=host-env-model-only\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        scenario_boot._resolve_llm(host_env)
